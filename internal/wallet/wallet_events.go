// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import "time"

// Retention for the consent registry. The registry lives for the process
// and a shared demo serves anonymous visitors, so it prunes itself: a
// resolved request stays visible long enough for a late poll, and every
// request goes eventually (the consent flows time out after five minutes,
// so an hour-old pending entry has no waiter left).
const (
	resolvedConsentRetention = 10 * time.Minute
	consentRequestMaxAge     = time.Hour
)

// CreateConsentRequest creates a new consent request and notifies subscribers.
func (w *Wallet) CreateConsentRequest(req *ConsentRequest) {
	rt := w.runtimeState()
	rt.mu.Lock()
	now := time.Now()
	// The registry owns the timestamp its retention is measured against.
	if req.CreatedAt.IsZero() {
		req.CreatedAt = now
	}
	for id, r := range rt.requests {
		age := now.Sub(r.CreatedAt)
		if age > consentRequestMaxAge || (r.Status != "pending" && age > resolvedConsentRetention) {
			delete(rt.requests, id)
		}
	}
	rt.requests[req.ID] = req
	subs := make([]chan *ConsentRequest, 0, len(rt.subscribers))
	for _, ch := range rt.subscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
}

// GetRequest returns a consent request by ID.
func (w *Wallet) GetRequest(id string) (*ConsentRequest, bool) {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	req, ok := rt.requests[id]
	return req, ok
}

// statusExpired is what a request nobody answered in time becomes. Telling it
// apart from "denied" is what lets the wallet say which one happened when it
// refuses a late answer.
const statusExpired = "expired"

// ResolveRequest atomically transitions a consent request from "pending" to
// the given status. It returns false if the request was not found or was
// already resolved.
func (w *Wallet) ResolveRequest(id, status string) (*ConsentRequest, bool) {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	req, ok := rt.requests[id]
	if !ok || req.Status != "pending" {
		return req, false
	}
	req.Status = status
	return req, true
}

// PendingRequestDocsFor lists the pending requests one caller may see: its own,
// the unowned ones, and one it names by id. The wallet hands that id to a
// browser in the redirect it answers with, so a browser that keeps no cookie
// still reaches the request it was redirected for. Marshaled under the
// registry lock: Status is written under that lock when a request resolves, so
// the snapshot and the read are ordered.
func (w *Wallet) PendingRequestDocsFor(owners []string, named string) []map[string]any {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	docs := make([]map[string]any, 0, len(rt.requests))
	for _, r := range rt.requests {
		if r.Status == "pending" && ownsRequest(owners, r, named) {
			docs = append(docs, marshalConsentRequestFor(r, owners))
		}
	}
	return docs
}

// RequestDocFor marshals one consent request as one caller sees it, under the
// registry lock that PendingRequestDocsFor holds for the same ordering reason.
func (w *Wallet) RequestDocFor(r *ConsentRequest, owners []string) map[string]any {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return marshalConsentRequestFor(r, owners)
}

// marshalConsentRequestFor adds "mine", which is what decides between the
// dialog and the banner.
func marshalConsentRequestFor(r *ConsentRequest, owners []string) map[string]any {
	doc := MarshalConsentRequest(r)
	doc["mine"] = ownedBy(owners, r.Owner)
	return doc
}

// GetPendingRequests returns all pending consent requests.
func (w *Wallet) GetPendingRequests() []*ConsentRequest {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var out []*ConsentRequest
	for _, r := range rt.requests {
		if r.Status == "pending" {
			out = append(out, r)
		}
	}
	return out
}

// AttachedUIs reports how many event streams are open. A wallet with one does
// not need to open a browser for a request: the tab watching is told.
func (w *Wallet) AttachedUIs() int {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return len(rt.subscribers)
}

// Subscribe returns a channel for new consent requests and an unsubscribe function.
func (w *Wallet) Subscribe() (<-chan *ConsentRequest, func()) {
	ch := make(chan *ConsentRequest, 16)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.subID++
	id := rt.subID
	rt.subscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.subscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// SubscribeErrors returns a channel for error events and an unsubscribe function.
func (w *Wallet) SubscribeErrors() (<-chan WalletError, func()) {
	ch := make(chan WalletError, 16)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.errSubID++
	id := rt.errSubID
	rt.errSubscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.errSubscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// SubscribeAuthorization returns a channel carrying authorization URLs the user
// must visit to finish an issuance, plus an unsubscribe function. A local
// wallet opens one; a hosted wallet hands the URL to the open UI tab. Either
// way the login happens inside the flow, between the authorization request and
// the token exchange.
func (w *Wallet) SubscribeAuthorization() (<-chan AuthorizationPrompt, func()) {
	ch := make(chan AuthorizationPrompt, 4)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.authSubID++
	id := rt.authSubID
	rt.authSubscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.authSubscribers, id)
		rt.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// NotifyAuthorization offers an authorization URL to the open UIs. It reports
// whether anyone took it, so a wallet with no UI attached can fall back to
// opening a browser locally.
func (w *Wallet) NotifyAuthorization(prompt AuthorizationPrompt) bool {
	rt := w.runtimeState()
	rt.mu.Lock()
	subs := make([]chan AuthorizationPrompt, 0, len(rt.authSubscribers))
	for _, ch := range rt.authSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	delivered := false
	for _, ch := range subs {
		select {
		case ch <- prompt:
			delivered = true
		default:
		}
	}
	return delivered
}

// NotifyError sends an error event to the subscribers it belongs to and stores
// it for polling.
func (w *Wallet) NotifyError(err WalletError) {
	rt := w.runtimeState()
	rt.mu.Lock()
	now := time.Now()
	// The unowned slot is a key like any other, so the oldest one is tracked
	// with a flag rather than by an empty name.
	var oldest string
	var haveOldest bool
	for owner, stored := range rt.lastErrors {
		if now.Sub(stored.at) > lastErrorRetention {
			delete(rt.lastErrors, owner)
			continue
		}
		if !haveOldest || stored.at.Before(rt.lastErrors[oldest].at) {
			oldest, haveOldest = owner, true
		}
	}
	// Callers choose the key, so age alone does not bound this.
	if _, held := rt.lastErrors[err.Owner]; !held && len(rt.lastErrors) >= maxStoredErrors && haveOldest {
		delete(rt.lastErrors, oldest)
	}
	rt.lastErrors[err.Owner] = &storedError{err: err, at: now}
	subs := make([]chan WalletError, 0, len(rt.errSubscribers))
	for _, ch := range rt.errSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- err:
		default:
		}
	}
}

// PeekLastError returns the last error one caller may read, without clearing.
func (w *Wallet) PeekLastError(owners []string) *WalletError {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, owner := range errorSlots(owners) {
		if stored := rt.lastErrors[owner]; stored != nil && time.Since(stored.at) <= lastErrorRetention {
			err := stored.err
			return &err
		}
	}
	return nil
}

// ClearLastError clears every slot the same caller may read, so an error a
// caller was shown is one it can dismiss. It clears the unowned slot too, both
// on a dismissal and when a caller starts something new: the alternative is a
// report nobody named a browser for surfacing later against an unrelated flow,
// in a tab whose visitor had nothing to do with it. A client with no browser
// prints its own failure where it was run, so that slot is the wallet's second
// channel for it, not its only one.
func (w *Wallet) ClearLastError(owners []string) {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, slot := range errorSlots(owners) {
		delete(rt.lastErrors, slot)
	}
}

// errorSlots are the slots a caller may read, its own first. The unowned slot
// holds what a client that named no browser ran into, which is every client
// with no browser to name, so it stays readable by all of them.
func errorSlots(owners []string) []string {
	return append(append([]string{}, owners...), "")
}

// SetNextError sets a one-shot error override for the next presentation request.
func (w *Wallet) SetNextError(e *NextErrorOverride) {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.nextError = e
}

// ConsumeNextError returns and clears the next error override, if any.
func (w *Wallet) ConsumeNextError() *NextErrorOverride {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e := rt.nextError
	rt.nextError = nil
	return e
}

// SubscribeState returns a channel that receives a signal whenever wallet
// state changed (credentials, status entries, activity log), so open UIs can
// refresh immediately. The signal carries no payload.
func (w *Wallet) SubscribeState() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.stateSubID++
	id := rt.stateSubID
	rt.stateSubscribers[id] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.stateSubscribers, id)
		rt.mu.Unlock()
	}
}

// NotifyStateChanged signals all state subscribers. Sends never block: the
// one-slot channel coalesces bursts into a single refresh.
func (w *Wallet) NotifyStateChanged() {
	rt := w.runtimeState()
	rt.mu.Lock()
	subs := make([]chan struct{}, 0, len(rt.stateSubscribers))
	for _, ch := range rt.stateSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// AuthorizationPrompt is an issuer sign-in the wallet needs a browser to
// perform. Owner is the browser whose issuance it belongs to, empty when the
// client that started it named none.
type AuthorizationPrompt struct {
	URL   string
	Owner string
}

// storedError is the last error one owner ran into, with when it arrived. A
// caller names its own owner, so the map is keyed by a value callers choose
// and has to shed what nobody came back for.
type storedError struct {
	err WalletError
	at  time.Time
}

// lastErrorRetention is how long an unread error waits for the browser it
// belongs to. It outlasts a page load and a reconnect, which is all the tab
// needs to come back and read it.
const lastErrorRetention = 10 * time.Minute

// maxStoredErrors caps how many slots are held at once, because a caller names
// its own and can name a new one on every call. Age alone would let a burst
// grow the map before anything in it expires.
const maxStoredErrors = 64
