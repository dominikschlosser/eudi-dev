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

// CreateConsentRequest creates a new consent request and notifies subscribers.
func (w *Wallet) CreateConsentRequest(req *ConsentRequest) {
	rt := w.runtimeState()
	rt.mu.Lock()
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
func (w *Wallet) SubscribeAuthorization() (<-chan string, func()) {
	ch := make(chan string, 4)
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
func (w *Wallet) NotifyAuthorization(authURL string) bool {
	rt := w.runtimeState()
	rt.mu.Lock()
	subs := make([]chan string, 0, len(rt.authSubscribers))
	for _, ch := range rt.authSubscribers {
		subs = append(subs, ch)
	}
	rt.mu.Unlock()

	delivered := false
	for _, ch := range subs {
		select {
		case ch <- authURL:
			delivered = true
		default:
		}
	}
	return delivered
}

// NotifyError sends an error event to all subscribers and stores it for polling.
func (w *Wallet) NotifyError(err WalletError) {
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.lastError = &err
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

// PopLastError returns and clears the last error, if any.
func (w *Wallet) PopLastError() *WalletError {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	err := rt.lastError
	rt.lastError = nil
	return err
}

// PeekLastError returns the last error without clearing it.
func (w *Wallet) PeekLastError() *WalletError {
	rt := w.runtimeState()
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if rt.lastError == nil {
		return nil
	}
	err := *rt.lastError
	return &err
}

// ClearLastError clears the last error, if any.
func (w *Wallet) ClearLastError() {
	rt := w.runtimeState()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.lastError = nil
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
