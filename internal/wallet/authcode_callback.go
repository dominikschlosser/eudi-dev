package wallet

import (
	"net/url"
)

// RegisterAuthorizationCodeCallback reserves a callback slot for the given state.
// The returned channel receives the eventual redirect query values.
func (w *Wallet) RegisterAuthorizationCodeCallback(state string) (<-chan url.Values, func()) {
	ch := make(chan url.Values, 1)
	rt := w.runtimeState()
	rt.mu.Lock()
	rt.authCodeCallbacks[state] = ch
	rt.mu.Unlock()

	return ch, func() {
		rt.mu.Lock()
		delete(rt.authCodeCallbacks, state)
		rt.mu.Unlock()
	}
}

// CompleteAuthorizationCodeCallback delivers the redirect query values to a waiting flow.
func (w *Wallet) CompleteAuthorizationCodeCallback(values url.Values) bool {
	state := values.Get("state")
	if state == "" {
		return false
	}

	rt := w.runtimeState()
	rt.mu.Lock()
	ch, ok := rt.authCodeCallbacks[state]
	if ok {
		delete(rt.authCodeCallbacks, state)
	}
	rt.mu.Unlock()
	if !ok {
		return false
	}

	select {
	case ch <- values:
	default:
	}
	return true
}
