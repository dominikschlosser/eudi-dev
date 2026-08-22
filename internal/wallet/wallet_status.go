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

import (
	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/statuslist"
)

// SetCredentialStatus sets the status value for a credential. Section 7 of
// draft-ietf-oauth-status-list bounds it: "Status Types MUST have a numeric
// value between 0 and 255." A value outside that has no encoding in any
// allowed width, so it is refused rather than truncated when published.
func (w *Wallet) SetCredentialStatus(credID string, status int) (StatusEntry, bool) {
	if status < 0 || status > 255 {
		return StatusEntry{}, false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, c := range w.Credentials {
		if c.ID == credID && c.Protected {
			// Revoking the shared baseline would break the demo for everyone.
			return StatusEntry{}, false
		}
	}
	entry, ok := w.StatusEntries[credID]
	if !ok {
		return StatusEntry{}, false
	}
	entry.Status = status
	w.StatusEntries[credID] = entry
	return entry, true
}

// BuildStatusList builds the published status list: the bits per entry and the
// packed bitstring. The width follows the largest status value held, as
// section 7 requires ("The Status Issuer MUST choose an adequate bits value
// [...] to describe the required Status Types"). Fixed at one bit, a
// SUSPENDED credential would be published as INVALID.
func (w *Wallet) BuildStatusList() (int, []byte) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	maxStatus := 0
	for _, entry := range w.StatusEntries {
		if entry.Index >= 0 && entry.Status > maxStatus {
			maxStatus = entry.Status
		}
	}
	bits, err := statuslist.BitsForStatus(maxStatus)
	if err != nil {
		// SetCredentialStatus refuses anything outside 0..255, so a stored
		// value that does not fit came from a hand-edited wallet file. The
		// widest list the specification allows is the honest answer.
		bits = 8
	}

	entries := w.StatusListCounter
	numBytes := (entries*bits + 7) / 8
	// A floor of 16 bytes, which is this wallet's choice rather than a
	// requirement: the specification sets no minimum size. A list only as
	// long as the credentials issued so far would shrink to a couple of
	// bytes on a fresh wallet, and a one-entry list identifies the
	// credential that reads it.
	if numBytes < 16 {
		numBytes = 16
	}
	bitstring := make([]byte, numBytes)
	capacity := len(bitstring) * 8 / bits

	for _, entry := range w.StatusEntries {
		if entry.Status == 0 {
			continue
		}
		// A negative index passes a bounds check written as "less than the
		// length" and then raises "negative shift amount". The index is
		// adopted from an imported credential's own status claim, so the
		// number is whoever issued it, and this bitstring is served to anyone
		// who asks for the status list.
		if entry.Index < 0 || entry.Index >= capacity {
			continue
		}
		bitPos := entry.Index * bits
		mask := (1 << bits) - 1
		bitstring[bitPos/8] |= byte((entry.Status & mask) << (bitPos % 8))
	}

	return bits, bitstring
}

// nextStatusIndex returns the next status list index and increments the counter.
func (w *Wallet) nextStatusIndex() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.StatusListCounter
	w.StatusListCounter++
	return idx
}

// NextStatusIndex reserves and returns the next wallet-managed status list index.
func (w *Wallet) NextStatusIndex() int {
	return w.nextStatusIndex()
}

// registerStatusEntry records a status entry for a credential. A negative
// index is dropped: import adopts the index from the credential's own status
// claim, so the number comes from whoever issued it.
func (w *Wallet) registerStatusEntry(credID string, idx int) {
	if idx < 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.StatusEntries == nil {
		w.StatusEntries = make(map[string]StatusEntry)
	}
	w.StatusEntries[credID] = StatusEntry{Index: idx, Status: 0}
}

// RegisterStatusEntry records a wallet-managed status list entry for a credential.
func (w *Wallet) RegisterStatusEntry(credID string, idx int) {
	w.registerStatusEntry(credID, idx)
}

// StatusEntryFor returns the wallet's own status list entry for a credential.
func (w *Wallet) StatusEntryFor(credID string) (StatusEntry, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	entry, ok := w.StatusEntries[credID]
	return entry, ok
}

// CredentialStatusRef extracts the status list reference embedded in a
// credential: the status claim for SD-JWT and JWT VC, the MSO status for
// mdoc.
func CredentialStatusRef(c StoredCredential) *statuslist.StatusRef {
	switch c.Format {
	case "mso_mdoc":
		doc, err := mdoc.Parse(c.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.Status == nil {
			return nil
		}
		return statuslist.ExtractStatusRef(map[string]any{"status": doc.IssuerAuth.MSO.Status})
	default:
		return statuslist.ExtractStatusRef(c.Claims)
	}
}

// CredentialStatusInfo returns the status metadata included in credential
// summaries: the embedded status list reference plus, when the wallet manages
// the entry on its own status list, the current status value. It returns nil
// for credentials without any status list reference or entry.
func (w *Wallet) CredentialStatusInfo(c StoredCredential) map[string]any {
	ref := CredentialStatusRef(c)
	entry, managed := w.StatusEntryFor(c.ID)
	if ref == nil && !managed {
		return nil
	}
	info := map[string]any{"managed": managed}
	if ref != nil {
		if ref.Invalid != "" {
			// A status_list object that does not meet section 6.2 is a broken
			// credential. Reporting the parts of it that happened to parse
			// would read like a working reference.
			info["error"] = ref.Invalid
		} else {
			info["uri"] = ref.URI
			info["idx"] = ref.Idx
		}
	}
	if managed {
		info["status"] = entry.Status
		info["statusName"] = statuslist.StatusName(entry.Status)
	}
	return info
}

// CredentialSummaryWithStatus is CredentialSummary plus the wallet-aware
// status metadata.
func (w *Wallet) CredentialSummaryWithStatus(c StoredCredential) map[string]any {
	summary := CredentialSummary(c)
	if info := w.CredentialStatusInfo(c); info != nil {
		summary["status"] = info
	}
	// Only a credential this wallet cannot sign for says so, so a listing
	// stays quiet about the ordinary case.
	if w.keyBindingNotHeld(&c) {
		summary["key_binding_not_held"] = true
	}
	summary["holder_binding"] = w.credentialHolderBindingState(c)
	return summary
}
