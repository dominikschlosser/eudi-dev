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

// SetCredentialStatus sets the status value for a credential.
func (w *Wallet) SetCredentialStatus(credID string, status int) (StatusEntry, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.StatusEntries[credID]
	if !ok {
		return StatusEntry{}, false
	}
	entry.Status = status
	w.StatusEntries[credID] = entry
	return entry, true
}

// BuildStatusBitstring builds a bitstring from status entries (1 bit per entry).
func (w *Wallet) BuildStatusBitstring() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.StatusListCounter == 0 {
		// Minimum 1 byte
		return make([]byte, 1)
	}

	// Calculate number of bytes needed
	numBytes := (w.StatusListCounter + 7) / 8
	// Minimum 16 bytes as per RFC 9596
	if numBytes < 16 {
		numBytes = 16
	}
	bitstring := make([]byte, numBytes)

	for _, entry := range w.StatusEntries {
		if entry.Status != 0 {
			byteIdx := entry.Index / 8
			bitOffset := entry.Index % 8
			if byteIdx < len(bitstring) {
				bitstring[byteIdx] |= byte(1 << bitOffset)
			}
		}
	}

	return bitstring
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

// registerStatusEntry records a status entry for a credential.
func (w *Wallet) registerStatusEntry(credID string, idx int) {
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
		info["uri"] = ref.URI
		info["idx"] = ref.Idx
	}
	if managed {
		info["status"] = entry.Status
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
	return summary
}
