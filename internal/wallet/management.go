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
	"errors"
	"fmt"
)

var (
	ErrCredentialNotFound  = errors.New("credential not found")
	ErrCredentialProtected = errors.New("credential is protected and can only be removed through the wallet file")
)

// Management runs the credential management operations of the HTTP API and the
// local CLI. Each operation changes the wallet, writes its activity log entry
// and persists the change through commit. The result is the same whether a
// server runs or the CLI changes the store directly.
type Management struct {
	wallet *Wallet
	// commit applies change and persists the wallet when change succeeds.
	commit func(change func() error) error
}

// NewManagement persists each change with save.
func NewManagement(w *Wallet, save func() error) *Management {
	return &Management{wallet: w, commit: func(change func() error) error {
		if err := change(); err != nil {
			return err
		}
		return save()
	}}
}

// CredentialListing lists each batch once, newest first, without raw
// credentials and claims. A zero limit returns every credential from offset.
// total counts every listed credential.
func (m *Management) CredentialListing(offset, limit int) (listing []map[string]any, total int) {
	return m.wallet.CredentialsListingWindow(offset, limit), len(m.wallet.ListedCredentials())
}

func (m *Management) Credential(id string) (map[string]any, error) {
	cred, ok := m.wallet.GetCredential(id)
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return m.wallet.CredentialSummaryWithBatch(cred), nil
}

func (m *Management) ImportCredential(raw string) (map[string]any, error) {
	var imported *StoredCredential
	err := m.commit(func() error {
		var err error
		if imported, err = m.wallet.ImportCredential(raw); err != nil {
			return err
		}
		m.wallet.AddLog("management", fmt.Sprintf("Imported %s credential %s", imported.Format, credentialLabel(*imported)), true)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m.wallet.CredentialSummaryWithStatus(*imported), nil
}

func (m *Management) RemoveCredential(id string) error {
	if m.wallet.IsProtected(id) {
		return ErrCredentialProtected
	}
	label := id
	if cred, ok := m.wallet.GetCredential(id); ok {
		label = credentialLabel(cred)
	}
	return m.commit(func() error {
		if !m.wallet.RemoveCredential(id) {
			return ErrCredentialNotFound
		}
		m.wallet.AddLog("management", fmt.Sprintf("Deleted credential %s", label), true)
		return nil
	})
}

// RemovedCredentials reports a removal of every deletable credential.
type RemovedCredentials struct {
	Deleted       int `json:"deleted"`
	KeptProtected int `json:"kept_protected"`
}

func (m *Management) RemoveAllCredentials() (RemovedCredentials, error) {
	var removed RemovedCredentials
	err := m.commit(func() error {
		removed.Deleted = m.wallet.ClearCredentials()
		removed.KeptProtected = len(m.wallet.GetCredentials())
		detail := fmt.Sprintf("Deleted all credentials (%d)", removed.Deleted)
		if removed.KeptProtected > 0 {
			detail = fmt.Sprintf("Deleted all deletable credentials (%d, kept %d protected)", removed.Deleted, removed.KeptProtected)
		}
		m.wallet.AddLog("management", detail, true)
		return nil
	})
	return removed, err
}

func (m *Management) Issue(req IssueAPIRequest) (map[string]any, error) {
	opts, err := req.Options()
	if err != nil {
		return nil, err
	}
	var summary map[string]any
	err = m.commit(func() error {
		var err error
		if summary, err = m.wallet.IssueSummary(opts); err != nil {
			return err
		}
		m.wallet.AddLog("management", fmt.Sprintf("Issued %s credential %s", summary["format"], credentialTypeLabel(summary)), true)
		return nil
	})
	return summary, err
}
