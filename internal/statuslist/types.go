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

// Package statuslist checks credential revocation status using Token Status
// Lists (draft-ietf-oauth-status-list).
package statuslist

// StatusRef is a reference to a status list entry in a credential.
type StatusRef struct {
	URI string `json:"uri"`
	Idx int    `json:"idx"`
}

// StatusResult contains the revocation check result.
type StatusResult struct {
	URI            string `json:"uri"`
	Index          int    `json:"index"`
	Status         int    `json:"status"`
	IsValid        bool   `json:"isValid"`
	BitsPerEntry   int    `json:"bitsPerEntry"`
	SignatureValid *bool  `json:"signatureValid,omitempty"`
	SignatureInfo  string `json:"signatureInfo,omitempty"`
	Error          string `json:"error,omitempty"`
}

// CheckOptions configures optional validation behavior for status list checks.
type CheckOptions struct {
	// TrustListCerts are the trust list CA certificates used to validate the
	// status list JWT's x5c chain. If empty, signature validation is skipped.
	TrustListCerts []TrustCert
}

// TrustCert holds a raw trust list certificate for chain validation.
type TrustCert struct {
	Raw []byte
}
