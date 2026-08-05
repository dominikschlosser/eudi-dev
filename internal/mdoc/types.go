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

// Package mdoc parses and verifies ISO 18013-5 mDOC/mso_mdoc credentials encoded as CBOR/COSE.
package mdoc

import "time"

// Document represents a parsed mDOC credential.
type Document struct {
	Raw        []byte
	DocType    string
	NameSpaces map[string][]IssuerSignedItem
	IssuerAuth *IssuerAuth
	// DeviceSigned contains the device authentication data from a DeviceResponse.
	DeviceSigned *DeviceSigned
	// ResponseVersion and ResponseStatus are the DeviceResponse members that
	// sit outside the document itself.
	ResponseVersion string
	ResponseStatus  *uint64
	// IsDeviceResponse indicates this was parsed from a DeviceResponse wrapper.
	IsDeviceResponse bool
}

// DeviceSigned contains the device-signed portion of a DeviceResponse document.
type DeviceSigned struct {
	DeviceAuth map[string]any
	// RawDeviceSignature is the deviceSignature COSE_Sign1 as it arrived,
	// which is the only form its signature can be checked against.
	RawDeviceSignature []byte
}

// IssuerSignedItem represents a single claim within a namespace.
type IssuerSignedItem struct {
	DigestID          uint64
	Random            []byte
	ElementIdentifier string
	ElementValue      any
	// RawCBOR holds the original CBOR-encoded bytes (before Tag-24 unwrapping)
	// used for digest verification against MSO ValueDigests.
	RawCBOR []byte
}

// IssuerAuth represents the COSE_Sign1 issuer authentication.
type IssuerAuth struct {
	RawCOSE           []byte
	ProtectedHeader   map[any]any
	UnprotectedHeader map[any]any
	Payload           []byte
	Signature         []byte
	MSO               *MSO
}

// MSO is the Mobile Security Object.
type MSO struct {
	Version         string
	DigestAlgorithm string
	DocType         string
	ValueDigests    map[string]map[uint64][]byte
	ValidityInfo    *ValidityInfo
	DeviceKeyInfo   map[string]any
	Status          map[string]any
}

// ValidityInfo contains credential validity dates.
type ValidityInfo struct {
	Signed     *time.Time
	ValidFrom  *time.Time
	ValidUntil *time.Time
}
