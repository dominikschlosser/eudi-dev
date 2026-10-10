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

package registrar

import (
	"errors"
	"fmt"
	"slices"
)

// Enrolment registers a relying party, or changes its registration, and issues
// the certificates for it in one step. If a certificate fails, the
// registration stays as it was.
type Enrolment struct {
	RelyingParty WalletRelyingParty `json:"relyingParty"`
	// Access asks for an access certificate. The registrar fills in the
	// identifier.
	Access *AccessCertificateRequest `json:"access,omitempty"`
	// Registration asks for a registration certificate.
	Registration *EnrolmentRegistration `json:"registration,omitempty"`
}

// EnrolmentRegistration names the registration certificate of an enrolment.
type EnrolmentRegistration struct {
	// Provider asks for the provider certificate of the service. Otherwise the
	// certificate covers the intended use that the enrolment adds.
	Provider          bool   `json:"provider,omitempty"`
	ServiceIdentifier string `json:"serviceIdentifier,omitempty"`
	Validity          string `json:"validity,omitempty"`
}

type EnrolmentResult struct {
	RelyingParty WalletRelyingParty             `json:"relyingParty"`
	Access       *AccessCertificateResult       `json:"access,omitempty"`
	Registration *RegistrationCertificateResult `json:"registration,omitempty"`
}

// Enrol registers e.RelyingParty, or with update changes the registration with
// its first identifier, and issues the requested certificates.
func (r *Registrar) Enrol(e Enrolment, update bool) (*EnrolmentResult, error) {
	// The inputs are checked before the registration changes.
	if e.Access != nil {
		if _, _, err := e.Access.parse(); err != nil {
			return nil, err
		}
	}
	if e.Registration != nil {
		if _, err := registrationValidity(e.Registration.Validity); err != nil {
			return nil, err
		}
	}

	var before *WalletRelyingParty
	var stored WalletRelyingParty
	var err error
	if update {
		if len(e.RelyingParty.Identifier) == 0 {
			return nil, fmt.Errorf("an update needs the identifier of the registered relying party")
		}
		previous, ok := r.RelyingParty(e.RelyingParty.Identifier[0].Identifier)
		if !ok {
			return nil, fmt.Errorf("%w: %s", errRelyingPartyNotFound, e.RelyingParty.Identifier[0].Identifier)
		}
		before = &previous
		stored, err = r.UpdateRelyingParty(e.RelyingParty)
	} else {
		stored, err = r.RegisterRelyingParty(e.RelyingParty)
	}
	if err != nil {
		return nil, err
	}

	result, err := r.enrolmentCertificates(stored, before, e)
	if err != nil {
		identifier := stored.Identifier[0].Identifier
		var undo error
		if before != nil {
			_, undo = r.UpdateRelyingParty(*before)
		} else {
			undo = r.DeleteRelyingParty(identifier)
		}
		return nil, errors.Join(err, undo)
	}
	return result, nil
}

func (r *Registrar) enrolmentCertificates(stored WalletRelyingParty, before *WalletRelyingParty, e Enrolment) (*EnrolmentResult, error) {
	identifier := stored.Identifier[0].Identifier
	result := &EnrolmentResult{RelyingParty: stored}
	if e.Access != nil {
		access := *e.Access
		access.Identifier = identifier
		var err error
		if result.Access, err = r.IssueAccessCertificate(access); err != nil {
			return nil, err
		}
	}
	if e.Registration == nil {
		return result, nil
	}
	req := RegistrationCertificateRequest{Identifier: identifier, ServiceIdentifier: e.Registration.ServiceIdentifier, Validity: e.Registration.Validity}
	if !e.Registration.Provider {
		added := addedIntendedUses(stored, before)
		if len(added) != 1 {
			return nil, fmt.Errorf("a registration certificate covers one intended use, and this step adds %d", len(added))
		}
		req.IntendedUseIdentifier = added[0]
	}
	var err error
	result.Registration, err = r.IssueRegistrationCertificate(req)
	return result, err
}

// addedIntendedUses lists the intended uses of after that before doesn't have.
func addedIntendedUses(after WalletRelyingParty, before *WalletRelyingParty) []string {
	var known []string
	if before != nil {
		for _, service := range before.Services {
			for _, use := range service.IntendedUses {
				known = append(known, use.IntendedUseIdentifier)
			}
		}
	}
	var added []string
	for _, service := range after.Services {
		for _, use := range service.IntendedUses {
			if !slices.Contains(known, use.IntendedUseIdentifier) {
				added = append(added, use.IntendedUseIdentifier)
			}
		}
	}
	return added
}
