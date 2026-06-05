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

import "testing"

func TestPresentationSubmissionLogDetailsIncludePresentedCredentialMaterial(t *testing.T) {
	w := &Wallet{Credentials: []StoredCredential{
		{
			ID:     "cred-1",
			Format: "dc+sd-jwt",
			Raw:    "issuer.jwt~disclosure~kb.jwt",
			VCT:    "urn:eudi:pid:1",
			Claims: map[string]any{
				"given_name":  "Erika",
				"family_name": "Mustermann",
			},
		},
	}}

	details := PresentationSubmissionLogDetails(
		&AuthorizationRequestParams{
			ClientID:     "verifier.example",
			ResponseMode: "direct_post",
			RequestPayload: map[string]any{
				"nonce":         "n-1",
				"response_mode": "direct_post",
			},
		},
		w,
		[]CredentialMatch{
			{
				QueryID:      "pid",
				CredentialID: "cred-1",
				Format:       "dc+sd-jwt",
				VCT:          "urn:eudi:pid:1",
				Claims: map[string]any{
					"given_name": "Erika",
				},
				SelectedKeys: []string{"given_name"},
			},
		},
		&VPTokenMapResult{TokenMap: map[string]string{"pid": "presented.sdjwt~kb.jwt"}},
		"",
		&DirectPostResult{StatusCode: 200, Body: "ok"},
	)

	if details["request_object"] == nil {
		t.Fatalf("expected request_object detail: %#v", details)
	}
	presented, ok := details["presented_credentials"].([]map[string]any)
	if !ok || len(presented) != 1 {
		t.Fatalf("expected one presented credential, got %#v", details["presented_credentials"])
	}
	item := presented[0]
	if item["raw_credential"] != "issuer.jwt~disclosure~kb.jwt" {
		t.Fatalf("expected raw credential in verbose details, got %#v", item)
	}
	if item["presentation"] != "presented.sdjwt~kb.jwt" {
		t.Fatalf("expected generated presentation in verbose details, got %#v", item)
	}
	if claims, ok := item["claims"].(map[string]any); !ok || claims["given_name"] != "Erika" {
		t.Fatalf("expected selected claims in verbose details, got %#v", item["claims"])
	}
}
