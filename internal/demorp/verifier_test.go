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

package demorp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/wallet"
)

// The request carries state, so a response must return the same value.
func TestDecryptResponseRequiresTheRequestState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := &requestState{id: "req-1", encKey: key}
	respond := func(payload map[string]any) (string, error) {
		body, _ := json.Marshal(payload)
		jwe, _, err := wallet.EncryptJWE(body, &key.PublicKey, "", "ECDH-ES", "A128GCM", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return decryptResponse(req, url.Values{"response": {jwe}})
	}

	if _, err := respond(map[string]any{"vp_token": map[string]any{"q": []string{"x"}}, "state": "req-1"}); err != nil {
		t.Fatalf("a response with the request state: %v", err)
	}
	for _, state := range []any{nil, "req-2"} {
		payload := map[string]any{"vp_token": map[string]any{"q": []string{"x"}}}
		if state != nil {
			payload["state"] = state
		}
		if _, err := respond(payload); err == nil {
			t.Errorf("a response with state %v was accepted", state)
		}
	}
}

// Without credential_sets every query is required. With them, each required
// set needs one option that is answered in full.
func TestUnsatisfiedFollowsTheCredentialSets(t *testing.T) {
	queries := []credentialQuery{{id: "a"}, {id: "b"}, {id: "t"}}
	cases := []struct {
		name     string
		sets     []credentialSet
		answered []string
		ok       bool
	}{
		{"all queries answered", nil, []string{"a", "b", "t"}, true},
		{"one query missing", nil, []string{"a", "b"}, false},
		{"one option answered", []credentialSet{{options: [][]string{{"a"}, {"b"}}}, {options: [][]string{{"t"}}, optional: true}}, []string{"b"}, true},
		{"an option answered in part", []credentialSet{{options: [][]string{{"a", "t"}}}}, []string{"a"}, false},
		{"no option answered", []credentialSet{{options: [][]string{{"a"}, {"b"}}}}, []string{"t"}, false},
	}
	for _, tc := range cases {
		answered := map[string]bool{}
		for _, id := range tc.answered {
			answered[id] = true
		}
		req := &requestState{queries: queries, sets: tc.sets}
		if err := req.unsatisfied(answered); (err == nil) != tc.ok {
			t.Errorf("%s: unsatisfied = %v", tc.name, err)
		}
	}
}

// A vp_token answers only the queries of the request.
func TestVerifyPresentationRefusesUnknownQueryIDs(t *testing.T) {
	d := New(twoPIDWallet(t), func() string { return "https://verifier.example" })
	req := &requestState{queries: []credentialQuery{{id: "cred_0", format: "dc+sd-jwt", vct: PIDVCT}}}

	_, _, err := d.verifyPresentation(req, `{"cred_0":["a~"],"other":["b~"]}`)
	if err == nil || !strings.Contains(err.Error(), `no credential query "other"`) {
		t.Fatalf("error = %v", err)
	}
}
