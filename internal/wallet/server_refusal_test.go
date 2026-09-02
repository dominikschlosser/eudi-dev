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

// What a refused request reports. RFC 6749 §5.2 defines error and
// error_description, and a server answering outside that format puts the HTTP
// status phrase in error and its reason in a message, which is the difference
// between "Bad Request" and a sentence naming what was wrong.
func TestOAuthErrorMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{
			name: "the two fields RFC 6749 defines",
			body: `{"error":"invalid_grant","error_description":"the code expired"}`,
			want: "invalid_grant: the code expired",
		},
		{
			name: "a code with nothing beside it",
			body: `{"error":"invalid_grant"}`,
			want: "invalid_grant",
		},
		{
			name: "a status phrase and the reason in a message",
			body: `{"statusCode":400,"message":"Invalid grant_type, must be \"authorization_code\"","error":"Bad Request"}`,
			want: `Bad Request: Invalid grant_type, must be "authorization_code"`,
		},
		{
			name: "a message listing everything that was wrong",
			body: `{"message":["grant_type is required","code is required"],"error":"Bad Request"}`,
			want: "Bad Request: grant_type is required, code is required",
		},
		{
			name: "error_description wins over a message",
			body: `{"error":"invalid_request","error_description":"the reason","message":"the same in other words"}`,
			want: "invalid_request: the reason",
		},
		{
			name: "a message repeating the code says nothing twice",
			body: `{"error":"invalid_grant","message":"invalid_grant"}`,
			want: "invalid_grant",
		},
		{
			name: "a body that is not an error response",
			body: `{"access_token":"t","token_type":"Bearer","message":"issued"}`,
			want: "",
		},
		{
			name: "something that is not JSON at all",
			body: `<html>502</html>`,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := oauthErrorMessage([]byte(tc.body)); got != tc.want {
				t.Errorf("oauthErrorMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}
