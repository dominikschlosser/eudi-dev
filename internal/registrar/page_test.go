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
	"net/url"
	"testing"
)

// Both list endpoints page by one rule: a bad limit or offset is an error and
// the limit is capped.
func TestPage(t *testing.T) {
	cases := []struct {
		query             string
		start, end, limit int
		fails             bool
	}{
		{"", 0, 20, 20, false},
		{"limit=5&cursor=3", 3, 8, 5, false},
		{"limit=1000", 0, 50, maxPageSize, false},
		{"cursor=70", 50, 50, 20, false},
		{"limit=0", 0, 0, 0, true},
		{"limit=x", 0, 0, 0, true},
		{"cursor=-1", 0, 0, 0, true},
	}
	for _, tc := range cases {
		q, _ := url.ParseQuery(tc.query)
		start, end, limit, err := page(q, "cursor", 50)
		if (err != nil) != tc.fails || start != tc.start || end != tc.end || limit != tc.limit {
			t.Errorf("%q: page = %d, %d, %d, %v", tc.query, start, end, limit, err)
		}
	}
}
