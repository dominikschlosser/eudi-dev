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

package format

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// StripCBORTag removes a specific outer CBOR tag while preserving already-untagged values.
func StripCBORTag(data []byte, expected uint64) ([]byte, error) {
	var raw cbor.RawTag
	if err := cbor.Unmarshal(data, &raw); err != nil {
		// Not a tagged value, which is one of the two shapes this accepts.
		return data, nil
	}
	if raw.Number != expected {
		return nil, fmt.Errorf("unexpected CBOR tag %d, want %d", raw.Number, expected)
	}
	return raw.Content, nil
}
