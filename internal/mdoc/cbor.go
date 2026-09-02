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

package mdoc

import (
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

var cborDecMode cbor.DecMode

func init() {
	// Decoding unsigned integers as signed keeps a CBOR integer key from
	// arriving as uint64 in one document and int64 in the next.
	var err error
	cborDecMode, err = cbor.DecOptions{
		IntDec: cbor.IntDecConvertSigned,
	}.DecMode()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cbor: failed to initialize decode mode: %v\n", err)
		os.Exit(1)
	}
}

// unmarshalTag24 decodes CBOR Tag 24, returning the inner bytes.
func unmarshalTag24(data []byte) ([]byte, error) {
	var raw cbor.RawTag
	if err := cborDecMode.Unmarshal(data, &raw); err != nil {
		return data, nil
	}
	if raw.Number != 24 {
		return data, nil
	}

	var inner []byte
	if err := cborDecMode.Unmarshal(raw.Content, &inner); err != nil {
		return nil, fmt.Errorf("unwrapping tag 24 content: %w", err)
	}
	return inner, nil
}

// decodeCBOR decodes CBOR bytes into a generic Go value.
func decodeCBOR(data []byte) (any, error) {
	var result any
	if err := cborDecMode.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// convertCBORMapToStringKeys converts map[any]any to map[string]any recursively.
func convertCBORMapToStringKeys(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		key := fmt.Sprintf("%v", k)
		result[key] = convertCBORValue(v)
	}
	return result
}
