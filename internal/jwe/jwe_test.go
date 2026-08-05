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

package jwe

import (
	"testing"
)

func TestEncKeyBitLen(t *testing.T) {
	tests := []struct {
		enc     string
		want    int
		wantErr bool
	}{
		{"A128GCM", 128, false},
		{"A256GCM", 256, false},
		{"A128CBC-HS256", 256, false},
		{"UNKNOWN", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.enc, func(t *testing.T) {
			got, err := EncKeyBitLen(tt.enc)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncKeyBitLen(%q) error = %v, wantErr %v", tt.enc, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EncKeyBitLen(%q) = %d, want %d", tt.enc, got, tt.want)
			}
		})
	}
}

func TestConcatKDF(t *testing.T) {
	z := make([]byte, 32)
	for i := range z {
		z[i] = byte(i)
	}

	// Test with nil apu, 128-bit key
	derived128 := ConcatKDF(z, "A128GCM", nil, nil, 128)
	if len(derived128) != 16 {
		t.Errorf("expected 16-byte derived key, got %d bytes", len(derived128))
	}

	// Test with non-nil apu, 256-bit key
	derived256 := ConcatKDF(z, "A256GCM", []byte("test"), nil, 256)
	if len(derived256) != 32 {
		t.Errorf("expected 32-byte derived key, got %d bytes", len(derived256))
	}

	// Same inputs should produce same output (deterministic)
	derived256Again := ConcatKDF(z, "A256GCM", []byte("test"), nil, 256)
	for i := range derived256 {
		if derived256[i] != derived256Again[i] {
			t.Error("concatKDF is not deterministic")
			break
		}
	}

	// Different apu should produce different output
	derivedDiffApu := ConcatKDF(z, "A256GCM", []byte("other"), nil, 256)
	same := true
	for i := range derived256 {
		if derived256[i] != derivedDiffApu[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different apu should produce different derived keys")
	}
}
