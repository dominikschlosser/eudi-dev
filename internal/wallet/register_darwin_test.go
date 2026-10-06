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

//go:build darwin

package wallet

import (
	"slices"
	"testing"
)

func TestPlistCommandsRegisterEverySchemeUnderItsProtocol(t *testing.T) {
	var got []string
	for _, cmd := range plistCommands("Info.plist") {
		got = append(got, cmd[1])
	}
	want := []string{
		"Add :CFBundleIdentifier string dev.eudi.wallet",
		"Add :LSUIElement bool true",
		"Add :CFBundleURLTypes array",
		"Add :CFBundleURLTypes:0 dict",
		"Add :CFBundleURLTypes:0:CFBundleURLName string OID4VP",
		"Add :CFBundleURLTypes:0:CFBundleURLSchemes array",
		"Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string openid4vp",
		"Add :CFBundleURLTypes:0:CFBundleURLSchemes:1 string eudi-openid4vp",
		"Add :CFBundleURLTypes:0:CFBundleURLSchemes:2 string haip-vp",
		"Add :CFBundleURLTypes:1 dict",
		"Add :CFBundleURLTypes:1:CFBundleURLName string OID4VCI",
		"Add :CFBundleURLTypes:1:CFBundleURLSchemes array",
		"Add :CFBundleURLTypes:1:CFBundleURLSchemes:0 string openid-credential-offer",
		"Add :CFBundleURLTypes:1:CFBundleURLSchemes:1 string haip-vci",
		"Add :CFBundleURLTypes:1:CFBundleURLSchemes:2 string eu-eaa-offer",
	}
	if !slices.Equal(got, want) {
		t.Errorf("plist commands:\n%v\nwant\n%v", got, want)
	}
}
