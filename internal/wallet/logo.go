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

import "encoding/base64"

// LogoSVG returns the eudi-dev logo, shared by the demo issuer and the
// generated credentials that carry this tool's own appearance.
func LogoSVG() []byte {
	data, err := staticFiles.ReadFile("static/logo.svg")
	if err != nil {
		return nil
	}
	return data
}

// LogoDataURI returns the eudi-dev logo as a data URI.
func LogoDataURI() string {
	if data := LogoSVG(); data != nil {
		return svgDataURI(data)
	}
	return ""
}

// svgDataURI wraps SVG markup as a base64 data URI.
func svgDataURI(svg []byte) string {
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(svg)
}

// germanIDSpecimenDataURI is the public Personalausweis specimen ("MUSTER")
// image, the German ID card the generated German PID shows as its card art,
// the same document the reference deployments use. It is served as a data URI
// so the credential stays self-contained and offline.
func germanIDSpecimenDataURI() string {
	data, err := staticFiles.ReadFile("static/german-id-specimen.jpg")
	if err != nil {
		return ""
	}
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(data)
}
