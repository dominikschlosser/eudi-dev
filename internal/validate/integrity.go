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

package validate

import (
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

// CheckSDJWTIntegrity checks that every disclosure has its digest in the
// payload or in another disclosure (RFC 9901 §7.1 step 4).
func CheckSDJWTIntegrity(token *sdjwt.Token) Check {
	if len(token.Disclosures) == 0 {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No disclosures to verify"}
	}

	referenced := sdjwt.ReferencedDigests(token)
	matched := 0
	total := len(token.Disclosures)
	for _, d := range token.Disclosures {
		if referenced[d.Digest] {
			matched++
		}
	}

	if matched == total {
		return Check{Name: CheckIntegrity, Status: Pass, Detail: fmt.Sprintf("%d/%d disclosure digests verified", matched, total)}
	}
	return Check{Name: CheckIntegrity, Status: Fail, Detail: fmt.Sprintf("%d/%d disclosure digests matched", matched, total)}
}

// CheckSDJWTType verifies the typ header parameter of the Issuer-signed JWT.
// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1: "The Issuer MUST include the typ
// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt". A
// vc+sd-jwt token decodes but fails this check.
func CheckSDJWTType(token *sdjwt.Token) Check {
	if err := sdjwt.ValidateVCType(token.Header); err != nil {
		return Check{Name: CheckType, Status: Fail, Detail: err.Error()}
	}
	typ, _ := token.Header["typ"].(string)
	if typ == sdjwt.TypeSDJWTVCLegacy {
		return Check{Name: CheckType, Status: Fail, Detail: fmt.Sprintf("the typ header is %s, draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires %s", typ, sdjwt.TypeSDJWTVC)}
	}
	return Check{Name: CheckType, Status: Pass, Detail: typ}
}

// CheckMDOCIntegrity hashes the complete IssuerSignedItem encodings and
// compares them with the MSO valueDigests. The issuer signature covers only
// the MSO, so this check binds the element values to it.
func CheckMDOCIntegrity(doc *mdoc.Document) Check {
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No MSO available for digest verification"}
	}
	total := 0
	for _, items := range doc.NameSpaces {
		total += len(items)
	}
	if total == 0 {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No disclosed elements to verify"}
	}
	if err := mdoc.VerifyValueDigests(doc); err != nil {
		return Check{Name: CheckIntegrity, Status: Fail, Detail: err.Error()}
	}
	return Check{Name: CheckIntegrity, Status: Pass, Detail: fmt.Sprintf("%d/%d claim digests verified", total, total)}
}
