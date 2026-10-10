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

package trustlist

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

// Parse parses an ETSI TS 119 602 trust list JWT.
func Parse(raw string) (*TrustList, error) {
	raw = strings.TrimSpace(raw)

	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding header: %w", err)
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding payload: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parsing header: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parsing payload: %w", err)
	}

	tl := &TrustList{
		Raw:    raw,
		Header: header,
	}

	lote, ok := payload["LoTE"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parsing payload: missing top-level LoTE object")
	}

	if lsi, ok := lote["ListAndSchemeInformation"].(map[string]any); ok {
		tl.SchemeInfo = parseSchemeInfo(lsi)
	}

	if tel, ok := lote["TrustedEntitiesList"].([]any); ok {
		for _, entry := range tel {
			entryMap, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			entity, err := parseTrustedEntity(entryMap)
			if err != nil {
				continue
			}
			tl.Entities = append(tl.Entities, *entity)
		}
	}

	return tl, nil
}

func parseSchemeInfo(lsi map[string]any) *SchemeInfo {
	info := &SchemeInfo{}

	if lt, ok := lsi["LoTEType"].(string); ok {
		info.LoTEType = lt
	}

	info.SchemeOperatorName = firstMultiLangValue(lsi["SchemeOperatorName"])

	// Trust lists in the wild spell the key both "ListIssueDateTime" and
	// "ListIssueDatetime".
	for _, key := range []string{"ListIssueDateTime", "ListIssueDatetime"} {
		if lid, ok := lsi[key].(string); ok {
			info.ListIssueDatetime = lid
			break
		}
	}
	if next, ok := lsi["NextUpdate"].(string); ok {
		info.NextUpdate = next
	}
	info.SchemeTerritory, _ = lsi["SchemeTerritory"].(string)
	pointers, _ := lsi["PointersToOtherLoTE"].([]any)
	for _, raw := range pointers {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		pointer := Pointer{}
		pointer.Location, _ = entry["LoTELocation"].(string)
		if qualifiers, ok := entry["LoTEQualifiers"].([]any); ok && len(qualifiers) > 0 {
			if q, ok := qualifiers[0].(map[string]any); ok {
				pointer.LoTEType, _ = q["LoTEType"].(string)
				pointer.SchemeOperatorName = firstMultiLangValue(q["SchemeOperatorName"])
				pointer.SchemeTerritory, _ = q["SchemeTerritory"].(string)
			}
		}
		identities, _ := entry["ServiceDigitalIdentities"].([]any)
		for _, identity := range identities {
			if m, ok := identity.(map[string]any); ok {
				pointer.Certificates = append(pointer.Certificates, parseCertificates(m["X509Certificates"])...)
			}
		}
		info.Pointers = append(info.Pointers, pointer)
	}

	return info
}

func parseCertificates(raw any) []CertInfo {
	certs, _ := raw.([]any)
	var out []CertInfo
	for _, cert := range certs {
		certMap, ok := cert.(map[string]any)
		if !ok {
			continue
		}
		val, ok := certMap["val"].(string)
		if !ok {
			continue
		}
		if certInfo, err := parseCertificate(val); err == nil {
			out = append(out, *certInfo)
		}
	}
	return out
}

func parseTrustedEntity(entry map[string]any) (*TrustedEntity, error) {
	entity := &TrustedEntity{}

	if tei, ok := entry["TrustedEntityInformation"].(map[string]any); ok {
		if names, ok := tei["TEName"].([]any); ok && len(names) > 0 {
			if name, ok := names[0].(map[string]any); ok {
				if v, ok := name["value"].(string); ok {
					entity.Name = v
				}
			}
		}
	}

	if tes, ok := entry["TrustedEntityServices"].([]any); ok {
		for _, svc := range tes {
			svcMap, ok := svc.(map[string]any)
			if !ok {
				continue
			}
			service, err := parseTrustedService(svcMap)
			if err != nil {
				continue
			}
			entity.Services = append(entity.Services, *service)
		}
	}

	return entity, nil
}

func parseTrustedService(svc map[string]any) (*TrustedService, error) {
	service := &TrustedService{}

	si, ok := svc["ServiceInformation"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no ServiceInformation")
	}

	if st, ok := si["ServiceTypeIdentifier"].(string); ok {
		service.ServiceType = st
	}
	service.ServiceStatus, _ = si["ServiceStatus"].(string)

	if sdi, ok := si["ServiceDigitalIdentity"].(map[string]any); ok {
		service.Certificates = parseCertificates(sdi["X509Certificates"])
	}

	return service, nil
}

func parseCertificate(b64 string) (*CertInfo, error) {
	der, err := format.DecodeBase64Std(b64)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	return &CertInfo{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: cert.NotBefore.Format("2006-01-02"),
		NotAfter:  cert.NotAfter.Format("2006-01-02"),
		PublicKey: cert.PublicKey,
		Raw:       der,
	}, nil
}

// Service kinds of ServiceCertificates. ETSI TS 119 602 V1.1.1 names the
// service types of each list with these suffixes, such as
// http://uri.etsi.org/19602/SvcType/PID/Issuance and .../PID/Revocation.
const (
	IssuanceServices   = "Issuance"
	RevocationServices = "Revocation"
)

// ServiceCertificates returns the certificates of the services of one kind:
// the issuance services anchor credentials, the revocation services their
// status lists (ETSI TS 119 602 V1.1.1 Table D.3). Withdrawn services don't
// count. In a list whose services name neither kind, every service counts.
func ServiceCertificates(tl *TrustList, kind string) []CertInfo {
	typed := false
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			typed = typed || strings.HasSuffix(svc.ServiceType, "/"+IssuanceServices) || strings.HasSuffix(svc.ServiceType, "/"+RevocationServices)
		}
	}
	var certs []CertInfo
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			if strings.HasSuffix(svc.ServiceStatus, "/withdrawn") || (typed && !strings.HasSuffix(svc.ServiceType, "/"+kind)) {
				continue
			}
			certs = append(certs, svc.Certificates...)
		}
	}
	return certs
}

func ExtractPublicKeys(tl *TrustList) []CertInfo {
	var keys []CertInfo
	for _, entity := range tl.Entities {
		for _, svc := range entity.Services {
			keys = append(keys, svc.Certificates...)
		}
	}
	return keys
}

// firstMultiLangValue is the first value of a sequence of multilingual
// strings (ETSI TS 119 602 V1.1.1 §6.1.4).
func firstMultiLangValue(raw any) string {
	values, _ := raw.([]any)
	if len(values) == 0 {
		return ""
	}
	entry, _ := values[0].(map[string]any)
	value, _ := entry["value"].(string)
	return value
}

// CertInfos describes parsed certificates as trusted list entries.
func CertInfos(certs []*x509.Certificate) []CertInfo {
	infos := make([]CertInfo, 0, len(certs))
	for _, cert := range certs {
		infos = append(infos, CertInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), PublicKey: cert.PublicKey, Raw: cert.Raw})
	}
	return infos
}
