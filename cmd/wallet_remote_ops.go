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

package cmd

// Output helpers for the wallet management commands. They format the wallet
// server's API document shapes, which both walletService backends produce,
// so managing the local store and a remote instance print identically. The
// remote-only operations that have no local equivalent (accept flows and the
// deprecated generate-pid) live here too.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/dominikschlosser/eudi-dev/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/internal/output"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/sdjwt"
)

func docString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func docCredLabel(cred map[string]any) string {
	if vct := docString(cred, "vct"); vct != "" {
		return vct
	}
	if doctype := docString(cred, "doctype"); doctype != "" {
		return doctype
	}
	return docString(cred, "format")
}

func printCredentialList(creds []map[string]any) error {
	if len(creds) == 0 {
		fmt.Println("No credentials stored.")
		return nil
	}
	if jsonOutput {
		data, err := json.Marshal(creds)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tFORMAT\tTYPE\tCLAIMS\tSTATUS")
	for _, cred := range creds {
		claims, _ := cred["claims"].(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n",
			docString(cred, "id"), docString(cred, "format"), docCredLabel(cred), len(claims), credStatusLabel(cred))
	}
	return tw.Flush()
}

// credStatusLabel summarizes revocation state and protection for the list,
// e.g. "active, protected". Empty when the wallet knows neither.
func credStatusLabel(cred map[string]any) string {
	var parts []string
	if status, ok := cred["status"].(map[string]any); ok {
		value, hasValue := status["status"].(float64)
		switch {
		case hasValue && value == 1:
			parts = append(parts, "revoked")
		case hasValue:
			parts = append(parts, "active")
		case status["uri"] != nil:
			// Referenced somewhere else: this wallet cannot resolve it here.
			parts = append(parts, "external")
		}
	}
	if protected, _ := cred["protected"].(bool); protected {
		parts = append(parts, "protected")
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ", ")
}

func printCredentialDoc(cred map[string]any, decoded bool) error {
	raw := docString(cred, "raw")
	if !decoded {
		fmt.Println(raw)
		return nil
	}
	opts := output.Options{JSON: jsonOutput, NoColor: noColor, Verbose: verbose}
	switch docString(cred, "format") {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintSDJWT(token, opts)
	case "mso_mdoc":
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintMDOC(doc, opts)
	case "jwt_vc_json":
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return err
		}
		output.PrintJWT(token, opts)
	}
	return nil
}

func remoteGeneratePID(c *remote.Client, claims map[string]any, vct string) error {
	if err := c.GeneratePID(claims, vct); err != nil {
		return err
	}
	fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
	return nil
}

func remoteAccept(c *remote.Client, uri string) error {
	isVCI := isCredentialOfferURI(uri)
	var result map[string]any
	var err error
	if isVCI {
		result, err = c.AcceptOffer(uri)
	} else {
		result, err = c.Present(uri)
	}
	if err != nil {
		return err
	}
	data, marshalErr := json.MarshalIndent(result, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	fmt.Println(string(data))
	return nil
}

// isCredentialOfferURI reports whether a URI is an OID4VCI credential offer
// (matching the wallet UI's detection).
func isCredentialOfferURI(uri string) bool {
	return strings.Contains(uri, "credential_offer") ||
		strings.HasPrefix(uri, "openid-credential-offer://") ||
		strings.HasPrefix(uri, "haip-vci://")
}
