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

// Remote implementations of the wallet management commands. Each mirrors the
// local behavior but talks to a running wallet server's REST API (see
// internal/remote). The local and remote paths share the same output
// formatting where possible.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mdoc"
	"github.com/dominikschlosser/oid4vc-dev/internal/output"
	"github.com/dominikschlosser/oid4vc-dev/internal/remote"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func remoteString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func remoteCredLabel(cred map[string]any) string {
	if vct := remoteString(cred, "vct"); vct != "" {
		return vct
	}
	if doctype := remoteString(cred, "doctype"); doctype != "" {
		return doctype
	}
	return remoteString(cred, "format")
}

func remoteWalletList(c *remote.Client) error {
	creds, err := c.Credentials()
	if err != nil {
		return err
	}
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
	fmt.Fprintln(tw, "ID\tFORMAT\tTYPE\tCLAIMS")
	for _, cred := range creds {
		claims, _ := cred["claims"].(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", remoteString(cred, "id"), remoteString(cred, "format"), remoteCredLabel(cred), len(claims))
	}
	return tw.Flush()
}

func remoteWalletShow(c *remote.Client, id string, decoded bool) error {
	cred, err := c.Credential(id)
	if err != nil {
		return err
	}
	raw := remoteString(cred, "raw")
	if !decoded {
		fmt.Println(raw)
		return nil
	}
	opts := output.Options{JSON: jsonOutput, NoColor: noColor, Verbose: verbose}
	switch remoteString(cred, "format") {
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

func remoteWalletImport(c *remote.Client, input string) error {
	raw, err := format.ReadInputRaw(input)
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}
	imported, err := c.ImportCredential(raw)
	if err != nil {
		return err
	}
	claims, _ := imported["claims"].(map[string]any)
	fmt.Printf("Imported %s credential (%s) with %d claims\n", remoteString(imported, "format"), remoteCredLabel(imported), len(claims))
	return nil
}

func remoteWalletRemove(c *remote.Client, id string, all bool) error {
	if all {
		count, err := c.RemoveAllCredentials()
		if err != nil {
			return err
		}
		fmt.Printf("Removed %d credential(s)\n", count)
		return nil
	}
	if err := c.RemoveCredential(id); err != nil {
		return err
	}
	fmt.Printf("Removed credential %s\n", id)
	return nil
}

func remoteWalletLogs(c *remote.Client, follow bool) error {
	if follow {
		return fmt.Errorf("--follow is not supported with a remote wallet")
	}
	data, err := c.Log()
	if err != nil {
		return err
	}
	var entries []wallet.LogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("decoding remote log: %w", err)
	}
	return printWalletLogs(os.Stdout, entries, walletLogPrintOptions{Verbose: verbose, JSON: jsonOutput})
}

func remoteGeneratePID(c *remote.Client, claims map[string]any, vct string) error {
	if err := c.GeneratePID(claims, vct); err != nil {
		return err
	}
	fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
	return nil
}

func remoteCertificate(c *remote.Client, kind string, asJWKS bool, outPath string) error {
	certFormat := "pem"
	if asJWKS {
		certFormat = "jwks"
	}
	data, err := c.Certificate(kind, certFormat)
	if err != nil {
		return err
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return fmt.Errorf("writing certificate: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s certificate to %s\n", kind, outPath)
		return nil
	}
	fmt.Print(string(data))
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

// remoteIssue sends the issue flags to the remote wallet's POST /api/issue.
// Templates resolve on the remote side against its template directory.
func remoteIssue(c *remote.Client, req map[string]any) error {
	result, err := c.Issue(req)
	if err != nil {
		return err
	}
	fmt.Println(remoteString(result, "raw"))
	label := remoteString(result, "vct")
	if label == "" {
		label = remoteString(result, "doctype")
	}
	fmt.Fprintf(os.Stderr, "Issued %s credential (%s) into the remote wallet\n", remoteString(result, "format"), label)
	if path := remoteString(result, "template_path"); path != "" {
		fmt.Fprintf(os.Stderr, "Saved template on the remote wallet (%s)\n", path)
	}
	return nil
}

func remoteTemplatesList(c *remote.Client) error {
	templates, err := c.Templates()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFORMAT\tTYPE\tCLAIMS\tSOURCE")
	for _, tpl := range templates {
		credType := remoteString(tpl, "vct")
		if credType == "" {
			credType = remoteString(tpl, "doctype")
		}
		source := "user"
		if predefined, _ := tpl["predefined"].(bool); predefined {
			source = "pre-defined"
		}
		tplFormat := remoteString(tpl, "format")
		if tplFormat == "" {
			tplFormat = "any"
		}
		claims, _ := tpl["claims"].(map[string]any)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", remoteString(tpl, "name"), tplFormat, credType, len(claims), source)
	}
	return tw.Flush()
}

func remoteTemplatesShow(c *remote.Client, name string) error {
	tpl, err := c.Template(name)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(tpl, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func remoteTemplatesPut(c *remote.Client, name string, doc any) error {
	saved, err := c.PutTemplate(name, doc)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Saved template %q on the remote wallet\n", remoteString(saved, "name"))
	return nil
}

func remoteTemplatesDelete(c *remote.Client, name string) error {
	if err := c.DeleteTemplate(name); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Deleted template %q on the remote wallet\n", name)
	return nil
}

// isCredentialOfferURI reports whether a URI is an OID4VCI credential offer
// (matching the wallet UI's detection).
func isCredentialOfferURI(uri string) bool {
	return strings.Contains(uri, "credential_offer") ||
		strings.HasPrefix(uri, "openid-credential-offer://") ||
		strings.HasPrefix(uri, "haip-vci://")
}
