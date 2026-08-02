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

// Dynamic shell completion. The standard cobra `completion` command (bash,
// zsh, fish, powershell) exists on the root command; the functions here add
// value completion for everything the CLI can know: template names,
// credential IDs, and running wallet instances. Remote mode is honored, so
// completions come from the active remote wallet when one is configured.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
)

// completionClient returns a client for the active remote wallet with a
// completion-friendly short timeout, or nil for local management.
func completionClient() *remote.Client {
	url, err := activeRemoteURL()
	if err != nil || url == "" {
		return nil
	}
	c := remote.NewClient(url)
	c.HTTP.Timeout = 2 * time.Second
	return c
}

// completeTemplateNames completes credential template names, local or
// remote, with the format as description.
func completeTemplateNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var completions []string
	if c := completionClient(); c != nil {
		templates, err := c.Templates()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		for _, tpl := range templates {
			completions = append(completions, remoteString(tpl, "name")+"\t"+remoteString(tpl, "format"))
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	}

	templates, err := credtemplate.List(resolveTemplatesDir())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	for _, tpl := range templates {
		completions = append(completions, tpl.Name+"\t"+tpl.Format)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

// completeCredentialIDs completes stored credential IDs with the credential
// type as description.
func completeCredentialIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var completions []string
	if c := completionClient(); c != nil {
		creds, err := c.Credentials()
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		for _, cred := range creds {
			completions = append(completions, remoteString(cred, "id")+"\t"+remoteCredLabel(cred))
		}
		return completions, cobra.ShellCompDirectiveNoFileComp
	}

	// Only complete from an existing wallet: loading would otherwise create
	// one as a completion side effect.
	store := loadStore()
	if _, err := os.Stat(filepath.Join(store.Dir, "wallet.json")); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	for _, cred := range w.GetCredentials() {
		completions = append(completions, cred.ID+"\t"+credLabel(cred))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

// completeInstanceTargets completes running wallet instances for
// `wallet instances kill` (URLs, ports, and pids).
func completeInstanceTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var completions []string
	for _, inst := range remote.Discover(500 * time.Millisecond) {
		desc := fmt.Sprintf("pid %d", inst.PID)
		if inst.WalletDir != "" {
			desc += " " + inst.WalletDir
		}
		completions = append(completions, inst.URL+"\t"+desc)
		completions = append(completions, strconv.Itoa(inst.Port)+"\t"+inst.URL)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

// completeUseTargets completes `wallet instances use`: running instances
// plus the literal "local".
func completeUseTargets(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := []string{"local\tmanage the local wallet store"}
	for _, inst := range remote.Discover(500 * time.Millisecond) {
		desc := fmt.Sprintf("pid %d", inst.PID)
		if inst.WalletDir != "" {
			desc += " " + inst.WalletDir
		}
		completions = append(completions, inst.URL+"\t"+desc)
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

// completeRemoteFlag completes --remote: running instances plus "local".
func completeRemoteFlag(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return completeUseTargets(cmd, nil, toComplete)
}

// staticCompletion returns a completion function for a fixed value set.
func staticCompletion(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}
