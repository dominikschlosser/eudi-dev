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

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/remote"
	"github.com/dominikschlosser/eudi-dev/internal/wallet"
)

// startRemoteTestWallet starts a real wallet server on a random port and
// returns its base URL.
func startRemoteTestWallet(t *testing.T) (string, *wallet.Server) {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, false)
	w.AutoAccept = true
	w.TemplatesDir = t.TempDir()

	srv := wallet.NewServer(w, 0, nil)
	srv.ShutdownFunc = func() {} // never exit the test process
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("starting wallet server: %v", err)
	}
	url := "http://" + strings.TrimPrefix(addr, "http://")
	return url, srv
}

func resetRemoteTestState(t *testing.T) {
	t.Helper()
	t.Setenv("OID4VC_DEV_HOME", t.TempDir())
	resetTemplateTestState(t)
	remoteFlag = ""
	t.Cleanup(func() { remoteFlag = "" })
}

func TestRemoteWalletLifecycleViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	// wallet use verifies reachability and persists the target
	rootCmd.SetArgs([]string{"wallet", "instances", "use", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use: %v", err)
	}
	if remote.Active() != url {
		t.Fatalf("active remote not persisted: %q", remote.Active())
	}

	// issue on the remote wallet from a pre-defined template
	remoteFlag = ""
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote issue: %v", err)
	}

	// the credential is on the remote wallet, not in a local store
	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 remote credential, got %d", len(creds))
	}
	id, _ := creds[0]["id"].(string)

	// remove it through the CLI remote path
	rootCmd.SetArgs([]string{"wallet", "remove", id})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote remove: %v", err)
	}
	creds, err = client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 0 {
		t.Fatalf("expected empty remote wallet, got %d credentials", len(creds))
	}

	// switch back to local
	rootCmd.SetArgs([]string{"wallet", "instances", "use", "local"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use local: %v", err)
	}
	if remote.Active() != "" {
		t.Fatalf("expected local management, got %q", remote.Active())
	}
}

func TestAutoRouteThroughInstanceForSameWalletDir(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	// The registry says this running server owns the local wallet dir. The
	// registered pid must match the pid the server reports, otherwise
	// discovery prunes the file as stale.
	resolvedDir := wallet.NewWalletStore(walletDir).Dir
	if err := remote.RegisterInstance(remote.Instance{
		PID: os.Getpid(), Port: portFromURL(t, url), URL: url,
		WalletDir: resolvedDir, StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Issuing without --remote routes through the running instance instead
	// of writing the store directly (single-writer rule).
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("auto-routed issue: %v", err)
	}
	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected the credential on the running instance, got %d", len(creds))
	}
	if _, err := os.Stat(filepath.Join(walletDir, "wallet.json")); !os.IsNotExist(err) {
		t.Error("auto-routed issue must not write the local store")
	}

	// --remote local opts out and writes the local store directly.
	resetIssueFlagChanges(t)
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--remote", "local"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue with --remote local: %v", err)
	}
	store := wallet.NewWalletStore(walletDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.GetCredentials()) != 1 {
		t.Fatalf("expected 1 local credential after --remote local, got %d", len(w.GetCredentials()))
	}
	creds, err = client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("instance credentials must be untouched by --remote local: %v %v", creds, err)
	}

	// An explicit --templates-dir also forces the local store.
	resetIssueFlagChanges(t)
	tplDir := t.TempDir()
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--templates-dir", tplDir})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("issue with --templates-dir: %v", err)
	}
	w, err = store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.GetCredentials()) != 2 {
		t.Fatalf("expected 2 local credentials after --templates-dir issue, got %d", len(w.GetCredentials()))
	}
}

// resetIssueFlagChanges clears cobra's Changed state between Execute calls
// in a single test, mirroring fresh CLI invocations.
func resetIssueFlagChanges(t *testing.T) {
	t.Helper()
	saved := walletDir
	resetTemplateTestState(t)
	walletDir = saved
	remoteFlag = ""
}

func TestRemoteTemplatesViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url

	rootCmd.SetArgs([]string{"templates", "save", "remote-card",
		"--format", "sdjwt", "--vct", "urn:example:remote",
		"--claims", `{"a": "1"}`, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote templates save: %v", err)
	}

	client := remote.NewClient(url)
	tpl, err := client.Template("remote-card")
	if err != nil {
		t.Fatalf("template not on remote wallet: %v", err)
	}
	if tpl["vct"] != "urn:example:remote" {
		t.Errorf("unexpected remote template: %v", tpl)
	}

	rootCmd.SetArgs([]string{"templates", "delete", "remote-card", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote templates delete: %v", err)
	}
	if _, err := client.Template("remote-card"); err == nil {
		t.Error("template still on remote wallet after delete")
	}
}

func TestWalletUseRejectsUnreachable(t *testing.T) {
	resetRemoteTestState(t)
	rootCmd.SetArgs([]string{"wallet", "instances", "use", "http://localhost:1"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for unreachable wallet")
	}
	if remote.Active() != "" {
		t.Errorf("unreachable target must not be persisted, got %q", remote.Active())
	}
}

func TestWalletUseChecksVersionCompatibility(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)
	srv.SetVersion("2.4.0")
	withCLIVersion(t, "1.19.0")

	rootCmd.SetArgs([]string{"wallet", "instances", "use", url})
	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an instance a major release apart to be refused")
	}
	if !strings.Contains(err.Error(), "2.4.0") || !strings.Contains(err.Error(), "1.19.0") {
		t.Errorf("the error must name both releases, got %q", err)
	}
	if remote.Active() != "" {
		t.Errorf("an incompatible instance must not become the target, got %q", remote.Active())
	}

	// --force is the escape hatch for a user who knows better.
	rootCmd.SetArgs([]string{"wallet", "instances", "use", url, "--force"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet instances use --force: %v", err)
	}
	if remote.Active() != url {
		t.Errorf("--force must select the instance, got %q", remote.Active())
	}
	t.Cleanup(func() {
		rootCmd.SetArgs([]string{"wallet", "instances", "use", url, "--force=false"})
		_ = rootCmd.Execute()
	})

	// Within the major release the two are compatible, in either direction.
	srv.SetVersion("1.18.0")
	if err := remote.ClearActive(); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"wallet", "instances", "use", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("an older minor release must still be selectable: %v", err)
	}
	if remote.Active() != url {
		t.Errorf("expected the instance to be selected, got %q", remote.Active())
	}
}

func TestInstancesListShowsInstanceVersion(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)
	srv.SetVersion("1.42.0")
	withCLIVersion(t, "1.42.0")

	if err := remote.RegisterInstance(remote.Instance{
		PID: os.Getpid(), Port: portFromURL(t, url), URL: url, StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "instances", "list"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet instances list: %v", err)
		}
	})
	if !strings.Contains(out, "VERSION") || !strings.Contains(out, "1.42.0") {
		t.Errorf("the listing must report the instance version, got:\n%s", out)
	}
}

// withCLIVersion pins the version this CLI reports for the test.
func withCLIVersion(t *testing.T, version string) {
	t.Helper()
	previous := Version
	Version = version
	t.Cleanup(func() { Version = previous })
}

// captureStdout collects what fn writes to os.Stdout. The instance listing
// writes there directly rather than through cobra's output writer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		done <- buf.String()
	}()
	fn()
	os.Stdout = previous
	_ = writer.Close()
	out := <-done
	_ = reader.Close()
	return out
}

func TestWalletKillViaShutdownEndpoint(t *testing.T) {
	resetRemoteTestState(t)
	url, srv := startRemoteTestWallet(t)

	shutdownCalled := make(chan struct{})
	srv.ShutdownFunc = func() { close(shutdownCalled) }

	// Register the instance so discovery finds it without a process scan.
	port := portFromURL(t, url)
	if err := remote.RegisterInstance(remote.Instance{PID: 999999, Port: port, URL: url, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"wallet", "instances", "kill", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet kill: %v", err)
	}
	select {
	case <-shutdownCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown endpoint was not invoked")
	}
}

func portFromURL(t *testing.T, url string) int {
	t.Helper()
	idx := strings.LastIndex(url, ":")
	if idx < 0 {
		t.Fatalf("no port in %q", url)
	}
	port, err := strconv.Atoi(url[idx+1:])
	if err != nil {
		t.Fatalf("parsing port from %q: %v", url, err)
	}
	return port
}

func TestRemoteShowImportLogsInfoViaCLI(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url
	t.Cleanup(func() { remoteFlag = "" })

	// Seed one credential on the remote wallet.
	rootCmd.SetArgs([]string{"issue", "sdjwt", "--wallet", "--template", "german-pid-sdjwt", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote issue: %v", err)
	}
	client := remote.NewClient(url)
	creds, err := client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected 1 remote credential: %v %v", creds, err)
	}
	id, _ := creds[0]["id"].(string)
	raw, _ := creds[0]["raw"].(string)

	// show (raw and decoded) must succeed against the remote wallet
	rootCmd.SetArgs([]string{"wallet", "show", id, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show: %v", err)
	}
	rootCmd.SetArgs([]string{"wallet", "show", id, "--decoded", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show --decoded: %v", err)
	}

	// import: wipe and re-import the raw credential from a file
	if _, err := client.RemoveAllCredentials(); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(t.TempDir(), "cred.txt")
	if err := os.WriteFile(credFile, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{"wallet", "import", credFile, "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote import: %v", err)
	}
	creds, err = client.Credentials()
	if err != nil || len(creds) != 1 {
		t.Fatalf("expected re-imported credential: %v %v", creds, err)
	}

	// logs and info must succeed. --follow is rejected remotely
	rootCmd.SetArgs([]string{"wallet", "logs", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote logs: %v", err)
	}
	rootCmd.SetArgs([]string{"wallet", "logs", "--follow", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for remote --follow")
	}
	rootCmd.SetArgs([]string{"wallet", "info", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote info: %v", err)
	}
}

func TestRemoteTemplatesListShowUseRemoteStore(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	// One template exists only on the remote wallet, another only locally.
	client := remote.NewClient(url)
	if _, err := client.PutTemplate("remote-only", map[string]any{"format": "sdjwt", "claims": map[string]any{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := credtemplate.Save(credtemplate.DirForWallet(walletDir), credtemplate.Template{
		Name: "local-only", Format: "sdjwt", Claims: map[string]any{"b": 2},
	}); err != nil {
		t.Fatal(err)
	}

	// show resolves against the remote store: the remote-only template is
	// found, the local-only one is not.
	rootCmd.SetArgs([]string{"templates", "show", "remote-only", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote show must find the remote template: %v", err)
	}
	rootCmd.SetArgs([]string{"templates", "show", "local-only", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("remote show must not fall back to the local store")
	}

	// list runs against the remote store
	rootCmd.SetArgs([]string{"templates", "list", "--remote", url})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("remote list: %v", err)
	}
}

func TestCompletionFunctions(t *testing.T) {
	resetRemoteTestState(t)

	// Template completion lists pre-defined templates locally.
	names, directive := completeTemplateNames(nil, nil, "")
	if directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("unexpected directive: %v", directive)
	}
	joined := strings.Join(names, "\n")
	if !strings.Contains(joined, "german-pid-sdjwt") || !strings.Contains(joined, "german-pid-mdoc") {
		t.Errorf("expected pre-defined templates in completion, got %v", names)
	}

	// Credential completion never creates a wallet as a side effect.
	ids, _ := completeCredentialIDs(nil, nil, "")
	if len(ids) != 0 {
		t.Errorf("expected no completions without a wallet, got %v", ids)
	}
	if _, err := os.Stat(filepath.Join(walletDir, "wallet.json")); !os.IsNotExist(err) {
		t.Error("completion must not create a wallet store")
	}

	// With a remote configured, completions come from the remote wallet.
	url, _ := startRemoteTestWallet(t)
	remoteFlag = url
	client := remote.NewClient(url)
	if _, err := client.PutTemplate("completion-card", map[string]any{"format": "sdjwt", "claims": map[string]any{"a": 1}}); err != nil {
		t.Fatal(err)
	}
	names, _ = completeTemplateNames(nil, nil, "")
	if !strings.Contains(strings.Join(names, "\n"), "completion-card") {
		t.Errorf("expected remote template in completion, got %v", names)
	}

	// Instance completion offers running instances plus local for use.
	if err := remote.RegisterInstance(remote.Instance{PID: 424242, Port: portFromURL(t, url), URL: url, StartedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	targets, _ := completeUseTargets(nil, nil, "")
	joined = strings.Join(targets, "\n")
	if !strings.Contains(joined, "local") || !strings.Contains(joined, url) {
		t.Errorf("expected local and instance url in completion, got %v", targets)
	}
}

func TestCompletionInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// zsh: appends the source line once, second run is a no-op
	rootCmd.SetArgs([]string{"completion", "install", "zsh"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("completion install zsh: %v", err)
	}
	rootCmd.SetArgs([]string{"completion", "install", "zsh"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("second install: %v", err)
	}
	rc, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(rc), "completion zsh"); count != 1 {
		t.Errorf("expected exactly one source line, got %d:\n%s", count, rc)
	}

	// fish: writes the completion file
	rootCmd.SetArgs([]string{"completion", "install", "fish"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("completion install fish: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "fish", "completions", rootCmd.Name()+".fish")); err != nil {
		t.Errorf("fish completion file missing: %v", err)
	}

	// unsupported shell errors
	rootCmd.SetArgs([]string{"completion", "install", "tcsh"})
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected error for unsupported shell")
	}
}

// Every wallet has its own CA, so a trust list read from the local store while
// the CLI is pointed at a remote wallet anchors nothing the remote issues.
func TestTrustListFollowsTheRemoteWallet(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	// A local wallet with its own CA, which is what the command used to print.
	localHolder, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	localIssuer, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	local := wallet.New(localHolder, localIssuer, false)
	if err := loadStore().Save(local); err != nil {
		t.Fatal(err)
	}

	served, err := remote.NewClient(url).TrustList("", "", "")
	if err != nil {
		t.Fatalf("fetching the remote trust list: %v", err)
	}
	// Compared by anchor rather than by JWT: each list is signed when it is
	// asked for, so two fetches never match byte for byte.
	wantAnchors := trustListAnchors(t, served)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "trust-list", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet trust-list --remote: %v", err)
		}
	})

	anchors := trustListAnchors(t, strings.TrimSpace(out))
	if len(anchors) == 0 {
		t.Fatal("the printed trust list carries no certificate")
	}
	for der := range wantAnchors {
		if !anchors[der] {
			t.Error("trust-list --remote does not anchor the remote wallet's CA")
		}
	}
	if anchors[string(local.CertChain[len(local.CertChain)-1].Raw)] {
		t.Error("trust-list --remote anchored the local CA, which validates nothing the remote issues")
	}
}

// trustListAnchors returns the DER of every certificate a trust list JWT
// carries, keyed for lookup.
func trustListAnchors(t *testing.T, jwt string) map[string]bool {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		t.Fatalf("not a JWT: %.40s", jwt)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding the trust list payload: %v", err)
	}
	var doc any
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parsing the trust list payload: %v", err)
	}
	found := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if raw, ok := v["val"].(string); ok {
				if der, err := base64.StdEncoding.DecodeString(raw); err == nil {
					found[string(der)] = true
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	return found
}

// Without a listing the profile ids are only discoverable by reading the HTTP
// index, so a caller has to guess which one covers what it verifies.
func TestTrustListListsProfiles(t *testing.T) {
	resetRemoteTestState(t)
	url, _ := startRemoteTestWallet(t)

	out := captureStdout(t, func() {
		rootCmd.SetArgs([]string{"wallet", "trust-list", "--list", "--remote", url})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("wallet trust-list --list: %v", err)
		}
	})

	for _, want := range []string{"wallet-provider", "/api/trustlists/"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing does not mention %q:\n%s", want, out)
		}
	}

	// A listing plus a selection is a contradiction, not a narrowed listing.
	rootCmd.SetArgs([]string{"wallet", "trust-list", "--list", "--id", "pid", "--remote", url})
	if err := rootCmd.Execute(); err == nil {
		t.Error("--list with --id was accepted")
	}
}

// The same document reaches these renderers from two directions: through JSON
// from a remote instance (every number a float64) and straight out of the
// wallet in this process (numbers keep their Go type). Reading only float64
// made `wallet list --remote local` report a revoked credential as governed
// by someone else's status list.
func TestCredentialLabelsReadBothNumberShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status any
		want   string
	}{
		{"from JSON", float64(1), "revoked"},
		{"from this process", 1, "revoked"},
		{"active from this process", 0, "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := map[string]any{"status": map[string]any{
				"managed": true,
				"status":  tc.status,
				"uri":     "https://wallet.example/api/statuslist",
				"idx":     2,
			}}
			if got := credStatusLabel(cred); got != tc.want {
				t.Errorf("credStatusLabel = %q, want %q", got, tc.want)
			}
		})
	}
}

// The validity column answers "is this still good", so it has to distinguish
// an expired credential from one that never states a lifetime.
func TestCredentialValidityLabel(t *testing.T) {
	// RFC 3339 carries whole seconds, and the label floors rather than
	// overstating what is left, so the stamps get a second of slack.
	stamp := func(d time.Duration) map[string]any {
		return map[string]any{"expires_at": time.Now().Add(d + time.Second).UTC().Format(time.RFC3339)}
	}
	for _, tc := range []struct {
		name string
		cred map[string]any
		want string
	}{
		{"no expiry", map[string]any{}, "-"},
		{"unparseable", map[string]any{"expires_at": "soon"}, "-"},
		{"expired", stamp(-time.Hour), "expired"},
		{"days", stamp(72 * time.Hour), "3d"},
		{"hours", stamp(5 * time.Hour), "5h"},
		{"minutes", stamp(30 * time.Minute), "30m"},
		{"seconds", stamp(30 * time.Second), "<1m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := credValidityLabel(tc.cred); got != tc.want {
				t.Errorf("credValidityLabel = %q, want %q", got, tc.want)
			}
		})
	}
}
