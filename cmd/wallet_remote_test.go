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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/remote"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
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
	rootCmd.SetArgs([]string{"wallet", "use", url})
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
	rootCmd.SetArgs([]string{"wallet", "use", "local"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("wallet use local: %v", err)
	}
	if remote.Active() != "" {
		t.Fatalf("expected local management, got %q", remote.Active())
	}
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
	rootCmd.SetArgs([]string{"wallet", "use", "http://localhost:1"})
	if err := rootCmd.Execute(); err == nil {
		t.Fatal("expected error for unreachable wallet")
	}
	if remote.Active() != "" {
		t.Errorf("unreachable target must not be persisted, got %q", remote.Active())
	}
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

	rootCmd.SetArgs([]string{"wallet", "kill", url})
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

	// logs and info must succeed; --follow is rejected remotely
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
