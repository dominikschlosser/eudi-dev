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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

// spawnDetachedServe re-executes `wallet serve` without --detached as a
// child in its own session, waits until its HTTP endpoint responds, and
// returns while the child keeps serving. The child appears in
// `wallet instances list` through the normal instance registration.
func spawnDetachedServe(cmd *cobra.Command, port int, register, noRegister bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating executable: %w", err)
	}
	flags, err := serializeWalletServeArgs(cmd)
	if err != nil {
		return fmt.Errorf("serializing wallet serve flags: %w", err)
	}
	// serializeWalletServeArgs drops registration flags because the URL
	// scheme handler it was built for must not re-register; the detached
	// child should still honor them.
	if register {
		flags = append(flags, "--register")
	}
	if noRegister {
		flags = append(flags, "--no-register")
	}
	args := append([]string{"wallet", "serve"}, flags...)

	store := loadStore()
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		return fmt.Errorf("creating wallet dir: %w", err)
	}
	logPath := filepath.Join(store.Dir, "serve.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening serve log: %w", err)
	}
	defer logFile.Close()

	child := exec.Command(exe, args...)
	child.Stdout = logFile
	child.Stderr = logFile
	detachProcess(child)
	if err := child.Start(); err != nil {
		return fmt.Errorf("starting detached wallet serve: %w", err)
	}

	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()

	url := fmt.Sprintf("http://localhost:%d", port)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(15 * time.Second)
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("wallet serve exited during startup (%v), see %s", err, logPath)
		case <-timeout:
			_ = child.Process.Kill()
			return fmt.Errorf("wallet serve did not become ready within 15s, see %s", logPath)
		case <-ticker.C:
			if _, ok := healthSummary(url); !ok {
				continue
			}
			fmt.Printf("Wallet server running detached at %s (pid %d)\n", url, child.Process.Pid)
			fmt.Printf("  Log:  %s\n", logPath)
			fmt.Printf("  Stop: %s wallet instances kill %d\n", filepath.Base(exe), child.Process.Pid)
			return nil
		}
	}
}
