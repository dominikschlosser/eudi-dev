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

package remote

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
)

// Instance describes a running wallet server. Every `wallet serve` writes an
// instance file on startup and removes it on graceful shutdown; discovery
// prunes files whose process is gone.
type Instance struct {
	PID       int       `json:"pid"`
	Port      int       `json:"port"`
	URL       string    `json:"url"`
	WalletDir string    `json:"wallet_dir,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

// DiscoveredInstance is a running wallet instance found on the local system.
type DiscoveredInstance struct {
	Instance
	BuildID string `json:"build_id,omitempty"`
	// Source is "registry" (instance file) or "process" (found via process
	// scan without an instance file).
	Source string `json:"source"`
}

func instancesDir() string {
	return filepath.Join(configBaseDir(), "instances")
}

func instanceFile(pid int) string {
	return filepath.Join(instancesDir(), fmt.Sprintf("%d.json", pid))
}

// RegisterInstance records a running wallet server in the instance registry.
func RegisterInstance(inst Instance) error {
	if err := os.MkdirAll(instancesDir(), 0o755); err != nil {
		return fmt.Errorf("creating instances directory: %w", err)
	}
	data, err := json.MarshalIndent(inst, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(instanceFile(inst.PID), append(data, '\n'), 0o644)
}

// UnregisterInstance removes a wallet server from the instance registry.
func UnregisterInstance(pid int) {
	_ = os.Remove(instanceFile(pid))
}

// healthCheck probes a wallet server and returns its /api/version document.
func healthCheck(url string, timeout time.Duration) (map[string]any, bool) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/api/version")
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var version map[string]any
	if json.NewDecoder(resp.Body).Decode(&version) != nil {
		return nil, false
	}
	return version, true
}

// fetchInstanceConfig reads the instance's introspection document.
func fetchInstanceConfig(url string, timeout time.Duration) map[string]any {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/api/config")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var cfg map[string]any
	if json.NewDecoder(resp.Body).Decode(&cfg) != nil {
		return nil
	}
	return cfg
}

// Discover finds running wallet instances on the local system: everything in
// the instance registry (pruning entries whose server is gone) plus wallet
// serve processes found by scanning the process list.
func Discover(timeout time.Duration) []DiscoveredInstance {
	if timeout <= 0 {
		timeout = time.Second
	}
	var found []DiscoveredInstance
	seenPorts := map[int]bool{}

	entries, _ := os.ReadDir(instancesDir())
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(instancesDir(), entry.Name()))
		if err != nil {
			continue
		}
		var inst Instance
		if json.Unmarshal(data, &inst) != nil || inst.URL == "" {
			_ = os.Remove(filepath.Join(instancesDir(), entry.Name()))
			continue
		}
		version, alive := healthCheck(inst.URL, timeout)
		if !alive {
			// The server is gone: prune the stale registry entry.
			_ = os.Remove(filepath.Join(instancesDir(), entry.Name()))
			continue
		}
		di := DiscoveredInstance{Instance: inst, Source: "registry"}
		if build, ok := version["build_id"].(string); ok {
			di.BuildID = build
		}
		if pid, ok := version["pid"].(float64); ok && int(pid) != inst.PID {
			// A different process answers on this port now.
			di.PID = int(pid)
		}
		found = append(found, di)
		seenPorts[inst.Port] = true
	}

	for _, proc := range scanProcesses() {
		if seenPorts[proc.Port] {
			continue
		}
		url := fmt.Sprintf("http://localhost:%d", proc.Port)
		version, alive := healthCheck(url, timeout)
		if !alive {
			continue
		}
		di := DiscoveredInstance{
			Instance: Instance{PID: proc.PID, Port: proc.Port, URL: url},
			Source:   "process",
		}
		if build, ok := version["build_id"].(string); ok {
			di.BuildID = build
		}
		// The instance's introspection endpoint knows its wallet directory.
		if cfg := fetchInstanceConfig(url, timeout); cfg != nil {
			if dir, ok := cfg["wallet_dir"].(string); ok {
				di.WalletDir = dir
			}
		}
		found = append(found, di)
		seenPorts[proc.Port] = true
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Port < found[j].Port })
	return found
}

type scannedProcess struct {
	PID  int
	Port int
}

var portFlagPattern = regexp.MustCompile(`--port(?:[= ])(\d+)`)

// scanProcesses finds `wallet serve` processes in the local process list.
// Windows has no ps; there the instance registry is the only source.
func scanProcesses() []scannedProcess {
	if runtime.GOOS == "windows" {
		return nil
	}
	out, err := exec.Command("ps", "-axo", "pid=,command=").Output()
	if err != nil {
		return nil
	}
	var procs []scannedProcess
	self := os.Getpid()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "wallet serve") || !strings.Contains(line, "oid4vc") {
			continue
		}
		fields := strings.SplitN(line, " ", 2)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == self {
			continue
		}
		port := config.DefaultWalletPort
		if m := portFlagPattern.FindStringSubmatch(fields[1]); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil {
				port = p
			}
		}
		procs = append(procs, scannedProcess{PID: pid, Port: port})
	}
	return procs
}
