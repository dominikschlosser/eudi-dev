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

//go:build darwin

package wallet

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/internal/config"
)

const appBundleName = "OID4VC-Dev-Wallet.app"

func supportsURLSchemeRegistration() bool {
	return true
}

func appBundlePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", appBundleName)
}

func handlerScriptPath() string {
	home, _ := os.UserHomeDir()
	_ = home
	return filepath.Join(config.BaseDir(), "url-handler.sh")
}

// RegisterURLSchemes creates a macOS .app bundle via osacompile and registers URL scheme handlers.
// macOS delivers URLs via Apple Events, so we use an AppleScript with "on open location"
// that calls a bash handler script.
func RegisterURLSchemes(opts RegisterOptions) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding executable path: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	// Write the bash handler script
	handlerPath := handlerScriptPath()
	if err := os.MkdirAll(filepath.Dir(handlerPath), 0755); err != nil {
		return fmt.Errorf("creating handler directory: %w", err)
	}

	handler := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(`#!/bin/bash
BINARY="{{BINARY_PATH}}"
URI="$1"
LISTENER="http://localhost:{{PORT}}"
PORT="{{PORT}}"
AUTO_ACCEPT="{{AUTO_ACCEPT}}"
SERVE_ARGS=({{SERVE_ARGS}})
LOG_FILE="/tmp/oid4vc-dev-wallet.log"
SERVER_LOG="/tmp/oid4vc-dev-wallet-server.log"

listener_ready() {
  curl -sf "$LISTENER/api/credentials" >/dev/null 2>&1
}

# Restart the running server if it was built from an older binary than the one
# on disk. The server reports the SHA-256 of its own executable (hashed at
# startup) via /api/version; a mismatch means it outlived a rebuild.
stop_stale_listener() {
  LOCAL_ID=$(shasum -a 256 "$BINARY" 2>/dev/null | cut -d' ' -f1)
  [[ -z "$LOCAL_ID" ]] && return 0
  VERSION_JSON=$(curl -sf "$LISTENER/api/version" 2>/dev/null)
  SERVER_ID=$(printf '%s' "$VERSION_JSON" | sed -n 's/.*"build_id":"\([0-9a-f]*\)".*/\1/p')
  [[ "$SERVER_ID" == "$LOCAL_ID" ]] && return 0
  echo "wallet server is running an outdated build, restarting" >>"$SERVER_LOG"
  SERVER_PID=$(printf '%s' "$VERSION_JSON" | sed -n 's/.*"pid":\([0-9]*\).*/\1/p')
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null
  else
    lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null
  fi
  for _ in $(seq 1 20); do
    listener_ready || break
    sleep 0.25
  done
}

ensure_listener() {
  if listener_ready; then
    stop_stale_listener
    if listener_ready; then
      return 0
    fi
  fi
  ARGS=(wallet serve)
  if [[ ${#SERVE_ARGS[@]} -gt 0 ]]; then
    ARGS+=("${SERVE_ARGS[@]}")
  fi
  "$BINARY" "${ARGS[@]}" >>"$SERVER_LOG" 2>&1 &
  for _ in $(seq 1 40); do
    if listener_ready; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

submit_offer() {
  curl -sf -X POST "$LISTENER/api/offers" \
    -H "Content-Type: application/json" \
    -d "{\"uri\":\"$URI\"}" >/dev/null
}

submit_presentation() {
  curl -sf -X POST "$LISTENER/api/presentations" \
    -H "Content-Type: application/json" \
    -d "{\"uri\":\"$URI\"}" >/dev/null
}

accept_cli() {
  case "$1" in
    presentation)
      if [[ "$AUTO_ACCEPT" == "true" ]]; then
        "$BINARY" wallet accept --auto-accept "$URI" 2>&1 | tee -a "$LOG_FILE"
        return 0
      fi
      ;;
  esac
  "$BINARY" wallet accept "$URI" 2>&1 | tee -a "$LOG_FILE"
}

case "$URI" in
  openid-credential-offer://*|haip-vci://*)
    if ensure_listener; then
      submit_offer 2>>"$LOG_FILE" && exit 0
    fi
    accept_cli offer
    ;;
  *)
    if [[ "$AUTO_ACCEPT" == "true" ]]; then
      submit_presentation 2>>"$LOG_FILE" || accept_cli presentation
      exit 0
    fi
    if ensure_listener; then
      submit_presentation 2>>"$LOG_FILE" && exit 0
    fi
    accept_cli presentation
    ;;
esac
`, "{{BINARY_PATH}}", binaryPath), "{{PORT}}", fmt.Sprintf("%d", opts.ListenerPort)), "{{AUTO_ACCEPT}}", fmt.Sprintf("%t", opts.AutoAccept))
	handler = strings.ReplaceAll(handler, "{{SERVE_ARGS}}", joinShellArgs(opts.ServeArgs))

	if err := os.WriteFile(handlerPath, []byte(handler), 0755); err != nil {
		return fmt.Errorf("writing handler script: %w", err)
	}

	// Remove existing bundle so osacompile can create a fresh one
	bundlePath := appBundlePath()
	os.RemoveAll(bundlePath)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0755); err != nil {
		return fmt.Errorf("creating Applications directory: %w", err)
	}

	// Write AppleScript source — "on open location" receives the URL from macOS Apple Events
	appleScript := fmt.Sprintf(`on open location theURL
	do shell script quoted form of "%s" & " " & quoted form of theURL & " >> /tmp/oid4vc-dev-wallet.log 2>&1 &"
end open location
`, handlerPath)

	tmpScript, err := os.CreateTemp("", "oid4vc-dev-*.applescript")
	if err != nil {
		return fmt.Errorf("creating temp AppleScript: %w", err)
	}
	defer os.Remove(tmpScript.Name())

	if _, err := tmpScript.WriteString(appleScript); err != nil {
		tmpScript.Close()
		return fmt.Errorf("writing AppleScript: %w", err)
	}
	tmpScript.Close()

	// Compile AppleScript into .app bundle
	cmd := exec.Command("osacompile", "-o", bundlePath, tmpScript.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("osacompile failed: %s: %w", string(out), err)
	}

	// Patch Info.plist to add URL schemes and LSUIElement (no Dock icon)
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	plistBuddy := "/usr/libexec/PlistBuddy"

	plistCmds := [][]string{
		{"-c", "Add :CFBundleIdentifier string com.oid4vc-dev.wallet", plistPath},
		{"-c", "Add :LSUIElement bool true", plistPath},
		{"-c", "Add :CFBundleURLTypes array", plistPath},
		// OID4VP schemes
		{"-c", "Add :CFBundleURLTypes:0 dict", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLName string OID4VP", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes array", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string openid4vp", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:1 string eudi-openid4vp", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:2 string haip-vp", plistPath},
		// OID4VCI scheme
		{"-c", "Add :CFBundleURLTypes:1 dict", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLName string OID4VCI", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLSchemes array", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLSchemes:0 string openid-credential-offer", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLSchemes:1 string haip-vci", plistPath},
	}

	for _, args := range plistCmds {
		cmd := exec.Command(plistBuddy, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("PlistBuddy %v failed: %s: %w", args, string(out), err)
		}
	}

	// Re-sign the bundle (osacompile signs it, but PlistBuddy modifications invalidate the signature)
	cmd = exec.Command("codesign", "--force", "--sign", "-", bundlePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("codesign failed: %s: %w", string(out), err)
	}

	// Register with Launch Services
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	cmd = exec.Command(lsregister, "-R", bundlePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("lsregister failed: %s: %w", string(out), err)
	}

	fmt.Printf("Registered URL scheme handlers:\n")
	fmt.Printf("  App bundle: %s\n", bundlePath)
	fmt.Printf("  Handler:    %s\n", handlerPath)
	fmt.Printf("  Binary:     %s\n", binaryPath)
	fmt.Printf("  Mode:       ")
	if opts.AutoAccept {
		fmt.Printf("auto-accept\n")
	} else {
		fmt.Printf("interactive UI\n")
	}
	if len(opts.ServeArgs) > 0 {
		fmt.Printf("  Serve args: %s\n", strings.Join(slices.Clone(opts.ServeArgs), " "))
	}
	fmt.Printf("  Schemes:    openid4vp://, eudi-openid4vp://, haip-vp://, openid-credential-offer://, haip-vci://\n")
	return nil
}

func joinShellArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// UnregisterURLSchemes removes the macOS .app bundle and handler script.
func UnregisterURLSchemes() error {
	bundlePath := appBundlePath()

	// Unregister from Launch Services
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	cmd := exec.Command(lsregister, "-u", bundlePath)
	_, _ = cmd.CombinedOutput() // ignore errors if not registered

	// Remove the app bundle
	if err := os.RemoveAll(bundlePath); err != nil {
		return fmt.Errorf("removing app bundle: %w", err)
	}

	// Remove handler script
	os.Remove(handlerScriptPath()) // ignore errors if not present

	fmt.Printf("Unregistered URL scheme handlers and removed %s\n", bundlePath)
	return nil
}
