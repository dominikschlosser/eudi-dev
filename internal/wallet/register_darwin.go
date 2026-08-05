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

const appBundleName = "EUDI-Dev-Wallet.app"

// legacyAppBundleName is the pre-rename bundle. It has to be removed and
// deregistered explicitly: leaving it behind means Launch Services keeps a
// second handler for the same schemes, so macOS either shows the old name in
// the open dialog or asks which app to use.
const legacyAppBundleName = "OID4VC-Dev-Wallet.app"

func supportsURLSchemeRegistration() bool {
	return true
}

func appBundlePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", appBundleName)
}

func legacyAppBundlePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", legacyAppBundleName)
}

// removeBundle deregisters a bundle from Launch Services and deletes it.
func removeBundle(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	_, _ = exec.Command(lsregister, "-u", path).CombinedOutput() // not registered is fine
	return os.RemoveAll(path)
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

	handler := handlerScriptSource(binaryPath, opts)

	if err := os.WriteFile(handlerPath, []byte(handler), 0755); err != nil {
		return fmt.Errorf("writing handler script: %w", err)
	}

	// Remove existing bundles so osacompile can create a fresh one, including
	// the pre-rename one that would otherwise keep claiming the schemes.
	bundlePath := appBundlePath()
	os.RemoveAll(bundlePath)
	if err := removeBundle(legacyAppBundlePath()); err != nil {
		return fmt.Errorf("removing the previous %s: %w", legacyAppBundleName, err)
	}
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0755); err != nil {
		return fmt.Errorf("creating Applications directory: %w", err)
	}
	return compileHandlerBundle(handlerPath, bundlePath, binaryPath, opts)
}

// compileHandlerBundle builds the .app that macOS dispatches URL schemes to.
func compileHandlerBundle(handlerPath, bundlePath, binaryPath string, opts RegisterOptions) error {
	// Write AppleScript source. "on open location" receives the URL from macOS Apple Events
	appleScript := fmt.Sprintf(`on open location theURL
	do shell script quoted form of "%s" & " " & quoted form of theURL & " >> /tmp/eudi-dev-wallet.log 2>&1 &"
end open location
`, handlerPath)

	tmpScript, err := os.CreateTemp("", "eudi-dev-*.applescript")
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
		{"-c", "Add :CFBundleIdentifier string dev.eudi.wallet", plistPath},
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

// UnregisterURLSchemes removes the macOS .app bundle and handler script.
func UnregisterURLSchemes() error {
	bundlePath := appBundlePath()

	if err := removeBundle(bundlePath); err != nil {
		return fmt.Errorf("removing app bundle: %w", err)
	}
	// Also clean up the pre-rename bundle if this machine still has one.
	if err := removeBundle(legacyAppBundlePath()); err != nil {
		return fmt.Errorf("removing the previous %s: %w", legacyAppBundleName, err)
	}

	// Remove handler script
	os.Remove(handlerScriptPath()) // ignore errors if not present

	fmt.Printf("Unregistered URL scheme handlers and removed %s\n", bundlePath)
	return nil
}
