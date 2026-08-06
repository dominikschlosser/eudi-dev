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

// Package imprint renders the operator-supplied imprint (legal notice) page
// served at /imprint by the wallet and decoder servers. Hosting either UI
// publicly in the EU requires an imprint naming the site operator. The
// operator supplies the content, this package supplies the page shell.
package imprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// disclaimer mirrors the EU non-affiliation disclaimer from the README. It
// is appended to every imprint page.
const disclaimer = `This site runs <a href="https://github.com/dominikschlosser/eudi-dev">eudi-dev</a>, an independent open source project. It is <strong>not</strong> an official service of the European Commission or the European Union, has no affiliation with them, and is not endorsed by them. &ldquo;EUDI&rdquo; is used descriptively (a developer tool for the European Digital Identity ecosystem).`

// pageTemplate is the shell the operator's snippet goes into. It carries no
// script of any kind, including the back link: every server that mounts this
// page sends script-src 'self' without 'unsafe-inline', which blocks a
// scripted URL, so a link back to the site root is the only form that works.
const pageTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Imprint</title>
<style>
  body { font-family: system-ui, sans-serif; line-height: 1.6; max-width: 42rem; margin: 2rem auto; padding: 0 1rem; }
  @media (prefers-color-scheme: dark) { body { background: #1a1b26; color: #c0caf5; } a { color: #7aa2f7; } }
  hr { margin: 2rem 0; opacity: 0.4; }
  .disclaimer { font-size: 0.85rem; opacity: 0.8; }
</style>
</head>
<body>
<p><a href="/">&larr; Back</a></p>
%s
<hr>
<p class="disclaimer">%s</p>
</body>
</html>
`

// Load reads the operator's imprint HTML snippet and wraps it in a
// standalone page including the EU non-affiliation disclaimer. The snippet
// is trusted operator content and embedded as-is.
func Load(path string) ([]byte, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
	default:
		return nil, fmt.Errorf("imprint file %s must be an .html snippet", path)
	}
	snippet, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading imprint file: %w", err)
	}
	if strings.TrimSpace(string(snippet)) == "" {
		return nil, fmt.Errorf("imprint file %s is empty", path)
	}
	return []byte(fmt.Sprintf(pageTemplate, strings.TrimSpace(string(snippet)), disclaimer)), nil
}
