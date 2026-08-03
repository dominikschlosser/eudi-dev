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

package wallet

import "embed"

// A whole-directory pattern, not a file list: an explicit list silently drops
// newly added assets from the binary (the logo and favicon shipped missing
// that way), and everything under static/ belongs to the UI anyway.
//
//go:embed static
var staticFiles embed.FS
