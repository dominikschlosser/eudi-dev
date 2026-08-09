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

package proxy

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/fatih/color"
)

// Subprocess manages a child process whose stdout/stderr is scanned for
// encryption keys and credentials.
type Subprocess struct {
	cmd     *exec.Cmd
	scanner *OutputScanner
	// done is closed once the process has exited; err holds the exit status
	// and is written before the close, so any reader that waits on done
	// observes it. A closed channel unblocks every waiter, so Wait and Done can
	// be consumed by more than one goroutine without one stealing the result.
	done chan struct{}
	err  error
}

// StartSubprocess launches args[0] with args[1:] as a child process.
// Stdout and stderr are merged, scanned line-by-line, and forwarded to
// the terminal with a [service] prefix.
func StartSubprocess(args []string, scanner *OutputScanner) (*Subprocess, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	setProcAttr(cmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", args[0], err)
	}

	sub := &Subprocess{
		cmd:     cmd,
		scanner: scanner,
		done:    make(chan struct{}),
	}

	// Scan both stdout and stderr
	merged := io.MultiReader(stdout, stderr)
	go sub.scanOutput(merged)

	go func() {
		sub.err = cmd.Wait()
		close(sub.done)
	}()

	return sub, nil
}

// scanOutput reads lines from the merged stdout/stderr, scans each line,
// and prints it to the terminal with a [service] prefix.
func (s *Subprocess) scanOutput(r io.Reader) {
	dim := color.New(color.Faint)
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 0, 256*1024), 1024*1024) // allow long lines
	for scan.Scan() {
		line := scan.Text()
		s.scanner.Scan(line)
		dim.Printf("[service] ")
		fmt.Println(line)
	}
}

// Wait blocks until the subprocess exits and returns its error. It is safe to
// call from more than one goroutine.
func (s *Subprocess) Wait() error {
	<-s.done
	return s.err
}

// Done returns a channel that is closed when the process exits. Read the exit
// error with Wait afterwards.
func (s *Subprocess) Done() <-chan struct{} {
	return s.done
}
