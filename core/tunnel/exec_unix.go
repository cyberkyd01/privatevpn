//go:build darwin || (linux && !android)

package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const cmdTimeout = 20 * time.Second

// run executes path (absolute) with args — never through a shell — and
// returns its stdout (capped at 1 MiB).
func run(label, path string, args ...string) ([]byte, error) {
	return runInput(label, nil, path, args...)
}

// runInput is run with data on the command's stdin.
func runInput(label string, stdin []byte, path string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%s: refusing relative command path", label)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	stdout := &capBuffer{max: 1 << 20}
	stderr := &capBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	prepareCmd(cmd)
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			err = errors.New("timed out")
		}
		line, _, _ := strings.Cut(strings.TrimSpace(stderr.buf.String()), "\n")
		return stdout.buf.Bytes(), &cmdError{label: label, err: err, detail: Redact(strings.TrimSpace(line))}
	}
	return stdout.buf.Bytes(), nil
}

// findExe returns the first existing regular, non-writable-by-others file
// among candidates (all absolute), or "".
func findExe(candidates ...string) string {
	for _, p := range candidates {
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o022 == 0 && fi.Mode().Perm()&0o111 != 0 {
			return p
		}
	}
	return ""
}
