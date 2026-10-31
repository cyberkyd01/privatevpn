package tunnel

import "bytes"

// Command-execution helpers shared by the OS files (untagged so the pure
// classifiers in killswitch.go compile everywhere).

// capBuffer keeps at most max bytes of what is written to it.
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

// cmdError describes a failed command by a fixed label, never by its
// arguments (which may contain the gateway endpoint or client addresses).
type cmdError struct {
	label  string
	err    error
	detail string // first stderr line, redacted
}

func (e *cmdError) Error() string {
	if e.detail != "" {
		return e.label + ": " + e.err.Error() + ": " + e.detail
	}
	return e.label + ": " + e.err.Error()
}

func (e *cmdError) Unwrap() error { return e.err }
