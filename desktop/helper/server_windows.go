//go:build windows

package helper

import (
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

const pipePrefix = `\\.\pipe\`

// sanitizeEnv drops variables that steer wireguard-go (Windows APIs need
// the rest of the environment, e.g. SystemRoot).
func sanitizeEnv() {
	for _, k := range []string{"WG_TUN_NAME_FILE", "WG_TUN_FD", "WG_UAPI_FD", "WG_PROCESS_FOREGROUND"} {
		_ = os.Unsetenv(k)
	}
}

type helperOpts struct {
	pipe string // bare name: private-vpn-pro-helper-<16 hex>
	sid  string
}

func parseArgs(args []string) (helperOpts, error) {
	fs := flag.NewFlagSet("tunnel-helper", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pipe := fs.String("pipe", "", "")
	sid := fs.String("sid", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return helperOpts{}, errors.New("usage")
	}
	o := helperOpts{pipe: *pipe, sid: *sid}
	if !validPipeName(o.pipe) || !validSID(o.sid) {
		return helperOpts{}, errors.New("bad --pipe or --sid")
	}
	return o, nil
}

// validSID: sidSyntaxOK plus Windows must parse it.
func validSID(s string) bool {
	if !sidSyntaxOK(s) {
		return false
	}
	_, err := windows.StringToSid(s)
	return err == nil
}

// acceptOne creates the pipe, accepts exactly one client and stops
// listening. The DACL restricts who can connect.
func acceptOne(o helperOpts, timeout time.Duration) (net.Conn, error) {
	l, err := winio.ListenPipe(pipePrefix+o.pipe, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL(o.sid),
		MessageMode:        true,
		InputBufferSize:    MaxLine,
		OutputBufferSize:   MaxLine,
	})
	if err != nil {
		return nil, err
	}
	defer l.Close() // stop listening after the first connection
	timer := time.AfterFunc(timeout, func() { l.Close() })
	defer timer.Stop()
	return l.Accept()
}
