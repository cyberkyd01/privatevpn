//go:build (darwin || linux) && !android

package helper

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func shortTempDir(t *testing.T) string {
	t.Helper()
	// t.TempDir() can exceed the 104-byte sun_path limit on macOS.
	d, err := os.MkdirTemp("/tmp", "pvp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestSocketpairPeerUID(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		f := os.NewFile(uintptr(fd), "sp")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		uid, err := peerUID(c.(*net.UnixConn))
		if err != nil || uid != os.Getuid() {
			t.Fatalf("peerUID = %d, %v; want %d", uid, err, os.Getuid())
		}
	}
}

func TestValidSocketPath(t *testing.T) {
	for _, ok := range []string{"/run/user/1000/private-vpn-pro/helper-0123456789abcdef.sock", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock"} {
		if validSocketPath(ok) != nil {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{
		"relative/helper-0123456789abcdef.sock", "/tmp/../etc/helper-0123456789abcdef.sock", "/tmp//helper-0123456789abcdef.sock",
		"/tmp/helper-0123456789ABCDEF.sock", "/tmp/helper-0123.sock", "/tmp/sudoers", "/tmp/" + string(make([]byte, 120)) + "/helper-0123456789abcdef.sock",
	} {
		if validSocketPath(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseArgsUnix(t *testing.T) {
	o, err := parseArgs([]string{"--socket", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", "--uid", "501"})
	if err != nil || o.uid != 501 {
		t.Fatalf("%+v %v", o, err)
	}
	for _, bad := range [][]string{
		{"--socket", "/tmp/x.sock", "--uid", "501"},
		{"--socket", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", "--uid", "-1"},
		{"--socket", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", "--uid", "x"},
		{"--socket", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", "--uid", "501", "extra"},
		{"--pipe", "x"},
	} {
		if _, err := parseArgs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if Run([]string{"tunnel-helper", "--bogus"}) != exitUsage {
		t.Error("Run with bad args")
	}
	if os.Geteuid() != 0 {
		if code := Run([]string{"--socket", "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock", "--uid", "501"}); code != exitNotElevated {
			t.Errorf("unelevated Run = %d", code)
		}
	}
}

func TestCheckSocketDir(t *testing.T) {
	d := shortTempDir(t)
	if err := checkSocketDir(d, os.Getuid()); err != nil {
		t.Fatalf("own 0700 dir: %v", err)
	}
	if err := checkSocketDir(d, os.Getuid()+1); err == nil {
		t.Error("foreign owner accepted")
	}
	open := filepath.Join(d, "open")
	os.Mkdir(open, 0o755)
	os.Chmod(open, 0o755)
	if err := checkSocketDir(open, os.Getuid()); err == nil {
		t.Error("0755 dir accepted")
	}
	link := filepath.Join(d, "link")
	os.Symlink(d, link)
	if err := checkSocketDir(link, os.Getuid()); err == nil {
		t.Error("symlink accepted")
	}
	p, err := socketPath(filepath.Join(d, "missing", "deeper"), filepath.Join(d, "sock"))
	if err != nil || filepath.Dir(p) != filepath.Join(d, "sock") {
		t.Fatalf("socketPath = %s, %v", p, err)
	}
	if fi, _ := os.Lstat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
		t.Errorf("socket dir mode %v", fi.Mode().Perm())
	}
}

// TestAcceptOneOverUnixSocket runs the real listener (as the current user:
// lchown to ourselves needs no privileges) and a full client⇄helper session
// over the socket.
func TestAcceptOneOverUnixSocket(t *testing.T) {
	d := shortTempDir(t)
	h, _ := randomHex()
	path := filepath.Join(d, "helper-"+h+".sock")
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := acceptOne(helperOpts{socket: path, uid: os.Getuid()}, 5*time.Second)
		ch <- res{c, err}
	}()
	var cli net.Conn
	for i := 0; i < 200; i++ {
		var err error
		if cli, err = net.Dial("unix", path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cli == nil {
		t.Fatal("could not dial the helper socket")
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("acceptOne: %v", r.err)
	}
	defer r.c.Close()
	// One connection only: the socket is gone once accepted.
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("socket still present after accept: %v", err)
	}
	// Full session over the real socket.
	used := false
	hz := newHarness(t, "1.0.0", func() (net.Conn, net.Conn) {
		if used {
			t.Fatal("second launch")
		}
		used = true
		return cli, r.c
	})
	if _, err := hz.c.Up(testCfg(t)); err != nil {
		t.Fatalf("Up over unix socket: %v", err)
	}
	if st, err := hz.c.Status(); err != nil || st.RxBytes != 123 {
		t.Fatalf("Status: %+v %v", st, err)
	}
	hz.c.Close()
	waitFor(t, "teardown", func() bool { _, closed, _ := hz.ft.snapshot(); return closed })
}

// A pre-existing file (or symlink) at the socket path is refused before
// anything is bound: root must never bind through a path it did not create.
func TestAcceptOneRefusesExistingPath(t *testing.T) {
	d := shortTempDir(t)
	h, _ := randomHex()
	path := filepath.Join(d, "helper-"+h+".sock")
	if err := os.Symlink(filepath.Join(d, "elsewhere.sock"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := acceptOne(helperOpts{socket: path, uid: os.Getuid()}, time.Second); err == nil {
		t.Fatal("acceptOne bound over an existing path")
	}
	if _, err := os.Lstat(filepath.Join(d, "elsewhere.sock")); !os.IsNotExist(err) {
		t.Fatalf("symlink target was created: %v", err)
	}
}

// Under pkexec, --uid must name the invoking user.
func TestParseArgsPkexecUID(t *testing.T) {
	path := "/tmp/private-vpn-pro-501/helper-0123456789abcdef.sock"
	t.Setenv("PKEXEC_UID", "501")
	if _, err := parseArgs([]string{"--socket", path, "--uid", "501"}); err != nil {
		t.Fatalf("matching uid refused: %v", err)
	}
	if _, err := parseArgs([]string{"--socket", path, "--uid", "502"}); err == nil {
		t.Fatal("mismatching --uid accepted under pkexec")
	}
	t.Setenv("PKEXEC_UID", "")
	if _, err := parseArgs([]string{"--socket", path, "--uid", "502"}); err != nil {
		t.Fatalf("without pkexec any uid is fine: %v", err)
	}
}

// Loader and Go runtime variables never reach the launcher.
func TestLauncherEnvFilter(t *testing.T) {
	in := []string{"PATH=/usr/bin", "DYLD_INSERT_LIBRARIES=/x.dylib", "LD_PRELOAD=/x.so", "GOTRACEBACK=crash",
		"GODEBUG=x=1", "WG_TUN_NAME_FILE=/tmp/x", "CGO_ENABLED=1", "PKEXEC_UID=0", "HOME=/Users/x", "LANG=C", "GOOD=1"}
	got := filterEnv(in, launcherEnvDrop)
	want := []string{"PATH=/usr/bin", "HOME=/Users/x", "LANG=C"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAcceptOneSocketMode(t *testing.T) {
	d := shortTempDir(t)
	h, _ := randomHex()
	path := filepath.Join(d, "helper-"+h+".sock")
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := acceptOne(helperOpts{socket: path, uid: os.Getuid()}, 3*time.Second)
		if err == nil {
			c.Close()
		}
	}()
	var fi os.FileInfo
	for i := 0; i < 200; i++ {
		var err error
		if fi, err = os.Lstat(path); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi == nil {
		t.Fatal("socket never appeared")
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 || int(st.Uid) != os.Getuid() {
		t.Errorf("socket mode %v uid %d", fi.Mode(), st.Uid)
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
	}
	<-done
}
