//go:build !android

// Command privatevpn is the desktop app (ARCHITECTURE §13.1): one binary for
// the tray + loopback web UI + engine (default), the privileged tunnel
// helper (`tunnel-helper`, §13.5), the Windows firewall rule
// (`firewall add|remove`, §13.6) and the kill-switch recovery commands
// (`unblock`, `killswitch-boot`).
//
// Nothing is ever logged to disk; stderr is not a log either (the Windows
// build has no console) and is only used for command-line errors.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"sync"
	"syscall"

	"github.com/cyberkyd01/privatevpn/core/api"
	"github.com/cyberkyd01/privatevpn/core/engine"
	"github.com/cyberkyd01/privatevpn/core/eventlog"
	"github.com/cyberkyd01/privatevpn/core/state"
	"github.com/cyberkyd01/privatevpn/core/tunnel"
	"github.com/cyberkyd01/privatevpn/desktop/autostart"
	"github.com/cyberkyd01/privatevpn/desktop/firewall"
	"github.com/cyberkyd01/privatevpn/desktop/helper"
	"github.com/cyberkyd01/privatevpn/desktop/tray"
	"github.com/cyberkyd01/privatevpn/desktop/web"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

const usage = `PrivateVPN — private VPN gateways for your own devices.

Usage:
  privatevpn [--no-tray] [--autostart]   start the app (tray icon + web UI)
  privatevpn version                     print the version
  privatevpn firewall add|remove         Windows: manage the inbound firewall rule (run as administrator)
  privatevpn unblock                     remove a kill-switch block left by a crashed or deleted app and
                                         restore direct Internet access (run as administrator / with sudo)
  privatevpn tunnel-helper …             internal: privileged tunnel helper
  privatevpn killswitch-boot             internal: re-installs the kill switch at boot (LaunchDaemon / systemd unit)

Flags:
  --no-tray     no tray icon: print a one-time sign-in link and keep running
                (for Linux desktops without a system tray)
  --autostart   started at login (restores gateway mode and the last VPN session)
`

func main() {
	// Goroutine dumps on a crash must not include our data (§12.1).
	debug.SetTraceback("none")
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}

	// pkexec's auth_admin_keep lets any process of this user re-run us as
	// root without a prompt for a while: as root via pkexec we only ever act
	// as the tunnel helper.
	if sub != "tunnel-helper" && os.Getenv("PKEXEC_UID") != "" {
		fmt.Fprintln(os.Stderr, "privatevpn: launched through pkexec; only the tunnel-helper subcommand is allowed")
		return 2
	}

	switch sub {
	case "tunnel-helper":
		helper.Version = version
		return helper.Run(args[1:])
	case "firewall":
		return firewallCmd(args[1:])
	case "unblock":
		return unblockCmd(args[1:])
	case "killswitch-boot":
		return killSwitchBootCmd(args[1:])
	case "version", "--version", "-version":
		fmt.Println(version)
		return 0
	case "help", "-h", "--help", "-help":
		fmt.Print(usage)
		return 0
	}

	fs := flag.NewFlagSet("privatevpn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	noTray := fs.Bool("no-tray", false, "")
	auto := fs.Bool("autostart", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	// The engine, tray and web UI always run as the logged-in user; only
	// the helper is privileged (D4).
	if runningAsRoot() {
		fmt.Fprintln(os.Stderr, "privatevpn: do not run PrivateVPN as root; start it as your normal user (it asks for administrator rights only when connecting)")
		return 2
	}
	return runApp(*noTray, *auto)
}

var semver = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

// appVersion is what the engine announces in beacons (major.minor.patch):
// "v1.2.3" → "1.2.3"; a non-release build ("dev") → "0.0.0".
func appVersion() string {
	if m := semver.FindStringSubmatch(version); m != nil {
		return m[1]
	}
	return "0.0.0"
}

func runApp(noTray, autostartLaunch bool) int {
	// Third-party packages (systray, net/http) must not print anything.
	log.SetOutput(io.Discard)

	dir, err := state.DefaultDir()
	if err != nil {
		fatal("cannot find the data directory: " + err.Error())
		return 1
	}
	lock, err := state.AcquireLock(dir)
	if errors.Is(err, state.ErrAlreadyRunning) {
		notifyAlreadyRunning(noTray)
		return 0
	}
	if err != nil {
		fatal("cannot lock the data directory: " + err.Error())
		return 1
	}
	defer lock.Release()

	exe, err := os.Executable()
	if err != nil {
		fatal("cannot find the program path: " + err.Error())
		return 1
	}

	var quitOnce sync.Once
	quitCh := make(chan struct{})
	quit := func() {
		quitOnce.Do(func() {
			close(quitCh)
			if !noTray {
				tray.Quit()
			}
		})
	}

	evlog := eventlog.Default
	helper.Version = version
	plat := engine.Platform{
		NewTunnel: func() (tunnel.Tunnel, error) {
			return helper.New(exe, version, evlog), nil
		},
		SetAutostart: autostart.Set,
		Quit:         quit,
	}
	if firewall.Supported() {
		plat.FirewallAdd = func() error { return firewall.AddElevated(exe) }
		plat.FirewallCheck = func() (bool, error) { return firewall.Check(exe) }
	}

	eng, err := engine.New(engine.Options{
		DataDir:    dir,
		AppVersion: appVersion(),
		Platform:   plat,
		Log:        evlog,
		Autostart:  autostartLaunch,
	})
	if err != nil {
		fatal("cannot start: " + err.Error())
		return 1
	}
	defer eng.Close()

	srv := web.New(eng, web.Options{Port: uiPort(eng)})
	if err := srv.Start(); err != nil {
		fatal(err.Error())
		return 1
	}
	defer srv.Close()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigs:
			quit()
		case <-quitCh:
		}
	}()

	if !noTray && !trayAvailable() {
		// Linux session without a StatusNotifier host: the icon would never
		// appear, so behave like --no-tray and open the UI once.
		noTray = true
		tray.OpenBrowser(srv.MintLoginURL())
	}

	if noTray {
		runHeadless(srv, quitCh)
		return 0
	}
	tray.Run(tray.Options{
		Backend:  eng,
		LoginURL: srv.MintLoginURL,
		OnExit:   func() { quitOnce.Do(func() { close(quitCh) }) },
	})
	return 0
}

// uiPort reads settings ui.port; 0 (= default 47771) when unavailable.
func uiPort(b interface {
	Call(string, []byte) ([]byte, *api.Error)
}) int {
	res, aerr := b.Call(api.SettingsGet, nil)
	if aerr != nil {
		return 0
	}
	var s struct {
		UI struct {
			Port int `json:"port"`
		} `json:"ui"`
	}
	if json.Unmarshal(res, &s) != nil {
		return 0
	}
	return s.UI.Port
}

// runHeadless prints a one-time sign-in link and keeps running until quit.
// Enter (or SIGUSR1 on Unix) prints a fresh link.
func runHeadless(srv *web.Server, quitCh <-chan struct{}) {
	printLink := func() {
		fmt.Println(srv.MintLoginURL())
	}
	fmt.Println("PrivateVPN is running. Open this link in a browser on this computer (it works once, within 60 seconds):")
	printLink()
	fmt.Println("Press Enter for a new link, Ctrl+C to quit.")

	again := make(chan struct{}, 1)
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			select {
			case again <- struct{}{}:
			default:
			}
		}
	}()
	refresh := refreshSignal()
	for {
		select {
		case <-again:
			printLink()
		case <-refresh:
			printLink()
		case <-quitCh:
			return
		}
	}
}

func firewallCmd(args []string) int {
	if !firewall.Supported() {
		fmt.Fprintln(os.Stderr, "privatevpn: the firewall rule is only needed on Windows")
		return 2
	}
	if len(args) != 1 || (args[0] != "add" && args[0] != "remove") {
		fmt.Fprintln(os.Stderr, "usage: privatevpn firewall add|remove")
		return 2
	}
	var err error
	if args[0] == "add" {
		var exe string
		if exe, err = os.Executable(); err == nil {
			err = firewall.Add(exe)
		}
	} else {
		err = firewall.Remove()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "privatevpn:", err)
		return 1
	}
	return 0
}

// unblockCmd is the manual kill-switch recovery (elevated): it removes the
// OS-level block, its boot-time pieces (persistent WFP objects, LaunchDaemon,
// systemd unit), tunnel leftovers, host routes and DNS changes.
func unblockCmd(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: privatevpn unblock")
		return 2
	}
	if !tunnel.IsElevated() {
		fmt.Fprintln(os.Stderr, "privatevpn: unblock needs administrator rights: run it as administrator (Windows) or with sudo (macOS, Linux)")
		return 3
	}
	if err := tunnel.Unblock(eventlog.New(64)); err != nil {
		fmt.Fprintln(os.Stderr, "privatevpn: unblock failed:", err)
		fmt.Fprintln(os.Stderr, "If this keeps failing, restarting the computer and running it again, or removing the boot-time pieces by hand, restores direct Internet access (see docs/DECISIONS.md).")
		return 1
	}
	fmt.Println("PrivateVPN: kill switch removed; direct Internet access restored.")
	return 0
}

// killSwitchBootCmd re-installs the block at boot (run by the LaunchDaemon
// / systemd unit the helper registers while the kill switch is engaged).
func killSwitchBootCmd(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: privatevpn killswitch-boot")
		return 2
	}
	if err := tunnel.KillSwitchBoot(eventlog.New(64)); err != nil {
		if errors.Is(err, tunnel.ErrNotElevated) {
			fmt.Fprintln(os.Stderr, "privatevpn: killswitch-boot must run as root / administrator")
			return 3
		}
		fmt.Fprintln(os.Stderr, "privatevpn: killswitch-boot failed:", err)
		return 1
	}
	return 0
}

const alreadyRunning = "PrivateVPN is already running (use the tray icon)."

// fatal reports a start-up error where the user can see it.
func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "privatevpn:", msg)
	showMessage("PrivateVPN could not start: " + msg)
}

func notifyAlreadyRunning(noTray bool) {
	fmt.Fprintln(os.Stderr, alreadyRunning)
	if !noTray {
		showMessage(alreadyRunning)
	}
}
