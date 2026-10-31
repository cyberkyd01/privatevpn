package sysinfo

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultWatchInterval is used when NewWatcher is given a non-positive
// interval (§10.3: 10 s).
const defaultWatchInterval = 10 * time.Second

// Watcher polls the interface list and addresses and reports changes
// (ARCHITECTURE §10.3). Polling is portable; Android uses the app's
// ConnectivityManager callback instead.
type Watcher struct {
	interval time.Duration
	onChange func()
	snap     func() (string, error)
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

// NewWatcher starts polling net.Interfaces() and their addresses every
// interval (10 s if ≤ 0) and calls onChange from the watcher's goroutine
// when the set differs from the previous poll — hence at most once per
// interval. onChange must not block for long and must not call Stop.
func NewWatcher(interval time.Duration, onChange func()) *Watcher {
	return newWatcher(interval, onChange, netSnapshot)
}

func newWatcher(interval time.Duration, onChange func(), snap func() (string, error)) *Watcher {
	if interval <= 0 {
		interval = defaultWatchInterval
	}
	w := &Watcher{
		interval: interval,
		onChange: onChange,
		snap:     snap,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go w.run()
	return w
}

// Stop ends polling and waits for the watcher goroutine; after it returns
// onChange is not called again. Stop is idempotent.
func (w *Watcher) Stop() {
	w.stopOnce.Do(func() { close(w.stop) })
	<-w.done
}

func (w *Watcher) run() {
	defer close(w.done)
	prev, err := w.snap()
	have := err == nil
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-t.C:
		}
		cur, err := w.snap()
		if err != nil {
			continue // keep the last good snapshot
		}
		changed := !have || cur != prev
		prev, have = cur, true
		if !changed || w.onChange == nil {
			continue
		}
		select {
		case <-w.stop:
			return
		default:
		}
		w.onChange()
	}
}

// netSnapshot renders the interface set as a canonical string: one line per
// interface with index, name, up/running flags and sorted addresses.
func netSnapshot() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	return snapshotOf(ifs, interfaceAddrs), nil
}

func snapshotOf(ifs []net.Interface, addrsOf func(net.Interface) ([]net.Addr, error)) string {
	lines := make([]string, 0, len(ifs))
	for _, ifi := range ifs {
		var as []string
		if addrs, err := addrsOf(ifi); err == nil {
			for _, a := range addrs {
				as = append(as, a.String())
			}
		}
		sort.Strings(as)
		lines = append(lines, strconv.Itoa(ifi.Index)+"|"+ifi.Name+"|"+
			strconv.FormatUint(uint64(ifi.Flags&(net.FlagUp|net.FlagRunning)), 10)+"|"+strings.Join(as, ","))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
