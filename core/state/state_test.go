package state

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenUpdateReload(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pvn")
	s, err := Open(dir, func(st *State) {
		if st.DeviceName == "" {
			st.DeviceName = "PC-TEST"
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(func(st *State) error {
		st.Keyring = append(st.Keyring, KeyEntry{ID: "a", Key: make([]byte, 32), Label: "Home"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(st *State) error { st.DeviceName = "x"; return errors.New("abort") }); err == nil {
		t.Fatal("expected error")
	}
	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Get()
	if got.DeviceName != "PC-TEST" || len(got.Keyring) != 1 || got.Keyring[0].Label != "Home" {
		t.Fatalf("reloaded %+v", got)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(filepath.Join(dir, "state.json"))
		di, _ := os.Stat(dir)
		if fi.Mode().Perm() != 0o600 || di.Mode().Perm() != 0o700 {
			t.Fatalf("perms file %v dir %v", fi.Mode().Perm(), di.Mode().Perm())
		}
	}
}

func TestMalformedEntriesDropped(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"schema":2,"keyring":[{"id":"a","key":"AAAA"},{"id":"","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`), 0o600)
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.Get().Keyring); n != 0 {
		t.Fatalf("kept %d malformed keys", n)
	}
}

func TestLockExclusive(t *testing.T) {
	dir := t.TempDir()
	l, err := AcquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	if _, err := AcquireLock(dir); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second lock: %v", err)
	}
}
