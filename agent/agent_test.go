package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	st := &State{
		Name:       "x390",
		Server:     defaultServer,
		PrivateKey: fakeKey(0x01),
		PublicKey:  fakeKey(0x02),
		MeshIP:     "10.66.0.2",
		Peers:      []Peer{{Name: "r320", Pubkey: fakeKey(0x04), MeshIP: "10.66.0.1", AllowedIPs: "10.66.0.1/32"}},
	}
	if err := saveState(path, st); err != nil {
		t.Fatalf("saveState: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %o, want 0600 (it holds the private key)", info.Mode().Perm())
	}
	got, err := loadState(path)
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if got == nil {
		t.Fatal("loadState returned nil for a file that exists")
	}
	if got.Name != "x390" || got.MeshIP != "10.66.0.2" || got.PrivateKey != fakeKey(0x01) {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if len(got.Peers) != 1 || got.Peers[0].Name != "r320" {
		t.Errorf("peers did not survive round-trip: %+v", got.Peers)
	}
}

func TestLoadStateMissingIsNil(t *testing.T) {
	got, err := loadState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("loadState on a missing file: %v", err)
	}
	if got != nil {
		t.Errorf("loadState on a missing file returned %+v, want nil", got)
	}
}

func TestWriteConfigFileMode(t *testing.T) {
	dir := t.TempDir()
	st := &State{
		Name:       "x390",
		Server:     defaultServer,
		PrivateKey: fakeKey(0x01),
		PublicKey:  fakeKey(0x02),
		MeshIP:     "10.66.0.2",
		Peers:      []Peer{{Name: "r320", Pubkey: fakeKey(0x04), MeshIP: "10.66.0.1"}},
	}
	path := filepath.Join(dir, "wg0.conf")
	if err := writeConfigFile(path, st); err != nil {
		t.Fatalf("writeConfigFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode %o, want 0600 (it holds the private key)", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config file: %v", err)
	}
	if string(data) == "" {
		t.Fatal("config file is empty")
	}
}
