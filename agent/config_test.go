package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

// fakeKey returns a deterministic FAKE 32-byte key as base64. These are
// test fixtures only — never a real key. The byte value picks which key.
func fakeKey(b byte) string {
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = b
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestRenderConfigBasic(t *testing.T) {
	priv := fakeKey(0x01)
	selfPub := fakeKey(0x02)
	iface := Interface{PrivateKey: priv, Address: "10.66.0.5", ListenPort: 51820}
	peers := []Peer{
		{Name: "node5", Pubkey: selfPub, MeshIP: "10.66.0.5"},
		{Name: "x390", Pubkey: fakeKey(0x03), MeshIP: "10.66.0.2"},
		{Name: "r320", Pubkey: fakeKey(0x04), MeshIP: "10.66.0.1", Endpoint: "203.0.113.7:51820"},
	}
	out, err := RenderConfig(iface, selfPub, peers)
	if err != nil {
		t.Fatalf("RenderConfig: %v", err)
	}
	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.66.0.5/24",
		"ListenPort = 51820",
		"# x390",
		"PublicKey = " + fakeKey(0x03),
		"AllowedIPs = 10.66.0.2/32",
		"# r320",
		"Endpoint = 203.0.113.7:51820",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("config missing %q\n--- config ---\n%s", want, out)
		}
	}
	// The node itself must never appear as a peer.
	if strings.Contains(out, selfPub) {
		t.Errorf("config contains the node's own pubkey as a peer\n--- config ---\n%s", out)
	}
	// Only the peer with a known endpoint gets an Endpoint line.
	if n := strings.Count(out, "Endpoint ="); n != 1 {
		t.Errorf("got %d Endpoint lines, want 1\n--- config ---\n%s", n, out)
	}
}

func TestRenderConfigSortsPeers(t *testing.T) {
	iface := Interface{PrivateKey: fakeKey(0x01), Address: "10.66.0.5", ListenPort: 51820}
	peers := []Peer{
		{Name: "late", Pubkey: fakeKey(0x09), MeshIP: "10.66.0.9"},
		{Name: "early", Pubkey: fakeKey(0x03), MeshIP: "10.66.0.3"},
	}
	out, err := RenderConfig(iface, fakeKey(0x02), peers)
	if err != nil {
		t.Fatalf("RenderConfig: %v", err)
	}
	if strings.Index(out, "10.66.0.3") > strings.Index(out, "10.66.0.9") {
		t.Errorf("peers not sorted by mesh IP\n--- config ---\n%s", out)
	}
}

func TestRenderConfigRejectsBadInput(t *testing.T) {
	good := Interface{PrivateKey: fakeKey(0x01), Address: "10.66.0.5", ListenPort: 51820}
	cases := []struct {
		name  string
		iface Interface
		peers []Peer
	}{
		{"empty private key", Interface{Address: "10.66.0.5", ListenPort: 51820}, nil},
		{"empty address", Interface{PrivateKey: fakeKey(0x01), ListenPort: 51820}, nil},
		{"port zero", Interface{PrivateKey: fakeKey(0x01), Address: "10.66.0.5"}, nil},
		{"port too big", Interface{PrivateKey: fakeKey(0x01), Address: "10.66.0.5", ListenPort: 70000}, nil},
		{"peer missing pubkey", good, []Peer{{Name: "ghost", MeshIP: "10.66.0.7"}}},
		{"peer missing mesh IP", good, []Peer{{Name: "ghost", Pubkey: fakeKey(0x07)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderConfig(tc.iface, fakeKey(0x02), tc.peers); err == nil {
				t.Errorf("RenderConfig accepted %s, want an error", tc.name)
			}
		})
	}
}
