package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultServer is the coordinator address used when -server is not given.
// Same default as `wgmesh admin create-key` (slice S-A).
const defaultServer = "http://127.0.0.1:8080"

// meshListenPort is the WireGuard UDP port for the mesh (approved gate).
const meshListenPort = 51820

// State is the agent's on-disk record for one node. It holds the node's
// private key: the file is always written mode 0600 and must never be
// committed, shared, or pasted anywhere.
type State struct {
	Name       string    `json:"name"`
	Server     string    `json:"server"`
	PrivateKey string    `json:"private_key"` // base64, 32 bytes
	PublicKey  string    `json:"public_key"`  // base64, 32 bytes
	MeshIP     string    `json:"mesh_ip"`
	Peers      []Peer    `json:"peers"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// loadState reads the agent state file. A missing file is not an error;
// it means the node has not been initialised yet.
func loadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("state file %s is corrupt: %w", path, err)
	}
	return &st, nil
}

// saveState writes the state file atomically (temp file + rename) with
// mode 0600, because it holds the node's private key.
func saveState(path string, st *State) error {
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// generateKeypair creates a fresh X25519 keypair (stdlib crypto/ecdh).
// The private key is the raw 32-byte scalar; both keys are base64, the
// same encoding `wg pubkey` uses.
func generateKeypair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pub := priv.PublicKey()
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(pub.Bytes()), nil
}

// registerResponse is the coordinator's /register reply (slice S-A).
type registerResponse struct {
	MeshIP string `json:"mesh_ip"`
	Peers  []Peer `json:"peers"`
}

// register posts name + pubkey to the coordinator with a single-use
// pre-auth key and returns the allocated mesh IP and peer list.
// The key is never logged.
func register(server, name, pubkey, preauthKey string) (registerResponse, error) {
	var out registerResponse
	body, err := json.Marshal(map[string]string{"name": name, "pubkey": pubkey})
	if err != nil {
		return out, err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(server, "/")+"/register", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+preauthKey)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return out, fmt.Errorf("contact coordinator: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return out, err
	}
	if resp.StatusCode != http.StatusOK {
		var errBody struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &errBody) == nil && errBody.Error != "" {
			return out, fmt.Errorf("coordinator refused (%s): %s", resp.Status, errBody.Error)
		}
		return out, fmt.Errorf("coordinator refused (%s)", resp.Status)
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return out, fmt.Errorf("bad coordinator response: %w", err)
	}
	if out.MeshIP == "" {
		return out, errors.New("coordinator returned no mesh IP")
	}
	return out, nil
}

// writeConfigFile renders wg0.conf via RenderConfig and writes it
// atomically with mode 0600 (it holds the private key).
func writeConfigFile(path string, st *State) error {
	text, err := RenderConfig(Interface{
		PrivateKey: st.PrivateKey,
		Address:    st.MeshIP,
		ListenPort: meshListenPort,
	}, st.PublicKey, st.Peers)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runInit creates the node's keypair and state file. It refuses to
// overwrite existing state: a node is initialised once, and re-running
// init must never silently replace the keypair (that would orphan the
// node's mesh IP, which is keyed by pubkey).
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "node name (e.g. x390)")
	server := fs.String("server", defaultServer, "coordinator base URL")
	statePath := fs.String("state", "wgmesh-agent.json", "agent state file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("init requires -name")
	}
	if st, err := loadState(*statePath); err != nil {
		return err
	} else if st != nil {
		return fmt.Errorf("state file %s already exists for node %q; refusing to overwrite (delete it to start over)", *statePath, st.Name)
	}
	priv, pub, err := generateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	st := &State{Name: *name, Server: *server, PrivateKey: priv, PublicKey: pub}
	if err := saveState(*statePath, st); err != nil {
		return err
	}
	fmt.Printf("initialised node %q\n  state:  %s (mode 0600 — holds the private key)\n  pubkey: %s\n  next: mint a pre-auth key on the coordinator, then run: wgmesh-agent register\n",
		*name, *statePath, pub)
	return nil
}

// runRegister registers this node with the coordinator, saves the mesh IP
// and peer list to state, and writes wg0.conf. The pre-auth key comes
// from -key or WGMESH_PREAUTH_KEY and is never printed or logged.
func runRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	key := fs.String("key", "", "single-use pre-auth key (or WGMESH_PREAUTH_KEY)")
	server := fs.String("server", "", "coordinator base URL (default: from state file)")
	statePath := fs.String("state", "wgmesh-agent.json", "agent state file")
	configPath := fs.String("config", "wg0.conf", "WireGuard config to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	preauth := *key
	if preauth == "" {
		preauth = os.Getenv("WGMESH_PREAUTH_KEY")
	}
	if preauth == "" {
		return fmt.Errorf("register needs a pre-auth key: -key or WGMESH_PREAUTH_KEY (mint one on the coordinator with: wgmesh admin create-key)")
	}
	st, err := loadState(*statePath)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("no state file %s; run: wgmesh-agent init -name NAME", *statePath)
	}
	srv := *server
	if srv == "" {
		srv = st.Server
	}
	resp, err := register(srv, st.Name, st.PublicKey, preauth)
	if err != nil {
		return err
	}
	st.Server = srv
	st.MeshIP = resp.MeshIP
	st.Peers = resp.Peers
	if err := saveState(*statePath, st); err != nil {
		return err
	}
	if err := writeConfigFile(*configPath, st); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("registered %q as %s\n  config: %s\n  next: wgmesh-agent up\n", st.Name, st.MeshIP, *configPath)
	return nil
}

// runWriteConfig re-renders wg0.conf from the saved state without
// re-registering. Use it after the peer list changes (for example after
// another node joins) — but note the peer list only refreshes on
// register; live peer updates arrive with heartbeats (slice S-D).
func runWriteConfig(args []string) error {
	fs := flag.NewFlagSet("write-config", flag.ContinueOnError)
	statePath := fs.String("state", "wgmesh-agent.json", "agent state file")
	configPath := fs.String("config", "wg0.conf", "WireGuard config to write")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(*statePath)
	if err != nil {
		return err
	}
	if st == nil || st.MeshIP == "" {
		return fmt.Errorf("no registered state in %s; run: wgmesh-agent register", *statePath)
	}
	if err := writeConfigFile(*configPath, st); err != nil {
		return err
	}
	fmt.Printf("wrote %s for %q (%s)\n", *configPath, st.Name, st.MeshIP)
	return nil
}
