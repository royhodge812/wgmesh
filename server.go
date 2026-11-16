package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

// runServe starts the coordinator HTTP server (S-A endpoints only).
func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	dbPath := fs.String("db", "wgmesh.db", "path to the SQLite database")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := Open(*dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer store.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/preauth", preauthHandler(store))
	mux.HandleFunc("/register", registerHandler(store))

	// Log method, path, and status only. Never log keys, headers, or bodies.
	log.Printf("wgmesh coordinator listening on %s (db %s)", *listen, *dbPath)
	return http.ListenAndServe(*listen, logRequests(mux))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		log.Printf("%s %s %d", r.Method, r.URL.Path, rw.status)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// preauthHandler implements POST /preauth: coordinator-local CLI only.
// Requests from anywhere but loopback are rejected, so only a CLI running
// on the coordinator host itself can mint keys. The response carries the
// plaintext key exactly once; the server stores only its hash.
func preauthHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			writeError(w, http.StatusForbidden, "preauth is coordinator-local only")
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeError(w, http.StatusForbidden, "preauth is coordinator-local only")
			return
		}
		key, err := store.CreatePreauthKey()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not create key")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{"preauth_key": key})
	}
}

type registerRequest struct {
	Name   string `json:"name"`
	Pubkey string `json:"pubkey"`
}

type registerResponse struct {
	MeshIP string `json:"mesh_ip"`
	Peers  []Peer `json:"peers"`
}

// registerHandler implements POST /register: Bearer pre-auth key, body
// {name, pubkey} -> {mesh_ip, peers[]}. The key is consumed on success.
func registerHandler(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if key == "" || key == r.Header.Get("Authorization") {
			writeError(w, http.StatusUnauthorized, "missing pre-auth key")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeError(w, http.StatusBadRequest, "could not read body")
			return
		}
		var req registerRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		meshIP, peers, err := store.Register(req.Name, req.Pubkey, key)
		switch {
		case err == nil:
			writeJSON(w, http.StatusOK, registerResponse{MeshIP: meshIP, Peers: peers})
		case errors.Is(err, ErrBadKey):
			writeError(w, http.StatusUnauthorized, "invalid or consumed pre-auth key")
		case errors.Is(err, ErrBadInput):
			writeError(w, http.StatusBadRequest, "name and pubkey must be non-empty")
		case errors.Is(err, ErrNameTaken):
			writeError(w, http.StatusConflict, "name already registered to a different key")
		default:
			writeError(w, http.StatusInternalServerError, "registration failed")
		}
	}
}

// runAdmin implements: wgmesh admin create-key [-server URL].
// It asks the local coordinator (loopback) to mint a key and prints it once.
func runAdmin(args []string) error {
	if len(args) < 1 || args[0] != "create-key" {
		return errors.New("usage: wgmesh admin create-key [-server http://127.0.0.1:8080]")
	}
	fs := flag.NewFlagSet("create-key", flag.ContinueOnError)
	server := fs.String("server", "http://127.0.0.1:8080", "coordinator base URL")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	resp, err := http.Post(strings.TrimSuffix(*server, "/")+"/preauth", "application/json", nil)
	if err != nil {
		return fmt.Errorf("contact coordinator: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("coordinator refused (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out struct {
		PreauthKey string `json:"preauth_key"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("bad coordinator response: %w", err)
	}
	fmt.Println(out.PreauthKey)
	return nil
}
