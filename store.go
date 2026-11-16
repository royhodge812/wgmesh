package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Schema (S-A): nodes and single-use pre-auth key hashes only.
// The coordinator stores public keys only. Pre-auth keys are stored as
// SHA-256 hashes; the plaintext key is shown once at creation and never
// stored, logged, or committed.
const schema = `
CREATE TABLE IF NOT EXISTS nodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	pubkey TEXT NOT NULL UNIQUE,
	mesh_ip TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS preauth_keys (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	key_hash TEXT NOT NULL UNIQUE,
	created_at TEXT NOT NULL
);
`

// Peer is one entry of the peer list returned by /register.
// Endpoint is empty in S-A: endpoints arrive with heartbeats (slice S-D).
// AllowedIPs is always the node's mesh IP as a /32.
type Peer struct {
	Name       string `json:"name"`
	Pubkey     string `json:"pubkey"`
	MeshIP     string `json:"mesh_ip"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowed_ips"`
}

var (
	ErrBadKey    = errors.New("invalid or consumed pre-auth key")
	ErrBadInput  = errors.New("name and pubkey must be non-empty")
	ErrNameTaken = errors.New("name already registered to a different key")
)

// Store wraps the coordinator SQLite database.
type Store struct {
	db *sql.DB
}

// Open creates the database (if needed) and applies the S-A schema.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// CreatePreauthKey generates a single-use pre-auth key, stores only its
// SHA-256 hash, and returns the plaintext key. The caller must show it once
// and never store, log, or commit it.
func (s *Store) CreatePreauthKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	key := hex.EncodeToString(raw)
	_, err := s.db.Exec(
		`INSERT INTO preauth_keys (key_hash, created_at) VALUES (?, ?)`,
		hashKey(key), time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return "", err
	}
	return key, nil
}

// Register authenticates a single-use pre-auth key, allocates (or reclaims)
// a stable mesh IP keyed by pubkey, consumes the key, and returns the IP
// plus the full peer list. The key is consumed only on success: a bad body
// or a taken name leaves the key valid for another attempt.
func (s *Store) Register(name, pubkey, presentedKey string) (string, []Peer, error) {
	if name == "" || pubkey == "" {
		return "", nil, ErrBadInput
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()

	var keyID int64
	err = tx.QueryRow(
		`SELECT id FROM preauth_keys WHERE key_hash = ?`, hashKey(presentedKey),
	).Scan(&keyID)
	if err == sql.ErrNoRows {
		return "", nil, ErrBadKey
	}
	if err != nil {
		return "", nil, err
	}

	// Re-registering the same pubkey reclaims its stable IP.
	var existingIP string
	err = tx.QueryRow(
		`SELECT mesh_ip FROM nodes WHERE pubkey = ?`, pubkey,
	).Scan(&existingIP)
	if err != nil && err != sql.ErrNoRows {
		return "", nil, err
	}
	meshIP := existingIP
	if meshIP == "" {
		// A name may belong to only one pubkey.
		var holder string
		err = tx.QueryRow(
			`SELECT pubkey FROM nodes WHERE name = ?`, name,
		).Scan(&holder)
		if err != nil && err != sql.ErrNoRows {
			return "", nil, err
		}
		if holder != "" {
			return "", nil, ErrNameTaken
		}
		used := map[string]bool{}
		rows, err := tx.Query(`SELECT mesh_ip FROM nodes`)
		if err != nil {
			return "", nil, err
		}
		var ip string
		for rows.Next() {
			if err := rows.Scan(&ip); err != nil {
				rows.Close()
				return "", nil, err
			}
			used[ip] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", nil, err
		}
		meshIP, err = nextIP(used)
		if err != nil {
			return "", nil, err
		}
		if _, err := tx.Exec(
			`INSERT INTO nodes (name, pubkey, mesh_ip, created_at) VALUES (?, ?, ?, ?)`,
			name, pubkey, meshIP, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			return "", nil, err
		}
	}

	if _, err := tx.Exec(`DELETE FROM preauth_keys WHERE id = ?`, keyID); err != nil {
		return "", nil, err
	}
	peers, err := listPeers(tx)
	if err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return meshIP, peers, nil
}

func listPeers(q *sql.Tx) ([]Peer, error) {
	rows, err := q.Query(`SELECT name, pubkey, mesh_ip FROM nodes ORDER BY mesh_ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	peers := []Peer{}
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.Name, &p.Pubkey, &p.MeshIP); err != nil {
			return nil, err
		}
		p.Endpoint = ""
		p.AllowedIPs = p.MeshIP + "/32"
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return peers, nil
}

// nextIP returns the lowest free address in 10.66.0.0/24 starting at .3.
// Excluded: .0 (network), .1 (reserved for the R320 per the approved
// addressing gate), .2 (reserved for x390 per the approved addressing
// gate), .255 (broadcast). General allocation therefore starts at .3;
// the reserved addresses are never handed out to other nodes.
func nextIP(used map[string]bool) (string, error) {
	for i := 3; i <= 254; i++ {
		ip := fmt.Sprintf("10.66.0.%d", i)
		if !used[ip] {
			return ip, nil
		}
	}
	return "", errors.New("mesh address pool exhausted")
}
