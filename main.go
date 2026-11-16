// Command wgmesh is the wgmesh coordinator CLI (slice S-A: coordinator skeleton).
//
// Usage:
//
//	wgmesh serve [-listen 127.0.0.1:8080] [-db wgmesh.db]
//	wgmesh admin create-key [-server http://127.0.0.1:8080]
//
// S-A scope: SQLite schema, POST /preauth, POST /register, and the
// 10.66.0.0/24 IP allocator. No node agent, no tunnel, no WireGuard config,
// no other endpoints, no UI. The server binds loopback by default; the
// coordinator service itself is never publicly exposed.
package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  wgmesh serve [-listen 127.0.0.1:8080] [-db wgmesh.db]")
	fmt.Fprintln(os.Stderr, "  wgmesh admin create-key [-server http://127.0.0.1:8080]")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, os.Args[1]+":", err)
		os.Exit(1)
	}
}
