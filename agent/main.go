// Command wgmesh-agent is the wgmesh node agent (slice S-B).
//
// Usage:
//
//	wgmesh-agent init -name NAME [-server URL] [-state FILE]
//	wgmesh-agent register [-key KEY] [-server URL] [-state FILE] [-config FILE]
//	wgmesh-agent write-config [-state FILE] [-config FILE]
//	wgmesh-agent up [-config FILE] [-dry-run]
//	wgmesh-agent down [-config FILE] [-dry-run]
//	wgmesh-agent status [-state FILE]
//
// S-B scope: node keypair, registration client, and the WireGuard config
// writer. No heartbeat, no endpoint discovery, no revoke, no daemon —
// those are later slices. Registration reaches the coordinator over the
// existing tailnet or LAN; the mesh carries traffic only once the tunnel
// is up.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent init -name NAME [-server URL] [-state FILE]")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent register [-key KEY] [-server URL] [-state FILE] [-config FILE]")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent write-config [-state FILE] [-config FILE]")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent up [-config FILE] [-dry-run]")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent down [-config FILE] [-dry-run]")
	fmt.Fprintln(os.Stderr, "  wgmesh-agent status [-state FILE]")
	fmt.Fprintln(os.Stderr, "pre-auth key: -key flag or WGMESH_PREAUTH_KEY (never logged)")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "register":
		err = runRegister(os.Args[2:])
	case "write-config":
		err = runWriteConfig(os.Args[2:])
	case "up":
		err = runUp(os.Args[2:])
	case "down":
		err = runDown(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, os.Args[1]+":", err)
		os.Exit(1)
	}
}

// runUp brings the tunnel up with wg-quick. The config may be a path:
// wg-quick derives the interface name from it.
func runUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	configPath := fs.String("config", "wg0.conf", "WireGuard config file")
	dryRun := fs.Bool("dry-run", false, "print the command instead of running it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*configPath); err != nil {
		return fmt.Errorf("config %s not found; run: wgmesh-agent register", *configPath)
	}
	return wgQuick("up", *configPath, *dryRun)
}

// runDown takes the tunnel down with wg-quick.
func runDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	configPath := fs.String("config", "wg0.conf", "WireGuard config file")
	dryRun := fs.Bool("dry-run", false, "print the command instead of running it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return wgQuick("down", *configPath, *dryRun)
}

// wgQuick runs `wg-quick <action> <config>`. -dry-run prints the command
// instead of running it.
func wgQuick(action, configPath string, dryRun bool) error {
	if dryRun {
		fmt.Printf("wg-quick %s %s\n", action, configPath)
		return nil
	}
	cmd := exec.Command("wg-quick", action, configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg-quick %s failed: %w (is wireguard-tools installed?)", action, err)
	}
	return nil
}

// runStatus prints what the agent knows about this node from its state
// file. It never touches the network.
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	statePath := fs.String("state", "wgmesh-agent.json", "agent state file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := loadState(*statePath)
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("not initialised; run: wgmesh-agent init -name NAME")
		return nil
	}
	others := 0
	for _, p := range st.Peers {
		if p.Pubkey != st.PublicKey {
			others++
		}
	}
	fmt.Printf("node:   %s\nserver: %s\nmesh IP: %s\npubkey: %s\npeers:  %d other nodes\n",
		st.Name, st.Server, st.MeshIP, st.PublicKey, others)
	if st.MeshIP == "" {
		fmt.Println("not registered yet; run: wgmesh-agent register")
	}
	return nil
}
