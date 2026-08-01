package openwrt

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestSystemShellStopsACancelledCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (SystemShell{}).Run(ctx, "", os.Args[0], "-test.run=^$")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context canceled", err)
	}
}

func TestGetDistinguishesMissingFromCommandFailure(t *testing.T) {
	missing := Router{Shell: newFakeShell()}
	if _, err := missing.Get("shadow9.node.name"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get returned %v for a missing option, want ErrNotFound", err)
	}

	failedShell := newFakeShell()
	failedShell.failing["uci get shadow9.node.name"] = "uci: I/O error"
	failed := Router{Shell: failedShell}
	if _, err := failed.Get("shadow9.node.name"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Get returned %v for a command failure", err)
	}
}

func TestClearPeersAcceptsMissingNamedPeer(t *testing.T) {
	if err := (Router{Shell: newFakeShell()}).ClearPeers(DefaultInterface); err != nil {
		t.Fatalf("ClearPeers returned %v for a missing peer", err)
	}
}

func TestClearPeersReportsCommandFailure(t *testing.T) {
	shell := newFakeShell()
	shell.failing["uci delete network."+PeerSectionName(DefaultInterface)] = "uci: I/O error"
	err := (Router{Shell: shell}).ClearPeers(DefaultInterface)
	if err == nil {
		t.Fatal("ClearPeers hid the delete failure")
	}
}

func TestNextTableSkipsPersistentAndActiveTables(t *testing.T) {
	shell := newFakeShell()
	shell.output["uci -q show network"] = "network.wg1.ip4table='51820'\nnetwork.wg2.ip6table='51821'\n"
	shell.output["ip -4 rule show"] = "10000: from 10.0.0.0/24 lookup 51822\n"
	shell.output["ip -6 rule show"] = "10000: from fd00::/64 lookup 51823\n"
	shell.output["ip -4 route show table all"] = "default dev wg3 table 51824\n"
	shell.output["ip -6 route show table all"] = "default dev wg4 table 51825\n"

	table, err := (Router{Shell: shell}).NextTable(51820)
	if err != nil {
		t.Fatalf("NextTable: %v", err)
	}
	if table != 51826 {
		t.Errorf("NextTable returned %d, want 51826", table)
	}
}

func TestNextTableSkipsLinuxReservedTables(t *testing.T) {
	shell := newFakeShell()
	for _, command := range []string{
		"uci -q show network",
		"ip -4 rule show",
		"ip -6 rule show",
		"ip -4 route show table all",
		"ip -6 route show table all",
	} {
		shell.output[command] = ""
	}

	table, err := (Router{Shell: shell}).NextTable(253)
	if err != nil {
		t.Fatalf("NextTable: %v", err)
	}
	if table != 256 {
		t.Errorf("NextTable returned %d, want 256", table)
	}
}

func TestNextTableStopsWhenTableDiscoveryFails(t *testing.T) {
	shell := newFakeShell()
	shell.output["uci -q show network"] = ""
	shell.failing["ip -4 rule show"] = "ip: permission denied"

	_, err := (Router{Shell: shell}).NextTable(51820)
	if err == nil {
		t.Fatal("NextTable hid a failed kernel table check")
	}
}
