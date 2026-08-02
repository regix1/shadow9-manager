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
