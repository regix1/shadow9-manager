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
