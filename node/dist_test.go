package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistChecksumsMatchTheBinaries(t *testing.T) {
	entries, err := os.ReadDir("dist")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("dist is not present")
	}
	if err != nil {
		t.Fatalf("reading dist: %v", err)
	}

	file, err := os.Open(filepath.Join("dist", "SHA256SUMS"))
	if err != nil {
		t.Fatalf("opening SHA256SUMS: %v", err)
	}
	defer file.Close()
	recorded := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("SHA256SUMS has an invalid line: %q", scanner.Text())
		}
		name := strings.TrimPrefix(fields[1], "*")
		if _, err := hex.DecodeString(fields[0]); err != nil || len(fields[0]) != sha256.Size*2 {
			t.Fatalf("SHA256SUMS has an invalid hash for %s", name)
		}
		recorded[name] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading SHA256SUMS: %v", err)
	}

	found := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "shadow9-node-linux-") {
			continue
		}
		found++
		binary, err := os.Open(filepath.Join("dist", entry.Name()))
		if err != nil {
			t.Fatalf("opening %s: %v", entry.Name(), err)
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, binary)
		closeErr := binary.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			t.Fatalf("hashing %s: %v", entry.Name(), err)
		}
		got := fmt.Sprintf("%x", hash.Sum(nil))
		if want, ok := recorded[entry.Name()]; !ok {
			t.Errorf("SHA256SUMS has no entry for %s", entry.Name())
		} else if got != want {
			t.Errorf("%s hashes to %s, SHA256SUMS records %s", entry.Name(), got, want)
		}
		delete(recorded, entry.Name())
	}
	if found == 0 {
		t.Fatal("dist exists but contains no shadow9-node binaries")
	}
	for name := range recorded {
		if strings.HasPrefix(name, "shadow9-node-linux-") {
			t.Errorf("SHA256SUMS names missing binary %s", name)
		}
	}
}

func TestOpenWrtPackageRemovalKeepsAnUpgradeEnrolled(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "packaging", "openwrt", "Makefile"))
	if err != nil {
		t.Fatalf("reading the OpenWrt package Makefile: %v", err)
	}
	makefile := string(contents)
	upgradeGuard := `[ "$${PKG_UPGRADE}" = "1" ] && exit 0`
	uninstall := `/usr/sbin/shadow9-node uninstall -quiet`
	guardAt := strings.Index(makefile, upgradeGuard)
	uninstallAt := strings.Index(makefile, uninstall)
	if guardAt == -1 || uninstallAt == -1 || guardAt > uninstallAt {
		t.Error("package removal does not guard the tunnel cleanup during an upgrade")
	}
	if !strings.Contains(makefile, "DEPENDS:=+wireguard-tools +luci-proto-wireguard +ca-bundle +pbr") {
		t.Error("the OpenWrt package does not install its policy-routing dependency")
	}
}
