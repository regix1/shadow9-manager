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
	// default_prerm sources this script and only then disables and stops the
	// package's init scripts, so deleting one here strands its /etc/rc.d link.
	if strings.Contains(makefile, "rm -f /etc/init.d/") {
		t.Error("package removal deletes an init script the package manager still needs")
	}
	// default_prerm returns this script's status and opkg aborts removal on a
	// nonzero one, so a refused cleanup has to warn rather than exit.
	if strings.Contains(makefile, uninstall+" || exit") {
		t.Error("a refused cleanup makes the package unremovable")
	}
	if !strings.Contains(makefile, uninstall+` || \`) {
		t.Error("package removal hides a failed ownership-checked cleanup")
	}
	if !strings.Contains(makefile,
		"DEPENDS:=+wireguard-tools +luci-proto-wireguard +ca-bundle +pbr +luci-app-pbr") {
		t.Error("the OpenWrt package does not install its policy-routing dependency and its web UI")
	}
	if !strings.Contains(makefile, "$(1)/etc/init.d/shadow9-node") {
		t.Error("the boot refresh script is not owned by the OpenWrt package")
	}
	// default_postinst runs a bare "uci commit" whenever a package owns a
	// uci-defaults script, which would commit an operator's pending changes.
	if strings.Contains(makefile, "$(1)/etc/uci-defaults") {
		t.Error("the package ships a uci-defaults script, so installing it commits pending UCI changes")
	}
}

func TestBootServiceEnrollsAndRetriesABoundedNumberOfTimes(t *testing.T) {
	contents, err := os.ReadFile(
		filepath.Join("..", "packaging", "openwrt", "files", "shadow9-node.init"))
	if err != nil {
		t.Fatalf("reading the OpenWrt boot service: %v", err)
	}
	service := string(contents)
	for _, wanted := range []string{
		`"$BINARY" join \`,
		`"$BINARY" refresh`,
		`[ "$try" -ge "$ATTEMPTS" ] && break`,
		"procd_open_instance reconcile",
	} {
		if !strings.Contains(service, wanted) {
			t.Errorf("the boot service is missing %q", wanted)
		}
	}
	// The retry sleeps, so it has to run as a procd instance rather than
	// inline in start_service, or every boot waits on the hub.
	startAt := strings.Index(service, "start_service()")
	reconcileAt := strings.Index(service, "reconcile() {")
	if startAt == -1 || reconcileAt == -1 || reconcileAt > startAt {
		t.Error("the boot service does not define its retry before start_service")
	}
	if strings.Contains(service[startAt:], "sleep") {
		t.Error("start_service sleeps, so it holds up boot")
	}
}
