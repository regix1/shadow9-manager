package openwrt

import (
	"strings"
	"testing"
)

// These names have to match what .github/workflows/release.yml publishes. A
// mismatch is a 404 on a router rather than a failing build, which is why they
// are pinned here as literals rather than rebuilt from the same code.
func TestPackageFileMatchesWhatTheReleasePublishes(t *testing.T) {
	for _, c := range []struct {
		machine string
		release string
		file    string
		manager string
	}{
		{"x86_64", "24.10.2", "shadow9-node_0.1.9-r1_x86_64.ipk", "opkg"},
		{"x86_64", "25.12.0", "shadow9-node-0.1.9-r1_x86-64.apk", "apk"},
		{"aarch64", "24.10.0", "shadow9-node_0.1.9-r1_aarch64_generic.ipk", "opkg"},
		{"aarch64", "25.12.1", "shadow9-node-0.1.9-r1_armsr-armv8.apk", "apk"},
		{"mipsel", "24.10.2", "shadow9-node_0.1.9-r1_mipsel_24kc.ipk", "opkg"},
	} {
		shell := newFakeShell()
		shell.output["uname -m"] = c.machine + "\n"
		shell.output["cat "+ReleasePath] = "DISTRIB_RELEASE='" + c.release + "'\n"

		file, manager, err := (Router{Shell: shell}).PackageFile("0.1.9")
		if err != nil {
			t.Errorf("%s on %s: %v", c.machine, c.release, err)
			continue
		}
		if file != c.file || manager != c.manager {
			t.Errorf("%s on %s gave %s via %s, want %s via %s",
				c.machine, c.release, file, manager, c.file, c.manager)
		}
	}
}

func TestPackageFileRefusesWhatIsNotPublished(t *testing.T) {
	for _, c := range []struct{ machine, release, complaint string }{
		{"riscv64", "24.10.2", "no shadow9 package is published for riscv64"},
		{"x86_64", "23.05.0", "no shadow9 package is published for OpenWrt 23.05.0"},
	} {
		shell := newFakeShell()
		shell.output["uname -m"] = c.machine + "\n"
		shell.output["cat "+ReleasePath] = "DISTRIB_RELEASE='" + c.release + "'\n"

		_, _, err := (Router{Shell: shell}).PackageFile("0.1.9")
		if err == nil || !strings.Contains(err.Error(), c.complaint) {
			t.Errorf("%s on %s returned %v, want %q", c.machine, c.release, err, c.complaint)
		}
	}
}

// An upgrade must go through the package manager, because that is what makes
// the package scripts see PKG_UPGRADE=1 and leave the tunnel enrolled.
func TestInstallPackageUsesTheRightManager(t *testing.T) {
	for _, c := range []struct{ manager, call string }{
		{"opkg", "opkg install /tmp/shadow9-node.ipk"},
		{"apk", "apk add --allow-untrusted /tmp/shadow9-node.ipk"},
	} {
		shell := newFakeShell()
		if err := (Router{Shell: shell}).InstallPackage("/tmp/shadow9-node.ipk", c.manager); err != nil {
			t.Errorf("%s: %v", c.manager, err)
		}
		if got := strings.Join(shell.calls, "\n"); !strings.Contains(got, c.call) {
			t.Errorf("%s ran %q, want %q", c.manager, got, c.call)
		}
	}
}
