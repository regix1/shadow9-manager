package openwrt

import (
	"fmt"
	"strings"
)

// ReleasePath is the file OpenWrt records its own version in.
const ReleasePath = "/etc/openwrt_release"

// packageArch maps what uname reports to the two architecture spellings the
// release publishes under. They differ: opkg uses aarch64_generic where apk
// uses armsr-armv8, so the same router needs a different name per format.
var packageArch = map[string]struct{ ipk, apk string }{
	"x86_64":  {"x86_64", "x86-64"},
	"aarch64": {"aarch64_generic", "armsr-armv8"},
	"mips":    {"mipsel_24kc", "ramips-mt7621"},
}

// PackageFile names the release artifact this router installs, and the manager
// that installs it. The two formats are not interchangeable: 24.10 takes an
// .ipk through opkg and 25.12 takes an .apk through apk.
func (r Router) PackageFile(version string) (file, manager string, err error) {
	machine, err := r.run(packageTimeout, "", "uname", "-m")
	if err != nil {
		return "", "", fmt.Errorf("reading this router's architecture: %w", err)
	}
	arch, known := packageArch[archKey(strings.TrimSpace(string(machine)))]
	if !known {
		return "", "", fmt.Errorf(
			"no shadow9 package is published for %s", strings.TrimSpace(string(machine)))
	}

	release, err := r.osRelease()
	if err != nil {
		return "", "", err
	}
	switch {
	case strings.HasPrefix(release, "24.10."):
		return fmt.Sprintf("shadow9-node_%s-r1_%s.ipk", version, arch.ipk), "opkg", nil
	case strings.HasPrefix(release, "25.12."):
		return fmt.Sprintf("shadow9-node-%s-r1_%s.apk", version, arch.apk), "apk", nil
	default:
		return "", "", fmt.Errorf("no shadow9 package is published for OpenWrt %s", release)
	}
}

// archKey folds the mips spellings onto one entry, because uname reports
// mips, mipsel and mips64el for routers the same package covers.
func archKey(machine string) string {
	if strings.HasPrefix(machine, "mips") {
		return "mips"
	}
	return machine
}

// osRelease reads DISTRIB_RELEASE, which is what decides the package format.
func (r Router) osRelease() (string, error) {
	out, err := r.run(fileTimeout, "", "cat", ReleasePath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", ReleasePath, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		value, found := strings.CutPrefix(strings.TrimSpace(line), "DISTRIB_RELEASE=")
		if !found {
			continue
		}
		if release := strings.Trim(value, "'\""); release != "" {
			return release, nil
		}
	}
	return "", fmt.Errorf("%s names no DISTRIB_RELEASE", ReleasePath)
}

// InstallPackage hands a downloaded package to its manager. This is an upgrade
// rather than a fresh install, so the package's own scripts see PKG_UPGRADE=1
// and leave the enrolled tunnel in place.
func (r Router) InstallPackage(path, manager string) error {
	var args []string
	switch manager {
	case "opkg":
		args = []string{"install", path}
	case "apk":
		args = []string{"add", "--allow-untrusted", path}
	default:
		return fmt.Errorf("%q is not a package manager this client knows", manager)
	}
	out, err := r.run(packageTimeout, "", manager, args...)
	if err != nil {
		return fmt.Errorf("installing %s with %s: %w: %s",
			path, manager, err, strings.TrimSpace(string(out)))
	}
	return nil
}
