package openwrt

import (
	"fmt"
	"strings"
)

// ProtocolPackage is the LuCI package that supplies the WireGuard protocol
// handler and the status page. Without it netifd still brings the tunnel up,
// because that is wireguard-tools, but LuCI has no form for the protocol and
// the interface does not render as a WireGuard interface.
const ProtocolPackage = "luci-proto-wireguard"

// PolicyPackage supplies the policy selector used with the isolated default
// route written by a policy-ready join.
const PolicyPackage = "pbr"

// PackageState is what could be determined about an installed package.
type PackageState int

const (
	// PackageUnknown means neither package manager answered, so nothing was
	// determined either way. Reported as unknown rather than as missing,
	// because a wrong "not installed" sends someone installing a package they
	// already have.
	PackageUnknown PackageState = iota
	// PackageInstalled means a package manager confirmed it is present.
	PackageInstalled
	// PackageMissing means a package manager answered and it is not present.
	PackageMissing
)

// InstalledState asks both package managers whether a package is installed.
// Current OpenWrt releases ship apk and 24.10 ships opkg, so the client tries
// each and uses whichever is on the router.
func (r Router) InstalledState(name string) PackageState {
	answered := false
	if r.Shell.Look("apk") == nil {
		answered = true
		if out, err := r.run(packageTimeout, "", "apk", "info", "-e", name); err == nil &&
			strings.Contains(string(out), name) {
			return PackageInstalled
		}
	}
	if r.Shell.Look("opkg") == nil {
		answered = true
		if out, err := r.run(packageTimeout, "", "opkg", "list-installed", name); err == nil &&
			strings.Contains(string(out), name) {
			return PackageInstalled
		}
	}
	if !answered {
		return PackageUnknown
	}
	return PackageMissing
}

// ProtocolPackageNotice returns what to tell the operator about the LuCI
// protocol handler, or an empty string when it is installed and there is
// nothing to say.
func (r Router) ProtocolPackageNotice(iface string) string {
	switch r.InstalledState(ProtocolPackage) {
	case PackageInstalled:
		return ""
	case PackageMissing:
		return ProtocolPackage + " is not installed, so " + iface +
			" will come up but LuCI will not render it as a WireGuard interface" +
			" and Status > WireGuard will be missing.\n" +
			"    Install it with \"apk add " + ProtocolPackage + "\" or \"opkg install " +
			ProtocolPackage + "\", then run \"service rpcd restart\" so the protocol appears."
	default:
		return "could not determine whether " + ProtocolPackage +
			" is installed, because neither apk nor opkg answered.\n" +
			"    Check it by hand if " + iface + " does not render as a WireGuard interface in LuCI."
	}
}

// RequirePolicyPackage prevents a raw binary from writing policy-ready routes
// that the operator cannot select. Packaged installs normally satisfy this
// through the package dependency before the client runs.
func (r Router) RequirePolicyPackage() error {
	switch r.InstalledState(PolicyPackage) {
	case PackageInstalled:
		return nil
	case PackageMissing:
		return fmt.Errorf("%s is required for policy routing; install it with "+
			"\"apk add %s\" or \"opkg install %s\"", PolicyPackage, PolicyPackage, PolicyPackage)
	default:
		return fmt.Errorf("could not determine whether %s is installed because neither apk nor opkg answered", PolicyPackage)
	}
}
