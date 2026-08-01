package openwrt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"shadow9-node/internal/wgkey"
)

// SettingsPath is the UCI package recording where this node enrolled. It is
// declared as a conffile by the OpenWrt package, which is what makes it
// survive a sysupgrade.
const SettingsPath = "/etc/config/shadow9"

const (
	TokenPath    = "/etc/shadow9.token"
	DefaultsPath = "/etc/uci-defaults/99-shadow9-node"
	InitScript   = "/etc/init.d/shadow9-node"
)

// packages is every UCI package a join touches, in commit order.
var packages = []string{"network", "firewall", "shadow9"}

type Snapshot struct {
	Package string
	Config  Stdin
}

// WriteIdentity saves the private half before the hub records the public half.
// The name ties the key to an enrollment retry, so a different node name does
// not silently inherit an identity that the hub knows under another name.
func (r Router) WriteIdentity(name, privateKey string) error {
	// The key goes in through a uci batch on stdin, so it has to be a key and
	// not something that could end the line and start another command.
	if _, err := wgkey.Parse(privateKey); err != nil {
		return fmt.Errorf("the private key is unusable: %w", err)
	}
	if _, err := r.run(fileTimeout, "", "touch", SettingsPath); err != nil {
		return fmt.Errorf("creating %s: %w", SettingsPath, err)
	}
	commands := []Command{
		set(nodeSection, "node"),
		set(nodeSection+".name", name),
		setSecret(nodeSection+".private_key", privateKey),
	}
	if err := r.Apply(commands); err != nil {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", "shadow9")
		return err
	}
	if err := r.Commit("shadow9"); err != nil {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", "shadow9")
		return err
	}
	return nil
}

// WriteRefreshKey saves the derived refresh credential after enrollment succeeds.
func (r Router) WriteRefreshKey(refreshKey string) error {
	raw, err := hex.DecodeString(refreshKey)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("the refresh key is unusable")
	}
	commands := []Command{setSecret(nodeSection+".refresh_key", refreshKey)}
	if err := r.Apply(commands); err != nil {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", "shadow9")
		return err
	}
	if err := r.Commit("shadow9"); err != nil {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", "shadow9")
		return err
	}
	return nil
}

func (r Router) checkOwnership(tunnel Tunnel) error {
	sections := []struct {
		path   string
		saved  string
		wanted string
	}{
		{"network." + tunnel.Interface, nodeSection + ".interface", tunnel.Interface},
		{"firewall." + tunnel.Zone, nodeSection + ".zone", tunnel.Zone},
	}
	for _, section := range sections {
		if _, err := r.Get(section.path); err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return fmt.Errorf("checking %s before writing it: %w", section.path, err)
		}
		owner, err := r.Get(section.saved)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("checking %s before writing %s: %w", section.saved, section.path, err)
		}
		if err != nil || owner != section.wanted {
			return fmt.Errorf(
				"%s already exists, and %s does not show that shadow9 owns it",
				section.path, section.saved)
		}
	}
	return nil
}

// WriteTunnel writes the network, firewall and settings configuration, then
// commits and reloads.
//
// Nothing is committed until every uci call has succeeded. uci stages changes
// until commit, so a failure part of the way through is reverted and the
// router is left exactly as it was.
func (r Router) WriteTunnel(tunnel Tunnel, hub string) error {
	if err := tunnel.Validate(); err != nil {
		return err
	}
	if err := r.checkOwnership(tunnel); err != nil {
		return err
	}
	// uci cannot create the package file itself, and a node that installed
	// the binary by hand has no shadow9 package yet.
	if _, err := r.run(fileTimeout, "", "touch", SettingsPath); err != nil {
		return fmt.Errorf("creating %s: %w", SettingsPath, err)
	}
	snapshots, err := r.snapshot()
	if err != nil {
		return err
	}

	if err := r.ClearPeers(tunnel.Interface); err != nil {
		return r.revertAll(err)
	}

	staged := [][]Command{
		tunnel.NetworkCommands(),
		tunnel.FirewallCommands(),
		tunnel.SettingsCommands(hub),
	}
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			return r.revertAll(err)
		}
	}

	for _, pkg := range packages {
		if err := r.Commit(pkg); err != nil {
			return r.restoreAfter(err, snapshots)
		}
	}

	// Reload rather than restart, so interfaces this client did not create
	// stay up. The saved packages remain available until netifd reports the
	// interface up; a failed or timed-out check restores them.
	for _, service := range []string{"network", "firewall"} {
		if err := r.Reload(service); err != nil {
			return r.restoreAfter(err, snapshots)
		}
	}
	if err := r.waitForTunnel(tunnel.Interface); err != nil {
		return r.restoreAfter(err, snapshots)
	}
	return nil
}

// RemoveTunnel deletes only the UCI sections whose ownership can be proven by
// the interface key and names saved during enrollment. Other WireGuard
// interfaces, firewall zones, routing tables and PBR policies are untouched.
func (r Router) RemoveTunnel() (bool, error) {
	iface, err := r.Get(nodeSection + ".interface")
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading the shadow9 interface before uninstalling: %w", err)
	}
	zone, err := r.Get(nodeSection + ".zone")
	if err != nil {
		return false, fmt.Errorf("reading the shadow9 firewall zone before uninstalling: %w", err)
	}
	lanZone, err := r.Get(nodeSection + ".lan_zone")
	if err != nil {
		return false, fmt.Errorf("reading the shadow9 LAN zone before uninstalling: %w", err)
	}

	sectionType, err := r.Get("network." + iface)
	if errors.Is(err, ErrNotFound) {
		return false, r.removeSettings()
	}
	if err != nil {
		return false, fmt.Errorf("checking the shadow9 interface before uninstalling: %w", err)
	}
	if sectionType != "interface" {
		return false, fmt.Errorf("network.%s is not a Shadow9-managed interface; no changes were made", iface)
	}
	savedKey, savedErr := r.Get(nodeSection + ".private_key")
	if errors.Is(savedErr, ErrNotFound) {
		return false, r.removeSettings()
	}
	if savedErr != nil {
		return false, fmt.Errorf("checking the saved Shadow9 identity before uninstalling: %w", savedErr)
	}
	if savedKey == "" {
		return false, r.removeSettings()
	}
	interfaceKey, interfaceErr := r.Get("network." + iface + ".private_key")
	if interfaceErr != nil || interfaceKey != savedKey {
		return false, fmt.Errorf("ownership of network.%s cannot be proven; no changes were made", iface)
	}
	if _, err := wgkey.Parse(savedKey); err != nil {
		return false, fmt.Errorf("ownership of network.%s cannot be proven; no changes were made", iface)
	}

	peer := "network." + PeerSectionName(iface)
	peerType, err := r.Get(peer)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("checking the shadow9 peer before uninstalling: %w", err)
	}
	if err == nil && peerType != PeerSectionType(iface) {
		return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", peer)
	}

	zonePath := "firewall." + zone
	zoneType, err := r.Get(zonePath)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("checking the shadow9 firewall zone before uninstalling: %w", err)
	}
	if err == nil {
		zoneName, nameErr := r.Get(zonePath + ".name")
		networks, networkErr := r.Get(zonePath + ".network")
		owned := zoneType == "zone" && nameErr == nil && zoneName == zone && networkErr == nil
		if owned {
			members := strings.Fields(networks)
			owned = len(members) == 1 && members[0] == iface
		}
		if !owned {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", zonePath)
		}
	}

	for _, forwarding := range []struct {
		path string
		src  string
		dest string
	}{
		{"firewall." + zone + "_to_" + lanZone, zone, lanZone},
		{"firewall." + lanZone + "_to_" + zone, lanZone, zone},
	} {
		kind, err := r.Get(forwarding.path)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("checking %s before uninstalling: %w", forwarding.path, err)
		}
		src, srcErr := r.Get(forwarding.path + ".src")
		dest, destErr := r.Get(forwarding.path + ".dest")
		if kind != "forwarding" || srcErr != nil || destErr != nil ||
			src != forwarding.src || dest != forwarding.dest {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", forwarding.path)
		}
	}

	inbound := "firewall." + zone + "_in"
	kind, err := r.Get(inbound)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("checking %s before uninstalling: %w", inbound, err)
	}
	if err == nil {
		name, nameErr := r.Get(inbound + ".name")
		src, srcErr := r.Get(inbound + ".src")
		target, targetErr := r.Get(inbound + ".target")
		if kind != "rule" || nameErr != nil || srcErr != nil || targetErr != nil ||
			name != "Allow-"+zone || src != "wan" || target != "ACCEPT" {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", inbound)
		}
	}

	snapshots, err := r.snapshot()
	if err != nil {
		return false, err
	}
	staged := [][]Command{
		{remove("network." + iface), remove(peer)},
		{
			remove(zonePath),
			remove("firewall." + zone + "_to_" + lanZone),
			remove("firewall." + lanZone + "_to_" + zone),
			remove(inbound),
		},
		{remove(nodeSection)},
	}
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			return false, r.revertAll(err)
		}
	}
	for _, pkg := range packages {
		if err := r.Commit(pkg); err != nil {
			return false, r.restoreAfter(err, snapshots)
		}
	}
	for _, service := range []string{"network", "firewall"} {
		if err := r.Reload(service); err != nil {
			return false, r.restoreAfter(err, snapshots)
		}
	}
	return true, nil
}

func (r Router) removeSettings() error {
	if err := r.Apply([]Command{remove(nodeSection)}); err != nil {
		return err
	}
	if err := r.Commit("shadow9"); err != nil {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", "shadow9")
		return err
	}
	return nil
}

// DisableRefresh keeps an uninstalled node from being recreated at boot.
func (r Router) DisableRefresh() error {
	if err := r.Shell.Look(InitScript); err != nil {
		return nil
	}
	out, err := r.run(fileTimeout, "", InitScript, "disable")
	if err != nil {
		return fmt.Errorf("disabling the shadow9-node boot service: %w: %s", err, out)
	}
	return nil
}

// RemoveEnrollmentFiles deletes package-owned enrollment inputs that could
// recreate the tunnel. The binary and package dependencies remain installed.
func (r Router) RemoveEnrollmentFiles() error {
	out, err := r.run(fileTimeout, "", "rm", "-f", TokenPath, DefaultsPath)
	if err != nil {
		return fmt.Errorf("removing Shadow9 enrollment files: %w: %s", err, out)
	}
	return nil
}

type interfaceState struct {
	Up      bool `json:"up"`
	Pending bool `json:"pending"`
}

func (r Router) waitForTunnel(iface string) error {
	timeout := r.checkTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		commandTimeout := uciTimeout
		if remaining < commandTimeout {
			commandTimeout = remaining
		}
		out, err := r.run(commandTimeout, "", "ifstatus", iface)
		if err == nil {
			var state interfaceState
			if err = json.Unmarshal(out, &state); err == nil && state.Up && !state.Pending {
				return nil
			}
			if err == nil {
				err = fmt.Errorf("the interface is not up")
			}
		}
		lastErr = err
		remaining = time.Until(deadline)
		if remaining <= 0 {
			break
		}
		pause := time.Second
		if remaining < pause {
			pause = remaining
		}
		timer := time.NewTimer(pause)
		<-timer.C
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no status was returned")
	}
	return fmt.Errorf("interface %s did not come up within %s: %w", iface, timeout, lastErr)
}

func (r Router) snapshot() ([]Snapshot, error) {
	snapshots := make([]Snapshot, 0, len(packages))
	for _, pkg := range packages {
		out, err := r.run(uciTimeout, "", "uci", "export", pkg)
		if err != nil {
			return nil, fmt.Errorf("saving the current %s configuration: %w", pkg, err)
		}
		snapshots = append(snapshots, Snapshot{Package: pkg, Config: Stdin(out)})
	}
	return snapshots, nil
}

func (r Router) restoreAfter(cause error, snapshots []Snapshot) error {
	var restoreErrors []error
	for _, snapshot := range snapshots {
		if _, err := r.run(uciTimeout, snapshot.Config, "uci", "import", snapshot.Package); err != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("restoring the prior %s configuration: %w", snapshot.Package, err))
			continue
		}
		if err := r.Commit(snapshot.Package); err != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("committing the restored %s configuration: %w", snapshot.Package, err))
		}
	}
	for _, service := range []string{"network", "firewall"} {
		if err := r.Reload(service); err != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("reloading %s after restoring configuration: %w", service, err))
		}
	}
	if restoreErr := errors.Join(restoreErrors...); restoreErr != nil {
		return fmt.Errorf("%w; the prior configuration could not be fully restored: %v", cause, restoreErr)
	}
	return cause
}

// revertAll discards staged changes after a failure. A revert that itself
// fails is not reported, because the error being handled is the one worth
// telling the operator about.
func (r Router) revertAll(cause error) error {
	var revertErrors []error
	for _, pkg := range packages {
		out, err := r.run(uciTimeout, "", "uci", "revert", pkg)
		if err != nil {
			revertErrors = append(revertErrors,
				fmt.Errorf("reverting uncommitted %s configuration: %w: %s", pkg, err, out))
		}
	}
	if revertErr := errors.Join(revertErrors...); revertErr != nil {
		return fmt.Errorf("%w; staged changes could not be fully reverted: %v", cause, revertErr)
	}
	return cause
}
