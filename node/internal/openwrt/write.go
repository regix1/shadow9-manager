package openwrt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"shadow9-node/internal/wgkey"
)

// SettingsPath is the UCI package recording where this node enrolled. It is
// declared as a conffile by the OpenWrt package, which is what makes it
// survive a sysupgrade.
const SettingsPath = "/etc/config/shadow9"

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
	// uci cannot create the package file itself, and a node that installed
	// the binary by hand has no shadow9 package yet.
	if _, err := r.run(fileTimeout, "", "touch", SettingsPath); err != nil {
		return fmt.Errorf("creating %s: %w", SettingsPath, err)
	}
	snapshots, err := r.snapshot()
	if err != nil {
		return err
	}

	r.ClearPeers(tunnel.Interface)

	staged := [][]Command{
		tunnel.NetworkCommands(),
		tunnel.FirewallCommands(),
		tunnel.SettingsCommands(hub),
	}
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			r.revertAll()
			return err
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
func (r Router) revertAll() {
	for _, pkg := range packages {
		_, _ = r.run(uciTimeout, "", "uci", "-q", "revert", pkg)
	}
}
