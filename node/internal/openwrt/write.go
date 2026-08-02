package openwrt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"shadow9-node/internal/wgkey"
)

// SettingsPath is the UCI package recording where this node enrolled. It is
// declared as a conffile by the OpenWrt package, which is what makes it
// survive a sysupgrade.
const SettingsPath = "/etc/config/shadow9"

const (
	TokenPath = "/etc/shadow9.token"
	// DefaultsPath is no longer shipped, because a packaged uci-defaults
	// script makes OpenWrt's default post-install run a bare "uci commit".
	// It is still deleted here, so a node that enrolled from an older package
	// does not re-join from a leftover copy.
	DefaultsPath = "/etc/uci-defaults/99-shadow9-node"
	InitScript   = "/etc/init.d/shadow9-node"
)

const (
	pbrSection         = "pbr.config"
	pbrInterfaceOption = pbrSection + ".supported_interface"
	pbrEnabledOption   = pbrSection + ".enabled"
	pbrOwnerOption     = nodeSection + ".pbr_interface"
	pbrEnabledOwner    = nodeSection + ".pbr_enabled"
)

type pbrChange struct {
	commands     []Command
	iface        string
	enabledOwned bool
	disabled     bool
	touched      bool
}

func (change pbrChange) settings() []Command {
	commands := []Command{remove(pbrOwnerOption), remove(pbrEnabledOwner)}
	if change.iface != "" {
		commands = append(commands, set(pbrOwnerOption, change.iface))
	}
	if change.enabledOwned {
		commands = append(commands, set(pbrEnabledOwner, "1"))
	}
	return commands
}

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
	if err := r.checkChanges("shadow9"); err != nil {
		return err
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

// SaveSettings copies the shadow9 package so a step that fails after writing
// to it can put the node back exactly as it was. The file is created first,
// because a node that installed the binary by hand has no shadow9 package yet.
func (r Router) SaveSettings() ([]Snapshot, error) {
	if _, err := r.run(fileTimeout, "", "touch", SettingsPath); err != nil {
		return nil, fmt.Errorf("creating %s: %w", SettingsPath, err)
	}
	return r.snapshot([]string{"shadow9"})
}

// RestoreSettings puts back what SaveSettings copied and returns cause, with
// any restore failure joined onto it.
func (r Router) RestoreSettings(cause error, snapshots []Snapshot) error {
	return r.restoreAfter(cause, snapshots, nil)
}

// WriteRefreshKey saves the derived refresh credential after enrollment succeeds.
func (r Router) WriteRefreshKey(refreshKey string) error {
	raw, err := hex.DecodeString(refreshKey)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("the refresh key is unusable")
	}
	if err := r.checkChanges("shadow9"); err != nil {
		return err
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
	ownedRoutes, err := r.savedRoutes(tunnel.Interface)
	if err != nil {
		return err
	}
	owned := map[string]bool{}
	for _, name := range ownedRoutes {
		owned[name] = true
		route := "network." + name
		kind, routeErr := r.Get(route)
		if errors.Is(routeErr, ErrNotFound) {
			continue
		}
		if routeErr != nil {
			return fmt.Errorf("checking %s before writing it: %w", route, routeErr)
		}
		routeIface, ifaceErr := r.Get(route + ".interface")
		if (kind != "route" && kind != "route6") || ifaceErr != nil || routeIface != tunnel.Interface {
			return fmt.Errorf("ownership of %s cannot be proven; no changes were made", route)
		}
	}
	for index := range tunnel.RouteTargets() {
		name := routeSectionName(tunnel.Interface, index)
		if owned[name] {
			continue
		}
		if _, err := r.Get("network." + name); err == nil {
			return fmt.Errorf("%s", orphanMessage("network."+name, nodeSection+".route"))
		} else if !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("checking network.%s before writing it: %w", name, err)
		}
	}
	if rule := tunnel.RuleSection(); rule != "" {
		if err := r.checkRuleOwnership(rule); err != nil {
			return err
		}
	}
	return nil
}

// checkRuleOwnership refuses to write over a rule section this node cannot
// prove it created. An operator's own rule sharing the name would otherwise be
// replaced, and a rule is what decides where their traffic goes.
func (r Router) checkRuleOwnership(rule string) error {
	owner, err := r.Get(nodeSection + ".rule")
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("reading the Shadow9-owned rule: %w", err)
	}
	kind, kindErr := r.Get("network." + rule)
	if errors.Is(kindErr, ErrNotFound) {
		return nil
	}
	if kindErr != nil {
		return fmt.Errorf("checking network.%s before writing it: %w", rule, kindErr)
	}
	if owner != rule || kind != "rule" {
		return fmt.Errorf("%s", orphanMessage("network."+rule, nodeSection+".rule"))
	}
	return nil
}

// savedRule returns the rule section this node recorded, or "" when it has none.
func (r Router) savedRule() (string, error) {
	rule, err := r.Get(nodeSection + ".rule")
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading the Shadow9-owned rule: %w", err)
	}
	return rule, nil
}

// orphanMessage explains a section this node will not write over. Refusing is
// right, but an operator whose earlier install left the section behind has no
// way to tell that from a section of their own, so the way out is spelled out.
func orphanMessage(section, marker string) string {
	return fmt.Sprintf(
		"%s already exists, and %s does not show that shadow9 owns it. "+
			"If an earlier install left it behind, remove it with "+
			"\"uci delete %s; uci commit network\" and join again. "+
			"If it is yours, join with a different -iface.",
		section, marker, section)
}

func (r Router) savedRoutes(iface string) ([]string, error) {
	value, err := r.Get(nodeSection + ".route")
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the Shadow9-owned tunnel routes: %w", err)
	}
	names := strings.Fields(value)
	for index, name := range names {
		if name != routeSectionName(iface, index) {
			return nil, fmt.Errorf("ownership of network.%s cannot be proven; no changes were made", name)
		}
	}
	return names, nil
}

func hasListValue(values, wanted string) bool {
	for _, value := range strings.Fields(values) {
		if value == wanted {
			return true
		}
	}
	return false
}

func uciEnabled(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "on", "true", "yes", "enabled":
		return true
	default:
		return false
	}
}

func (r Router) pbrHasPolicies() (bool, error) {
	for _, kind := range []string{"policy", "dns_policy", "include"} {
		for index := 0; ; index++ {
			section := fmt.Sprintf("pbr.@%s[%d]", kind, index)
			_, err := r.Get(section)
			if errors.Is(err, ErrNotFound) {
				break
			}
			if err != nil {
				return false, fmt.Errorf("checking %s: %w", section, err)
			}
			enabled, err := r.Get(section + ".enabled")
			if errors.Is(err, ErrNotFound) || (err == nil && uciEnabled(enabled)) {
				return true, nil
			}
			if err != nil {
				return false, fmt.Errorf("checking %s.enabled: %w", section, err)
			}
		}
	}
	return false, nil
}

func (r Router) pbrCommands(tunnel Tunnel) (pbrChange, error) {
	owned, err := r.Get(pbrOwnerOption)
	if errors.Is(err, ErrNotFound) {
		owned = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading the Shadow9-owned PBR interface: %w", err)
	}
	enabledOwner, err := r.Get(pbrEnabledOwner)
	if errors.Is(err, ErrNotFound) {
		enabledOwner = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading the Shadow9-owned PBR state: %w", err)
	}
	if tunnel.Table == 0 && owned == "" && enabledOwner == "" {
		return pbrChange{}, nil
	}

	kind, err := r.Get(pbrSection)
	if errors.Is(err, ErrNotFound) {
		if tunnel.Table != 0 {
			return pbrChange{}, fmt.Errorf(
				"%s is missing; reinstall pbr before joining in policy-routing mode", pbrSection)
		}
		return pbrChange{}, nil
	}
	if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrSection, err)
	}
	if kind != "pbr" {
		if tunnel.Table != 0 {
			return pbrChange{}, fmt.Errorf("%s is not a pbr section", pbrSection)
		}
		return pbrChange{}, nil
	}

	supported, err := r.Get(pbrInterfaceOption)
	if errors.Is(err, ErrNotFound) {
		supported = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrInterfaceOption, err)
	}
	enabled, err := r.Get(pbrEnabledOption)
	if errors.Is(err, ErrNotFound) {
		enabled = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrEnabledOption, err)
	}

	change := pbrChange{enabledOwned: enabledOwner == "1"}
	if owned != "" && (tunnel.Table == 0 || owned != tunnel.Interface) &&
		hasListValue(supported, owned) {
		change.commands = append(change.commands, removeList(pbrInterfaceOption, supported, owned)...)
		change.touched = true
	}
	if tunnel.Table == 0 {
		if change.enabledOwned && uciEnabled(enabled) {
			otherInterfaces := false
			for _, supportedIface := range strings.Fields(supported) {
				otherInterfaces = otherInterfaces || supportedIface != owned
			}
			hasPolicies, err := r.pbrHasPolicies()
			if err != nil {
				return pbrChange{}, err
			}
			if !otherInterfaces && !hasPolicies {
				change.commands = append(change.commands, set(pbrEnabledOption, "0"))
				change.disabled = true
				change.touched = true
			}
		}
		change.enabledOwned = false
		return change, nil
	}
	if !uciEnabled(enabled) {
		if enabledOwner != "1" {
			hasPolicies, err := r.pbrHasPolicies()
			if err != nil {
				return pbrChange{}, err
			}
			if hasPolicies {
				return pbrChange{}, fmt.Errorf(
					"PBR is disabled and has enabled user policies; enable PBR deliberately before joining")
			}
		}
		change.commands = append(change.commands, set(pbrEnabledOption, "1"))
		change.enabledOwned = true
		change.touched = true
	}
	if hasListValue(supported, tunnel.Interface) {
		if owned == tunnel.Interface {
			change.iface = tunnel.Interface
		}
		return change, nil
	}
	// pbr already treats a wireguard interface as a tunnel and builds its table
	// without being told, which is why a working install can have an empty
	// supported_interface. The entry is added anyway because the list is an
	// extra way in rather than a restriction: it survives auto-detection
	// changing, and it is what uninstall reads back to know what to undo.
	change.commands = append(change.commands, addList(pbrInterfaceOption, tunnel.Interface))
	change.iface = tunnel.Interface
	change.touched = true
	return change, nil
}

func (r Router) removePBRInterface(iface string) (pbrChange, error) {
	owned, err := r.Get(pbrOwnerOption)
	if errors.Is(err, ErrNotFound) {
		owned = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading the Shadow9-owned PBR interface: %w", err)
	}
	enabledOwner, err := r.Get(pbrEnabledOwner)
	if errors.Is(err, ErrNotFound) {
		enabledOwner = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading the Shadow9-owned PBR state: %w", err)
	}
	if (owned == "" || owned != iface) && enabledOwner == "" {
		return pbrChange{}, nil
	}

	kind, err := r.Get(pbrSection)
	if errors.Is(err, ErrNotFound) {
		return pbrChange{}, nil
	}
	if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrSection, err)
	}
	if kind != "pbr" {
		return pbrChange{}, nil
	}

	supported, err := r.Get(pbrInterfaceOption)
	if errors.Is(err, ErrNotFound) {
		supported = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrInterfaceOption, err)
	}
	enabled, err := r.Get(pbrEnabledOption)
	if errors.Is(err, ErrNotFound) {
		enabled = ""
	} else if err != nil {
		return pbrChange{}, fmt.Errorf("reading %s: %w", pbrEnabledOption, err)
	}

	change := pbrChange{}
	if owned == iface && hasListValue(supported, owned) {
		change.commands = append(change.commands, removeList(pbrInterfaceOption, supported, owned)...)
		change.touched = true
	}
	if enabledOwner == "1" && uciEnabled(enabled) {
		otherInterfaces := false
		for _, supportedIface := range strings.Fields(supported) {
			otherInterfaces = otherInterfaces || supportedIface != owned
		}
		hasPolicies, err := r.pbrHasPolicies()
		if err != nil {
			return pbrChange{}, err
		}
		if !otherInterfaces && !hasPolicies {
			change.commands = append(change.commands, set(pbrEnabledOption, "0"))
			change.disabled = true
			change.touched = true
		}
	}
	return change, nil
}

func (r Router) reloadPBR(action string) {
	if err := r.Reload("pbr"); err != nil && r.Report != nil {
		r.Report(fmt.Sprintf(
			"PBR configuration was %s, but the pbr service did not reload cleanly: %v", action, err))
	}
}

func (r Router) stopPBR(action string) {
	out, err := r.run(reloadTimeout, "", "/etc/init.d/pbr", "stop")
	if err != nil && r.Report != nil {
		r.Report(fmt.Sprintf(
			"PBR configuration was %s, but the pbr service did not stop cleanly: %v: %s",
			action, err, strings.TrimSpace(string(out))))
	}
}

func (r Router) applyPBR(change pbrChange, action string) {
	if change.disabled {
		r.stopPBR(action)
		return
	}
	r.reloadPBR(action)
}

func (r Router) checkPBR(iface string) error {
	addresses, err := r.Get("network." + iface + ".addresses")
	if err != nil {
		return fmt.Errorf("reading network.%s.addresses before checking PBR: %w", iface, err)
	}
	addressFields := strings.Fields(addresses)
	if len(addressFields) == 0 {
		return fmt.Errorf("network.%s has no address before checking PBR", iface)
	}
	family := "-4"
	if strings.Contains(addressFields[0], ":") {
		family = "-6"
	}
	table := "pbr_" + iface
	out, err := r.run(uciTimeout, "", "ip", family, "route", "show", "table", table)
	if err != nil {
		return fmt.Errorf("PBR did not create routing table %s: %w: %s",
			table, err, strings.TrimSpace(string(out)))
	}
	hasDefault := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "default" {
			continue
		}
		for index, field := range fields[:len(fields)-1] {
			if field == "dev" && fields[index+1] == iface {
				hasDefault = true
				break
			}
		}
	}
	if !hasDefault {
		return fmt.Errorf("PBR routing table %s has no default route through %s", table, iface)
	}

	out, err = r.run(uciTimeout, "", "ip", family, "rule", "show")
	if err != nil {
		return fmt.Errorf("checking the PBR rules for %s: %w: %s",
			table, err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		hasMark := false
		hasTable := false
		for index, field := range fields {
			if field == "fwmark" {
				hasMark = true
			}
			if index+1 < len(fields) && (field == "lookup" || field == "table") &&
				fields[index+1] == table {
				hasTable = true
			}
		}
		if hasMark && hasTable {
			return nil
		}
	}
	return fmt.Errorf("PBR has no fwmark rule for routing table %s", table)
}

func (r Router) waitForPBR(iface string) error {
	timeout := r.checkTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	stable := false
	for {
		if err := r.checkPBR(iface); err == nil {
			if stable {
				return nil
			}
			stable = true
		} else {
			lastErr = err
			stable = false
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		pause := r.PBRSettle
		if pause <= 0 {
			if stable {
				continue
			}
			pause = time.Second
		}
		if remaining < pause {
			pause = remaining
		}
		timer := time.NewTimer(pause)
		<-timer.C
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("PBR routes did not remain stable before the timeout")
	}
	uplink, uplinkErr := r.Get("pbr.config.uplink_interface")
	if errors.Is(uplinkErr, ErrNotFound) || strings.TrimSpace(uplink) == "" {
		uplink = "wan"
		uplinkErr = nil
	}
	if uplinkErr == nil {
		if _, err := r.Get("network." + uplink); errors.Is(err, ErrNotFound) {
			return fmt.Errorf(
				"PBR did not create working routes for %s: pbr's uplink interface %q is not configured; set pbr.config.uplink_interface to the real uplink: %w",
				iface, uplink, lastErr)
		}
	}
	return fmt.Errorf("PBR did not create working routes for %s within %s: %w",
		iface, timeout, lastErr)
}

func (r Router) pbrNetworkCommands(iface string) ([]Command, error) {
	interfacePath := "network." + iface
	peer := "network." + PeerSectionName(iface)
	commands := []Command{}
	ownedIface, err := r.Get(nodeSection + ".interface")
	if err != nil || ownedIface != iface {
		return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", interfacePath)
	}
	sectionType, err := r.Get(interfacePath)
	if err != nil || sectionType != "interface" {
		return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", interfacePath)
	}
	savedKey, savedErr := r.Get(nodeSection + ".private_key")
	interfaceKey, interfaceErr := r.Get(interfacePath + ".private_key")
	if savedErr != nil || interfaceErr != nil || savedKey != interfaceKey {
		return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", interfacePath)
	}
	if _, err := wgkey.Parse(savedKey); err != nil {
		return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", interfacePath)
	}
	peerType, err := r.Get(peer)
	if err != nil || peerType != PeerSectionType(iface) {
		return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", peer)
	}
	savedTable, err := r.Get(nodeSection + ".table")
	if errors.Is(err, ErrNotFound) {
		savedTable = ""
	} else if err != nil {
		return nil, fmt.Errorf("reading the saved routing mode: %w", err)
	}
	if savedTable != "1" {
		commands = append(commands, set(nodeSection+".table", "1"))
	}

	// pbr decides an interface is netifd-managed purely by whether it carries
	// ip4table or ip6table, and then hands its table to netifd instead of
	// building the fwmark rules. A node upgrading from the numeric-table
	// layout still has those, so they have to go before pbr sees them.
	for _, option := range []string{"ip4table", "ip6table"} {
		_, err := r.Get(interfacePath + "." + option)
		if err == nil {
			commands = append(commands, remove(interfacePath+"."+option))
		} else if !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("checking %s.%s: %w", interfacePath, option, err)
		}
	}
	routeAllowed, err := r.Get(peer + ".route_allowed_ips")
	if errors.Is(err, ErrNotFound) {
		routeAllowed = ""
	} else if err != nil {
		return nil, fmt.Errorf("checking %s.route_allowed_ips: %w", peer, err)
	}
	if routeAllowed != "0" {
		commands = append(commands, set(peer+".route_allowed_ips", "0"))
	}

	addresses, err := r.Get(interfacePath + ".addresses")
	if err != nil {
		return nil, fmt.Errorf("reading %s.addresses for its tunnel route: %w", interfacePath, err)
	}
	fields := strings.Fields(addresses)
	if len(fields) == 0 {
		return nil, fmt.Errorf("%s has no tunnel address", interfacePath)
	}
	_, network, err := net.ParseCIDR(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%s address %q is unusable: %w", interfacePath, fields[0], err)
	}
	if network.IP.To4() == nil {
		return nil, fmt.Errorf(
			"policy-routing mode currently supports IPv4 tunnels; use -site-only for %s",
			network.String())
	}
	allowed, err := r.Get(peer + ".allowed_ips")
	if errors.Is(err, ErrNotFound) {
		allowed = ""
	} else if err != nil {
		return nil, fmt.Errorf("reading %s.allowed_ips: %w", peer, err)
	}
	tunnel := Tunnel{
		Interface:  iface,
		Address:    fields[0],
		Network:    network.String(),
		AllowedIPs: strings.Fields(allowed),
		Table:      1,
	}
	targets := tunnel.RouteTargets()
	ownedRoutes, err := r.savedRoutes(iface)
	if err != nil {
		return nil, err
	}
	owned := map[string]bool{}
	for _, name := range ownedRoutes {
		owned[name] = true
		route := "network." + name
		kind, routeErr := r.Get(route)
		if errors.Is(routeErr, ErrNotFound) {
			continue
		}
		if routeErr != nil {
			return nil, fmt.Errorf("checking %s: %w", route, routeErr)
		}
		routeIface, ifaceErr := r.Get(route + ".interface")
		if (kind != "route" && kind != "route6") || ifaceErr != nil || routeIface != iface {
			return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", route)
		}
	}
	planned := make([]string, 0, len(targets))
	for index, target := range targets {
		name := routeSectionName(iface, index)
		planned = append(planned, name)
		route := "network." + name
		kind, kindErr := r.Get(route)
		if errors.Is(kindErr, ErrNotFound) {
			kind = ""
		} else if kindErr != nil {
			return nil, fmt.Errorf("checking %s: %w", route, kindErr)
		}
		if kind != "" && !owned[name] {
			return nil, fmt.Errorf("%s already exists, and %s does not show that shadow9 owns it",
				route, nodeSection+".route")
		}
		routeIface, ifaceErr := r.Get(route + ".interface")
		if errors.Is(ifaceErr, ErrNotFound) {
			routeIface = ""
		} else if ifaceErr != nil {
			return nil, fmt.Errorf("checking %s.interface: %w", route, ifaceErr)
		}
		currentTarget, targetErr := r.Get(route + ".target")
		if errors.Is(targetErr, ErrNotFound) {
			currentTarget = ""
		} else if targetErr != nil {
			return nil, fmt.Errorf("checking %s.target: %w", route, targetErr)
		}
		wantedKind := "route"
		if strings.Contains(target, ":") {
			wantedKind = "route6"
		}
		if kind != wantedKind || routeIface != iface || currentTarget != target {
			commands = append(commands,
				remove(route),
				set(route, wantedKind),
				set(route+".interface", iface),
				set(route+".target", target),
			)
		}
	}
	plannedSet := map[string]bool{}
	for _, name := range planned {
		plannedSet[name] = true
	}
	for _, name := range ownedRoutes {
		if !plannedSet[name] {
			commands = append(commands, remove("network."+name))
		}
	}
	if strings.Join(ownedRoutes, " ") != strings.Join(planned, " ") {
		commands = append(commands, remove(nodeSection+".route"))
		if len(planned) != 0 {
			commands = append(commands, set(nodeSection+".route", planned[0]))
			for _, name := range planned[1:] {
				commands = append(commands, addList(nodeSection+".route", name))
			}
		}
	}
	ruleCommands, err := r.ruleCommands(iface)
	if err != nil {
		return nil, err
	}
	return append(commands, ruleCommands...), nil
}

// ruleCommands brings the steering rule up to date on a node that was enrolled
// before it existed. An existing rule this node owns is left almost alone: only
// the table it points at is corrected, because the source subnet and the
// enabled state are the operator's to choose.
func (r Router) ruleCommands(iface string) ([]Command, error) {
	lan, lanErr := LanNetwork(r)
	owned, err := r.savedRule()
	if err != nil {
		return nil, err
	}
	wanted := Tunnel{Interface: iface, Table: 1, LanSubnet: lan}.RuleSection()
	if wanted == "" {
		// Nothing to match, so an existing rule is left exactly as it is
		// rather than being removed on the strength of a failed lookup.
		if lanErr != nil && owned == "" {
			return nil, nil
		}
		return nil, nil
	}
	if err := r.checkRuleOwnership(wanted); err != nil {
		return nil, err
	}
	key := "network." + wanted
	kind, kindErr := r.Get(key)
	if kindErr != nil && !errors.Is(kindErr, ErrNotFound) {
		return nil, fmt.Errorf("checking %s: %w", key, kindErr)
	}
	if errors.Is(kindErr, ErrNotFound) || kind != "rule" {
		commands := []Command{
			remove(key),
			set(key, "rule"),
			set(key+".src", lan),
			set(key+".lookup", PolicyTable(iface)),
			set(key+".priority", strconv.Itoa(policyRulePriority)),
			set(key+".disabled", "1"),
		}
		if owned != wanted {
			commands = append(commands, set(nodeSection+".rule", wanted))
		}
		return commands, nil
	}
	commands := []Command{}
	lookup, lookupErr := r.Get(key + ".lookup")
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return nil, fmt.Errorf("checking %s.lookup: %w", key, lookupErr)
	}
	if lookup != PolicyTable(iface) {
		commands = append(commands, set(key+".lookup", PolicyTable(iface)))
	}
	if owned != wanted {
		commands = append(commands, set(nodeSection+".rule", wanted))
	}
	return commands, nil
}

// EnsurePBR repairs the local PBR registration without rewriting a tunnel
// whose hub revision has not changed.
func (r Router) EnsurePBR(iface string, table int) error {
	if iface == "" {
		return fmt.Errorf("the interface name is empty")
	}
	change, err := r.pbrCommands(Tunnel{Interface: iface, Table: table})
	if err != nil {
		return err
	}
	networkCommands := []Command{}
	if table != 0 {
		networkCommands, err = r.pbrNetworkCommands(iface)
		if err != nil {
			return err
		}
	}
	if !change.touched && len(networkCommands) == 0 {
		if table == 0 {
			return nil
		}
		if err := r.checkPBR(iface); err != nil {
			r.reloadPBR("repaired")
		}
		// The same stable check every writing path uses. A single passing
		// check can catch a table that pbr is still rebuilding.
		return r.waitForPBR(iface)
	}

	pkgs := []string{"shadow9"}
	services := []string{}
	if change.touched {
		pkgs = append(pkgs, "pbr")
	}
	if len(networkCommands) != 0 {
		pkgs = append(pkgs, "network")
		services = append(services, "network")
	}
	if change.touched {
		services = append(services, "pbr")
	}
	snapshots, err := r.snapshot(pkgs)
	if err != nil {
		return err
	}
	staged := [][]Command{networkCommands}
	if change.touched {
		staged = append(staged, change.commands)
	}
	// Ownership is rewritten on every path that writes anything, so a repair
	// that only touched the network never leaves a marker naming a PBR entry
	// this node no longer owns.
	staged = append(staged, change.settings())
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			return r.revertAll(err, pkgs)
		}
	}
	for _, pkg := range pkgs {
		if err := r.Commit(pkg); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}
	if len(networkCommands) != 0 {
		if err := r.Reload("network"); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
		if err := r.waitForTunnel(iface); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}
	r.applyPBR(change, "saved")
	if table != 0 {
		if err := r.waitForPBR(iface); err != nil {
			return r.restoreAfter(err, snapshots, services)
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
	// Carry the operator's own choice forward. Recreating the section would
	// otherwise switch a rule they had turned on back off every time the hub
	// changed its topology.
	if rule := tunnel.RuleSection(); rule != "" {
		current, err := r.Get("network." + rule + ".disabled")
		if err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("checking whether %s is enabled: %w", rule, err)
		}
		if err == nil {
			tunnel.RuleDisabled = current
		}
	}
	oldRoutes, err := r.savedRoutes(tunnel.Interface)
	if err != nil {
		return err
	}
	// uci cannot create the package file itself, and a node that installed
	// the binary by hand has no shadow9 package yet.
	if _, err := r.run(fileTimeout, "", "touch", SettingsPath); err != nil {
		return fmt.Errorf("creating %s: %w", SettingsPath, err)
	}
	pbr, err := r.pbrCommands(tunnel)
	if err != nil {
		return err
	}
	pkgs := []string{"shadow9"}
	if pbr.touched {
		pkgs = append(pkgs, "pbr")
	}
	pkgs = append(pkgs, "network", "firewall")
	services := []string{"network", "firewall"}
	if tunnel.Table != 0 || pbr.touched {
		services = append(services, "pbr")
	}
	snapshots, err := r.snapshot(pkgs)
	if err != nil {
		return err
	}

	if err := r.ClearPeers(tunnel.Interface); err != nil {
		return r.revertAll(err, pkgs)
	}

	settings := tunnel.SettingsCommands(hub)
	settings = append(settings, pbr.settings()...)
	tunnelCommands := tunnel.NetworkCommands()
	networkCommands := make([]Command, 0, len(oldRoutes)+len(tunnelCommands))
	for _, name := range oldRoutes {
		networkCommands = append(networkCommands, remove("network."+name))
	}
	networkCommands = append(networkCommands, tunnelCommands...)
	staged := [][]Command{
		networkCommands,
		tunnel.FirewallCommands(),
		pbr.commands,
		settings,
	}
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			return r.revertAll(err, pkgs)
		}
	}

	for _, pkg := range pkgs {
		if err := r.Commit(pkg); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}

	// Reload rather than restart, so interfaces this client did not create
	// stay up. The saved packages remain available until netifd reports the
	// interface up; a failed or timed-out check restores them.
	for _, service := range []string{"network", "firewall"} {
		if err := r.Reload(service); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}
	if err := r.waitForTunnel(tunnel.Interface); err != nil {
		return r.restoreAfter(err, snapshots, services)
	}
	if tunnel.Table != 0 || pbr.touched {
		r.applyPBR(pbr, "saved")
	}
	if tunnel.Table != 0 {
		if err := r.waitForPBR(tunnel.Interface); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}
	return nil
}

// RemoveTunnel deletes only the UCI sections whose ownership can be proven by
// the interface key and names saved during enrollment. Other WireGuard
// interfaces, firewall zones, routing tables and PBR policies are untouched.
// The supported-interface entry is removed only when the saved settings show
// that Shadow9 added it.
func (r Router) RemoveTunnel() (bool, error) {
	iface, err := r.Get(nodeSection + ".interface")
	if errors.Is(err, ErrNotFound) {
		kind, kindErr := r.Get(nodeSection)
		if errors.Is(kindErr, ErrNotFound) {
			return false, nil
		}
		if kindErr != nil {
			return false, fmt.Errorf("checking for an incomplete Shadow9 enrollment: %w", kindErr)
		}
		savedKey, keyErr := r.Get(nodeSection + ".private_key")
		if kind != "node" || keyErr != nil {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", nodeSection)
		}
		if _, keyErr := wgkey.Parse(savedKey); keyErr != nil {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", nodeSection)
		}
		return false, r.removeSettings("")
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
	interfaceExists := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("checking the shadow9 interface before uninstalling: %w", err)
	}
	if interfaceExists && sectionType != "interface" {
		return false, fmt.Errorf("network.%s is not a Shadow9-managed interface; no changes were made", iface)
	}
	if interfaceExists {
		savedKey, savedErr := r.Get(nodeSection + ".private_key")
		if errors.Is(savedErr, ErrNotFound) {
			return false, r.removeSettings(iface)
		}
		if savedErr != nil {
			return false, fmt.Errorf("checking the saved Shadow9 identity before uninstalling: %w", savedErr)
		}
		if savedKey == "" {
			return false, r.removeSettings(iface)
		}
		interfaceKey, interfaceErr := r.Get("network." + iface + ".private_key")
		if interfaceErr != nil || interfaceKey != savedKey {
			return false, fmt.Errorf("ownership of network.%s cannot be proven; no changes were made", iface)
		}
		if _, err := wgkey.Parse(savedKey); err != nil {
			return false, fmt.Errorf("ownership of network.%s cannot be proven; no changes were made", iface)
		}
	}

	peer := "network." + PeerSectionName(iface)
	peerType, err := r.Get(peer)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, fmt.Errorf("checking the shadow9 peer before uninstalling: %w", err)
	}
	if err == nil && peerType != PeerSectionType(iface) {
		return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", peer)
	}
	ruleName, err := r.savedRule()
	if err != nil {
		return false, err
	}
	if ruleName != "" {
		rule := "network." + ruleName
		kind, ruleErr := r.Get(rule)
		if ruleErr != nil && !errors.Is(ruleErr, ErrNotFound) {
			return false, fmt.Errorf("checking %s before uninstalling: %w", rule, ruleErr)
		}
		if ruleErr == nil && kind != "rule" {
			return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", rule)
		}
	}
	routeNames, err := r.savedRoutes(iface)
	if err != nil {
		return false, err
	}
	for _, routeName := range routeNames {
		route := "network." + routeName
		kind, routeErr := r.Get(route)
		if routeErr != nil && !errors.Is(routeErr, ErrNotFound) {
			return false, fmt.Errorf("checking %s before uninstalling: %w", route, routeErr)
		}
		if routeErr == nil {
			routeIface, ifaceErr := r.Get(route + ".interface")
			if (kind != "route" && kind != "route6") || ifaceErr != nil || routeIface != iface {
				return false, fmt.Errorf("ownership of %s cannot be proven; no changes were made", route)
			}
		}
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

	pbr, err := r.removePBRInterface(iface)
	if err != nil {
		return false, err
	}
	pkgs := []string{"network", "firewall"}
	if pbr.touched {
		pkgs = append(pkgs, "pbr")
	}
	pkgs = append(pkgs, "shadow9")
	services := []string{"network", "firewall"}
	if pbr.touched {
		services = append(services, "pbr")
	}
	snapshots, err := r.snapshot(pkgs)
	if err != nil {
		return false, err
	}
	network := []Command{remove("network." + iface), remove(peer)}
	for _, routeName := range routeNames {
		network = append(network, remove("network."+routeName))
	}
	if ruleName != "" {
		network = append(network, remove("network."+ruleName))
	}
	staged := [][]Command{
		network,
		{
			remove(zonePath),
			remove("firewall." + zone + "_to_" + lanZone),
			remove("firewall." + lanZone + "_to_" + zone),
			remove(inbound),
		},
		pbr.commands,
		{remove(nodeSection)},
	}
	for _, commands := range staged {
		if err := r.Apply(commands); err != nil {
			return false, r.revertAll(err, pkgs)
		}
	}
	for _, pkg := range pkgs {
		if err := r.Commit(pkg); err != nil {
			return false, r.restoreAfter(err, snapshots, services)
		}
	}
	for _, service := range []string{"network", "firewall"} {
		if err := r.Reload(service); err != nil {
			return false, r.restoreAfter(err, snapshots, services)
		}
	}
	if pbr.touched {
		r.applyPBR(pbr, "removed")
	}
	return true, nil
}

func (r Router) removeSettings(iface string) error {
	// An enrollment that never reached the interface still records which PBR
	// entry it added, so the owner is read back rather than guessed. Without
	// it the supported_interface entry outlives the settings that prove it.
	if iface == "" {
		owner, err := r.Get(pbrOwnerOption)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("reading the Shadow9-owned PBR interface: %w", err)
		}
		iface = owner
	}
	pbr, err := r.removePBRInterface(iface)
	if err != nil {
		return err
	}
	// The settings are about to go, and they are the only record of which
	// route and rule sections belong to this node. Anything still provable has
	// to be removed now or it is orphaned for good: a later join cannot prove
	// ownership of it either, and refuses.
	network, err := r.orphanedSections(iface)
	if err != nil {
		return err
	}
	pkgs := []string{}
	services := []string{}
	if len(network) != 0 {
		pkgs = append(pkgs, "network")
		services = append(services, "network")
	}
	if pbr.touched {
		pkgs = append(pkgs, "pbr")
		services = append(services, "pbr")
	}
	pkgs = append(pkgs, "shadow9")
	snapshots, err := r.snapshot(pkgs)
	if err != nil {
		return err
	}
	staged := append(network, pbr.commands...)
	if err := r.Apply(append(staged, remove(nodeSection))); err != nil {
		return r.revertAll(err, pkgs)
	}
	for _, pkg := range pkgs {
		if err := r.Commit(pkg); err != nil {
			return r.restoreAfter(err, snapshots, services)
		}
	}
	if pbr.touched {
		r.applyPBR(pbr, "removed")
	}
	return nil
}

// orphanedSections returns the deletes for route and rule sections this node
// still records, so cleaning up an incomplete enrollment does not leave behind
// sections that nothing can prove ownership of afterwards. A section whose
// ownership cannot be proven right now is left alone and reported.
func (r Router) orphanedSections(iface string) ([]Command, error) {
	if iface == "" {
		return nil, nil
	}
	commands := []Command{}
	routes, err := r.savedRoutes(iface)
	if err != nil {
		return nil, err
	}
	for _, name := range routes {
		route := "network." + name
		kind, kindErr := r.Get(route)
		if errors.Is(kindErr, ErrNotFound) {
			continue
		}
		if kindErr != nil {
			return nil, fmt.Errorf("checking %s before removing it: %w", route, kindErr)
		}
		routeIface, ifaceErr := r.Get(route + ".interface")
		if (kind != "route" && kind != "route6") || ifaceErr != nil || routeIface != iface {
			return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", route)
		}
		commands = append(commands, remove(route))
	}
	rule, err := r.savedRule()
	if err != nil {
		return nil, err
	}
	if rule != "" {
		key := "network." + rule
		kind, kindErr := r.Get(key)
		if kindErr != nil && !errors.Is(kindErr, ErrNotFound) {
			return nil, fmt.Errorf("checking %s before removing it: %w", key, kindErr)
		}
		if kindErr == nil {
			if kind != "rule" {
				return nil, fmt.Errorf("ownership of %s cannot be proven; no changes were made", key)
			}
			commands = append(commands, remove(key))
		}
	}
	return commands, nil
}

// DisableRefresh keeps an uninstalled node from being recreated at boot.
func (r Router) DisableRefresh() error {
	if _, err := r.run(fileTimeout, "", "test", "-f", InitScript); err != nil {
		return nil
	}
	command := []string{InitScript, "disable"}
	if err := r.Shell.Look(InitScript); err != nil {
		// A hook whose execute bit was lost still has to be disabled, or its
		// /etc/rc.d link survives and recreates the tunnel. This is the form
		// OpenWrt's own package scripts use to run one.
		command = []string{"/bin/sh", "/etc/rc.common", InitScript, "disable"}
	}
	out, err := r.run(fileTimeout, "", command[0], command[1:]...)
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

func (r Router) snapshot(pkgs []string) ([]Snapshot, error) {
	snapshots := make([]Snapshot, 0, len(pkgs))
	for _, pkg := range pkgs {
		if err := r.checkChanges(pkg); err != nil {
			return nil, err
		}
		out, err := r.run(uciTimeout, "", "uci", "export", pkg)
		if err != nil {
			return nil, fmt.Errorf("saving the current %s configuration: %w", pkg, err)
		}
		snapshots = append(snapshots, Snapshot{Package: pkg, Config: Stdin(out)})
	}
	return snapshots, nil
}

func (r Router) checkChanges(pkg string) error {
	changes, err := r.run(uciTimeout, "", "uci", "changes", pkg)
	if err != nil {
		return fmt.Errorf("checking for uncommitted %s configuration: %w", pkg, err)
	}
	if strings.TrimSpace(string(changes)) != "" {
		return fmt.Errorf(
			"%s has uncommitted UCI changes; apply or revert them before running shadow9-node",
			pkg)
	}
	return nil
}

func (r Router) restoreAfter(cause error, snapshots []Snapshot, services []string) error {
	var restoreErrors []error
	for _, snapshot := range snapshots {
		if out, err := r.run(uciTimeout, "", "uci", "revert", snapshot.Package); err != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("clearing staged %s changes before restoring: %w: %s",
					snapshot.Package, err, out))
			continue
		}
		if _, err := r.run(uciTimeout, snapshot.Config, "uci", "import", snapshot.Package); err != nil {
			restoreErrors = append(restoreErrors,
				fmt.Errorf("restoring the prior %s configuration: %w", snapshot.Package, err))
		}
	}
	for _, service := range services {
		if service == "pbr" {
			enabled, err := r.Get(pbrEnabledOption)
			if errors.Is(err, ErrNotFound) || (err == nil && !uciEnabled(enabled)) {
				r.stopPBR("restored")
				continue
			}
			if err != nil {
				restoreErrors = append(restoreErrors,
					fmt.Errorf("checking PBR after restoring configuration: %w", err))
				continue
			}
			r.reloadPBR("restored")
			continue
		}
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

// revertAll discards staged changes after a failure and reports any revert
// failure, because that means the working UCI state may still be dirty.
func (r Router) revertAll(cause error, pkgs []string) error {
	var revertErrors []error
	for _, pkg := range pkgs {
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
