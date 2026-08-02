package openwrt

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"shadow9-node/internal/wgkey"
)

// PeerSectionName is the named UCI section holding the hub peer. A named
// section keeps a stable address, so a later join replaces this peer instead
// of adding a second one, and an operator's own peer added in LuCI does not
// shift its index.
func PeerSectionName(iface string) string {
	return iface + "_hub"
}

// RouteSectionName is the named route that keeps the tunnel network reachable
// outside PBR. Policy-selected traffic uses PBR's own pbr_<interface> table.
func RouteSectionName(iface string) string {
	return iface + "_route"
}

// RuleSectionName is the named rule that sends this router's LAN through the
// tunnel. It is written disabled, because a join must never move traffic on
// its own; enabling it is one checkbox on LuCI's Routing page.
func RuleSectionName(iface string) string {
	return iface + "_rule"
}

// PolicyTable is the routing table PBR builds for an interface. The rule
// points at it by name, which PBR registers in /etc/iproute2/rt_tables.
func PolicyTable(iface string) string {
	return "pbr_" + iface
}

// LanSectionName is the network and dhcp section for the tunnel LAN: a
// separate subnet whose traffic goes through the tunnel, so an operator does
// not have to build one and attach it themselves.
func LanSectionName(iface string) string {
	return iface + "_lan"
}

// LanDeviceSection is the named section holding the tunnel LAN's bridge. It is
// named rather than anonymous so a later run addresses the same bridge instead
// of whatever now sits at an index.
func LanDeviceSection(iface string) string {
	return "br_" + iface + "_lan"
}

// LanDevice is the bridge itself. Linux caps an interface name at 15
// characters, which "br-wg0-lan" stays well inside.
func LanDevice(iface string) string {
	return "br-" + iface + "-lan"
}

// LanZoneName is the tunnel LAN's own firewall zone. It is deliberately not
// the tunnel's zone: that one masquerades, and traffic from this LAN to the
// router's other networks should keep its real source address.
func LanZoneName(zone string) string {
	return zone + "lan"
}

// LanAddress puts the router at the first host address of the tunnel LAN, the
// convention every other LAN on an OpenWrt router follows.
func LanAddress(subnet string) (string, error) {
	address, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("the tunnel LAN %q is not a subnet: %w", subnet, err)
	}
	if network.IP.To4() == nil {
		return "", fmt.Errorf("the tunnel LAN must be IPv4, and %s is not", subnet)
	}
	if !address.Equal(network.IP) {
		return "", fmt.Errorf(
			"the tunnel LAN should name a subnet rather than a host: use %s", network)
	}
	ones, bits := network.Mask.Size()
	if ones > bits-2 {
		return "", fmt.Errorf("the tunnel LAN %s has no room for hosts", subnet)
	}
	router := make(net.IP, len(network.IP.To4()))
	copy(router, network.IP.To4())
	router[3]++
	return fmt.Sprintf("%s/%d", router, ones), nil
}

func routeSectionName(iface string, index int) string {
	if index == 0 {
		return RouteSectionName(iface)
	}
	return RouteSectionName(iface) + "_" + strconv.Itoa(index)
}

// Tunnel is the state the router should end up in after a join. Every field
// comes either from a flag or from the hub's enrollment response, so this
// struct is the whole of what a join changes.
type Tunnel struct {
	Interface  string
	Zone       string
	LanZone    string
	PrivateKey string
	Address    string
	Network    string
	// LanSubnet is this router's LAN in CIDR form. Policy mode writes one
	// disabled rule matching it, so an operator has a ready-made way to send
	// the LAN through the tunnel without hand-building one.
	LanSubnet string
	// RuleDisabled carries the rule's current disabled value forward, so a
	// later join or refresh does not switch a rule the operator turned on back
	// off. Empty means the rule is new and starts disabled.
	RuleDisabled string
	// TunnelLan is a subnet to build a LAN on, in CIDR form. Empty means the
	// operator did not ask for one and none is created.
	TunnelLan         string
	ListenPort        int
	MTU               int
	Revision          int
	MTUOverride       *int
	KeepaliveOverride *int
	Table             int

	HubPublicKey   string
	PresharedKey   string
	EndpointHost   string
	EndpointPort   int
	Keepalive      int
	AllowedIPs     []string
	HubDescription string
}

// DefaultInterface, DefaultZone and DefaultLanZone are the names used when
// nothing else is given.
const (
	DefaultInterface = "wg0"
	DefaultZone      = "wgvpn"
	DefaultLanZone   = "lan"
	DefaultIPv4Route = "0.0.0.0/0"
	DefaultIPv6Route = "::/0"
	nodeSection      = "shadow9.node"
)

// longestZoneName is the documented working maximum for a firewall zone name.
const longestZoneName = 11

// Validate reports what is missing or wrong before anything is written, so a
// bad response never leaves the router half configured.
func (t Tunnel) Validate() error {
	switch {
	case t.Interface == "":
		return fmt.Errorf("the interface name is empty")
	case t.Zone == "":
		return fmt.Errorf("the firewall zone name is empty")
	case len(t.Zone) > longestZoneName:
		return fmt.Errorf("the firewall zone name %q is %d characters, the working maximum is %d",
			t.Zone, len(t.Zone), longestZoneName)
	case t.LanZone == "":
		return fmt.Errorf("the LAN firewall zone name is empty")
	case t.PrivateKey == "":
		return fmt.Errorf("the private key is empty")
	case t.Address == "":
		return fmt.Errorf("the hub gave no address for this interface")
	case t.Table != 0 && t.Network == "":
		return fmt.Errorf("the hub gave no tunnel network for policy routing")
	case t.Table < 0:
		return fmt.Errorf("the routing table cannot be negative")
	case t.Table >= 253 && t.Table <= 255:
		return fmt.Errorf("routing table %d is reserved by Linux", t.Table)
	case t.HubPublicKey == "":
		return fmt.Errorf("the hub gave no public key")
	case t.EndpointHost == "":
		return fmt.Errorf("the hub gave no endpoint host")
	case len(t.AllowedIPs) == 0:
		return fmt.Errorf("the hub gave no allowed IPs, so nothing would route through the tunnel")
	}
	if t.Table != 0 {
		_, network, err := net.ParseCIDR(t.Network)
		if err != nil {
			return fmt.Errorf("the tunnel network %q is unusable: %w", t.Network, err)
		}
		if network.IP.To4() == nil {
			return fmt.Errorf(
				"policy-routing mode currently supports IPv4 tunnels; use -site-only for %s",
				network.String())
		}
		address, _, err := net.ParseCIDR(t.Address)
		if err != nil || !network.Contains(address) {
			return fmt.Errorf("the tunnel address %q is outside %s", t.Address, network)
		}
	}
	// Keys reach uci through a batch on stdin, which is a parser: a value
	// carrying a quote or a newline would end the line and start a command.
	// Requiring every key to be 32 base64 bytes leaves nothing that can.
	for _, key := range []struct {
		name  string
		value string
	}{
		{"private key", t.PrivateKey},
		{"hub public key", t.HubPublicKey},
		{"preshared key", t.PresharedKey},
	} {
		if key.value == "" {
			continue
		}
		if _, err := wgkey.Parse(key.value); err != nil {
			return fmt.Errorf("the %s is unusable: %w", key.name, err)
		}
	}
	return nil
}

// TakesOverTheDefaultRoute reports whether the hub's allowed IPs contain a
// default route. Combined with route_allowed_ips this sends everything,
// including the operator's own way back in, through the tunnel.
func (t Tunnel) TakesOverTheDefaultRoute() bool {
	if t.Table != 0 {
		return false
	}
	for _, a := range t.AllowedIPs {
		if a == DefaultIPv4Route || a == DefaultIPv6Route {
			return true
		}
	}
	return false
}

// policyRulePriority sits just past PBR's own fwmark rules, which run from
// 29994 to 30000, so a LAN-wide rule is considered after a narrower PBR policy
// has had its chance to mark a packet for a different interface.
const policyRulePriority = 30001

// LanSection names the tunnel LAN this tunnel builds, or "" when none was
// asked for. Site-only mode has no policy table for it to use.
func (t Tunnel) LanSection() string {
	if t.Table == 0 || t.TunnelLan == "" {
		return ""
	}
	return LanSectionName(t.Interface)
}

// ruleSource is the subnet the steering rule matches. A tunnel LAN exists only
// to use the tunnel, so it takes precedence over the router's own LAN.
func (t Tunnel) ruleSource() string {
	if t.TunnelLan != "" {
		return t.TunnelLan
	}
	return t.LanSubnet
}

// RuleSection names the steering rule this tunnel writes, or "" when there is
// none: site-only mode has no policy table to point at, and a router whose LAN
// subnet could not be read has nothing to match.
func (t Tunnel) RuleSection() string {
	if t.Table == 0 || t.ruleSource() == "" {
		return ""
	}
	return RuleSectionName(t.Interface)
}

func (t Tunnel) RouteTargets() []string {
	if t.Table == 0 {
		return nil
	}
	targets := []string{}
	seen := map[string]bool{}
	add := func(value string) {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return
		}
		value = network.String()
		if value == DefaultIPv4Route || value == DefaultIPv6Route || seen[value] {
			return
		}
		seen[value] = true
		targets = append(targets, value)
	}
	add(t.Network)
	for _, allowed := range t.AllowedIPs {
		add(allowed)
	}
	return targets
}

// NetworkCommands returns the uci invocations that write /etc/config/network.
//
// Each section is deleted before it is recreated, because add_list appends:
// re-running a join would otherwise leave two copies of every allowed_ips
// entry. Router.ClearPeers deletes the named peer before these commands
// recreate it.
func (t Tunnel) NetworkCommands() []Command {
	iface := "network." + t.Interface
	peer := "network." + PeerSectionName(t.Interface)

	commands := []Command{
		remove(iface),
		set(iface, "interface"),
		set(iface+".proto", "wireguard"),
		setSecret(iface+".private_key", t.PrivateKey),
	}
	for index, target := range t.RouteTargets() {
		route := "network." + routeSectionName(t.Interface, index)
		kind := "route"
		if strings.Contains(target, ":") {
			kind = "route6"
		}
		commands = append(commands,
			remove(route),
			set(route, kind),
			set(route+".interface", t.Interface),
			set(route+".target", target),
		)
	}
	// The rule is written disabled and sits above PBR's own fwmark rules, so
	// enabling it sends the whole LAN through the tunnel while a PBR policy
	// still picks out narrower traffic. netifd ignores a disabled rule
	// entirely, so nothing is installed until an operator ticks the box.
	// The bridge is created with no ports. Only the operator knows which port,
	// VLAN or SSID belongs on it, and taking one from an existing bridge would
	// move whatever is plugged into it.
	if lan := t.LanSection(); lan != "" {
		device := "network." + LanDeviceSection(t.Interface)
		key := "network." + lan
		address, err := LanAddress(t.TunnelLan)
		if err == nil {
			mtu := t.MTU
			if mtu == 0 {
				mtu = 1420
			}
			commands = append(commands,
				remove(device),
				set(device, "device"),
				set(device+".name", LanDevice(t.Interface)),
				set(device+".type", "bridge"),
				remove(key),
				set(key, "interface"),
				set(key+".device", LanDevice(t.Interface)),
				set(key+".proto", "static"),
				set(key+".ipaddr", address),
				// Matching the tunnel keeps a full-sized packet from this LAN
				// from needing fragmentation the moment it is encrypted.
				set(key+".mtu", strconv.Itoa(mtu)),
			)
		}
	}
	if rule := t.RuleSection(); rule != "" {
		key := "network." + rule
		disabled := t.RuleDisabled
		if disabled == "" {
			// A LAN built for the tunnel has nothing on it yet, so switching
			// it on moves no existing traffic and it starts live. The router's
			// own LAN is the opposite case and starts off.
			disabled = "1"
			if t.TunnelLan != "" {
				disabled = "0"
			}
		}
		commands = append(commands,
			remove(key),
			set(key, "rule"),
			set(key+".src", t.ruleSource()),
			set(key+".lookup", PolicyTable(t.Interface)),
			set(key+".priority", strconv.Itoa(policyRulePriority)),
			set(key+".disabled", disabled),
		)
	}
	if t.ListenPort != 0 {
		commands = append(commands, set(iface+".listen_port", strconv.Itoa(t.ListenPort)))
	}
	if t.MTU != 0 {
		commands = append(commands, set(iface+".mtu", strconv.Itoa(t.MTU)))
	}
	commands = append(commands, addList(iface+".addresses", t.Address))

	description := t.HubDescription
	if description == "" {
		description = "shadow9 hub"
	}
	commands = append(commands,
		remove(peer),
		set(peer, PeerSectionType(t.Interface)),
		set(peer+".description", description),
		set(peer+".public_key", t.HubPublicKey),
	)
	if t.PresharedKey != "" {
		commands = append(commands, setSecret(peer+".preshared_key", t.PresharedKey))
	}
	routeAllowed := "1"
	if t.Table != 0 {
		// allowed_ips carries 0.0.0.0/0 in policy mode, and netifd would turn
		// that into a main-table default that replaces WAN. PBR builds
		// pbr_<interface> and its fwmark rules from the peer instead, and the
		// named route sections keep the tunnel and the other sites reachable.
		routeAllowed = "0"
	}
	commands = append(commands,
		set(peer+".endpoint_host", t.EndpointHost),
		set(peer+".endpoint_port", strconv.Itoa(t.EndpointPort)),
		set(peer+".persistent_keepalive", strconv.Itoa(t.Keepalive)),
		set(peer+".route_allowed_ips", routeAllowed),
	)
	for _, allowed := range t.AllowedIPs {
		commands = append(commands, addList(peer+".allowed_ips", allowed))
	}
	return commands
}

// FirewallCommands returns the uci invocations that write
// /etc/config/firewall.
//
// This goes through zones and forwardings and nothing else. fw4 renders its
// whole ruleset from UCI and emits "flush table inet fw4" first, so any
// hand-written nftables rule is gone on the next firewall reload.
func (t Tunnel) FirewallCommands() []Command {
	zone := "firewall." + t.Zone
	masqueradeOption := ".masq"
	if strings.Contains(t.Address, ":") {
		masqueradeOption = ".masq6"
	}
	masquerade := "0"
	if t.Table != 0 {
		// Policy-routed LAN traffic must enter the hub as this node's tunnel
		// address so the hub's tunnel-range masquerade covers internet access.
		masquerade = "1"
	}
	commands := []Command{
		remove(zone),
		set(zone, "zone"),
		set(zone+".name", t.Zone),
		set(zone+".input", "ACCEPT"),
		set(zone+".output", "ACCEPT"),
		set(zone+".forward", "ACCEPT"),
		set(zone+masqueradeOption, masquerade),
		// Clamps TCP MSS on forwarded traffic, which is what stops the case
		// where ping and SSH work but some HTTPS connections hang.
		set(zone+".mtu_fix", "1"),
		addList(zone+".network", t.Interface),
	}
	// The masquerade above is for internet access through the hub. Without
	// these exclusions it also rewrites traffic to the tunnel and the other
	// sites, so a remote LAN sees this node's tunnel address instead of the
	// host that started the connection. fw4 turns a negated masq_dest list
	// into one "daddr != {...}" match ahead of the masquerade.
	for _, target := range t.RouteTargets() {
		commands = append(commands, addList(zone+".masq_dest", "!"+target))
	}

	// One forwarding covers one direction only. With just LAN to tunnel, the
	// remote side cannot open a connection into this router's LAN.
	for _, f := range []struct{ name, src, dest string }{
		{t.Zone + "_to_" + t.LanZone, t.Zone, t.LanZone},
		{t.LanZone + "_to_" + t.Zone, t.LanZone, t.Zone},
	} {
		key := "firewall." + f.name
		commands = append(commands,
			remove(key),
			set(key, "forwarding"),
			set(key+".src", f.src),
			set(key+".dest", f.dest),
		)
	}

	// The tunnel LAN gets its own zone rather than joining the tunnel's. The
	// tunnel zone masquerades, and traffic from this LAN to the router's other
	// networks should arrive with the real source address, not the router's.
	if t.LanSection() != "" {
		lanZone := "firewall." + LanZoneName(t.Zone)
		commands = append(commands,
			remove(lanZone),
			set(lanZone, "zone"),
			set(lanZone+".name", LanZoneName(t.Zone)),
			set(lanZone+".input", "ACCEPT"),
			set(lanZone+".output", "ACCEPT"),
			set(lanZone+".forward", "ACCEPT"),
			set(lanZone+".mtu_fix", "1"),
			addList(lanZone+".network", t.LanSection()),
		)
		for _, f := range []struct{ name, src, dest string }{
			{LanZoneName(t.Zone) + "_out", LanZoneName(t.Zone), t.Zone},
			{LanZoneName(t.Zone) + "_lan", LanZoneName(t.Zone), t.LanZone},
		} {
			key := "firewall." + f.name
			commands = append(commands,
				remove(key),
				set(key, "forwarding"),
				set(key+".src", f.src),
				set(key+".dest", f.dest),
			)
		}
	}

	// Only needed when this node listens. A dial-out node's return traffic is
	// conntracked and needs no rule.
	inbound := "firewall." + t.Zone + "_in"
	commands = append(commands, remove(inbound))
	if t.ListenPort != 0 {
		commands = append(commands,
			set(inbound, "rule"),
			set(inbound+".name", "Allow-"+t.Zone),
			set(inbound+".src", "wan"),
			set(inbound+".proto", "udp"),
			set(inbound+".dest_port", strconv.Itoa(t.ListenPort)),
			set(inbound+".target", "ACCEPT"),
		)
	}
	return commands
}

// DHCPCommands hands out addresses on the tunnel LAN. Without this the bridge
// is a subnet nothing can join without a static address, which is most of the
// work an operator would otherwise be left to do themselves.
//
// No dhcp_option for DNS is set on purpose: the router's own resolver is the
// default, and naming a public resolver here would quietly send this LAN's
// lookups outside the tunnel it was built to use.
func (t Tunnel) DHCPCommands() []Command {
	lan := t.LanSection()
	if lan == "" {
		return nil
	}
	key := "dhcp." + lan
	return []Command{
		remove(key),
		set(key, "dhcp"),
		set(key+".interface", lan),
		set(key+".start", "100"),
		set(key+".limit", "150"),
		set(key+".leasetime", "12h"),
	}
}

// SettingsCommands records where this node enrolled, so the init script and
// the uci-defaults script can re-apply the tunnel after a reboot or a flash
// without being told the hub again.
func (t Tunnel) SettingsCommands(hub string) []Command {
	commands := []Command{
		set(nodeSection, "node"),
		set(nodeSection+".hub", hub),
		set(nodeSection+".interface", t.Interface),
		set(nodeSection+".zone", t.Zone),
		set(nodeSection+".lan_zone", t.LanZone),
		set(nodeSection+".revision", strconv.Itoa(t.Revision)),
		set(nodeSection+".enabled", "1"),
	}
	commands = append(commands,
		remove(nodeSection+".mtu_override"),
		remove(nodeSection+".keepalive_override"),
		remove(nodeSection+".table"),
		remove(nodeSection+".route"),
		remove(nodeSection+".rule"),
		remove(nodeSection+".lan"),
		remove(nodeSection+".lan_subnet"),
	)
	if rule := t.RuleSection(); rule != "" {
		commands = append(commands, set(nodeSection+".rule", rule))
	}
	if lan := t.LanSection(); lan != "" {
		commands = append(commands,
			set(nodeSection+".lan", lan),
			set(nodeSection+".lan_subnet", t.TunnelLan),
		)
	}
	if t.Table != 0 {
		commands = append(commands, set(nodeSection+".table", strconv.Itoa(t.Table)))
		for index := range t.RouteTargets() {
			name := routeSectionName(t.Interface, index)
			if index == 0 {
				commands = append(commands, set(nodeSection+".route", name))
			} else {
				commands = append(commands, addList(nodeSection+".route", name))
			}
		}
	}
	if t.MTUOverride != nil {
		commands = append(commands, set(nodeSection+".mtu_override", strconv.Itoa(*t.MTUOverride)))
	}
	if t.KeepaliveOverride != nil {
		commands = append(commands,
			set(nodeSection+".keepalive_override", strconv.Itoa(*t.KeepaliveOverride)))
	}
	return commands
}

// FindZoneForNetwork returns the name of the firewall zone carrying a
// network, or an empty string when it cannot be determined. The LAN zone is
// called "lan" on a stock image but nothing guarantees it, and writing a
// forwarding to a zone that does not exist produces a firewall that does not
// forward with no error at the time it is written.
func FindZoneForNetwork(router Router, network string) (string, error) {
	const mostZonesWorthReading = 32
	for i := 0; i < mostZonesWorthReading; i++ {
		key := fmt.Sprintf("firewall.@zone[%d]", i)
		name, err := router.Get(key + ".name")
		if errors.Is(err, ErrNotFound) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if name == "" {
			return "", nil
		}
		// uci get prints a list as its values separated by spaces.
		members, err := router.Get(key + ".network")
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		for _, member := range strings.Fields(members) {
			if member == network {
				return name, nil
			}
		}
	}
	return "", nil
}
