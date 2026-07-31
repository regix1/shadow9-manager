package openwrt

import (
	"fmt"
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

// Tunnel is the state the router should end up in after a join. Every field
// comes either from a flag or from the hub's enrollment response, so this
// struct is the whole of what a join changes.
type Tunnel struct {
	Interface         string
	Zone              string
	LanZone           string
	PrivateKey        string
	Address           string
	ListenPort        int
	MTU               int
	Revision          int
	MTUOverride       *int
	KeepaliveOverride *int

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
	case t.HubPublicKey == "":
		return fmt.Errorf("the hub gave no public key")
	case t.EndpointHost == "":
		return fmt.Errorf("the hub gave no endpoint host")
	case len(t.AllowedIPs) == 0:
		return fmt.Errorf("the hub gave no allowed IPs, so nothing would route through the tunnel")
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
	for _, a := range t.AllowedIPs {
		if a == "0.0.0.0/0" || a == "::/0" {
			return true
		}
	}
	return false
}

// NetworkCommands returns the uci invocations that write /etc/config/network.
//
// Each section is deleted before it is recreated, because add_list appends:
// re-running a join would otherwise leave two copies of every allowed_ips
// entry. Peer sections are not deleted here, because they are addressed by
// type index rather than by name; Router.ClearPeers does that.
func (t Tunnel) NetworkCommands() []Command {
	iface := "network." + t.Interface
	peer := "network." + PeerSectionName(t.Interface)

	commands := []Command{
		remove(iface),
		set(iface, "interface"),
		set(iface+".proto", "wireguard"),
		setSecret(iface+".private_key", t.PrivateKey),
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
	commands = append(commands,
		set(peer+".endpoint_host", t.EndpointHost),
		set(peer+".endpoint_port", strconv.Itoa(t.EndpointPort)),
		set(peer+".persistent_keepalive", strconv.Itoa(t.Keepalive)),
		// allowed_ips filters inbound traffic and picks the peer for outbound
		// traffic, but it adds no route. Without this the LAN has no way to
		// reach the hub or the other sites.
		set(peer+".route_allowed_ips", "1"),
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
	commands := []Command{
		remove(zone),
		set(zone, "zone"),
		set(zone+".name", t.Zone),
		set(zone+".input", "ACCEPT"),
		set(zone+".output", "ACCEPT"),
		set(zone+".forward", "ACCEPT"),
		// Straight routing is the point, so the hub sees real LAN addresses.
		set(zone+".masq", "0"),
		// Clamps TCP MSS on forwarded traffic, which is what stops the case
		// where ping and SSH work but some HTTPS connections hang.
		set(zone+".mtu_fix", "1"),
		addList(zone+".network", t.Interface),
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
	)
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
func FindZoneForNetwork(router Router, network string) string {
	const mostZonesWorthReading = 32
	for i := 0; i < mostZonesWorthReading; i++ {
		key := fmt.Sprintf("firewall.@zone[%d]", i)
		name := router.Get(key + ".name")
		if name == "" {
			return ""
		}
		// uci get prints a list as its values separated by spaces.
		for _, member := range strings.Fields(router.Get(key + ".network")) {
			if member == network {
				return name
			}
		}
	}
	return ""
}
