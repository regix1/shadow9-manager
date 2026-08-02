package openwrt

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// siteGateway is the case the criteria describe: a router advertising its own
// LAN, reaching the hub and one other site through the tunnel.
func siteGateway() Tunnel {
	return Tunnel{
		Interface:    DefaultInterface,
		Zone:         DefaultZone,
		LanZone:      DefaultLanZone,
		PrivateKey:   "AJXKLmQ2vN8pR4tY6uI0oP1aSdF3gH5jKlZxCvB7nE0=",
		Address:      "10.9.0.7/32",
		Network:      "10.9.0.0/24",
		ListenPort:   51820,
		MTU:          1420,
		HubPublicKey: "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		PresharedKey: "Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=",
		EndpointHost: "hub.example.com",
		EndpointPort: 51820,
		Keepalive:    25,
		AllowedIPs:   []string{"10.9.0.0/24", "192.168.50.0/24"},
	}
}

func writeGateway(t *testing.T, tunnel Tunnel) *fakeShell {
	t.Helper()
	shell := newFakeShell()
	if tunnel.Table != 0 {
		shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	}
	if err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	return shell
}

func assertConfig(t *testing.T, got, want string) {
	t.Helper()
	if strings.TrimRight(got, "\n") != strings.TrimRight(want, "\n") {
		t.Errorf("config does not match.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The peer section type must be exactly "wireguard_<ifname>", because netifd
// looks peers up by that name and finds nothing under any other spelling.
func TestNetworkConfigMatchesTheDocumentedShape(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	assertConfig(t, shell.render("network"), `config interface 'wg0'
	option proto 'wireguard'
	option private_key 'AJXKLmQ2vN8pR4tY6uI0oP1aSdF3gH5jKlZxCvB7nE0='
	option listen_port '51820'
	option mtu '1420'
	list addresses '10.9.0.7/32'

config wireguard_wg0 'wg0_hub'
	option description 'shadow9 hub'
	option public_key 'hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0='
	option preshared_key 'Zm9vYmFyMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A='
	option endpoint_host 'hub.example.com'
	option endpoint_port '51820'
	option persistent_keepalive '25'
	option route_allowed_ips '1'
	list allowed_ips '10.9.0.0/24'
	list allowed_ips '192.168.50.0/24'
`)
}

// Zones and forwardings only. fw4 renders its whole ruleset from UCI and
// flushes the table first, so anything written straight to nftables is gone
// after the next firewall reload.
func TestFirewallConfigIsZonesAndForwardingsOnly(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	assertConfig(t, shell.render("firewall"), `config zone 'wgvpn'
	option name 'wgvpn'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '0'
	option mtu_fix '1'
	list network 'wg0'

config forwarding 'wgvpn_to_lan'
	option src 'wgvpn'
	option dest 'lan'

config forwarding 'lan_to_wgvpn'
	option src 'lan'
	option dest 'wgvpn'

config rule 'wgvpn_in'
	option name 'Allow-wgvpn'
	option src 'wan'
	option proto 'udp'
	option dest_port '51820'
	option target 'ACCEPT'
`)
}

// A policy join leaves a ready-made way to send the LAN through the tunnel,
// because an operator should not have to hand-build the rule. It is written
// disabled: netifd installs nothing until the box is ticked, so a join never
// moves traffic on its own.
func TestAPolicyJoinWritesADisabledSteeringRule(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	tunnel.LanSubnet = "192.168.1.0/24"
	shell := writeGateway(t, tunnel)

	network := shell.render("network")
	for _, want := range []string{
		"config rule 'wg0_rule'",
		"option src '192.168.1.0/24'",
		"option lookup 'pbr_wg0'",
		"option priority '30001'",
		"option disabled '1'",
	} {
		if !strings.Contains(network, want) {
			t.Errorf("the steering rule is missing %q:\n%s", want, network)
		}
	}
	if !strings.Contains(shell.render("shadow9"), "option rule 'wg0_rule'") {
		t.Errorf("the rule was not recorded as owned:\n%s", shell.render("shadow9"))
	}
}

func TestSiteOnlyAndUnknownLanWriteNoRule(t *testing.T) {
	siteOnly := siteGateway()
	siteOnly.LanSubnet = "192.168.1.0/24"
	if got := siteOnly.RuleSection(); got != "" {
		t.Errorf("site-only mode named a rule %q, and it has no policy table to point at", got)
	}

	noLan := siteGateway()
	noLan.Address = "10.9.0.7/24"
	noLan.Table = 1
	if got := noLan.RuleSection(); got != "" {
		t.Errorf("a router with no readable LAN named a rule %q", got)
	}
	shell := writeGateway(t, noLan)
	if strings.Contains(shell.render("network"), "config rule") {
		t.Error("a rule was written with nothing to match")
	}
}

// A node enrolled before the rule existed gets one from a refresh, without
// needing a new token.
func TestRefreshAddsTheRuleToAnAlreadyEnrolledNode(t *testing.T) {
	shell := newFakeShell("shadow9")
	privateKey := siteGateway().PrivateKey
	shell.addSection("network", "lan", "interface", map[string][]string{
		"ipaddr": {"192.168.1.1"}, "netmask": {"255.255.255.0"},
	})
	shell.addSection("network", "wg0", "interface", map[string][]string{
		"addresses": {"10.9.0.7/24"}, "private_key": {privateKey}, "proto": {"wireguard"},
	})
	shell.addSection("network", PeerSectionName("wg0"), PeerSectionType("wg0"), map[string][]string{
		"route_allowed_ips": {"0"}, "allowed_ips": {DefaultIPv4Route + " 10.9.0.0/24"},
	})
	shell.addSection("network", "wg0_route", "route", map[string][]string{
		"interface": {"wg0"}, "target": {"10.9.0.0/24"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"interface": {"wg0"}, "private_key": {privateKey}, "table": {"1"}, "route": {"wg0_route"},
	})
	shell.addSection("pbr", "config", "pbr", map[string][]string{
		"enabled": {"1"}, "supported_interface": {"wg0"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{"pbr_interface": {"wg0"}})

	if err := (Router{Shell: shell}).EnsurePBR("wg0", 1); err != nil {
		t.Fatalf("EnsurePBR: %v", err)
	}
	network := shell.render("network")
	for _, want := range []string{
		"config rule 'wg0_rule'",
		"option src '192.168.1.0/24'",
		"option lookup 'pbr_wg0'",
		"option disabled '1'",
	} {
		if !strings.Contains(network, want) {
			t.Errorf("refresh did not write %q:\n%s", want, network)
		}
	}
	if !strings.Contains(shell.render("shadow9"), "option rule 'wg0_rule'") {
		t.Error("refresh did not record the rule as owned")
	}
}

// Turning the rule on is the operator's decision, so neither a refresh nor a
// later topology change may switch it back off.
func TestAnEnabledRuleStaysEnabled(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	tunnel.LanSubnet = "192.168.1.0/24"
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}

	if err := router.Apply([]Command{set("network.wg0_rule.disabled", "0")}); err != nil {
		t.Fatalf("enabling the rule: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("commit: %v", err)
	}

	tunnel.Revision = 7
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("the second WriteTunnel: %v", err)
	}
	if strings.Contains(shell.render("network"), "option disabled '1'") {
		t.Errorf("a topology change switched the operator's rule back off:\n%s",
			shell.render("network"))
	}
}

// The rule decides where traffic goes, so an operator's own section under that
// name is never replaced.
func TestAnUnownedRuleSectionStopsAJoin(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.addSection("network", "wg0_rule", "rule", map[string][]string{
		"src": {"10.0.0.0/8"}, "lookup": {"main"},
	})
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	tunnel.LanSubnet = "192.168.1.0/24"

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "does not show that shadow9 owns it") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if got := shell.render("network"); !strings.Contains(got, "option lookup 'main'") {
		t.Errorf("the operator's own rule was changed:\n%s", got)
	}
}

// Policy mode masquerades so the hub's tunnel-range masquerade covers
// internet access. Traffic to the tunnel and to the other sites has to stay
// unrewritten, or a remote LAN sees this node's tunnel address instead of the
// host that opened the connection.
func TestPolicyModeMasqueradesTheInternetButNotTheOtherSites(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24", "192.168.50.0/24"}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)

	assertConfig(t, shell.render("firewall"), `config zone 'wgvpn'
	option name 'wgvpn'
	option input 'ACCEPT'
	option output 'ACCEPT'
	option forward 'ACCEPT'
	option masq '1'
	option mtu_fix '1'
	list network 'wg0'
	list masq_dest '!10.9.0.0/24'
	list masq_dest '!192.168.50.0/24'

config forwarding 'wgvpn_to_lan'
	option src 'wgvpn'
	option dest 'lan'

config forwarding 'lan_to_wgvpn'
	option src 'lan'
	option dest 'wgvpn'

config rule 'wgvpn_in'
	option name 'Allow-wgvpn'
	option src 'wan'
	option proto 'udp'
	option dest_port '51820'
	option target 'ACCEPT'
`)
}

// Each forwarding covers one direction. With only lan to wgvpn the remote
// side cannot open a connection into this router's LAN, which is half of what
// a site gateway is for.
func TestBothForwardingDirectionsArePresent(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	firewall := shell.render("firewall")
	for _, want := range []string{
		"config forwarding 'wgvpn_to_lan'",
		"config forwarding 'lan_to_wgvpn'",
	} {
		if !strings.Contains(firewall, want) {
			t.Errorf("the firewall config has no %s", want)
		}
	}
	if strings.Count(firewall, "config forwarding") != 2 {
		t.Errorf("expected exactly two forwardings, got:\n%s", firewall)
	}
}

// route_allowed_ips is what turns allowed_ips into real routes. Without it the
// LAN has no route to the hub or the other sites and the tunnel looks up but
// carries nothing.
func TestSiteGatewayRoutesItsAllowedIPs(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	if !strings.Contains(shell.render("network"), "option route_allowed_ips '1'") {
		t.Error("the peer section does not set route_allowed_ips")
	}
}

func TestPolicyTableKeepsTheDefaultRouteSeparate(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24", "192.168.50.0/24"}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	for _, check := range []struct {
		text string
		want string
	}{
		{shell.render("network"), "config route 'wg0_route'"},
		{shell.render("network"), "option target '10.9.0.0/24'"},
		{shell.render("network"), "config route 'wg0_route_1'"},
		{shell.render("network"), "option target '192.168.50.0/24'"},
		{shell.render("network"), "option route_allowed_ips '0'"},
		{shell.render("network"), "list allowed_ips '0.0.0.0/0'"},
		{shell.render("firewall"), "option masq '1'"},
		{shell.render("shadow9"), "option table '1'"},
		{shell.render("shadow9"), "option pbr_interface 'wg0'"},
		{shell.render("shadow9"), "option pbr_enabled '1'"},
		{shell.render("shadow9"), "list route 'wg0_route_1'"},
		{shell.render("pbr"), "option enabled '1'"},
		{shell.render("pbr"), "list supported_interface 'wg0'"},
	} {
		if !strings.Contains(check.text, check.want) {
			t.Errorf("the policy-ready config has no %s:\n%s", check.want, check.text)
		}
	}
	if strings.Contains(shell.render("network"), "option ip4table") {
		t.Error("the policy-ready config incorrectly selects PBR's netifd-integration mode")
	}
	if got := strings.Join(shell.reloaded, ","); got != "network,firewall,pbr" {
		t.Errorf("reloaded %s, want network,firewall,pbr", got)
	}
}

func TestPolicyJoinKeepsAnExistingPBRRegistrationUserOwned(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"1"}})
	router := Router{Shell: shell}
	if err := router.Apply([]Command{addList(pbrInterfaceOption, tunnel.Interface)}); err != nil {
		t.Fatalf("adding the operator's PBR interface: %v", err)
	}
	if err := router.Commit("pbr"); err != nil {
		t.Fatalf("committing the operator's PBR interface: %v", err)
	}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	if count := strings.Count(shell.render("pbr"), "list supported_interface 'wg0'"); count != 1 {
		t.Errorf("the existing PBR interface appears %d times:\n%s", count, shell.render("pbr"))
	}
	if strings.Contains(shell.render("shadow9"), "option pbr_interface") {
		t.Errorf("Shadow9 claimed an operator-owned PBR entry:\n%s", shell.render("shadow9"))
	}
	if strings.Contains(shell.render("shadow9"), "option pbr_enabled") {
		t.Errorf("Shadow9 claimed an operator-enabled PBR service:\n%s", shell.render("shadow9"))
	}
	removed, err := router.RemoveTunnel()
	if err != nil || !removed {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if !strings.Contains(shell.render("pbr"), "list supported_interface 'wg0'") {
		t.Errorf("uninstall removed the operator-owned PBR entry:\n%s", shell.render("pbr"))
	}
}

func TestPolicyJoinDoesNotActivateParkedUserPolicies(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	tunnel.Table = 1
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.addSection("pbr", "operator", "policy", map[string][]string{
		"name":      {"parked policy"},
		"interface": {"wan"},
	})
	want := shell.render("pbr")

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "enabled user policies") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if got := shell.render("pbr"); got != want {
		t.Errorf("the disabled PBR configuration changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") {
		t.Error("the tunnel was written before the PBR safety check")
	}
}

func TestChangingToSiteOnlyRemovesTheOwnedPBRRegistration(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.addSection("pbr", "sample", "policy", map[string][]string{"enabled": {"0"}})
	shell.addSection("pbr", "sample_dns", "dns_policy", map[string][]string{"enabled": {"false"}})
	router := Router{Shell: shell}
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("policy WriteTunnel: %v", err)
	}
	if err := router.WriteTunnel(siteGateway(), "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("site-only WriteTunnel: %v", err)
	}
	if strings.Contains(shell.render("pbr"), "supported_interface 'wg0'") {
		t.Errorf("the site-only join left its old PBR registration:\n%s", shell.render("pbr"))
	}
	if strings.Contains(shell.render("shadow9"), "option pbr_interface") {
		t.Errorf("the site-only join left its PBR ownership marker:\n%s", shell.render("shadow9"))
	}
	if !strings.Contains(shell.render("pbr"), "option enabled '0'") {
		t.Errorf("the site-only join did not restore PBR's disabled state:\n%s", shell.render("pbr"))
	}
	if len(shell.stopped) != 1 || shell.stopped[0] != "pbr" {
		t.Errorf("site-only stopped %v, want pbr", shell.stopped)
	}
}

func TestRemovingOwnedPBRInterfaceRebuildsAnOptionSafely(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("pbr", "config", "pbr", map[string][]string{
		"enabled":             {"1"},
		"supported_interface": {"wg1 wg0 wg2"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"pbr_interface": {"wg0"},
	})
	router := Router{Shell: shell}
	change, err := router.removePBRInterface("wg0")
	if err != nil {
		t.Fatalf("removePBRInterface: %v", err)
	}
	if err := router.Apply(change.commands); err != nil {
		t.Fatalf("applying PBR removal: %v", err)
	}
	if err := router.Commit("pbr"); err != nil {
		t.Fatalf("committing PBR removal: %v", err)
	}
	pbr := shell.render("pbr")
	if strings.Contains(pbr, "wg0") || !strings.Contains(pbr, "wg1") || !strings.Contains(pbr, "wg2") {
		t.Errorf("PBR interfaces were not rebuilt safely:\n%s", pbr)
	}
	if strings.Count(pbr, "supported_interface") != 2 {
		t.Errorf("PBR interfaces were duplicated while rebuilding the list:\n%s", pbr)
	}
}

func TestPolicyModeRejectsIPv6UntilPBRSupportsIt(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "fd09::7/64"
	tunnel.Network = "fd09::/64"
	tunnel.AllowedIPs = []string{DefaultIPv6Route}
	tunnel.Table = 51820
	err := tunnel.Validate()
	if err == nil || !strings.Contains(err.Error(), "supports IPv4") ||
		!strings.Contains(err.Error(), "-site-only") {
		t.Fatalf("Validate returned %v", err)
	}
}

func TestPolicyTableCoversEveryAllowedAddressFamily(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, DefaultIPv6Route}
	tunnel.Table = 51820
	shell := writeGateway(t, tunnel)
	network := shell.render("network")
	if strings.Contains(network, "ip4table") || strings.Contains(network, "ip6table") {
		t.Errorf("the policy config made PBR skip its own routing setup:\n%s", network)
	}
	if !strings.Contains(network, "config route 'wg0_route'") {
		t.Errorf("the policy config has no tunnel-network route:\n%s", network)
	}
}

func TestRemoveTunnelDeletesOnlyShadow9Sections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table int
	}{
		{"site-only", 0},
		{"policy-routing", 51820},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel := siteGateway()
			tunnel.Table = tc.table
			if tc.table != 0 {
				tunnel.Address = "10.9.0.7/24"
				tunnel.AllowedIPs = []string{
					DefaultIPv4Route, "10.9.0.0/24", "192.168.50.0/24",
				}
			}
			shell := writeGateway(t, tunnel)
			router := Router{Shell: shell}
			if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
				t.Fatalf("WriteIdentity: %v", err)
			}
			shell.addSection("network", "wg1", "interface", map[string][]string{
				"proto":       {"wireguard"},
				"private_key": {"operator-key"},
			})
			shell.addSection("firewall", "vpn", "zone", map[string][]string{
				"name":    {"vpn"},
				"network": {"wg1"},
			})
			if tc.table == 0 {
				shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"1"}})
			}
			if err := router.Apply([]Command{addList(pbrInterfaceOption, "wg1")}); err != nil {
				t.Fatalf("adding the operator's supported interface: %v", err)
			}
			if err := router.Commit("pbr"); err != nil {
				t.Fatalf("committing the operator's supported interface: %v", err)
			}
			shell.addSection("pbr", "operator", "policy", map[string][]string{
				"name":      {"operator policy"},
				"interface": {"wg1"},
			})

			removed, err := router.RemoveTunnel()
			if err != nil {
				t.Fatalf("RemoveTunnel: %v", err)
			}
			if !removed {
				t.Fatal("RemoveTunnel did not report removing the managed tunnel")
			}
			if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
				strings.Contains(shell.render("network"), "config wireguard_wg0 'wg0_hub'") ||
				strings.Contains(shell.render("network"), "wg0_route") {
				t.Errorf("the Shadow9 network sections remain:\n%s", shell.render("network"))
			}
			if strings.Contains(shell.render("firewall"), "config zone 'wgvpn'") {
				t.Errorf("the Shadow9 firewall zone remains:\n%s", shell.render("firewall"))
			}
			if !strings.Contains(shell.render("network"), "config interface 'wg1'") ||
				!strings.Contains(shell.render("firewall"), "config zone 'vpn'") ||
				!strings.Contains(shell.render("pbr"), "operator policy") ||
				!strings.Contains(shell.render("pbr"), "list supported_interface 'wg1'") {
				t.Error("uninstall changed configuration that Shadow9 does not own")
			}
			if strings.Contains(shell.render("pbr"), "list supported_interface 'wg0'") {
				t.Errorf("uninstall left the Shadow9-owned PBR entry:\n%s", shell.render("pbr"))
			}
			if !strings.Contains(shell.render("pbr"), "option enabled '1'") {
				t.Errorf("uninstall disabled PBR despite the operator's remaining policy:\n%s",
					shell.render("pbr"))
			}
			if strings.Contains(shell.render("shadow9"), "config node 'node'") {
				t.Errorf("the enrollment settings remain:\n%s", shell.render("shadow9"))
			}
		})
	}
}

func TestRemoveTunnelCleansALegacyPolicyInstallWithoutRouteMarkers(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{
		remove("network.wg0_route"),
		remove(nodeSection + ".route"),
	}); err != nil {
		t.Fatalf("removing the newer route markers: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("committing the legacy network state: %v", err)
	}
	if err := router.Commit("shadow9"); err != nil {
		t.Fatalf("committing the legacy enrollment state: %v", err)
	}

	removed, err := router.RemoveTunnel()
	if err != nil || !removed {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
		strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("the legacy policy install remained after uninstall")
	}
}

func TestRemoveTunnelRefusesAnInterfaceItCannotProveItOwns(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("network", "wg1", "interface", map[string][]string{
		"proto":       {"wireguard"},
		"private_key": {"operator-key"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"interface":   {"wg1"},
		"zone":        {"wgvpn"},
		"lan_zone":    {"lan"},
		"private_key": {siteGateway().PrivateKey},
	})
	want := shell.render("network")

	removed, err := (Router{Shell: shell}).RemoveTunnel()
	if err == nil || !strings.Contains(err.Error(), "cannot be proven") {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if removed || shell.render("network") != want {
		t.Error("an interface without Shadow9's key was changed")
	}
}

func TestRemoveTunnelDoesNotTouchTheDefaultInterfaceBeforeEnrollment(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("network", "wg0", "interface", map[string][]string{
		"proto":       {"wireguard"},
		"private_key": {"operator-key"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"interface": {"wg0"},
		"zone":      {"wgvpn"},
		"lan_zone":  {"lan"},
	})
	want := shell.render("network")

	removed, err := (Router{Shell: shell}).RemoveTunnel()
	if err != nil {
		t.Fatalf("RemoveTunnel: %v", err)
	}
	if removed || shell.render("network") != want {
		t.Error("the package defaults caused a user-created wg0 to be changed")
	}
	if strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("the unused package defaults remain after uninstall")
	}
}

func TestRemoveTunnelRefusesAZoneThatContainsAUserNetwork(t *testing.T) {
	tunnel := siteGateway()
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{addList("firewall.wgvpn.network", "guest")}); err != nil {
		t.Fatalf("adding the user network: %v", err)
	}
	if err := router.Commit("firewall"); err != nil {
		t.Fatalf("committing the user network: %v", err)
	}
	want := shell.render("firewall")

	removed, err := router.RemoveTunnel()
	if err == nil || !strings.Contains(err.Error(), "cannot be proven") {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if removed || shell.render("firewall") != want {
		t.Error("a firewall zone containing a user network was changed")
	}
}

func TestRemoveTunnelRestoresEverythingWhenACommitFails(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	if err := (Router{Shell: shell}).WriteIdentity("branch-gateway", siteGateway().PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	wantNetwork := shell.render("network")
	wantFirewall := shell.render("firewall")
	wantSettings := shell.render("shadow9")
	shell.failures["uci commit firewall"] = 1

	removed, err := (Router{Shell: shell}).RemoveTunnel()
	if err == nil {
		t.Fatal("RemoveTunnel succeeded despite a failed commit")
	}
	if removed {
		t.Error("RemoveTunnel reported success after restoring the old configuration")
	}
	if shell.render("network") != wantNetwork || shell.render("firewall") != wantFirewall ||
		shell.render("shadow9") != wantSettings {
		t.Error("a failed uninstall did not restore every UCI package")
	}
}

func TestRemoveTunnelCleansOwnedSectionsAfterTheInterfaceDisappears(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{remove("network.wg0")}); err != nil {
		t.Fatalf("removing the interface externally: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("committing the external removal: %v", err)
	}

	removed, err := router.RemoveTunnel()
	if err != nil || !removed {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	for _, remaining := range []string{
		"config wireguard_wg0 'wg0_hub'",
		"config route 'wg0_route'",
		"config zone 'wgvpn'",
		"config node 'node'",
		"list supported_interface 'wg0'",
	} {
		if strings.Contains(shell.render("network")+shell.render("firewall")+
			shell.render("shadow9")+shell.render("pbr"), remaining) {
			t.Errorf("the owned section %q survived uninstall", remaining)
		}
	}
}

func TestUninstallSupportUsesOnlyPackageOwnedFiles(t *testing.T) {
	shell := newFakeShell()
	router := Router{Shell: shell}
	if err := router.DisableRefresh(); err != nil {
		t.Fatalf("DisableRefresh: %v", err)
	}
	if err := router.RemoveEnrollmentFiles(); err != nil {
		t.Fatalf("RemoveEnrollmentFiles: %v", err)
	}
	calls := strings.Join(shell.calls, "\n")
	if !strings.Contains(calls, InitScript+" disable") {
		t.Errorf("the boot service was not disabled:\n%s", calls)
	}
	if !strings.Contains(calls, "rm -f "+TokenPath+" "+DefaultsPath) {
		t.Errorf("the package-owned enrollment files were not removed:\n%s", calls)
	}
}

// A join writes the identity before it contacts the hub, so a power cut
// cannot lose the private half of a key the hub may already know. When the
// hub answers with an error there is no such key, and keeping the half-written
// identity would leave an enrolled node unable to prove it owns its interface.
func TestARefusedEnrollmentRestoresTheSavedIdentity(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", siteGateway().PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	want := shell.render("shadow9")

	settings, err := router.SaveSettings()
	if err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if err := router.WriteIdentity("second-gateway",
		"hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0="); err != nil {
		t.Fatalf("the second WriteIdentity: %v", err)
	}
	if shell.render("shadow9") == want {
		t.Fatal("the second identity was never written, so the rollback proves nothing")
	}

	refused := errors.New("the hub rejected the token")
	if err := router.RestoreSettings(refused, settings); !errors.Is(err, refused) {
		t.Fatalf("RestoreSettings returned %v, want the hub failure", err)
	}
	if got := shell.render("shadow9"); got != want {
		t.Errorf("the refused enrollment left the identity changed.\n--- got ---\n%s\n--- want ---\n%s",
			got, want)
	}
}

// A delete that fails for a reason other than "it was not there" leaves the
// section behind. Committing the rest anyway would drop the marker that proves
// a later attempt is allowed to remove it.
func TestAFailedOwnedDeleteStopsBeforeCommit(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	if err := (Router{Shell: shell}).WriteIdentity("branch-gateway", siteGateway().PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	shell.failing["uci delete firewall.wgvpn"] = "uci: Permission denied"

	removed, err := (Router{Shell: shell}).RemoveTunnel()
	if err == nil || !strings.Contains(err.Error(), "Permission denied") {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if !strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("the ownership marker went away although the cleanup failed")
	}
	if !strings.Contains(shell.render("firewall"), "config zone 'wgvpn'") {
		t.Error("the zone was committed as removed although its delete failed")
	}
}

// A hook that lost its execute bit is still a hook: its /etc/rc.d link is
// what recreates the tunnel, so leaving it enabled undoes the uninstall.
func TestABootHookWithoutItsExecuteBitIsStillDisabled(t *testing.T) {
	shell := newFakeShell()
	shell.absent[InitScript] = true

	if err := (Router{Shell: shell}).DisableRefresh(); err != nil {
		t.Fatalf("DisableRefresh: %v", err)
	}
	calls := strings.Join(shell.calls, "\n")
	if !strings.Contains(calls, "/bin/sh /etc/rc.common "+InitScript+" disable") {
		t.Errorf("a present but unrunnable boot hook was not disabled:\n%s", calls)
	}
}

func TestAnAbsentBootHookIsLeftAlone(t *testing.T) {
	shell := newFakeShell()
	shell.missing[InitScript] = true

	if err := (Router{Shell: shell}).DisableRefresh(); err != nil {
		t.Fatalf("DisableRefresh: %v", err)
	}
	if calls := strings.Join(shell.calls, "\n"); strings.Contains(calls, "disable") {
		t.Errorf("a boot hook that is not installed was disabled anyway:\n%s", calls)
	}
}

// An enrollment that saved its identity but never reached the interface still
// recorded the PBR entry it added, so uninstall has to read that back rather
// than give up because it has no interface name to compare against.
func TestIncompleteEnrollmentCleanupRemovesItsOwnPBREntry(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"name":          {"router"},
		"private_key":   {siteGateway().PrivateKey},
		"pbr_interface": {"wg0"},
	})
	shell.addSection("pbr", "config", "pbr", map[string][]string{
		"enabled":             {"1"},
		"supported_interface": {"wg0", "wg9"},
	})

	removed, err := (Router{Shell: shell}).RemoveTunnel()
	if err != nil {
		t.Fatalf("RemoveTunnel: %v", err)
	}
	if removed {
		t.Error("RemoveTunnel reported a tunnel although none was written")
	}
	pbr := shell.render("pbr")
	if strings.Contains(pbr, "list supported_interface 'wg0'") {
		t.Errorf("the Shadow9-owned PBR entry survived cleanup:\n%s", pbr)
	}
	if !strings.Contains(pbr, "list supported_interface 'wg9'") {
		t.Errorf("cleanup removed an entry it does not own:\n%s", pbr)
	}
}

// PBR builds its table after the reload returns, so a client that checks once
// straight afterwards sees nothing. The fake makes the first queries answer
// "no such table" to prove the client reloads and then keeps polling.
func TestAPolicyJoinWaitsForPBRToBuildItsTable(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.pbrSettleQueries = 2
	router := Router{Shell: shell, PBRSettle: time.Millisecond}

	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel gave up before PBR finished building its table: %v", err)
	}
	if !strings.Contains(strings.Join(shell.reloaded, ","), "pbr") {
		t.Errorf("the pbr service was never reloaded: %v", shell.reloaded)
	}
}

func TestAPolicyJoinFailsWhenPBRIsNeverReloaded(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.absent["/etc/init.d/pbr"] = true
	router := Router{
		Shell:        shell,
		checkTimeout: 10 * time.Millisecond,
		Report:       func(string) {},
	}

	err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "did not create routing table pbr_wg0") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") {
		t.Error("a join whose PBR table never appeared was not rolled back")
	}
}

// A dial-out node has no listen port, and then it needs no inbound rule
// either, because its return traffic is conntracked.
func TestDialOutNodeWritesNoListenPortAndNoInboundRule(t *testing.T) {
	tunnel := siteGateway()
	tunnel.ListenPort = 0
	shell := writeGateway(t, tunnel)
	if strings.Contains(shell.render("network"), "listen_port") {
		t.Error("a node with no listen port still got one written")
	}
	if strings.Contains(shell.render("firewall"), "config rule") {
		t.Error("a node with no listen port still got an inbound rule")
	}
}

func TestPresharedKeyIsOmittedWhenTheHubSendsNone(t *testing.T) {
	tunnel := siteGateway()
	tunnel.PresharedKey = ""
	shell := writeGateway(t, tunnel)
	if strings.Contains(shell.render("network"), "preshared_key") {
		t.Error("an empty preshared key was written anyway")
	}
}

func TestPrivateKeysNeverAppearInArgumentsOrErrors(t *testing.T) {
	tunnel := siteGateway()
	shell := newFakeShell()
	shell.failing["uci batch"] = tunnel.PrivateKey

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel succeeded despite uci batch failing")
	}
	for _, secret := range []string{tunnel.PrivateKey, tunnel.PresharedKey} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error contains key material: %v", err)
		}
		for _, call := range shell.calls {
			if strings.Contains(call, secret) {
				t.Errorf("the command arguments contain key material: %s", call)
			}
		}
	}
	privateSent := false
	for _, stdin := range shell.stdin {
		privateSent = privateSent || strings.Contains(string(stdin), tunnel.PrivateKey)
	}
	if !privateSent {
		t.Error("the private key was not sent to uci over stdin")
	}
}

func TestWriteTunnelLeavesExistingStagedUCIChangesAlone(t *testing.T) {
	shell := newFakeShell()
	router := Router{Shell: shell}
	if err := router.Apply([]Command{set("network.lan", "interface"), set("network.lan.proto", "static")}); err != nil {
		t.Fatalf("staging operator changes: %v", err)
	}

	err := router.WriteTunnel(siteGateway(), "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "uncommitted UCI changes") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if value, getErr := router.Get("network.lan.proto"); getErr != nil || value != "static" {
		t.Fatalf("the staged operator change was lost: value=%q err=%v", value, getErr)
	}
	if strings.Contains(shell.render("network"), "config interface 'lan'") {
		t.Error("the operator's staged change was committed")
	}
}

func TestWriteTunnelCommitsOwnershipBeforeManagedSections(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	calls := strings.Join(shell.calls, "\n")
	settings := strings.Index(calls, "uci commit shadow9")
	network := strings.Index(calls, "uci commit network")
	firewall := strings.Index(calls, "uci commit firewall")
	if settings < 0 || network < 0 || firewall < 0 || settings > network || network > firewall {
		t.Errorf("unexpected commit order:\n%s", calls)
	}
}

// add_list appends, so a second join has to clear first or the peer ends up
// with every allowed_ips entry twice and the interface silently routes more
// than the hub said it should.
func TestJoiningTwiceDoesNotDuplicateAnything(t *testing.T) {
	shell := newFakeShell()
	router := Router{Shell: shell}
	for i := 0; i < 3; i++ {
		if err := router.WriteTunnel(siteGateway(), "http://203.0.113.10:8080"); err != nil {
			t.Fatalf("WriteTunnel run %d: %v", i+1, err)
		}
	}
	network := shell.render("network")
	if count := strings.Count(network, "list allowed_ips '10.9.0.0/24'"); count != 1 {
		t.Errorf("allowed_ips appears %d times after three joins:\n%s", count, network)
	}
	if count := strings.Count(network, "config wireguard_wg0"); count != 1 {
		t.Errorf("the peer section appears %d times after three joins:\n%s", count, network)
	}
	if count := strings.Count(shell.render("firewall"), "config zone"); count != 1 {
		t.Error("the firewall zone was written more than once")
	}
}

func TestPolicyJoinDoesNotDuplicateThePBRRegistration(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	router := Router{Shell: shell}
	for i := 0; i < 3; i++ {
		if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
			t.Fatalf("WriteTunnel run %d: %v", i+1, err)
		}
	}
	if count := strings.Count(shell.render("pbr"), "list supported_interface 'wg0'"); count != 1 {
		t.Errorf("the PBR interface appears %d times after three joins:\n%s", count, shell.render("pbr"))
	}
}

func TestEnsurePBRRepairsOnlyTheLocalRegistration(t *testing.T) {
	shell := newFakeShell("shadow9")
	privateKey := siteGateway().PrivateKey
	shell.addSection("network", "wg0", "interface", map[string][]string{
		"addresses":   {"10.9.0.7/24"},
		"ip4table":    {"51820"},
		"private_key": {privateKey},
		"proto":       {"wireguard"},
	})
	shell.addSection("network", PeerSectionName("wg0"), PeerSectionType("wg0"), map[string][]string{
		"route_allowed_ips": {"1"},
		"allowed_ips":       {DefaultIPv4Route + " 10.9.0.0/24 192.168.50.0/24"},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"interface":   {"wg0"},
		"private_key": {privateKey},
		"table":       {"51820"},
	})
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	if err := (Router{Shell: shell}).EnsurePBR("wg0", 51820); err != nil {
		t.Fatalf("EnsurePBR: %v", err)
	}
	network := shell.render("network")
	for _, unwanted := range []string{"option ip4table", "option route_allowed_ips '1'"} {
		if strings.Contains(network, unwanted) {
			t.Errorf("PBR reconciliation left %s:\n%s", unwanted, network)
		}
	}
	for _, want := range []string{
		"config route 'wg0_route'",
		"option target '10.9.0.0/24'",
		"config route 'wg0_route_1'",
		"option target '192.168.50.0/24'",
		"option route_allowed_ips '0'",
	} {
		if !strings.Contains(network, want) {
			t.Errorf("PBR reconciliation did not write %s:\n%s", want, network)
		}
	}
	for _, want := range []string{
		"option enabled '1'",
		"list supported_interface 'wg0'",
		"option pbr_interface 'wg0'",
		"option pbr_enabled '1'",
		"option table '1'",
		"list route 'wg0_route'",
		"list route 'wg0_route_1'",
	} {
		if !strings.Contains(shell.render("pbr")+shell.render("shadow9"), want) {
			t.Errorf("PBR reconciliation did not write %s", want)
		}
	}
	if got := strings.Join(shell.reloaded, ","); got != "network,pbr" {
		t.Errorf("reloaded %s, want network,pbr", got)
	}
}

func TestPolicyRefreshRemovesRoutesTheHubNoLongerAdvertises(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{
		DefaultIPv4Route, "10.9.0.0/24", "192.168.50.0/24",
	}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}

	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("refreshing the tunnel: %v", err)
	}
	if strings.Contains(shell.render("network"), "wg0_route_1") ||
		strings.Contains(shell.render("shadow9"), "wg0_route_1") {
		t.Error("a route removed by the hub remained in the router configuration")
	}
}

func TestEnsurePBRDoesNotReloadAnAlreadyCurrentConfiguration(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	if err := (Router{Shell: shell}).WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	shell.reloaded = nil

	if err := (Router{Shell: shell}).EnsurePBR("wg0", 1); err != nil {
		t.Fatalf("EnsurePBR: %v", err)
	}
	if len(shell.reloaded) != 0 {
		t.Errorf("an unchanged configuration reloaded %v", shell.reloaded)
	}
}

func TestEnsurePBRDoesNotReloadPBRWhenOnlyANetworkRepairFails(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{remove("network.wg0_route")}); err != nil {
		t.Fatalf("removing the route: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("committing the missing route: %v", err)
	}
	shell.reloaded = nil
	shell.failures["uci commit network"] = 1

	err := router.EnsurePBR("wg0", 1)
	if err == nil {
		t.Fatal("EnsurePBR hid the failed network commit")
	}
	if got := strings.Join(shell.reloaded, ","); got != "network" {
		t.Errorf("the network-only failure reloaded %q, want network", got)
	}
}

func TestEnsurePBRRefusesAnInterfaceWhoseKeyChanged(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{set("network.wg0.private_key", "different")}); err != nil {
		t.Fatalf("replacing the interface key: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("committing the replacement interface: %v", err)
	}
	shell.reloaded = nil

	err := router.EnsurePBR("wg0", 1)
	if err == nil || !strings.Contains(err.Error(), "ownership of network.wg0 cannot be proven") {
		t.Fatalf("EnsurePBR returned %v", err)
	}
	if len(shell.reloaded) != 0 {
		t.Errorf("the foreign interface triggered reloads: %v", shell.reloaded)
	}
}

func TestEnsurePBRRefusesARouteThatWasRepurposed(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{
		DefaultIPv4Route, "10.9.0.0/24", "192.168.50.0/24",
	}
	tunnel.Table = 1
	shell := writeGateway(t, tunnel)
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	if err := router.Apply([]Command{set("network.wg0_route_1.interface", "wg1")}); err != nil {
		t.Fatalf("repurposing the route: %v", err)
	}
	if err := router.Commit("network"); err != nil {
		t.Fatalf("committing the repurposed route: %v", err)
	}
	shell.reloaded = nil

	err := router.EnsurePBR("wg0", 1)
	if err == nil || !strings.Contains(err.Error(), "ownership of network.wg0_route_1 cannot be proven") {
		t.Fatalf("EnsurePBR returned %v", err)
	}
	if len(shell.reloaded) != 0 {
		t.Errorf("the repurposed route triggered reloads: %v", shell.reloaded)
	}
}

func TestAPBRReloadFailureDoesNotRemoveAWorkingTunnel(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.failures["/etc/init.d/pbr reload"] = 1
	var reports []string
	router := Router{Shell: shell, Report: func(message string) { reports = append(reports, message) }}

	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel failed because PBR returned a diagnostic status: %v", err)
	}
	if !strings.Contains(shell.render("network"), "config interface 'wg0'") {
		t.Error("the working tunnel was rolled back after the PBR reload failure")
	}
	if len(reports) != 1 || !strings.Contains(reports[0], "did not reload cleanly") {
		t.Errorf("the PBR reload failure was not reported: %v", reports)
	}
}

func TestMissingPBRTableRollsBackAPolicyJoin(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.failing["ip -4 route show table pbr_wg0"] = "FIB table does not exist"

	err := (Router{Shell: shell, checkTimeout: 10 * time.Millisecond}).WriteTunnel(
		tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "did not create routing table pbr_wg0") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
		strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("a policy join without a PBR table was not rolled back")
	}
	if got := strings.Join(shell.stopped, ","); got != "pbr" {
		t.Errorf("restoring disabled PBR stopped %q, want pbr", got)
	}
}

func TestPBRRetryWaitsForTheTableToSettle(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	tunnel.Table = 1
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.failures["ip -4 route show table pbr_wg0"] = 1

	router := Router{Shell: shell, PBRSettle: time.Millisecond, checkTimeout: 100 * time.Millisecond}
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel did not wait for PBR: %v", err)
	}
	if !strings.Contains(shell.render("network"), "config interface 'wg0'") {
		t.Error("the working tunnel was rolled back during the PBR retry")
	}
}

func TestMissingPBRUplinkNamesTheSettingToFix(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
	tunnel.Table = 1
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.failing["ip -4 route show table pbr_wg0"] = "FIB table does not exist"

	err := (Router{Shell: shell, checkTimeout: time.Millisecond}).WriteTunnel(
		tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), `uplink interface "wan" is not configured`) ||
		!strings.Contains(err.Error(), "pbr.config.uplink_interface") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
}

func TestMissingPBRRuleRollsBackAPolicyJoin(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 1
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{"enabled": {"0"}})
	shell.output["ip -4 rule show"] = ""

	err := (Router{Shell: shell, checkTimeout: 10 * time.Millisecond}).WriteTunnel(
		tunnel, "http://203.0.113.10:8080")
	if err == nil || !strings.Contains(err.Error(), "no fwmark rule") {
		t.Fatalf("WriteTunnel returned %v", err)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
		strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("a policy join without a PBR rule was not rolled back")
	}
}

func TestPolicyJoinRequiresAValidPBRConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
		want string
	}{
		{name: "missing", want: "is missing; reinstall pbr"},
		{name: "wrong section type", kind: "interface", want: "is not a pbr section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel := siteGateway()
			tunnel.Address = "10.9.0.7/24"
			tunnel.AllowedIPs = []string{DefaultIPv4Route, "10.9.0.0/24"}
			tunnel.Table = 1
			shell := newFakeShell()
			if tc.kind != "" {
				shell.addSection("pbr", "config", tc.kind, map[string][]string{})
			}

			err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("WriteTunnel returned %v", err)
			}
			if strings.Contains(shell.render("network"), "config interface 'wg0'") {
				t.Error("the tunnel was written without a valid PBR configuration")
			}
		})
	}
}

func TestAPBRReloadFailureDoesNotUndoUninstall(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := writeGateway(t, tunnel)
	var reports []string
	router := Router{Shell: shell, Report: func(message string) { reports = append(reports, message) }}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	shell.failures["/etc/init.d/pbr stop"] = 1

	removed, err := router.RemoveTunnel()
	if err != nil || !removed {
		t.Fatalf("RemoveTunnel returned removed=%t, err=%v", removed, err)
	}
	if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
		strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("the PBR reload failure restored the removed tunnel")
	}
	if len(reports) != 1 || !strings.Contains(reports[0], "did not stop cleanly") {
		t.Errorf("the PBR stop failure was not reported: %v", reports)
	}
}

func TestWriteTunnelRefusesForeignInterface(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("network", "lan", "interface", map[string][]string{
		"ipaddr": {"192.168.1.1"},
		"proto":  {"static"},
	})
	shell.addSection("network", "operator_peer", PeerSectionType("lan"), map[string][]string{
		"public_key": {"operatoroperatoroperatoroperatoroperatorop="},
	})
	want := shell.render("network")
	tunnel := siteGateway()
	tunnel.Interface = "lan"

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel replaced an existing interface that shadow9 does not own")
	}
	if got := shell.render("network"); got != want {
		t.Errorf("the foreign interface or peer changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWriteTunnelRefusesForeignZone(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("firewall", "lan", "zone", map[string][]string{
		"name":    {"lan"},
		"network": {"lan"},
	})
	want := shell.render("firewall")
	tunnel := siteGateway()
	tunnel.Zone = "lan"

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel replaced an existing zone that shadow9 does not own")
	}
	if got := shell.render("firewall"); got != want {
		t.Errorf("the foreign zone changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestWriteTunnelKeepsOperatorPeer(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("network", DefaultInterface, "interface", map[string][]string{
		"proto": {"wireguard"},
	})
	shell.addSection("firewall", DefaultZone, "zone", map[string][]string{
		"name": {DefaultZone},
	})
	shell.addSection("shadow9", "node", "node", map[string][]string{
		"interface": {DefaultInterface},
		"zone":      {DefaultZone},
	})
	shell.addSection("network", "operator_peer", PeerSectionType(DefaultInterface), map[string][]string{
		"public_key": {"operatoroperatoroperatoroperatoroperatorop="},
	})

	if err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	if !strings.Contains(shell.render("network"), "operatoroperator") {
		t.Errorf("the operator peer was removed:\n%s", shell.render("network"))
	}
}

// An anonymous peer cannot be proven to belong to shadow9, even if an older
// version may have created it. It must be left for the operator to identify.
func TestAnAnonymousPeerFromAnEarlierJoin(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("network", "", PeerSectionType(DefaultInterface), map[string][]string{
		"public_key": {"oldoldoldoldoldoldoldoldoldoldoldoldoldoldo="},
	})
	if err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	if !strings.Contains(shell.render("network"), "oldoldold") {
		t.Errorf("the anonymous peer was removed:\n%s", shell.render("network"))
	}
}

// A LAN zone that is not called "lan" is the case where a wrong guess writes a
// forwarding to a zone that does not exist, and the firewall then quietly
// forwards nothing.
func TestFindZoneForNetworkReadsTheZoneCarryingTheLan(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("firewall", "", "zone", map[string][]string{
		"name": {"wan"}, "network": {"wan", "wan6"},
	})
	shell.addSection("firewall", "", "zone", map[string][]string{
		"name": {"trusted"}, "network": {"lan", "guest"},
	})
	got, err := FindZoneForNetwork(Router{Shell: shell}, "lan")
	if err != nil {
		t.Fatalf("FindZoneForNetwork: %v", err)
	}
	if got != "trusted" {
		t.Errorf("the LAN zone came back as %q, want \"trusted\"", got)
	}
	got, err = FindZoneForNetwork(Router{Shell: shell}, "iot")
	if err != nil {
		t.Fatalf("FindZoneForNetwork: %v", err)
	}
	if got != "" {
		t.Errorf("a network in no zone came back as %q, want an empty string", got)
	}
}

func TestValidateRejectsAResponseThatWouldWriteABrokenTunnel(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Tunnel)
		want   string
	}{
		{"no address", func(t *Tunnel) { t.Address = "" }, "no address"},
		{"no hub key", func(t *Tunnel) { t.HubPublicKey = "" }, "no public key"},
		{"no endpoint", func(t *Tunnel) { t.EndpointHost = "" }, "no endpoint host"},
		{"no allowed ips", func(t *Tunnel) { t.AllowedIPs = nil }, "no allowed IPs"},
		{"no private key", func(t *Tunnel) { t.PrivateKey = "" }, "private key is empty"},
		{"long zone name", func(t *Tunnel) { t.Zone = "averylongzonename" }, "working maximum"},
		{"negative routing table", func(t *Tunnel) { t.Table = -1 }, "cannot be negative"},
		{"reserved routing table", func(t *Tunnel) { t.Table = 254 }, "reserved by Linux"},
		{
			"a private key that would end the batch line",
			func(t *Tunnel) { t.PrivateKey = "x'\nset network.lan.proto='none" },
			"private key is unusable",
		},
		{
			"a preshared key that would end the batch line",
			func(t *Tunnel) { t.PresharedKey = "x'\nset network.lan.proto='none" },
			"preshared key is unusable",
		},
		{
			"a hub key that is the wrong length",
			func(t *Tunnel) { t.HubPublicKey = "c2hvcnQ=" },
			"hub public key is unusable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tunnel := siteGateway()
			tc.change(&tunnel)
			err := tunnel.Validate()
			if err == nil {
				t.Fatal("Validate accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error was %q, which does not say %q", err, tc.want)
			}
		})
	}
}

// Nothing is committed until every uci call has succeeded, so a router whose
// uci fails part of the way through is left exactly as it was rather than half
// configured with the network reloaded on top of it.
func TestAFailedWriteCommitsNothingAndReloadsNothing(t *testing.T) {
	shell := newFakeShell()
	shell.failing["uci set firewall.wgvpn.mtu_fix"] = "uci: I/O error"
	err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel succeeded despite uci failing")
	}
	if !strings.Contains(err.Error(), "mtu_fix") {
		t.Errorf("the error does not say what it was doing: %v", err)
	}
	if got := shell.render("network"); got != "" {
		t.Errorf("network was committed after a failure:\n%s", got)
	}
	if len(shell.reloaded) != 0 {
		t.Errorf("services were reloaded after a failure: %v", shell.reloaded)
	}
}

func TestAStagingFailureIncludesRevertFailure(t *testing.T) {
	shell := newFakeShell()
	shell.failing["uci set firewall.wgvpn.mtu_fix"] = "uci: I/O error"
	shell.failing["uci revert network"] = "uci: revert failed"

	err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel succeeded despite uci and its recovery both failing")
	}
	if !strings.Contains(err.Error(), "revert failed") {
		t.Errorf("the recovery failure is missing from the error: %v", err)
	}
}

func TestASecondPackageCommitFailureRestoresEveryPackage(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("network", "oldnet", "interface", map[string][]string{"proto": {"static"}})
	shell.addSection("firewall", "oldzone", "zone", map[string][]string{"name": {"oldzone"}})
	shell.addSection("shadow9", "node", "node", map[string][]string{"enabled": {"0"}})
	wantNetwork := shell.render("network")
	wantFirewall := shell.render("firewall")
	wantSettings := shell.render("shadow9")
	shell.failures["uci commit firewall"] = 1

	err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel succeeded despite the firewall commit failing")
	}
	if got := shell.render("network"); got != wantNetwork {
		t.Errorf("network was not restored.\n--- got ---\n%s\n--- want ---\n%s", got, wantNetwork)
	}
	if got := shell.render("firewall"); got != wantFirewall {
		t.Errorf("firewall was not restored.\n--- got ---\n%s\n--- want ---\n%s", got, wantFirewall)
	}
	if got := shell.render("shadow9"); got != wantSettings {
		t.Errorf("shadow9 was not restored.\n--- got ---\n%s\n--- want ---\n%s", got, wantSettings)
	}
}

func TestAPBRCommitFailureRestoresEveryPackage(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "10.9.0.7/24"
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := newFakeShell()
	shell.addSection("pbr", "config", "pbr", map[string][]string{
		"enabled":             {"0"},
		"supported_interface": {"wg1", "wg2"},
	})
	wantPBR := shell.render("pbr")
	shell.failures["uci commit pbr"] = 1

	err := (Router{Shell: shell}).WriteTunnel(tunnel, "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel succeeded despite the PBR commit failing")
	}
	if got := shell.render("network"); got != "" {
		t.Errorf("network was not restored:\n%s", got)
	}
	if got := shell.render("firewall"); got != "" {
		t.Errorf("firewall was not restored:\n%s", got)
	}
	if got := shell.render("shadow9"); got != "" {
		t.Errorf("shadow9 was not restored:\n%s", got)
	}
	if got := shell.render("pbr"); got != wantPBR {
		t.Errorf("PBR was not restored.\n--- got ---\n%s\n--- want ---\n%s", got, wantPBR)
	}
	calls := strings.Join(shell.calls, "\n")
	if revert, imported := strings.Index(calls, "uci revert pbr"), strings.Index(calls, "uci import pbr"); revert < 0 || imported < 0 || revert > imported {
		t.Errorf("PBR was imported before its staged delta was cleared:\n%s", calls)
	}
}

func TestATunnelThatDoesNotComeUpIsReverted(t *testing.T) {
	shell := newFakeShell("shadow9")
	shell.addSection("network", "oldnet", "interface", map[string][]string{"proto": {"static"}})
	shell.addSection("firewall", "oldzone", "zone", map[string][]string{"name": {"oldzone"}})
	shell.addSection("shadow9", "node", "node", map[string][]string{"enabled": {"0"}})
	wantNetwork := shell.render("network")
	wantFirewall := shell.render("firewall")
	wantSettings := shell.render("shadow9")
	shell.failing["ifstatus wg0"] = "interface is down"

	router := Router{Shell: shell, checkTimeout: time.Millisecond}
	err := router.WriteTunnel(siteGateway(), "http://203.0.113.10:8080")
	if err == nil {
		t.Fatal("WriteTunnel kept a tunnel that never came up")
	}
	if !strings.Contains(err.Error(), "did not come up") {
		t.Errorf("the error does not say the tunnel stayed down: %v", err)
	}
	if got := shell.render("network"); got != wantNetwork {
		t.Errorf("network was not reverted.\n--- got ---\n%s\n--- want ---\n%s", got, wantNetwork)
	}
	if got := shell.render("firewall"); got != wantFirewall {
		t.Errorf("firewall was not reverted.\n--- got ---\n%s\n--- want ---\n%s", got, wantFirewall)
	}
	if got := shell.render("shadow9"); got != wantSettings {
		t.Errorf("shadow9 was not reverted.\n--- got ---\n%s\n--- want ---\n%s", got, wantSettings)
	}
}

func TestASuccessfulWriteReloadsNetworkAndFirewall(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	if len(shell.reloaded) != 2 || shell.reloaded[0] != "network" || shell.reloaded[1] != "firewall" {
		t.Errorf("reloaded %v, want network then firewall", shell.reloaded)
	}
	for _, call := range shell.calls {
		if strings.HasPrefix(call, "/etc/init.d/") && strings.Contains(call, "restart") {
			t.Errorf("a service was restarted rather than reloaded: %s", call)
		}
	}
}

func TestEveryRouterCommandHasADeadline(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	(Router{Shell: shell}).ProtocolPackageNotice(DefaultInterface)

	if len(shell.deadlines) != len(shell.calls) {
		t.Fatalf("recorded %d deadlines for %d commands", len(shell.deadlines), len(shell.calls))
	}
	for i, timeout := range shell.deadlines {
		if timeout <= 0 {
			t.Errorf("command %q has no deadline", shell.calls[i])
		}
		if timeout > 2*time.Minute {
			t.Errorf("command %q has an excessive deadline of %s", shell.calls[i], timeout)
		}
	}
}

// The hub URL has to be recorded, or the init script and the uci-defaults
// script have nothing to re-enroll against after a reboot or a flash.
func TestTheHubIsRecordedForTheInitScript(t *testing.T) {
	shell := writeGateway(t, siteGateway())
	assertConfig(t, shell.render("shadow9"), `config node 'node'
	option hub 'http://203.0.113.10:8080'
	option interface 'wg0'
	option zone 'wgvpn'
	option lan_zone 'lan'
	option revision '0'
	option enabled '1'
`)
}

func TestIdentityIsCommittedBeforeEnrollmentCanStart(t *testing.T) {
	tunnel := siteGateway()
	shell := newFakeShell()
	if err := (Router{Shell: shell}).WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	assertConfig(t, shell.render("shadow9"), `config node 'node'
	option name 'branch-gateway'
	option private_key 'AJXKLmQ2vN8pR4tY6uI0oP1aSdF3gH5jKlZxCvB7nE0='
`)
}

func TestUninstallRemovesAnIncompleteEnrollmentIdentity(t *testing.T) {
	tunnel := siteGateway()
	shell := newFakeShell()
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}

	removed, err := router.RemoveTunnel()
	if err != nil {
		t.Fatalf("RemoveTunnel: %v", err)
	}
	if removed {
		t.Error("RemoveTunnel reported a tunnel for an incomplete enrollment")
	}
	if strings.Contains(shell.render("shadow9"), "config node 'node'") {
		t.Error("the incomplete Shadow9 identity survived uninstall")
	}
}

func TestIdentityDoesNotCommitPendingShadow9Changes(t *testing.T) {
	tunnel := siteGateway()
	shell := newFakeShell("shadow9")
	router := Router{Shell: shell}
	if err := router.Apply([]Command{set("shadow9.operator", "note"), set("shadow9.operator.value", "pending")}); err != nil {
		t.Fatalf("staging operator changes: %v", err)
	}

	err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey)
	if err == nil || !strings.Contains(err.Error(), "uncommitted UCI changes") {
		t.Fatalf("WriteIdentity returned %v", err)
	}
	if value, getErr := router.Get("shadow9.operator.value"); getErr != nil || value != "pending" {
		t.Fatalf("the staged operator change was lost: value=%q err=%v", value, getErr)
	}
	if strings.Contains(shell.render("shadow9"), "config note 'operator'") {
		t.Error("the operator's staged Shadow9 change was committed")
	}
}

func TestRefreshKeyIsCommittedOnlyToTheShadow9Package(t *testing.T) {
	shell := newFakeShell("shadow9")
	key := "b92a5ead82224c3e5f1ad5905d4027d441348999e6e5999923438f5ce8237ff0"
	if err := (Router{Shell: shell}).WriteRefreshKey(key); err != nil {
		t.Fatalf("WriteRefreshKey: %v", err)
	}
	if !strings.Contains(shell.render("shadow9"), "option refresh_key '"+key+"'") {
		t.Errorf("the refresh key was not saved:\n%s", shell.render("shadow9"))
	}
	for _, call := range shell.calls {
		if strings.Contains(call, key) {
			t.Errorf("the refresh key appeared in command arguments: %s", call)
		}
	}
}

func TestRefreshKeyDoesNotCommitPendingShadow9Changes(t *testing.T) {
	shell := newFakeShell("shadow9")
	router := Router{Shell: shell}
	if err := router.Apply([]Command{set("shadow9.operator", "note"), set("shadow9.operator.value", "pending")}); err != nil {
		t.Fatalf("staging operator changes: %v", err)
	}

	err := router.WriteRefreshKey("b92a5ead82224c3e5f1ad5905d4027d441348999e6e5999923438f5ce8237ff0")
	if err == nil || !strings.Contains(err.Error(), "uncommitted UCI changes") {
		t.Fatalf("WriteRefreshKey returned %v", err)
	}
	if value, getErr := router.Get("shadow9.operator.value"); getErr != nil || value != "pending" {
		t.Fatalf("the staged operator change was lost: value=%q err=%v", value, getErr)
	}
}

func TestWritingARefreshedTunnelKeepsTheSavedIdentity(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Revision = 9
	shell := newFakeShell("shadow9")
	router := Router{Shell: shell}
	if err := router.WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
		t.Fatalf("WriteIdentity: %v", err)
	}
	key := "b92a5ead82224c3e5f1ad5905d4027d441348999e6e5999923438f5ce8237ff0"
	if err := router.WriteRefreshKey(key); err != nil {
		t.Fatalf("WriteRefreshKey: %v", err)
	}
	if err := router.WriteTunnel(tunnel, "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	settings := shell.render("shadow9")
	for _, want := range []string{
		"option name 'branch-gateway'",
		"option private_key '" + tunnel.PrivateKey + "'",
		"option refresh_key '" + key + "'",
		"option revision '9'",
	} {
		if !strings.Contains(settings, want) {
			t.Errorf("the settings lost %s:\n%s", want, settings)
		}
	}
}

func TestTakesOverTheDefaultRouteSpotsAFullTunnel(t *testing.T) {
	tunnel := siteGateway()
	if tunnel.TakesOverTheDefaultRoute() {
		t.Error("a split tunnel was reported as taking over the default route")
	}
	tunnel.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	if !tunnel.TakesOverTheDefaultRoute() {
		t.Error("a default route in allowed_ips was not spotted")
	}
	tunnel.Table = 51820
	if tunnel.TakesOverTheDefaultRoute() {
		t.Error("a default route in a separate table was reported as taking over main")
	}
}
