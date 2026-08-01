package openwrt

import (
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
	tunnel.AllowedIPs = []string{DefaultIPv4Route}
	tunnel.Table = 51820
	shell := writeGateway(t, tunnel)
	for _, check := range []struct {
		text string
		want string
	}{
		{shell.render("network"), "option ip4table '51820'"},
		{shell.render("network"), "list allowed_ips '0.0.0.0/0'"},
		{shell.render("firewall"), "option masq '1'"},
		{shell.render("shadow9"), "option table '51820'"},
	} {
		if !strings.Contains(check.text, check.want) {
			t.Errorf("the policy-ready config has no %s:\n%s", check.want, check.text)
		}
	}
}

func TestPolicyTableFollowsTheTunnelAddressFamily(t *testing.T) {
	tunnel := siteGateway()
	tunnel.Address = "fd09::7/64"
	tunnel.AllowedIPs = []string{DefaultIPv6Route}
	tunnel.Table = 51820
	shell := writeGateway(t, tunnel)
	for _, check := range []struct {
		text string
		want string
	}{
		{shell.render("network"), "option ip6table '51820'"},
		{shell.render("network"), "list allowed_ips '::/0'"},
		{shell.render("firewall"), "option masq6 '1'"},
	} {
		if !strings.Contains(check.text, check.want) {
			t.Errorf("the IPv6 policy config has no %s:\n%s", check.want, check.text)
		}
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
				tunnel.AllowedIPs = []string{DefaultIPv4Route}
			}
			shell := writeGateway(t, tunnel)
			if err := (Router{Shell: shell}).WriteIdentity("branch-gateway", tunnel.PrivateKey); err != nil {
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
			shell.addSection("pbr", "operator", "policy", map[string][]string{
				"name":      {"operator policy"},
				"interface": {"wg1"},
			})

			removed, err := (Router{Shell: shell}).RemoveTunnel()
			if err != nil {
				t.Fatalf("RemoveTunnel: %v", err)
			}
			if !removed {
				t.Fatal("RemoveTunnel did not report removing the managed tunnel")
			}
			if strings.Contains(shell.render("network"), "config interface 'wg0'") ||
				strings.Contains(shell.render("network"), "config wireguard_wg0 'wg0_hub'") {
				t.Errorf("the Shadow9 network sections remain:\n%s", shell.render("network"))
			}
			if strings.Contains(shell.render("firewall"), "config zone 'wgvpn'") {
				t.Errorf("the Shadow9 firewall zone remains:\n%s", shell.render("firewall"))
			}
			if !strings.Contains(shell.render("network"), "config interface 'wg1'") ||
				!strings.Contains(shell.render("firewall"), "config zone 'vpn'") ||
				!strings.Contains(shell.render("pbr"), "operator policy") {
				t.Error("uninstall changed configuration that Shadow9 does not own")
			}
			if strings.Contains(shell.render("shadow9"), "config node 'node'") {
				t.Errorf("the enrollment settings remain:\n%s", shell.render("shadow9"))
			}
		})
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
