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

// A peer left by an older version of this client is anonymous, so it cannot be
// deleted by name. It still has to go, or the interface keeps talking to a hub
// the operator has moved away from.
func TestAnAnonymousPeerFromAnEarlierJoinIsRemoved(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("network", "", PeerSectionType(DefaultInterface), map[string][]string{
		"public_key": {"oldoldoldoldoldoldoldoldoldoldoldoldoldoldo="},
	})
	if err := (Router{Shell: shell}).WriteTunnel(siteGateway(), "http://203.0.113.10:8080"); err != nil {
		t.Fatalf("WriteTunnel: %v", err)
	}
	if strings.Contains(shell.render("network"), "oldoldold") {
		t.Errorf("the peer from an earlier join is still there:\n%s", shell.render("network"))
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
	if got := FindZoneForNetwork(Router{Shell: shell}, "lan"); got != "trusted" {
		t.Errorf("the LAN zone came back as %q, want \"trusted\"", got)
	}
	if got := FindZoneForNetwork(Router{Shell: shell}, "iot"); got != "" {
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
}
