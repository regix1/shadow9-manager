package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shadow9-node/internal/enroll"
	"shadow9-node/internal/openwrt"
	"shadow9-node/internal/wgkey"
)

// answering is a Shell that returns canned uci values, which is enough for the
// parts of the command that only read configuration.
type answering map[string]string

func (a answering) Run(_ context.Context, _ openwrt.Stdin, name string, args ...string) ([]byte, error) {
	if name == "uci" && len(args) == 2 && args[0] == "get" {
		if value, known := a[args[1]]; known {
			return []byte(value + "\n"), nil
		}
		return nil, fmt.Errorf("uci: Entry not found")
	}
	return nil, fmt.Errorf("%s: not found", name)
}

func (a answering) Look(string) error { return nil }

func routerAnswering(values map[string]string) openwrt.Router {
	return openwrt.Router{Shell: answering(values)}
}

func TestBuildTunnelTurnsTheHubsAnswerIntoUciValues(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol := 1412, 20, enroll.Protocol
	answer := enroll.Response{
		Address:       "10.9.0.7",
		HubPublicKey:  "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint:   "203.0.113.10:51820",
		TunnelNetwork: "10.9.0.0/24",
		MTU:           &mtu,
		Keepalive:     &keepalive,
		Protocol:      &protocol,
	}
	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, -1, -1, defaultTable)
	if err != nil {
		t.Fatalf("buildTunnel: %v", err)
	}
	if tunnel.Address != "10.9.0.7/24" {
		t.Errorf("the address came out as %q, want the tunnel prefix", tunnel.Address)
	}
	if tunnel.EndpointHost != "203.0.113.10" || tunnel.EndpointPort != 51820 {
		t.Errorf("the endpoint came out as %s:%d", tunnel.EndpointHost, tunnel.EndpointPort)
	}
	if got := strings.Join(tunnel.AllowedIPs, ","); got != openwrt.DefaultIPv4Route+","+answer.TunnelNetwork {
		t.Errorf("the allowed IPs came out as %v", tunnel.AllowedIPs)
	}
	if tunnel.Table != defaultTable {
		t.Errorf("the routing table is %d, want %d", tunnel.Table, defaultTable)
	}
	if tunnel.PrivateKey != private.String() {
		t.Error("the private key did not reach the tunnel")
	}
	if tunnel.MTU != mtu || tunnel.Keepalive != keepalive {
		t.Errorf("the hub settings became MTU %d and keepalive %d", tunnel.MTU, tunnel.Keepalive)
	}
	if err := tunnel.Validate(); err != nil {
		t.Errorf("the tunnel built from a good answer does not validate: %v", err)
	}
}

func TestBuildTunnelKeepsSiteOnlyRoutesWhenRequested(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol := 1412, 20, enroll.Protocol
	answer := enroll.Response{
		Address:       "10.9.0.7",
		HubPublicKey:  "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint:   "203.0.113.10:51820",
		TunnelNetwork: "10.9.0.0/24",
		MTU:           &mtu,
		Keepalive:     &keepalive,
		Protocol:      &protocol,
	}

	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, -1, -1, 0)
	if err != nil {
		t.Fatalf("buildTunnel: %v", err)
	}
	if tunnel.Address != "10.9.0.7/32" {
		t.Errorf("the address came out as %q, want a host route", tunnel.Address)
	}
	if len(tunnel.AllowedIPs) != 1 || tunnel.AllowedIPs[0] != answer.TunnelNetwork {
		t.Errorf("site-only AllowedIPs came out as %v", tunnel.AllowedIPs)
	}
	if tunnel.Table != 0 {
		t.Errorf("site-only routing table came out as %d", tunnel.Table)
	}
}

func TestBuildTunnelUsesTheIPv6PolicyRouteForAnIPv6Hub(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol := 1412, 20, enroll.Protocol
	answer := enroll.Response{
		Address:       "fd09::7",
		HubPublicKey:  "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint:   "[2001:db8::10]:51820",
		TunnelNetwork: "fd09::/64",
		MTU:           &mtu,
		Keepalive:     &keepalive,
		Protocol:      &protocol,
	}

	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, -1, -1, defaultTable)
	if err != nil {
		t.Fatalf("buildTunnel: %v", err)
	}
	if tunnel.Address != "fd09::7/64" || strings.Join(tunnel.AllowedIPs, ",") !=
		openwrt.DefaultIPv6Route+","+answer.TunnelNetwork {
		t.Errorf("the IPv6 policy route came out as address %s, AllowedIPs %v",
			tunnel.Address, tunnel.AllowedIPs)
	}
	if err := tunnel.Validate(); err == nil || !strings.Contains(err.Error(), "supports IPv4") {
		t.Errorf("the IPv6 policy route validated with %v", err)
	}
}

func TestBuildTunnelLetsFlagsOverrideTheHubSettings(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol := 1412, 20, enroll.Protocol
	answer := enroll.Response{
		Address:       "10.9.0.7",
		HubPublicKey:  "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint:   "203.0.113.10:51820",
		TunnelNetwork: "10.9.0.0/24",
		MTU:           &mtu,
		Keepalive:     &keepalive,
		Protocol:      &protocol,
	}

	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, 1280, 0, defaultTable)
	if err != nil {
		t.Fatalf("buildTunnel: %v", err)
	}
	if tunnel.MTU != 1280 || tunnel.Keepalive != 0 {
		t.Errorf("the flags produced MTU %d and keepalive %d", tunnel.MTU, tunnel.Keepalive)
	}
}

func TestBuildRefreshTunnelUsesTheCompleteAllowedIPs(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol, revision := 1412, 20, enroll.Protocol, 8
	answer := enroll.RefreshResponse{
		Address: "10.9.0.7", HubPublicKey: "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint: "203.0.113.10:51820", TunnelNetwork: "10.9.0.0/24",
		AllowedIPs: []string{"10.9.0.0/24", "192.168.2.0/24"},
		MTU:        &mtu, Keepalive: &keepalive, Protocol: &protocol, Revision: &revision,
	}
	tunnel, err := buildRefreshTunnel(answer, private, "wg0", "wgvpn", 0, nil, nil, 0)
	if err != nil {
		t.Fatalf("buildRefreshTunnel: %v", err)
	}
	if got := strings.Join(tunnel.AllowedIPs, ","); got != "10.9.0.0/24,192.168.2.0/24" {
		t.Errorf("the allowed IPs are %s", got)
	}
	if tunnel.Revision != revision {
		t.Errorf("revision is %d, want %d", tunnel.Revision, revision)
	}
}

func TestBuildRefreshTunnelKeepsThePolicyTable(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol, revision := 1412, 20, enroll.Protocol, 8
	answer := enroll.RefreshResponse{
		Address: "10.9.0.7", HubPublicKey: "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint: "203.0.113.10:51820", TunnelNetwork: "10.9.0.0/24",
		AllowedIPs: []string{"10.9.0.0/24", "192.168.2.0/24"},
		MTU:        &mtu, Keepalive: &keepalive, Protocol: &protocol, Revision: &revision,
	}
	tunnel, err := buildRefreshTunnel(
		answer, private, "wg0", "wgvpn", 0, nil, nil, defaultTable)
	if err != nil {
		t.Fatalf("buildRefreshTunnel: %v", err)
	}
	if got := strings.Join(tunnel.AllowedIPs, ","); got != openwrt.DefaultIPv4Route+",10.9.0.0/24,192.168.2.0/24" {
		t.Errorf("the allowed IPs are %s", got)
	}
	if tunnel.Address != "10.9.0.7/24" || tunnel.Table != defaultTable {
		t.Errorf("refresh produced address %s in table %d", tunnel.Address, tunnel.Table)
	}
}

func TestBuildRefreshTunnelKeepsLocalOverrides(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive, protocol, revision := 1412, 20, enroll.Protocol, 8
	mtuOverride, keepaliveOverride := 1280, 0
	answer := enroll.RefreshResponse{
		Address: "10.9.0.7", HubPublicKey: "hR3n0oPxK9zLm2vQwE4tYuIoP1aSdF6gH8jKlZxCvB0=",
		HubEndpoint: "203.0.113.10:51820", AllowedIPs: []string{"10.9.0.0/24"},
		MTU: &mtu, Keepalive: &keepalive, Protocol: &protocol, Revision: &revision,
	}
	tunnel, err := buildRefreshTunnel(
		answer, private, "wg0", "wgvpn", 0, &mtuOverride, &keepaliveOverride, 0)
	if err != nil {
		t.Fatalf("buildRefreshTunnel: %v", err)
	}
	if tunnel.MTU != mtuOverride || tunnel.Keepalive != keepaliveOverride {
		t.Errorf("refresh changed the local overrides: MTU %d, keepalive %d",
			tunnel.MTU, tunnel.Keepalive)
	}
}

func TestBuildTunnelRefusesAnAnswerItCannotUse(t *testing.T) {
	private, _, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	mtu, keepalive := 1412, 20
	for _, tc := range []struct {
		name   string
		answer enroll.Response
		says   string
	}{
		{"address is not an address", enroll.Response{
			Address: "not-an-address", HubEndpoint: "203.0.113.10:51820",
			MTU: &mtu, Keepalive: &keepalive}, "address"},
		{"endpoint has no port", enroll.Response{
			Address: "10.9.0.7", HubEndpoint: "203.0.113.10",
			MTU: &mtu, Keepalive: &keepalive}, "endpoint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildTunnel(tc.answer, private, "wg0", "wgvpn", 0, -1, -1, 0)
			if err == nil {
				t.Fatal("buildTunnel accepted it")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the error does not say %q: %v", tc.says, err)
			}
		})
	}
}

func TestReadTokenPrefersTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  from-the-file.key  \n"), 0o600); err != nil {
		t.Fatalf("writing the token file: %v", err)
	}
	got, err := readToken("from-the-flag.key", path)
	if err != nil {
		t.Fatalf("readToken: %v", err)
	}
	if got != "from-the-file.key" {
		t.Errorf("readToken returned %q", got)
	}
}

func TestReadTokenSaysHowToGiveOne(t *testing.T) {
	if _, err := readToken("", ""); err == nil {
		t.Fatal("readToken accepted no token at all")
	} else if !strings.Contains(err.Error(), "-token-file") {
		t.Errorf("the error does not say what to pass: %v", err)
	}
	if _, err := readToken("", filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("readToken accepted a token file that is not there")
	}
}

func TestChooseRoutesDefaultsToTheLanSubnet(t *testing.T) {
	router := routerAnswering(map[string]string{
		"network.lan.ipaddr":  "192.168.1.1",
		"network.lan.netmask": "255.255.255.0",
	})
	routes, err := chooseRoutes("", false, router)
	if err != nil {
		t.Fatalf("chooseRoutes: %v", err)
	}
	if len(routes) != 1 || routes[0] != "192.168.1.0/24" {
		t.Errorf("the routes came out as %v", routes)
	}
}

func TestChooseRoutesHonoursWhatWasAsked(t *testing.T) {
	empty := routerAnswering(nil)
	routes, err := chooseRoutes(" 10.1.0.0/16 , 10.2.0.0/16 ", false, empty)
	if err != nil {
		t.Fatalf("chooseRoutes: %v", err)
	}
	if len(routes) != 2 || routes[0] != "10.1.0.0/16" || routes[1] != "10.2.0.0/16" {
		t.Errorf("the routes came out as %v", routes)
	}

	// A node that is not a site gateway announces nothing, and the hub's model
	// wants an empty list rather than a null.
	none, err := chooseRoutes("", true, empty)
	if err != nil {
		t.Fatalf("chooseRoutes with -no-routes: %v", err)
	}
	if none == nil || len(none) != 0 {
		t.Errorf("-no-routes gave %v, want an empty list", none)
	}
}

// A LAN on DHCP has no address to read, and advertising a guess would announce
// a subnet this router does not have.
func TestChooseRoutesSaysWhatToPassWhenThereIsNoLan(t *testing.T) {
	_, err := chooseRoutes("", false, routerAnswering(nil))
	if err == nil {
		t.Fatal("chooseRoutes invented a subnet")
	}
	for _, want := range []string{"-advertise", "-no-routes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}

func TestChooseNameFallsBackToTheHostname(t *testing.T) {
	router := routerAnswering(map[string]string{
		"system.@system[0].hostname": "branch.example.com",
	})
	got, err := chooseName("", router)
	if err != nil {
		t.Fatalf("chooseName: %v", err)
	}
	if got != "branch-example-com" {
		t.Errorf("the name came out as %q", got)
	}
	if got, err := chooseName("given-name", router); err != nil || got != "given-name" {
		t.Errorf("chooseName ignored what was passed: %q %v", got, err)
	}
	if _, err := chooseName("", routerAnswering(nil)); err == nil {
		t.Error("chooseName invented a name for a router with no hostname")
	}
}

func TestChooseKeyGeneratesOrKeepsOne(t *testing.T) {
	private, public, err := chooseKey(false, "wg0", "branch-gateway", routerAnswering(nil))
	if err != nil {
		t.Fatalf("chooseKey: %v", err)
	}
	derived, err := wgkey.PublicFor(private)
	if err != nil || derived != public {
		t.Fatal("chooseKey returned a pair that does not match")
	}

	router := routerAnswering(map[string]string{"network.wg0.private_key": private.String()})
	kept, keptPublic, err := chooseKey(true, "wg0", "branch-gateway", router)
	if err != nil {
		t.Fatalf("chooseKey with -keep-key: %v", err)
	}
	if kept != private || keptPublic != public {
		t.Error("-keep-key did not return the key already in UCI")
	}
}

func TestChooseKeyRefusesToInventOneWhenAskedToKeep(t *testing.T) {
	if _, _, err := chooseKey(true, "wg0", "branch-gateway", routerAnswering(nil)); err == nil {
		t.Error("-keep-key generated a new key when there was none to keep")
	}
	router := routerAnswering(map[string]string{"network.wg0.private_key": "not-a-key"})
	_, _, err := chooseKey(true, "wg0", "branch-gateway", router)
	if err == nil {
		t.Fatal("-keep-key accepted a private key that is not a key")
	}
	if strings.Contains(err.Error(), "not-a-key") {
		t.Errorf("the error repeats the stored key: %v", err)
	}
}

func TestChooseKeyReusesTheSavedIdentityForTheSameName(t *testing.T) {
	private, public, err := wgkey.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	router := routerAnswering(map[string]string{
		"shadow9.node.name":        "branch-gateway",
		"shadow9.node.private_key": private.String(),
	})

	gotPrivate, gotPublic, err := chooseKey(false, "wg0", "branch-gateway", router)
	if err != nil {
		t.Fatalf("chooseKey: %v", err)
	}
	if gotPrivate != private || gotPublic != public {
		t.Error("chooseKey did not return the saved pair")
	}
}

func TestChooseLanZoneFindsTheZoneCarryingTheLan(t *testing.T) {
	router := routerAnswering(map[string]string{
		"firewall.@zone[0].name":    "wan",
		"firewall.@zone[0].network": "wan wan6",
		"firewall.@zone[1].name":    "trusted",
		"firewall.@zone[1].network": "lan guest",
	})
	got, err := chooseLanZone("", router)
	if err != nil {
		t.Fatalf("chooseLanZone: %v", err)
	}
	if got != "trusted" {
		t.Errorf("the LAN zone came out as %q", got)
	}
	got, err = chooseLanZone("given", router)
	if err != nil {
		t.Fatalf("chooseLanZone: %v", err)
	}
	if got != "given" {
		t.Errorf("chooseLanZone ignored what was passed: %q", got)
	}
	got, err = chooseLanZone("", routerAnswering(nil))
	if err != nil {
		t.Fatalf("chooseLanZone: %v", err)
	}
	if got != openwrt.DefaultLanZone {
		t.Errorf("with nothing to read the LAN zone came out as %q", got)
	}
}

func TestANodeListensOnNoPortByDefault(t *testing.T) {
	flags, options := joinFlags()
	listen := flags.Lookup("listen-port")
	if listen == nil || listen.DefValue != "0" {
		t.Errorf("the node's listen-port default is not zero")
	}
	for _, restored := range []string{"mtu", "keepalive"} {
		option := flags.Lookup(restored)
		if option == nil || option.DefValue != "-1" {
			t.Errorf("-%s does not default to the hub's enrollment response", restored)
		}
	}
	if options.table != 0 || options.siteOnly {
		t.Errorf("join defaults to table %d with site-only %t", options.table, options.siteOnly)
	}
	if err := flags.Parse([]string{"--site-only"}); err != nil {
		t.Fatalf("the compatibility option did not parse: %v", err)
	}
	if !options.siteOnly {
		t.Error("--site-only did not select the compatibility mode")
	}
}

func TestChooseTableUsesPBRManagedMode(t *testing.T) {
	table, err := chooseTable(0, false)
	if err != nil {
		t.Fatalf("chooseTable: %v", err)
	}
	if table != defaultTable {
		t.Errorf("chooseTable returned %d, want PBR mode", table)
	}
}

func TestChooseTableRejectsLegacyPinningAndHonorsSiteOnly(t *testing.T) {
	if _, err := chooseTable(60000, false); err == nil {
		t.Fatal("an explicit table was accepted")
	}
	table, err := chooseTable(0, true)
	if err != nil || table != 0 {
		t.Fatalf("site-only came out as table %d, err=%v", table, err)
	}
}

func TestJoinRejectsLegacyRoutingTablePinningBeforeEnrollment(t *testing.T) {
	err := join([]string{"-hub", "http://203.0.113.10:8081", "-table", "254"})
	if err == nil || !strings.Contains(err.Error(), "PBR selects its own table") {
		t.Fatalf("join returned %v", err)
	}
}

func TestJoiningUnderADifferentInterfaceIsRefused(t *testing.T) {
	router := routerAnswering(map[string]string{"shadow9.node.interface": "wg0"})

	err := requireSameInterface(router, "wg1")
	if err == nil || !strings.Contains(err.Error(), "already enrolled on wg0") {
		t.Fatalf("a join that moves the enrollment returned %v", err)
	}
	if err := requireSameInterface(router, "wg0"); err != nil {
		t.Errorf("rejoining the same interface was refused: %v", err)
	}
	if err := requireSameInterface(routerAnswering(nil), "wg0"); err != nil {
		t.Errorf("a first join was refused: %v", err)
	}
}

// recording answers uci reads and remembers every command, so a test can see
// what ran and in which order.
type recording struct {
	values map[string]string
	calls  *[]string
}

func (r recording) Run(_ context.Context, _ openwrt.Stdin, name string, args ...string) ([]byte, error) {
	*r.calls = append(*r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if name == "uci" && len(args) == 2 && args[0] == "get" {
		if value, known := r.values[args[1]]; known {
			return []byte(value + "\n"), nil
		}
		return nil, fmt.Errorf("uci: Entry not found")
	}
	if name == "test" || name == "rm" {
		return nil, nil
	}
	return nil, fmt.Errorf("%s: not found", name)
}

func (recording) Look(string) error { return nil }

// A cleanup that cannot prove ownership leaves the tunnel up, so the boot
// service is the only thing left that can repair it. Disabling it first would
// take that away and still fail.
func TestARefusedUninstallLeavesTheBootServiceEnabled(t *testing.T) {
	var calls []string
	router := openwrt.Router{Shell: recording{
		values: map[string]string{
			"shadow9.node.interface":   "wg0",
			"shadow9.node.zone":        "wgvpn",
			"shadow9.node.lan_zone":    "lan",
			"shadow9.node.private_key": "AJXKLmQ2vN8pR4tY6uI0oP1aSdF3gH5jKlZxCvB7nE0=",
			"network.wg0":              "interface",
			"network.wg0.private_key":  "Zm9yZ2VkS2V5MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
		},
		calls: &calls,
	}}

	err := removeInstallation(router, true)
	if err == nil || !strings.Contains(err.Error(), "ownership of network.wg0 cannot be proven") {
		t.Fatalf("removeInstallation returned %v", err)
	}
	for _, call := range calls {
		if strings.Contains(call, "disable") || strings.HasPrefix(call, "rm ") {
			t.Errorf("a refused cleanup still ran %q", call)
		}
	}
}

// At boot the uplink can still be negotiating. Local repair has to run from
// the saved settings anyway, or a hub that is late costs the node its routes
// as well as its topology update.
func TestRefreshRepairsLocalStateWhenTheHubIsUnreachable(t *testing.T) {
	var calls []string
	router := openwrt.Router{Shell: recording{
		values: map[string]string{
			"shadow9.node.name": "branch-gateway",
			"shadow9.node.refresh_key": "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a6978" +
				"8796a5b4c3d2e1f0",
			// Port 1 refuses immediately, so this is the transport failure a
			// boot-time refresh sees, not a timeout the test has to wait out.
			"shadow9.node.hub":         "http://127.0.0.1:1",
			"shadow9.node.interface":   "wg0",
			"shadow9.node.zone":        "wgvpn",
			"shadow9.node.lan_zone":    "lan",
			"shadow9.node.private_key": "AJXKLmQ2vN8pR4tY6uI0oP1aSdF3gH5jKlZxCvB7nE0=",
			"shadow9.node.revision":    "4",
			"shadow9.node.table":       "0",
		},
		calls: &calls,
	}}

	err := refreshNode(router, 2*time.Second)
	if err == nil {
		t.Fatal("refresh succeeded although the hub was unreachable")
	}
	if !strings.Contains(strings.Join(calls, "\n"), "uci get shadow9.node.pbr_interface") {
		t.Errorf("local repair never ran after the hub failed:\n%s", strings.Join(calls, "\n"))
	}
}
