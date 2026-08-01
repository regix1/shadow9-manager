package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, -1, -1)
	if err != nil {
		t.Fatalf("buildTunnel: %v", err)
	}
	if tunnel.Address != "10.9.0.7/32" {
		t.Errorf("the address came out as %q, want a host route", tunnel.Address)
	}
	if tunnel.EndpointHost != "203.0.113.10" || tunnel.EndpointPort != 51820 {
		t.Errorf("the endpoint came out as %s:%d", tunnel.EndpointHost, tunnel.EndpointPort)
	}
	if len(tunnel.AllowedIPs) != 1 || tunnel.AllowedIPs[0] != "10.9.0.0/24" {
		t.Errorf("the allowed IPs came out as %v", tunnel.AllowedIPs)
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

	tunnel, err := buildTunnel(answer, private, "wg0", "wgvpn", 0, 1280, 0)
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
	tunnel, err := buildRefreshTunnel(answer, private, "wg0", "wgvpn", 0, nil, nil)
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
		answer, private, "wg0", "wgvpn", 0, &mtuOverride, &keepaliveOverride)
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
			_, err := buildTunnel(tc.answer, private, "wg0", "wgvpn", 0, -1, -1)
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
	flags, _ := joinFlags()
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
}
