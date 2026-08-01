package openwrt

import (
	"strings"
	"testing"
)

// The hub hands out a plain address and UCI wants a prefix. A /24 here would
// make the router treat every other peer as on-link, so the host route is not
// a detail.
func TestAddressWithPrefixGivesAHostRoute(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.9.0.7", "10.9.0.7/32"},
		{" 10.9.0.7 ", "10.9.0.7/32"},
		{"fd00:9::7", "fd00:9::7/128"},
		{"10.9.0.7/32", "10.9.0.7/32"},
		{"10.9.0.0/24", "10.9.0.0/24"},
	} {
		got, err := AddressWithPrefix(tc.in)
		if err != nil {
			t.Errorf("AddressWithPrefix(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("AddressWithPrefix(%q) is %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "  ", "not an address", "10.9.0.999", "10.9.0.7/64"} {
		if got, err := AddressWithPrefix(bad); err == nil {
			t.Errorf("AddressWithPrefix(%q) returned %q rather than an error", bad, got)
		}
	}
}

func TestSplitEndpointSeparatesHostFromPort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		host string
		port int
	}{
		{"203.0.113.10:51820", "203.0.113.10", 51820},
		{"hub.example.com:51820", "hub.example.com", 51820},
		{"[fd00:9::1]:51820", "fd00:9::1", 51820},
	} {
		host, port, err := SplitEndpoint(tc.in)
		if err != nil {
			t.Errorf("SplitEndpoint(%q): %v", tc.in, err)
			continue
		}
		if host != tc.host || port != tc.port {
			t.Errorf("SplitEndpoint(%q) is %q and %d, want %q and %d", tc.in, host, port, tc.host, tc.port)
		}
	}
	for _, bad := range []string{"", "hub.example.com", "hub.example.com:", "hub.example.com:0",
		"hub.example.com:70000", ":51820", "hub.example.com:http"} {
		if _, _, err := SplitEndpoint(bad); err == nil {
			t.Errorf("SplitEndpoint(%q) succeeded, want an error", bad)
		}
	}
}

func TestLanNetworkReadsTheSubnetToAdvertise(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("network", "lan", "interface", map[string][]string{
		"ipaddr": {"192.168.1.1"}, "netmask": {"255.255.255.0"},
	})
	got, err := LanNetwork(Router{Shell: shell})
	if err != nil {
		t.Fatalf("LanNetwork: %v", err)
	}
	if got != "192.168.1.0/24" {
		t.Errorf("the LAN subnet came out as %q", got)
	}
}

func TestLanNetworkHandlesTheOtherWaysALanIsWritten(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options map[string][]string
		want    string
	}{
		{"no netmask defaults to /24", map[string][]string{"ipaddr": {"10.0.0.1"}}, "10.0.0.0/24"},
		{"a wider mask", map[string][]string{
			"ipaddr": {"172.16.4.1"}, "netmask": {"255.255.0.0"}}, "172.16.0.0/16"},
		{"an address written as CIDR", map[string][]string{"ipaddr": {"192.168.8.1/22"}}, "192.168.8.0/22"},
		{"more than one address", map[string][]string{
			"ipaddr": {"192.168.1.1", "192.168.2.1"}, "netmask": {"255.255.255.0"}}, "192.168.1.0/24"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shell := newFakeShell()
			shell.addSection("network", "lan", "interface", tc.options)
			got, err := LanNetwork(Router{Shell: shell})
			if err != nil {
				t.Fatalf("LanNetwork: %v", err)
			}
			if got != tc.want {
				t.Errorf("the LAN subnet came out as %q, want %q", got, tc.want)
			}
		})
	}
}

// A LAN on DHCP has no ipaddr, and guessing one would advertise a subnet this
// router does not have.
func TestLanNetworkSaysSoWhenThereIsNoLanAddress(t *testing.T) {
	shell := newFakeShell()
	_, err := LanNetwork(Router{Shell: shell})
	if err == nil {
		t.Fatal("LanNetwork invented a subnet for a router with no LAN address")
	}
	if !strings.Contains(err.Error(), "network.lan.ipaddr") {
		t.Errorf("the error does not say what was missing: %v", err)
	}
}

func TestHostnameReadsTheSystemSection(t *testing.T) {
	shell := newFakeShell()
	shell.addSection("system", "", "system", map[string][]string{"hostname": {"branch-gateway"}})
	got, err := Hostname(Router{Shell: shell})
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if got != "branch-gateway" {
		t.Errorf("the hostname came out as %q", got)
	}
	got, err = Hostname(Router{Shell: newFakeShell()})
	if err != nil {
		t.Fatalf("Hostname: %v", err)
	}
	if got != "" {
		t.Errorf("a router with no hostname gave %q", got)
	}
}

// The hub wants 3 to 64 letters, digits, underscores or hyphens, and a dotted
// hostname is common enough to convert rather than refuse.
func TestPeerNameMakesAHostnameUsable(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"OpenWrt", "OpenWrt"},
		{"branch-gateway", "branch-gateway"},
		{"branch.example.com", "branch-example-com"},
		{"  spaced name  ", "spaced-name"},
		{"...leading.and.trailing...", "leading-and-trailing"},
		{strings.Repeat("a", 80), strings.Repeat("a", 64)},
	} {
		got, err := PeerName(tc.in)
		if err != nil {
			t.Errorf("PeerName(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("PeerName(%q) is %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPeerNameSaysToPassOneWhenTheHostnameIsUnusable(t *testing.T) {
	for _, bad := range []string{"", "  ", "..", "a"} {
		_, err := PeerName(bad)
		if err == nil {
			t.Errorf("PeerName(%q) invented a name", bad)
			continue
		}
		if !strings.Contains(err.Error(), "-name") {
			t.Errorf("the error does not say what to do: %v", err)
		}
	}
}
