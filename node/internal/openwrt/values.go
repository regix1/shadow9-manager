package openwrt

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AddressWithPrefix turns the plain address the hub hands out into the form
// the addresses list takes. Policy-ready nodes use the tunnel prefix so their
// explicit tunnel-subnet route has the same address family and scope.
func AddressWithPrefix(address string, network ...string) (string, error) {
	if len(network) > 1 {
		return "", fmt.Errorf("only one tunnel network may supply the prefix")
	}
	address = strings.TrimSpace(address)
	if address == "" {
		return "", fmt.Errorf("the address is empty")
	}
	var parsed net.IP
	if strings.Contains(address, "/") {
		var err error
		parsed, _, err = net.ParseCIDR(address)
		if err != nil {
			return "", fmt.Errorf("%q is not an address: %w", address, err)
		}
		if len(network) == 0 {
			return address, nil
		}
	} else {
		parsed = net.ParseIP(address)
		if parsed == nil {
			return "", fmt.Errorf("%q is not an address", address)
		}
	}
	if len(network) == 1 {
		_, subnet, err := net.ParseCIDR(strings.TrimSpace(network[0]))
		if err != nil {
			return "", fmt.Errorf("%q is not a tunnel network: %w", network[0], err)
		}
		if !subnet.Contains(parsed) {
			return "", fmt.Errorf("%s is outside tunnel network %s", parsed, subnet)
		}
		ones, _ := subnet.Mask.Size()
		return parsed.String() + "/" + strconv.Itoa(ones), nil
	}
	if parsed.To4() != nil {
		return address + "/32", nil
	}
	return address + "/128", nil
}

// SplitEndpoint separates the host:port the hub answers with into the two UCI
// options netifd wants. An IPv6 endpoint arrives in brackets and the brackets
// are not part of the host.
func SplitEndpoint(endpoint string) (host string, port int, err error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, fmt.Errorf("the hub endpoint is empty")
	}
	host, text, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not a host and port: %w", endpoint, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("%q has no host", endpoint)
	}
	port, err = strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("%q does not have a usable port", endpoint)
	}
	return host, port, nil
}

// LanNetwork returns the router's LAN subnet in CIDR form, which is what a
// site gateway advertises to the rest of the tunnel.
func LanNetwork(router Router) (string, error) {
	address, err := router.Get("network.lan.ipaddr")
	if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("network.lan.ipaddr is not set")
	}
	if err != nil {
		return "", err
	}
	if address == "" {
		return "", fmt.Errorf("network.lan.ipaddr is not set")
	}
	// uci get prints a list as its values separated by spaces, and a LAN can
	// carry more than one address. The first is the one to advertise.
	address = strings.Fields(address)[0]

	if strings.Contains(address, "/") {
		_, network, err := net.ParseCIDR(address)
		if err != nil {
			return "", fmt.Errorf("network.lan.ipaddr is %q, which is not an address", address)
		}
		return network.String(), nil
	}

	mask, err := router.Get("network.lan.netmask")
	if errors.Is(err, ErrNotFound) {
		mask = "255.255.255.0"
	} else if err != nil {
		return "", err
	} else if mask == "" {
		mask = "255.255.255.0"
	}
	ip := net.ParseIP(address).To4()
	dotted := net.ParseIP(mask).To4()
	if ip == nil || dotted == nil {
		return "", fmt.Errorf("cannot read a subnet from %s and %s", address, mask)
	}
	netmask := net.IPMask(dotted)
	ones, bits := netmask.Size()
	if bits == 0 {
		return "", fmt.Errorf("%s is not a usable netmask", mask)
	}
	return fmt.Sprintf("%s/%d", ip.Mask(netmask).String(), ones), nil
}

// Hostname returns the router's configured hostname, or an empty string when
// it has none.
func Hostname(router Router) (string, error) {
	hostname, err := router.Get("system.@system[0].hostname")
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	return hostname, err
}

// PeerName turns a hostname into a name the hub will accept: 3 to 64 letters,
// digits, underscores or hyphens. A hostname is usually already one, but a
// dotted name is common enough to be worth converting rather than refusing.
func PeerName(hostname string) (string, error) {
	var name strings.Builder
	for _, r := range strings.TrimSpace(hostname) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			name.WriteRune(r)
		default:
			name.WriteByte('-')
		}
	}
	cleaned := strings.Trim(name.String(), "-")
	const shortestName, longestName = 3, 64
	if len(cleaned) < shortestName {
		return "", fmt.Errorf(
			"%q does not make a peer name of at least %d usable characters, pass -name",
			hostname, shortestName)
	}
	if len(cleaned) > longestName {
		cleaned = cleaned[:longestName]
	}
	return cleaned, nil
}
