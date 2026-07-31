// Command shadow9-node enrolls and refreshes an OpenWrt router on a shadow9
// WireGuard hub.
//
// It does four things: generate a keypair, call the hub, write UCI and reload.
// The hub stays entirely Python and none of its logic belongs here.
//
// The configuration goes into /etc/config/network and /etc/config/firewall
// rather than into a wg-quick .conf file, because a .conf file works and is
// completely invisible to LuCI. Written this way the tunnel is a real LuCI
// interface with status, handshake time, transfer counters and a peer list.
//
// Standard library only, so there is no third-party code in the path of a
// private key that sits on a router.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"shadow9-node/internal/enroll"
	"shadow9-node/internal/openwrt"
	"shadow9-node/internal/wgkey"
)

// version is set at build time by the Makefile.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "join":
		if err := join(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "shadow9-node: %v\n", err)
			os.Exit(1)
		}
	case "refresh":
		if err := refresh(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "shadow9-node: %v\n", err)
			os.Exit(1)
		}
	case "version", "-version", "--version":
		fmt.Printf("shadow9-node %s\n", version)
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "shadow9-node: %q is not a command\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `shadow9-node %s

  shadow9-node join -hub URL -token-file PATH [options]
  shadow9-node refresh [options]
  shadow9-node version

Enrolls or refreshes this router on a shadow9 WireGuard hub and writes the
matching UCI network and firewall configuration.
`, version)
}

// joinOptions is everything the join command takes from the command line.
type joinOptions struct {
	hub        string
	token      string
	tokenFile  string
	name       string
	iface      string
	zone       string
	lanZone    string
	advertise  string
	noRoutes   bool
	keepKey    bool
	listenPort int
	mtu        int
	keepalive  int
	timeout    time.Duration
}

// joinFlags builds the join command's flag set and the options it fills.
//
// Separate from join so a test can read the defaults without running anything.
func joinFlags() (*flag.FlagSet, *joinOptions) {
	flags := flag.NewFlagSet("join", flag.ExitOnError)
	options := &joinOptions{}
	flags.StringVar(&options.hub, "hub", "",
		"base URL of the shadow9 hub, for example http://203.0.113.10:8081")
	flags.StringVar(&options.token, "token", "",
		"the join token. Prefer -token-file, because this lands in shell history")
	flags.StringVar(&options.tokenFile, "token-file", "",
		"read the join token from this file")
	flags.StringVar(&options.name, "name", "",
		"peer name to register, defaults to this router's hostname")
	flags.StringVar(&options.iface, "iface", openwrt.DefaultInterface,
		"WireGuard interface name")
	flags.StringVar(&options.zone, "zone", openwrt.DefaultZone,
		"firewall zone to create, 11 characters at most")
	flags.StringVar(&options.lanZone, "lan-zone", "",
		"existing firewall zone for the LAN, found automatically when not given")
	flags.StringVar(&options.advertise, "advertise", "",
		"comma separated subnets to announce, defaults to this router's LAN subnet")
	flags.BoolVar(&options.noRoutes, "no-routes", false,
		"announce no subnets, for a node that is not a site gateway")
	flags.BoolVar(&options.keepKey, "keep-key", false,
		"reuse the private key already in UCI instead of generating one")
	flags.IntVar(&options.listenPort, "listen-port", 0,
		"UDP port to listen on. Leave at 0 for a node that dials out")
	flags.IntVar(&options.mtu, "mtu", -1,
		"override the hub's interface MTU")
	flags.IntVar(&options.keepalive, "keepalive", -1,
		"override the hub's keepalive seconds; 0 turns keepalives off")
	flags.DurationVar(&options.timeout, "timeout", 20*time.Second,
		"how long to wait on the hub")
	return flags, options
}

func join(args []string) error {
	flags, options := joinFlags()
	if err := flags.Parse(args); err != nil {
		return err
	}

	tokenText, err := readToken(options.token, options.tokenFile)
	if err != nil {
		return err
	}
	joinToken, err := enroll.ParseToken(tokenText)
	if err != nil {
		return err
	}
	if options.hub == "" {
		return fmt.Errorf("-hub is required")
	}

	router := openwrt.Router{Shell: openwrt.SystemShell{}}
	if err := router.Require("uci", "the OpenWrt base system"); err != nil {
		return fmt.Errorf("%w. This does not look like an OpenWrt router", err)
	}
	if err := router.Require("wg", "wireguard-tools"); err != nil {
		return err
	}
	// Said before anything is written, so the operator learns about it while
	// the router is still untouched.
	if notice := router.ProtocolPackageNotice(options.iface); notice != "" {
		fmt.Fprintf(os.Stderr, "Note: %s\n", notice)
	}

	peerName, err := chooseName(options.name, router)
	if err != nil {
		return err
	}
	routes, err := chooseRoutes(options.advertise, options.noRoutes, router)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := chooseKey(options.keepKey, options.iface, peerName, router)
	if err != nil {
		return err
	}
	if err := router.WriteIdentity(peerName, privateKey.String()); err != nil {
		return fmt.Errorf("saving the WireGuard identity before enrollment: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()

	// Enroll verifies the hub's key against the token before it returns, so
	// nothing below can run against a hub the token does not name.
	client := enroll.Client{BaseURL: options.hub}
	answer, err := client.Enroll(ctx, joinToken, peerName, publicKey.String(), routes)
	if err != nil {
		return err
	}
	if err := router.WriteRefreshKey(joinToken.RefreshKey().String()); err != nil {
		return fmt.Errorf("saving the refresh key after enrollment: %w", err)
	}

	tunnel, err := buildTunnel(
		answer,
		privateKey,
		options.iface,
		options.zone,
		options.listenPort,
		options.mtu,
		options.keepalive,
	)
	if err != nil {
		return err
	}
	tunnel.LanZone = chooseLanZone(options.lanZone, router)
	if tunnel.TakesOverTheDefaultRoute() {
		fmt.Fprintf(os.Stderr,
			"Note: the hub's allowed IPs contain a default route, so all of this router's\n"+
				"    traffic will go through the tunnel, including the way you reach it now.\n")
	}

	if err := router.WriteTunnel(tunnel, strings.TrimSuffix(options.hub, "/")); err != nil {
		return err
	}

	fmt.Printf("Joined %s as %s.\n", strings.TrimSuffix(options.hub, "/"), peerName)
	fmt.Printf("    %s is %s, hub at %s:%d.\n",
		tunnel.Interface, tunnel.Address, tunnel.EndpointHost, tunnel.EndpointPort)
	if len(routes) > 0 {
		fmt.Printf("    Announcing %s to the rest of the tunnel.\n", strings.Join(routes, ", "))
	}
	fmt.Printf("    LuCI: Network then Interfaces then %s, status at Status then WireGuard.\n",
		tunnel.Interface)
	return nil
}

func refresh(args []string) error {
	flags := flag.NewFlagSet("refresh", flag.ContinueOnError)
	timeout := flags.Duration("timeout", 20*time.Second, "how long to wait on the hub")
	if err := flags.Parse(args); err != nil {
		return err
	}
	router := openwrt.Router{Shell: openwrt.SystemShell{}}
	if err := router.Require("uci", "the OpenWrt base system"); err != nil {
		return fmt.Errorf("%w. This does not look like an OpenWrt router", err)
	}

	name := router.Get("shadow9.node.name")
	keyText := router.Get("shadow9.node.refresh_key")
	if name == "" || keyText == "" {
		fmt.Println("This node has not enrolled; nothing to refresh.")
		return nil
	}
	key, err := enroll.ParseRefreshKey(keyText)
	if err != nil {
		return err
	}
	hub := router.Get("shadow9.node.hub")
	if hub == "" {
		return errors.New("the saved hub URL is empty")
	}
	iface := router.Get("shadow9.node.interface")
	if iface == "" {
		iface = openwrt.DefaultInterface
	}
	zone := router.Get("shadow9.node.zone")
	if zone == "" {
		zone = openwrt.DefaultZone
	}
	lanZone := router.Get("shadow9.node.lan_zone")
	if lanZone == "" {
		lanZone = openwrt.DefaultLanZone
	}
	privateKey, err := wgkey.Parse(router.Get("shadow9.node.private_key"))
	if err != nil {
		return fmt.Errorf("the saved private key is unusable: %w", err)
	}
	currentRevision, err := savedNumber(router.Get("shadow9.node.revision"), "revision")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	answer, err := (enroll.Client{BaseURL: hub}).Refresh(ctx, key, name)
	if err != nil {
		return err
	}
	if answer.Revision != nil && *answer.Revision == currentRevision {
		fmt.Printf("Tunnel settings are already at revision %d; nothing changed.\n", currentRevision)
		return nil
	}
	if err := router.Require("wg", "wireguard-tools"); err != nil {
		return err
	}
	listenPort, err := savedNumber(router.Get("network."+iface+".listen_port"), "listen port")
	if err != nil {
		return err
	}
	mtuOverride, err := savedOverride(router.Get("shadow9.node.mtu_override"), "MTU", false)
	if err != nil {
		return err
	}
	keepaliveOverride, err := savedOverride(
		router.Get("shadow9.node.keepalive_override"), "keepalive", true)
	if err != nil {
		return err
	}
	tunnel, err := buildRefreshTunnel(
		answer, privateKey, iface, zone, listenPort, mtuOverride, keepaliveOverride)
	if err != nil {
		return err
	}
	tunnel.LanZone = lanZone
	if err := router.WriteTunnel(tunnel, strings.TrimSuffix(hub, "/")); err != nil {
		return err
	}
	fmt.Printf("Refreshed %s to revision %d.\n", name, tunnel.Revision)
	return nil
}

func savedNumber(text, name string) (int, error) {
	if strings.TrimSpace(text) == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 {
		return 0, fmt.Errorf("the saved %s is unusable", name)
	}
	return value, nil
}

func savedOverride(text, name string, zeroAllowed bool) (*int, error) {
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 || (!zeroAllowed && value == 0) {
		return nil, fmt.Errorf("the saved %s override is unusable", name)
	}
	return &value, nil
}

// readToken prefers the file, because a token on the command line lands in
// shell history and in the process list.
func readToken(token, tokenFile string) (string, error) {
	if tokenFile != "" {
		raw, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading the token file: %w", err)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if token == "" {
		return "", fmt.Errorf("a join token is required, pass -token-file or -token")
	}
	return token, nil
}

func chooseName(given string, router openwrt.Router) (string, error) {
	if given != "" {
		return openwrt.PeerName(given)
	}
	hostname := openwrt.Hostname(router)
	if hostname == "" {
		return "", fmt.Errorf("this router has no hostname set, pass -name")
	}
	return openwrt.PeerName(hostname)
}

func chooseRoutes(advertise string, noRoutes bool, router openwrt.Router) ([]string, error) {
	if noRoutes {
		return []string{}, nil
	}
	if advertise != "" {
		var routes []string
		for _, subnet := range strings.Split(advertise, ",") {
			if subnet = strings.TrimSpace(subnet); subnet != "" {
				routes = append(routes, subnet)
			}
		}
		if len(routes) == 0 {
			return nil, fmt.Errorf("-advertise was given but names no subnets")
		}
		return routes, nil
	}
	subnet, err := openwrt.LanNetwork(router)
	if err != nil {
		return nil, fmt.Errorf(
			"could not read this router's LAN subnet (%w), pass -advertise or -no-routes", err)
	}
	return []string{subnet}, nil
}

func chooseKey(keepKey bool, iface, name string, router openwrt.Router) (private, public wgkey.Key, err error) {
	if router.Get("shadow9.node.name") == name {
		stored := router.Get("shadow9.node.private_key")
		private, err = wgkey.Parse(stored)
		if err != nil {
			return private, public, fmt.Errorf("the saved private key for %s is unusable: %w", name, err)
		}
		public, err = wgkey.PublicFor(private)
		return private, public, err
	}
	if !keepKey {
		return wgkey.Generate()
	}
	stored := router.Get("network." + iface + ".private_key")
	if stored == "" {
		return private, public, fmt.Errorf(
			"-keep-key was given but network.%s.private_key is empty, so there is no key to keep", iface)
	}
	private, err = wgkey.Parse(stored)
	if err != nil {
		return private, public, fmt.Errorf("the private key already in UCI is unusable: %w", err)
	}
	public, err = wgkey.PublicFor(private)
	return private, public, err
}

// chooseLanZone falls back to the flag, then to reading which zone carries the
// LAN, then to the stock name. A forwarding written to a zone that does not
// exist produces a firewall that quietly forwards nothing.
func chooseLanZone(given string, router openwrt.Router) string {
	if given != "" {
		return given
	}
	if found := openwrt.FindZoneForNetwork(router, "lan"); found != "" {
		return found
	}
	return openwrt.DefaultLanZone
}

func buildTunnel(answer enroll.Response, privateKey wgkey.Key,
	iface, zone string, listenPort, mtu, keepalive int) (openwrt.Tunnel, error) {

	if answer.MTU == nil || answer.Keepalive == nil {
		return openwrt.Tunnel{}, fmt.Errorf("the hub's answer has no tunnel settings")
	}
	var mtuOverride, keepaliveOverride *int
	if mtu == -1 {
		mtu = *answer.MTU
	} else if mtu <= 0 {
		return openwrt.Tunnel{}, fmt.Errorf("-mtu must be positive")
	} else {
		mtuOverride = &mtu
	}
	if keepalive == -1 {
		keepalive = *answer.Keepalive
	} else if keepalive < 0 {
		return openwrt.Tunnel{}, fmt.Errorf("-keepalive cannot be negative")
	} else {
		keepaliveOverride = &keepalive
	}
	return tunnelFor(tunnelSettings{
		address: answer.Address, hubPublicKey: answer.HubPublicKey,
		hubEndpoint: answer.HubEndpoint, allowedIPs: []string{answer.TunnelNetwork},
		mtu: mtu, keepalive: keepalive,
		mtuOverride: mtuOverride, keepaliveOverride: keepaliveOverride,
	}, privateKey, iface, zone, listenPort)
}

type tunnelSettings struct {
	address           string
	hubPublicKey      string
	hubEndpoint       string
	allowedIPs        []string
	mtu               int
	keepalive         int
	revision          int
	mtuOverride       *int
	keepaliveOverride *int
}

func buildRefreshTunnel(answer enroll.RefreshResponse, privateKey wgkey.Key,
	iface, zone string, listenPort int, mtuOverride, keepaliveOverride *int) (openwrt.Tunnel, error) {
	if answer.MTU == nil || answer.Keepalive == nil || answer.Revision == nil {
		return openwrt.Tunnel{}, fmt.Errorf("the hub's answer has no tunnel settings")
	}
	mtu, keepalive := *answer.MTU, *answer.Keepalive
	if mtuOverride != nil {
		mtu = *mtuOverride
	}
	if keepaliveOverride != nil {
		keepalive = *keepaliveOverride
	}
	return tunnelFor(tunnelSettings{
		address: answer.Address, hubPublicKey: answer.HubPublicKey,
		hubEndpoint: answer.HubEndpoint, allowedIPs: answer.AllowedIPs,
		mtu: mtu, keepalive: keepalive, revision: *answer.Revision,
		mtuOverride: mtuOverride, keepaliveOverride: keepaliveOverride,
	}, privateKey, iface, zone, listenPort)
}

func tunnelFor(settings tunnelSettings, privateKey wgkey.Key,
	iface, zone string, listenPort int) (openwrt.Tunnel, error) {
	address, err := openwrt.AddressWithPrefix(settings.address)
	if err != nil {
		return openwrt.Tunnel{}, fmt.Errorf("the address the hub gave is unusable: %w", err)
	}
	host, port, err := openwrt.SplitEndpoint(settings.hubEndpoint)
	if err != nil {
		return openwrt.Tunnel{}, fmt.Errorf("the endpoint the hub gave is unusable: %w", err)
	}
	return openwrt.Tunnel{
		Interface:         iface,
		Zone:              zone,
		LanZone:           openwrt.DefaultLanZone,
		PrivateKey:        privateKey.String(),
		Address:           address,
		ListenPort:        listenPort,
		MTU:               settings.mtu,
		Revision:          settings.revision,
		MTUOverride:       settings.mtuOverride,
		KeepaliveOverride: settings.keepaliveOverride,

		HubPublicKey: settings.hubPublicKey,
		EndpointHost: host,
		EndpointPort: port,
		Keepalive:    settings.keepalive,
		AllowedIPs:   settings.allowedIPs,
	}, nil
}
