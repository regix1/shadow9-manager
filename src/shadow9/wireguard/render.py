"""
The tunnel topology and the `wg-quick` configs rendered from it.

`AllowedIPs` does two different jobs and which one you are looking at depends on the side
of the tunnel. Inbound it is an access-control list: a packet from a peer is dropped unless
its source address falls inside that peer's `AllowedIPs`, and that is the only thing
stopping one spoke from claiming to be another. Outbound it is a routing table: the kernel
picks the peer whose `AllowedIPs` covers the destination. So on the hub each peer gets its
own address and nothing more, narrow, and on a spoke the hub peer gets the whole tunnel
network, wide. Swapping those two is the classic WireGuard mistake, and the symptom is a
tunnel that looks healthy while half the network is unreachable.

Which brings in the reason for a topology rather than a set of independent configs. A site
gateway advertises a LAN, say 192.168.1.0/24. That LAN is only reachable if *every other*
peer routes the range into the tunnel, so adding one gateway changes every other config
that already exists. Here that range is computed from the topology at render time, so peers
rendered from the same Topology cannot disagree about which subnets exist.
"""

import os
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path

import structlog

from ..paths import get_config_dir, write_file_safely
from .addresses import TunnelAddress, TunnelNetwork

logger = structlog.get_logger(__name__)

# The convention, and the only inbound port the whole design needs open. UDP, so it does
# not collide with the SOCKS5 listener or the API
DEFAULT_LISTEN_PORT = 51820

# The kernel's own default for a WireGuard device. Measured framing is 32 bytes plus
# padding of the inner packet up to a multiple of 16, and the outer UDP and IP headers add
# 28 over IPv4 or 48 over IPv6. 1420 therefore fits inside a 1500 byte path either way.
# Pin something smaller only when a link upstream is smaller, PPPoE at 1492 being the usual
# reason, where 1412 and 1380 are the values that work. A wrong MTU has a distinctive
# symptom: ping and SSH are fine, large downloads and file transfers hang.
DEFAULT_MTU = 1420

# Common NAT and firewall UDP mappings expire around 30 seconds, so a spoke refreshes at 25
DEFAULT_KEEPALIVE_SECONDS = 25

DEFAULT_INTERFACE = "wg0"

# What a spoke routes into the tunnel when it wants everything to go through the hub
FULL_TUNNEL_ALLOWED_IPS = ("0.0.0.0/0", "::/0")

# wg-quick warns about a world-readable config and then uses it anyway, and its check is
# satisfied as soon as the parent directory is locked down, so a readable config inside a
# readable directory produces no complaint at all. Both are set here instead.
CONFIG_FILE_MODE = 0o600
CONFIG_DIR_MODE = 0o700


class PeerRole(StrEnum):
    """What a peer is in the star."""

    # The cloud server: the reachable endpoint every spoke dials
    HUB = "hub"
    # A machine that joins itself, and the only kind that can be a site gateway
    NODE = "node"
    # Something that cannot run shadow9 and gets a config handed to it, such as a phone
    DEVICE = "device"


@dataclass(frozen=True)
class Peer:
    """
    One member of the tunnel.

    Carries no private key. A peer record is stored in the credential file and rendered
    into every other peer's config, and neither is a place for a secret. The private key is
    handed to a renderer at the moment a config is built and is not kept anywhere else.

    Attributes:
        name: The peer's name, also the name of its config file
        public_key: Base64 X25519 public key
        address: The peer's address inside the tunnel network
        role: Hub, node or device
        routes: Subnets behind this peer that other peers should reach through it. A peer
            with routes is a site gateway, and this is what makes the feature worth having
        endpoint: host:port other peers dial. Only the hub has one
        keepalive: Seconds between keepalives this peer sends to the hub, or None
        enabled: A disabled peer keeps its keys and is left out of every rendered config
    """

    name: str
    public_key: str
    address: TunnelAddress
    role: PeerRole
    routes: tuple[TunnelNetwork, ...] = ()
    endpoint: str | None = None
    keepalive: int | None = DEFAULT_KEEPALIVE_SECONDS
    enabled: bool = True


@dataclass(frozen=True)
class Topology:
    """
    The whole star: the hub, its spokes, and the settings every config shares.

    Attributes:
        tunnel_network: The range peer addresses come from
        hub: The hub peer, which needs an endpoint before any spoke config can be rendered
        spokes: Every other peer
        listen_port: The hub's UDP port
        mtu: Interface MTU, or None to let wg-quick work it out from the route
        dns: Resolver a spoke should use while the tunnel is up, usually the hub address.
            Without it a full-tunnel spoke keeps resolving names on the local network
        interface: The interface name, which wg-quick takes from the config file name
        masquerade_interface: The hub's internet-facing interface. Set it only when some
            spoke uses a full tunnel, because that is what NATs their traffic out
        forward_between_spokes: Whether the hub config carries the rules that let two
            spokes reach each other
    """

    tunnel_network: TunnelNetwork
    hub: Peer
    spokes: tuple[Peer, ...] = ()
    listen_port: int = DEFAULT_LISTEN_PORT
    mtu: int | None = DEFAULT_MTU
    dns: str | None = None
    interface: str = DEFAULT_INTERFACE
    masquerade_interface: str | None = None
    forward_between_spokes: bool = True

    def active_spokes(self) -> tuple[Peer, ...]:
        """
        Return the spokes that belong in a rendered config.

        Returns:
            Every enabled spoke, in the order they were added
        """
        return tuple(spoke for spoke in self.spokes if spoke.enabled)

    def with_peer(self, peer: Peer) -> "Topology":
        """
        Return a topology with this peer added, or replacing one of the same name.

        Args:
            peer: The peer to add or replace

        Returns:
            A new topology. The original is unchanged, so the caller decides when the
            change becomes real
        """
        if peer.role is PeerRole.HUB:
            return replace(self, hub=peer)

        existing = [spoke.name for spoke in self.spokes]
        if peer.name in existing:
            updated = tuple(peer if spoke.name == peer.name else spoke for spoke in self.spokes)
        else:
            updated = (*self.spokes, peer)
        return replace(self, spokes=updated)

    def without_peer(self, name: str) -> "Topology":
        """
        Return a topology with this peer gone.

        Args:
            name: The peer to drop

        Returns:
            A new topology without that peer
        """
        return replace(self, spokes=tuple(s for s in self.spokes if s.name != name))

    def find_peer(self, name: str) -> Peer | None:
        """
        Look a peer up by name.

        Args:
            name: The peer name, hub included

        Returns:
            The peer, or None if no peer has that name
        """
        if self.hub.name == name:
            return self.hub
        for spoke in self.spokes:
            if spoke.name == name:
                return spoke
        return None

    def routes_reachable_from(self, peer: Peer) -> tuple[TunnelNetwork, ...]:
        """
        Every subnet this peer must send into the tunnel to reach the LANs behind gateways.

        A gateway's own routes are left out of its own answer. That range sits on the other
        side of its own network interface, and routing it into the tunnel would send its
        LAN traffic to the hub and drop it there.

        Args:
            peer: The peer whose config is being rendered

        Returns:
            The advertised subnets, deduplicated and in a stable order
        """
        advertised: set[TunnelNetwork] = set()
        for other in self.active_spokes():
            if other.name == peer.name:
                continue
            advertised.update(other.routes)
        return _sorted_networks(advertised)


def check_peer_routes(topology: Topology, peer: Peer) -> None:
    """Refuse advertised ranges that can steal tunnel traffic from another peer."""
    peers = (topology.hub, *topology.spokes)
    for route in peer.routes:
        if route.prefixlen == 0:
            raise ValueError(f"Route {route} is a default route and cannot be advertised")

        if (
            route.version == topology.tunnel_network.version
            and route.overlaps(topology.tunnel_network)
        ):
            raise ValueError(
                f"Route {route} overlaps tunnel network {topology.tunnel_network}"
            )

        for other in peers:
            if other.name != peer.name and other.address.version == route.version:
                if other.address in route:
                    raise ValueError(
                        f"Route {route} covers tunnel address {other.address} held by "
                        f"peer '{other.name}'"
                    )

        for other in topology.spokes:
            if other.name == peer.name:
                continue
            for advertised in other.routes:
                if advertised.version == route.version and advertised.overlaps(route):
                    raise ValueError(
                        f"Route {route} overlaps route {advertised} advertised by "
                        f"peer '{other.name}'"
                    )


def render_hub_config(topology: Topology, private_key: str) -> str:
    """
    Render the hub's wg-quick config.

    Each peer gets its own address and its own advertised subnets, and nothing else. On
    this side that list is an access-control list, so it stays as narrow as it can be.

    No peer section carries PersistentKeepalive. The hub is the side with the stable
    reachable address and has no NAT mapping to hold open, so setting it here would only
    wake every phone on the tunnel every 25 seconds.

    Args:
        topology: The star being rendered
        private_key: The hub's base64 private key

    Returns:
        The config file text

    Raises:
        ValueError: If a text value could add or truncate a config line, or the outward
            interface is not a valid interface name
    """
    private_key = _checked_config_value(private_key, "hub private key")
    prefix = topology.tunnel_network.prefixlen
    lines: list[str] = [
        "[Interface]",
        f"Address = {topology.hub.address}/{prefix}",
        f"ListenPort = {topology.listen_port}",
    ]
    if topology.mtu is not None:
        lines.append(f"MTU = {topology.mtu}")
    lines.append(f"PrivateKey = {private_key}")

    lines.extend(_hub_firewall_lines(topology))

    for spoke in topology.active_spokes():
        check_peer_routes(topology, spoke)
        name = _checked_config_value(spoke.name, "peer name")
        public_key = _checked_config_value(spoke.public_key, "peer public key")
        allowed = (_host_network(spoke.address), *_sorted_networks(set(spoke.routes)))
        lines.extend(
            [
                "",
                "[Peer]",
                f"# {name}",
                f"PublicKey = {public_key}",
                f"AllowedIPs = {', '.join(str(entry) for entry in allowed)}",
            ]
        )

    return "\n".join(lines) + "\n"


def render_spoke_config(
    topology: Topology,
    peer: Peer,
    private_key: str,
    full_tunnel: bool = False,
) -> str:
    """
    Render a spoke's wg-quick config, with the hub as its only peer.

    Split tunnel is the default: the tunnel network plus every subnet advertised by any
    other peer, and nothing else. That is the useful shape once a site gateway exists,
    because the want is "reach my tunnel and my home LAN", not "send my phone's video
    through a rented server". A full tunnel replaces the whole list with a default route.

    Args:
        topology: The star being rendered
        peer: The spoke this config belongs to
        private_key: That spoke's base64 private key
        full_tunnel: Send all traffic through the hub instead of only tunnel destinations

    Returns:
        The config file text

    Raises:
        ValueError: If the hub has no endpoint, or a text value could add or truncate a
            config line
    """
    endpoint = topology.hub.endpoint
    if not endpoint:
        raise ValueError(
            "The hub has no endpoint, so a spoke would have nothing to dial. Set the hub "
            "endpoint to the address and port peers can reach it on."
        )
    endpoint = _checked_config_value(endpoint, "hub endpoint")
    private_key = _checked_config_value(private_key, "spoke private key")
    hub_name = _checked_config_value(topology.hub.name, "hub name")
    hub_public_key = _checked_config_value(topology.hub.public_key, "hub public key")

    lines: list[str] = [
        "[Interface]",
        f"Address = {_host_network(peer.address)}",
        f"PrivateKey = {private_key}",
    ]
    if topology.mtu is not None:
        lines.append(f"MTU = {topology.mtu}")
    if topology.dns:
        dns = _checked_config_value(topology.dns, "wireguard.dns")
        lines.append(f"DNS = {dns}")

    lines.extend(_gateway_forwarding_lines(peer))

    lines.extend(
        [
            "",
            "[Peer]",
            f"# {hub_name}",
            f"PublicKey = {hub_public_key}",
            f"Endpoint = {endpoint}",
            f"AllowedIPs = {', '.join(spoke_allowed_ips(topology, peer, full_tunnel))}",
        ]
    )
    if peer.keepalive:
        lines.append(f"PersistentKeepalive = {peer.keepalive}")

    return "\n".join(lines) + "\n"


def spoke_allowed_ips(topology: Topology, peer: Peer, full_tunnel: bool = False) -> tuple[str, ...]:
    """
    Work out what a spoke should route into the tunnel.

    Args:
        topology: The star being rendered
        peer: The spoke whose config is being built
        full_tunnel: Send everything through the hub

    Returns:
        The AllowedIPs entries, in the order they should be written
    """
    if full_tunnel:
        return FULL_TUNNEL_ALLOWED_IPS

    entries = [str(topology.tunnel_network)]
    entries.extend(str(route) for route in topology.routes_reachable_from(peer))
    return tuple(entries)


def config_path(name: str) -> Path:
    """
    Where a rendered config for this name is written.

    The name reaches this from a peer record, so it is checked the same way a user
    directory name is: a joined path is absolute-overriding, and "config/wireguard" plus
    "/etc/wireguard/wg0" is "/etc/wireguard/wg0".

    Args:
        name: The peer or interface name

    Returns:
        config/wireguard/<name>.conf under the install root

    Raises:
        ValueError: If the name is not a plain name
    """
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        raise ValueError(f"Not a usable name for a config file: {name!r}")

    directory = get_config_dir() / "wireguard"
    path = directory / f"{name}.conf"
    if directory.resolve() not in path.resolve().parents:
        raise ValueError(f"Name escapes the wireguard config directory: {name!r}")

    return path


def checked_interface(name: str) -> str:
    """Check a WireGuard interface name before it becomes a file or host command."""
    cleaned = name.strip()
    if not 1 <= len(cleaned) <= 15:
        raise ValueError("wireguard.interface must be 1 to 15 characters long")
    if not all(
        character.isascii() and (character.isalnum() or character in "_=+.-")
        for character in cleaned
    ):
        raise ValueError(
            "wireguard.interface can only hold letters, digits, underscores, equals, "
            "plus signs, periods and hyphens"
        )
    return cleaned


def _checked_config_value(value: str, setting: str) -> str:
    """Refuse characters that can end, add or truncate a WireGuard config line."""
    if "\r" in value or "\n" in value or "\0" in value:
        raise ValueError(
            f"{setting} cannot contain carriage returns, line feeds or NUL bytes"
        )
    return value


def write_config(path: Path, text: str) -> None:
    """
    Write a config at 0600 inside a 0700 directory.

    Args:
        path: Where the config goes
        text: The rendered config

    Raises:
        OSError: If the write fails, in which case any existing file is left as it was
    """
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(directory, CONFIG_DIR_MODE)

    write_file_safely(path, text.encode("utf-8"), mode=CONFIG_FILE_MODE)
    logger.info("Wrote WireGuard config", path=str(path))


def key_protection_notice(path: Path) -> str:
    """
    Say what the file mode does and does not guarantee for a config holding a private key.

    On Windows the mode bits only ever toggled the read-only attribute, so telling the
    operator the file is protected would be false. The caller prints this next to the path.

    Args:
        path: The config that was written

    Returns:
        A sentence to show the operator
    """
    if os.name == "nt":
        return (
            f"{path} holds a private key. Windows ignores the 0600 file mode, so the only "
            f"thing protecting it is the Windows permissions it inherits from its folder. "
            f"Anyone who can read this user profile can read the key."
        )

    return (
        f"{path} holds a private key. It is mode 0600 inside a 0700 directory, so only "
        f"this user account can read it."
    )


def _hub_firewall_lines(topology: Topology) -> list[str]:
    """
    The hub's PostUp and PostDown rules.

    Two separate things have to be true before one spoke can reach another, and most guides
    only mention the first: forwarding has to be on, and the FORWARD chain has to accept
    traffic that arrives on the tunnel and leaves on the tunnel. Any host with a
    default-deny FORWARD chain needs the second rule, which includes anything running
    Docker. A sysctl set here lasts until reboot, so a permanent hub wants it in
    /etc/sysctl.d as well.

    Args:
        topology: The star being rendered

    Returns:
        The config lines, or an empty list when nothing is needed
    """
    lines: list[str] = []
    is_ipv6 = topology.tunnel_network.version == 6
    firewall = "ip6tables" if is_ipv6 else "iptables"

    if topology.forward_between_spokes:
        forwarding = (
            "net.ipv6.conf.all.forwarding=1" if is_ipv6 else "net.ipv4.ip_forward=1"
        )
        lines.extend(
            [
                "",
                "# Spoke-to-spoke traffic arrives on the tunnel and leaves on the tunnel",
                f"PostUp = sysctl -qw {forwarding}",
                f"PostUp = {firewall} -A FORWARD -i %i -o %i -j ACCEPT",
                f"PostDown = {firewall} -D FORWARD -i %i -o %i -j ACCEPT",
            ]
        )

    if topology.masquerade_interface:
        out = checked_interface(
            _checked_config_value(
                topology.masquerade_interface, "wireguard.masquerade_interface"
            )
        )
        network = topology.tunnel_network
        lines.extend(
            [
                "",
                "# Full-tunnel spokes reach the internet through this address",
                f"PostUp = {firewall} -t nat -A POSTROUTING -s {network} -o {out} -j MASQUERADE",
                f"PostDown = {firewall} -t nat -D POSTROUTING -s {network} -o {out} -j MASQUERADE",
            ]
        )

    return lines


def _gateway_forwarding_lines(peer: Peer) -> list[str]:
    """
    Turn on forwarding for a spoke that advertises a LAN.

    A site gateway that cannot forward is reachable itself while everything behind it is
    not. The FORWARD rule between the tunnel and the LAN is left to the host, because its
    interface name and its firewall are not known here, and on OpenWRT it has to come from
    UCI or fw4 will regenerate the ruleset and wipe it.

    Args:
        peer: The spoke whose config is being built

    Returns:
        The config lines, or an empty list when the peer advertises nothing
    """
    if not peer.routes:
        return []

    families = {route.version for route in peer.routes}
    lines = ["", "# This peer forwards for the subnets it advertises"]
    if 4 in families:
        lines.append("PostUp = sysctl -qw net.ipv4.ip_forward=1")
    if 6 in families:
        lines.append("PostUp = sysctl -qw net.ipv6.conf.all.forwarding=1")
    lines.append("# The firewall still has to allow forwarding between this interface and the LAN")
    return lines


def _host_network(address: TunnelAddress) -> str:
    """
    Write a single address the way AllowedIPs and a spoke Address field want it.

    Args:
        address: The peer address

    Returns:
        The address with a single-host prefix, /32 or /128
    """
    prefix = 32 if address.version == 4 else 128
    return f"{address}/{prefix}"


def _sorted_networks(networks: set[TunnelNetwork]) -> tuple[TunnelNetwork, ...]:
    """
    Put networks in a stable order so a config only changes when the topology does.

    Args:
        networks: The networks to order

    Returns:
        The same networks, IPv4 first, then by address and prefix length
    """
    return tuple(
        sorted(networks, key=lambda n: (n.version, n.network_address.packed, n.prefixlen))
    )
