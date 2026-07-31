"""
Tunnel address allocation.

WireGuard does not police duplicate addresses, and this is the reason this module exists.
Handing peer B an address peer A already holds moves it silently: B works, A is left
holding nothing, and neither `wg` nor `wg-quick` reports anything. Overlapping ranges of
different lengths do coexist, longest prefix winning, so only an exact duplicate is fatal
and it is the case with no warning attached. Uniqueness is enforced here because nothing
underneath will catch the mistake.

Only stdlib `ipaddress` is used, so this works the same on Windows.
"""

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

# One tunnel address, of either family
TunnelAddress = IPv4Address | IPv6Address
# The range a tunnel hands addresses out of
TunnelNetwork = IPv4Network | IPv6Network


@dataclass(frozen=True)
class AddressClaim:
    """One tunnel address and the name of the peer holding it."""

    address: TunnelAddress
    peer: str


class AddressTaken(ValueError):
    """Raised when an address is already held by a different peer."""

    def __init__(self, address: TunnelAddress, holder: str) -> None:
        super().__init__(
            f"Tunnel address {address} is already assigned to peer '{holder}'. "
            f"WireGuard would hand the address to the new peer without an error and leave "
            f"'{holder}' with no address at all."
        )
        self.address = address
        self.holder = holder


class NetworkFull(ValueError):
    """Raised when every usable address in the tunnel network is already claimed."""

    def __init__(self, network: TunnelNetwork, capacity: int) -> None:
        super().__init__(
            f"Tunnel network {network} is full: all {capacity} usable addresses are "
            f"assigned. A larger network means reissuing every existing peer config, so "
            f"pick the size before the peers exist."
        )
        self.network = network
        self.capacity = capacity


def parse_network(text: str) -> TunnelNetwork:
    """
    Parse a tunnel network written in CIDR form.

    Host bits are rejected rather than masked off, so `10.9.0.1/24` is an error and not a
    silent `10.9.0.0/24`. Somebody writing that meant an address, and the difference decides
    which peers exist.

    Args:
        text: The network in CIDR form, for example "10.9.0.0/24"

    Returns:
        The parsed network

    Raises:
        ValueError: If the text is not a network in CIDR form
    """
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as e:
        raise ValueError(f"'{text}' is not a network in CIDR form: {e}") from e


def parse_address(text: str) -> TunnelAddress:
    """
    Parse a single tunnel address.

    Args:
        text: The address, for example "10.9.0.2"

    Returns:
        The parsed address

    Raises:
        ValueError: If the text is not an IP address
    """
    try:
        return ipaddress.ip_address(text)
    except ValueError as e:
        raise ValueError(f"'{text}' is not an IP address: {e}") from e


def usable_address_count(network: TunnelNetwork) -> int:
    """
    Count the addresses a peer can actually be given.

    This matches what `network.hosts()` yields: IPv4 loses its network and broadcast
    addresses, IPv6 loses the subnet-router anycast address, and the point-to-point sizes
    (/31 and /127, and the single-host sizes) lose neither.

    Args:
        network: The tunnel network

    Returns:
        How many addresses can be assigned
    """
    if network.prefixlen >= network.max_prefixlen - 1:
        return network.num_addresses
    if isinstance(network, IPv4Network):
        return network.num_addresses - 2
    return network.num_addresses - 1


def usable_addresses(network: TunnelNetwork) -> Iterable[TunnelAddress]:
    """
    Yield every assignable address in the network, lowest first.

    Args:
        network: The tunnel network

    Returns:
        The assignable addresses, in ascending order
    """
    return network.hosts()


def next_free_address(
    network: TunnelNetwork, claims: Sequence[AddressClaim]
) -> TunnelAddress:
    """
    Return the lowest address in the network that nobody holds.

    Args:
        network: The tunnel network
        claims: Every address currently held, whoever holds it

    Returns:
        The lowest free address

    Raises:
        NetworkFull: If every usable address is claimed
    """
    taken = {claim.address for claim in claims}
    for candidate in usable_addresses(network):
        if candidate not in taken:
            return candidate

    raise NetworkFull(network, usable_address_count(network))


def claim_address(
    network: TunnelNetwork,
    claims: Sequence[AddressClaim],
    peer: str,
    requested: TunnelAddress | None = None,
) -> AddressClaim:
    """
    Give a peer an address, either the one it asked for or the next one free.

    Asking again for an address the same peer already holds is not a conflict and returns
    that claim unchanged, which is what regenerating a peer's config does.

    Args:
        network: The tunnel network
        claims: Every address currently held, whoever holds it
        peer: The name of the peer being given an address
        requested: A specific address to assign, or None to take the next free one

    Returns:
        The new claim

    Raises:
        AddressTaken: If another peer already holds the requested address
        NetworkFull: If no address is free and none was requested
        ValueError: If the requested address is outside the tunnel network
    """
    if requested is not None and requested not in network:
        raise ValueError(f"Address {requested} is outside the tunnel network {network}")

    address = requested if requested is not None else next_free_address(network, claims)

    for claim in claims:
        if claim.address == address:
            if claim.peer == peer:
                return claim
            raise AddressTaken(address, claim.peer)

    return AddressClaim(address=address, peer=peer)
