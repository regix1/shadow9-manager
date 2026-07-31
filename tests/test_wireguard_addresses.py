"""Tests for tunnel address allocation."""

import pytest

from shadow9.wireguard.addresses import (
    AddressClaim,
    AddressTaken,
    NetworkFull,
    claim_address,
    next_free_address,
    parse_address,
    parse_network,
    usable_address_count,
    usable_addresses,
)


def claim(address: str, peer: str) -> AddressClaim:
    return AddressClaim(address=parse_address(address), peer=peer)


def test_parse_network_accepts_cidr() -> None:
    network = parse_network("10.9.0.0/24")

    assert str(network) == "10.9.0.0/24"
    assert network.prefixlen == 24


def test_parse_network_rejects_an_address_with_host_bits() -> None:
    # masking this off silently would turn "10.9.0.1/24" into a whole network, and whoever
    # wrote it meant an address
    with pytest.raises(ValueError, match="not a network in CIDR form"):
        parse_network("10.9.0.1/24")


def test_parse_network_rejects_nonsense() -> None:
    with pytest.raises(ValueError, match="not a network in CIDR form"):
        parse_network("the office")


def test_parse_address_rejects_a_network() -> None:
    with pytest.raises(ValueError, match="not an IP address"):
        parse_address("10.9.0.0/24")


def test_first_address_in_an_empty_network() -> None:
    network = parse_network("10.9.0.0/24")

    assert str(next_free_address(network, [])) == "10.9.0.1"


def test_allocation_skips_addresses_already_held() -> None:
    network = parse_network("10.9.0.0/24")
    claims = [claim("10.9.0.1", "hub"), claim("10.9.0.2", "phone")]

    assert str(next_free_address(network, claims)) == "10.9.0.3"


def test_allocation_fills_a_gap_left_by_a_removed_peer() -> None:
    network = parse_network("10.9.0.0/24")
    claims = [claim("10.9.0.1", "hub"), claim("10.9.0.3", "router")]

    assert str(next_free_address(network, claims)) == "10.9.0.2"


def test_claiming_an_address_another_peer_holds_is_refused_and_names_that_peer() -> None:
    # WireGuard would take the address off the existing peer without an error anywhere, so
    # this refusal is the only thing that catches it
    network = parse_network("10.9.0.0/24")
    claims = [claim("10.9.0.2", "phone")]

    with pytest.raises(AddressTaken) as caught:
        claim_address(network, claims, "laptop", requested=parse_address("10.9.0.2"))

    assert caught.value.holder == "phone"
    assert "phone" in str(caught.value)
    assert "10.9.0.2" in str(caught.value)


def test_a_peer_may_claim_the_address_it_already_holds() -> None:
    network = parse_network("10.9.0.0/24")
    claims = [claim("10.9.0.2", "phone")]

    result = claim_address(network, claims, "phone", requested=parse_address("10.9.0.2"))

    assert result == claims[0]


def test_claiming_an_address_outside_the_tunnel_network_is_refused() -> None:
    network = parse_network("10.9.0.0/24")

    with pytest.raises(ValueError, match="outside the tunnel network"):
        claim_address(network, [], "phone", requested=parse_address("192.168.1.5"))


def test_a_full_network_is_refused_and_names_the_network_and_its_size() -> None:
    network = parse_network("10.9.0.0/29")
    claims = [
        claim(str(address), f"peer{index}")
        for index, address in enumerate(usable_addresses(network))
    ]

    with pytest.raises(NetworkFull) as caught:
        claim_address(network, claims, "one-too-many")

    assert "10.9.0.0/29" in str(caught.value)
    assert "6" in str(caught.value)
    assert caught.value.capacity == 6


def test_the_next_free_address_is_claimed_when_none_is_requested() -> None:
    network = parse_network("10.9.0.0/24")
    claims = [claim("10.9.0.1", "hub")]

    result = claim_address(network, claims, "phone")

    assert str(result.address) == "10.9.0.2"
    assert result.peer == "phone"


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        ("10.9.0.0/24", 254),
        ("10.9.0.0/29", 6),
        ("10.9.0.0/31", 2),
        ("10.9.0.1/32", 1),
        ("10.9.0.0/16", 65534),
        ("fd09:9::/64", 2**64 - 1),
        ("fd09:9::/127", 2),
        ("fd09:9::1/128", 1),
    ],
)
def test_usable_address_count_matches_what_is_assignable(cidr: str, expected: int) -> None:
    assert usable_address_count(parse_network(cidr)) == expected


def test_ipv6_allocation_works_the_same_way() -> None:
    network = parse_network("fd09:9::/64")
    claims = [claim("fd09:9::1", "hub")]

    result = claim_address(network, claims, "phone")

    assert str(result.address) == "fd09:9::2"
