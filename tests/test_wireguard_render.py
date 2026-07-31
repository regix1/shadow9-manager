"""Tests for the tunnel topology and the wg-quick configs rendered from it."""

import inspect
import os
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import pytest

from shadow9.wireguard import addresses, keys, render
from shadow9.wireguard.addresses import parse_address, parse_network
from shadow9.wireguard.keys import Keypair, generate_keypair
from shadow9.wireguard.render import (
    CONFIG_DIR_MODE,
    CONFIG_FILE_MODE,
    DEFAULT_MTU,
    Peer,
    PeerRole,
    Topology,
    config_path,
    key_protection_notice,
    render_hub_config,
    render_spoke_config,
    spoke_allowed_ips,
    write_config,
)

HUB_ENDPOINT = "203.0.113.10:51820"
LAN = "192.168.1.0/24"


@pytest.fixture
def hub_keys() -> Keypair:
    return generate_keypair()


@pytest.fixture
def device_keys() -> Keypair:
    return generate_keypair()


@pytest.fixture
def gateway_keys() -> Keypair:
    return generate_keypair()


@pytest.fixture
def hub(hub_keys: Keypair) -> Peer:
    return Peer(
        name="hub",
        public_key=hub_keys.public_key,
        address=parse_address("10.9.0.1"),
        role=PeerRole.HUB,
        endpoint=HUB_ENDPOINT,
        keepalive=None,
    )


@pytest.fixture
def device(device_keys: Keypair) -> Peer:
    return Peer(
        name="phone",
        public_key=device_keys.public_key,
        address=parse_address("10.9.0.2"),
        role=PeerRole.DEVICE,
    )


@pytest.fixture
def gateway(gateway_keys: Keypair) -> Peer:
    return Peer(
        name="router",
        public_key=gateway_keys.public_key,
        address=parse_address("10.9.0.3"),
        role=PeerRole.NODE,
        routes=(parse_network(LAN),),
    )


@pytest.fixture
def star(hub: Peer, device: Peer) -> Topology:
    return Topology(tunnel_network=parse_network("10.9.0.0/24"), hub=hub, spokes=(device,))


@dataclass
class RecordingLogger:
    """Stands in for the module logger and keeps everything it was handed."""

    calls: list[str] = field(default_factory=list)

    def _record(self, *args: Any, **kwargs: Any) -> None:
        self.calls.append(f"{args} {kwargs}")

    def debug(self, *args: Any, **kwargs: Any) -> None:
        self._record(*args, **kwargs)

    def info(self, *args: Any, **kwargs: Any) -> None:
        self._record(*args, **kwargs)

    def warning(self, *args: Any, **kwargs: Any) -> None:
        self._record(*args, **kwargs)

    def error(self, *args: Any, **kwargs: Any) -> None:
        self._record(*args, **kwargs)

    def everything_said(self) -> str:
        return " ".join(self.calls)


def test_hub_interface_carries_the_fields_wg_quick_needs(
    star: Topology, hub_keys: Keypair
) -> None:
    config = render_hub_config(star, hub_keys.private_key)
    interface = config.split("[Peer]")[0]

    assert config.startswith("[Interface]\n")
    assert "Address = 10.9.0.1/24" in interface
    assert "ListenPort = 51820" in interface
    assert f"PrivateKey = {hub_keys.private_key}" in interface


def test_hub_has_one_peer_section_per_enrolled_peer(
    star: Topology, hub_keys: Keypair, gateway: Peer, device_keys: Keypair, gateway_keys: Keypair
) -> None:
    config = render_hub_config(star.with_peer(gateway), hub_keys.private_key)

    assert config.count("[Peer]") == 2
    assert f"PublicKey = {device_keys.public_key}" in config
    assert f"PublicKey = {gateway_keys.public_key}" in config


def test_hub_gives_each_peer_only_its_own_address(star: Topology, hub_keys: Keypair) -> None:
    # inbound this list is access control, and it is the only thing stopping one spoke
    # claiming to be another, so it stays as narrow as it can be
    config = render_hub_config(star, hub_keys.private_key)

    assert "AllowedIPs = 10.9.0.2/32" in config
    assert "10.9.0.0/24" not in config.split("[Peer]")[1]


def test_hub_routes_a_gateway_lan_to_that_gateway(
    star: Topology, hub_keys: Keypair, gateway: Peer
) -> None:
    config = render_hub_config(star.with_peer(gateway), hub_keys.private_key)

    assert f"AllowedIPs = 10.9.0.3/32, {LAN}" in config


def test_hub_sets_no_keepalive_on_any_peer(star: Topology, hub_keys: Keypair) -> None:
    # the hub is the reachable side and has no NAT mapping to hold open, so a keepalive
    # here would only wake every phone on the tunnel every 25 seconds
    config = render_hub_config(star, hub_keys.private_key)

    assert "PersistentKeepalive" not in config


def test_hub_turns_on_forwarding_so_two_spokes_can_reach_each_other(
    star: Topology, hub_keys: Keypair
) -> None:
    config = render_hub_config(star, hub_keys.private_key)

    assert "PostUp = sysctl -qw net.ipv4.ip_forward=1" in config
    assert "PostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT" in config
    assert "PostDown = iptables -D FORWARD -i %i -o %i -j ACCEPT" in config


def test_hub_masquerades_only_when_an_outward_interface_is_named(
    star: Topology, hub_keys: Keypair
) -> None:
    assert "MASQUERADE" not in render_hub_config(star, hub_keys.private_key)

    with_nat = replace(star, masquerade_interface="eth0")
    config = render_hub_config(with_nat, hub_keys.private_key)

    assert "-t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE" in config


def test_a_disabled_peer_is_left_out_of_the_hub_config(
    star: Topology, hub_keys: Keypair, device: Peer
) -> None:
    disabled = replace(device, enabled=False)

    config = render_hub_config(star.with_peer(disabled), hub_keys.private_key)

    assert "[Peer]" not in config


def test_spoke_has_the_hub_as_its_only_peer(
    star: Topology, device: Peer, device_keys: Keypair, hub_keys: Keypair
) -> None:
    config = render_spoke_config(star, device, device_keys.private_key)

    assert config.count("[Peer]") == 1
    assert f"PublicKey = {hub_keys.public_key}" in config
    assert f"Endpoint = {HUB_ENDPOINT}" in config
    assert "Address = 10.9.0.2/32" in config
    assert f"PrivateKey = {device_keys.private_key}" in config
    assert "PersistentKeepalive = 25" in config


def test_a_spoke_cannot_be_rendered_before_the_hub_has_an_endpoint(
    star: Topology, hub: Peer, device: Peer, device_keys: Keypair
) -> None:
    unreachable = star.with_peer(replace(hub, endpoint=None))

    with pytest.raises(ValueError, match="no endpoint"):
        render_spoke_config(unreachable, device, device_keys.private_key)


def test_split_tunnel_is_the_default_for_a_device(
    star: Topology, device: Peer, device_keys: Keypair
) -> None:
    config = render_spoke_config(star, device, device_keys.private_key)

    assert "AllowedIPs = 10.9.0.0/24" in config
    assert "0.0.0.0/0" not in config


def test_full_tunnel_sends_everything_through_the_hub(
    star: Topology, device: Peer, device_keys: Keypair
) -> None:
    config = render_spoke_config(star, device, device_keys.private_key, full_tunnel=True)

    assert "AllowedIPs = 0.0.0.0/0, ::/0" in config
    assert "10.9.0.0/24" not in config.split("[Peer]")[1]


def test_a_new_gateway_reaches_every_config_that_already_existed(
    star: Topology, device: Peer, device_keys: Keypair, gateway: Peer
) -> None:
    # the reason the topology exists. A LAN behind one peer is only reachable if every
    # other peer routes that range into the tunnel, so adding a gateway rewrites configs
    # that were already handed out
    before = render_spoke_config(star, device, device_keys.private_key)
    assert LAN not in before

    after = render_spoke_config(star.with_peer(gateway), device, device_keys.private_key)

    assert f"AllowedIPs = 10.9.0.0/24, {LAN}" in after


def test_a_gateway_does_not_route_its_own_lan_into_the_tunnel(
    star: Topology, gateway: Peer, gateway_keys: Keypair
) -> None:
    # that range is on the other side of its own interface, and sending it to the hub
    # would break the LAN it is meant to be serving
    config = render_spoke_config(star.with_peer(gateway), gateway, gateway_keys.private_key)

    assert LAN not in config
    assert "AllowedIPs = 10.9.0.0/24" in config


def test_a_gateway_turns_on_forwarding_for_the_subnets_it_advertises(
    star: Topology, gateway: Peer, gateway_keys: Keypair
) -> None:
    config = render_spoke_config(star.with_peer(gateway), gateway, gateway_keys.private_key)

    assert "PostUp = sysctl -qw net.ipv4.ip_forward=1" in config


def test_a_disabled_gateway_stops_advertising_its_lan(
    star: Topology, device: Peer, device_keys: Keypair, gateway: Peer
) -> None:
    topology = star.with_peer(replace(gateway, enabled=False))

    config = render_spoke_config(topology, device, device_keys.private_key)

    assert LAN not in config


def test_two_gateways_both_reach_every_other_peer(
    star: Topology, device: Peer, device_keys: Keypair, gateway: Peer
) -> None:
    second = Peer(
        name="office",
        public_key=generate_keypair().public_key,
        address=parse_address("10.9.0.4"),
        role=PeerRole.NODE,
        routes=(parse_network("192.168.7.0/24"),),
    )

    topology = star.with_peer(gateway).with_peer(second)
    entries = spoke_allowed_ips(topology, device)

    assert entries == ("10.9.0.0/24", LAN, "192.168.7.0/24")


def test_removing_a_gateway_takes_its_lan_back_out(
    star: Topology, device: Peer, device_keys: Keypair, gateway: Peer
) -> None:
    topology = star.with_peer(gateway).without_peer("router")

    assert LAN not in render_spoke_config(topology, device, device_keys.private_key)


def test_find_peer_covers_the_hub_and_the_spokes(star: Topology, device: Peer) -> None:
    assert star.find_peer("hub") is star.hub
    assert star.find_peer("phone") == device
    assert star.find_peer("nobody") is None


def test_mtu_defaults_to_the_documented_value_and_can_be_changed(
    star: Topology, hub_keys: Keypair, device: Peer, device_keys: Keypair
) -> None:
    assert f"MTU = {DEFAULT_MTU}" in render_hub_config(star, hub_keys.private_key)
    assert f"MTU = {DEFAULT_MTU}" in render_spoke_config(star, device, device_keys.private_key)

    pppoe = replace(star, mtu=1412)
    assert "MTU = 1412" in render_spoke_config(pppoe, device, device_keys.private_key)

    unset = replace(star, mtu=None)
    assert "MTU" not in render_spoke_config(unset, device, device_keys.private_key)


def test_a_spoke_gets_a_resolver_only_when_one_is_configured(
    star: Topology, device: Peer, device_keys: Keypair
) -> None:
    assert "DNS" not in render_spoke_config(star, device, device_keys.private_key)

    with_dns = replace(star, dns="10.9.0.1")
    assert "DNS = 10.9.0.1" in render_spoke_config(with_dns, device, device_keys.private_key)


def test_no_private_key_reaches_a_config_it_does_not_belong_in(
    star: Topology,
    hub_keys: Keypair,
    device: Peer,
    device_keys: Keypair,
    gateway: Peer,
    gateway_keys: Keypair,
) -> None:
    topology = star.with_peer(gateway)

    hub_config = render_hub_config(topology, hub_keys.private_key)
    device_config = render_spoke_config(topology, device, device_keys.private_key)
    gateway_config = render_spoke_config(topology, gateway, gateway_keys.private_key)

    assert hub_keys.private_key not in device_config
    assert hub_keys.private_key not in gateway_config
    assert device_keys.private_key not in hub_config
    assert device_keys.private_key not in gateway_config
    assert gateway_keys.private_key not in hub_config
    assert gateway_keys.private_key not in device_config

    # each config carries exactly one private key, its own
    for config, own in (
        (hub_config, hub_keys),
        (device_config, device_keys),
        (gateway_config, gateway_keys),
    ):
        assert config.count("PrivateKey") == 1
        assert own.private_key in config


def test_nothing_on_this_path_logs_a_private_key(
    star: Topology,
    hub_keys: Keypair,
    device: Peer,
    device_keys: Keypair,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded = RecordingLogger()
    monkeypatch.setattr(render, "logger", recorded)

    hub_config = render_hub_config(star, hub_keys.private_key)
    render_spoke_config(star, device, device_keys.private_key)
    write_config(tmp_path / "wg0.conf", hub_config)

    assert recorded.calls, "the write logs, so there is something here to check"
    assert hub_keys.private_key not in recorded.everything_said()
    assert device_keys.private_key not in recorded.everything_said()


def test_key_generation_and_address_allocation_do_not_log_at_all() -> None:
    # neither module holds a logger, so there is no path by which a private key or a peer
    # address can reach a log file from them
    for module in (keys, addresses):
        assert "logger" not in inspect.getsource(module)


def test_a_written_config_is_readable_only_by_its_owner(tmp_path: Path) -> None:
    # wg-quick warns about a world-readable config and then uses it anyway, and its check
    # passes as soon as the parent directory is locked down, so neither mode is trusted
    path = tmp_path / "wireguard" / "wg0.conf"

    write_config(path, "[Interface]\n")

    assert path.read_text(encoding="utf-8") == "[Interface]\n"
    if os.name == "nt":
        # Windows never had these bits, which is why the notice says so out loud
        assert "Windows ignores the 0600 file mode" in key_protection_notice(path)
    else:
        assert stat.S_IMODE(path.stat().st_mode) == CONFIG_FILE_MODE
        assert stat.S_IMODE(path.parent.stat().st_mode) == CONFIG_DIR_MODE
        assert "only" in key_protection_notice(path)


def test_the_key_protection_notice_names_the_file(tmp_path: Path) -> None:
    path = tmp_path / "wg0.conf"

    notice = key_protection_notice(path)

    assert str(path) in notice
    assert "private key" in notice


def test_config_path_lands_under_the_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(render, "get_config_dir", lambda: tmp_path)

    assert config_path("wg0") == tmp_path / "wireguard" / "wg0.conf"


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "sub/dir", "back\\slash"])
def test_config_path_refuses_a_name_that_is_not_a_plain_name(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(render, "get_config_dir", lambda: tmp_path)

    with pytest.raises(ValueError):
        config_path(name)


def test_an_ipv6_tunnel_renders_the_ipv6_forwarding_rules(hub_keys: Keypair) -> None:
    hub = Peer(
        name="hub",
        public_key=hub_keys.public_key,
        address=parse_address("fd09:9::1"),
        role=PeerRole.HUB,
        endpoint="[2001:db8::1]:51820",
        keepalive=None,
    )
    topology = Topology(tunnel_network=parse_network("fd09:9::/64"), hub=hub)

    config = render_hub_config(topology, hub_keys.private_key)

    assert "Address = fd09:9::1/64" in config
    assert "PostUp = sysctl -qw net.ipv6.conf.all.forwarding=1" in config
    assert "PostUp = ip6tables -A FORWARD -i %i -o %i -j ACCEPT" in config
