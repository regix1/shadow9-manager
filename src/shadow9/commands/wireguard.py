"""
WireGuard commands for the Shadow9 CLI.

Three commands carry the whole feature:

    hub:   shadow9 wg init
    node:  shadow9 wg join --url http://203.0.113.10:8081 --token <token> --route 192.168.1.0/24
    hub:   shadow9 wg device add phone

`--route` is what makes a node a site gateway rather than one more endpoint, and it is the
reason every peer's config is reissued whenever any peer changes: a LAN behind one node is
only reachable if every other peer routes that range into the tunnel.

`init` brings up the hub and prepares the host to restore it after a reboot. `join` brings
up a node configuring itself. `--no-apply` turns that off for either command.
"""

import hmac
import json
import os
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Optional, cast

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..auth import AuthManager
from ..config import Config
from ..paths import lock_file, write_file_safely
from .user import open_store
from ..services.wireguard_service import (
    BINARY_DOWNLOAD_NOTICE,
    CLEARTEXT_API_NOTICE,
    DEFAULT_TOKEN_HOURS,
    ENROLLMENT_PROTOCOL,
    HUB_PEER_NAME,
    NODE_ARCHITECTURES,
    NODE_PACKAGE_FILES,
    NODE_RELEASE_URL,
    PeerFieldsMissing,
    RenderedConfigs,
    TokenRejected,
    address_claims,
    checked_endpoint,
    checked_peer_name,
    clear_peer,
    create_join_token,
    hub_address,
    hub_key_path,
    hub_public_key,
    is_public_endpoint_host,
    join_mac_key,
    load_hub_private_key,
    load_topology,
    masquerade_interface_from_config,
    peer_from_credential,
    node_binary_checksums,
    node_package_checksums,
    regenerate_configs,
    read_stored_config,
    render_peer_config,
    request_mac,
    response_mac,
    save_hub_private_key,
    save_peer,
    split_join_token,
)
from ..wireguard import (
    DEFAULT_INTERFACE,
    AddressTaken,
    Keypair,
    NetworkFull,
    Peer,
    PeerRole,
    Topology,
    TunnelAddress,
    TunnelNetwork,
    claim_address,
    checked_interface,
    config_path,
    derive_public_key,
    generate_keypair,
    is_valid_key,
    key_protection_notice,
    parse_address,
    parse_network,
    write_config,
)

console = Console()

DEFAULT_CONFIG_FILE = "config/config.yaml"

# Where the enrollment endpoint sits under the public listener
ENROLL_PATH = "/api/wireguard/enroll"

# Used when nothing better is known, matching the API's own default
DEFAULT_API_PORT = 8080

WIREGUARD_SYSTEM_DIR = Path("/etc/wireguard")
FORWARDING_CONFIG = Path("/etc/sysctl.d/99-shadow9.conf")
COMMAND_TIMEOUT = 60


@dataclass(frozen=True)
class ActivationStep:
    """What one host activation step established."""

    label: str
    ready: bool
    detail: str


@dataclass(frozen=True)
class ActivationResult:
    """The four host facts an operator needs after hub setup."""

    interface: ActivationStep
    boot: ActivationStep
    forwarding: ActivationStep
    forward_rule: ActivationStep


@dataclass(frozen=True)
class OutwardAddress:
    """An address selected from the host's route table and where it came from."""

    address: str
    source: str


class Host:
    """The checked host operations used while activating WireGuard."""

    def is_windows(self) -> bool:
        return os.name == "nt"

    def is_root(self) -> bool:
        geteuid = getattr(os, "geteuid", None)
        return geteuid is not None and geteuid() == 0

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def outward_address(self) -> OutwardAddress | None:
        """Return the local address used for an internet route, without sending traffic."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("1.1.1.1", 53))
                address = str(probe.getsockname()[0])
        except Exception:
            return None
        return OutwardAddress(address, "this host's route to the internet")

    def interfaces(self) -> set[str] | None:
        """Return live WireGuard interfaces, or None when this host cannot answer."""
        binary = self.which("wg")
        if binary is None:
            return None
        try:
            result = self.run([binary, "show", "interfaces"])
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        return set(result.stdout.split())

    def run(
        self, command: list[str], timeout: int = COMMAND_TIMEOUT
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


_host = Host()

wg_app = typer.Typer(
    name="wg",
    help="WireGuard star topology: one hub, many spokes",
    no_args_is_help=True,
)

device_app = typer.Typer(
    name="device",
    help="Devices that cannot run shadow9, such as a phone",
    no_args_is_help=True,
)

hub_app = typer.Typer(
    name="hub",
    help="Hub-wide settings",
    no_args_is_help=True,
)

wg_app.add_typer(device_app, name="device")
wg_app.add_typer(hub_app, name="hub")


def post_enrollment(
    url: str, body: dict[str, object], timeout: float = 15.0
) -> tuple[int, dict[str, object]]:
    """
    Send an enrollment request to a hub and read its answer.

    stdlib only, on purpose: this runs on a node that may be a router, and the whole point
    of the node side is that it needs very little.

    Args:
        url: The hub's enrollment URL, for example `http://203.0.113.10:8081`
        body: The enrollment request
        timeout: Seconds to wait for the hub

    Returns:
        The HTTP status and the parsed JSON answer. A body that is not JSON comes back as
        an empty answer, which the caller reports as the hub not answering properly

    Raises:
        OSError: If the hub could not be reached at all
    """
    endpoint = url.rstrip("/") + ENROLL_PATH
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _decoded(response.read())
    except urllib.error.HTTPError as error:
        return error.code, _decoded(error.read())
    except urllib.error.URLError as error:
        raise OSError(f"Could not reach the hub at {endpoint}: {error.reason}") from error


@wg_app.command("init")
def init(
    endpoint: Annotated[
        Optional[str],
        typer.Option("--endpoint", "-e", help="host:port peers dial, e.g. 203.0.113.10:51820"),
    ] = None,
    network: Annotated[
        Optional[str], typer.Option("--network", "-n", help="Tunnel network, e.g. 10.9.0.0/24")
    ] = None,
    port: Annotated[
        Optional[int], typer.Option("--port", "-p", help="UDP port the hub listens on")
    ] = None,
    interface: Annotated[
        str, typer.Option("--interface", "-i", help="WireGuard interface name for this hub")
    ] = DEFAULT_INTERFACE,
    masquerade: Annotated[
        Optional[str],
        typer.Option(
            "--masquerade-interface",
            help="The hub's internet-facing interface, needed only for full-tunnel peers",
        ),
    ] = None,
    api_url: Annotated[
        Optional[str], typer.Option("--api-url", help="The enrollment URL nodes should call")
    ] = None,
    token_hours: Annotated[
        int, typer.Option("--token-hours", help="How long the printed join token lasts")
    ] = DEFAULT_TOKEN_HOURS,
    force: Annotated[
        bool, typer.Option("--force", help="Replace an existing hub key. Every peer must rejoin")
    ] = False,
    no_apply: Annotated[
        bool, typer.Option("--no-apply", help="Write the config but do not bring it up")
    ] = False,
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Set this host up as the hub: generate its key, write its config, print a join command.

    Examples:
        shadow9 wg init --endpoint 203.0.113.10:51820
        shadow9 wg init -e 203.0.113.10:51820 --network 10.9.0.0/24 --masquerade-interface eth0
    """
    try:
        _init_impl(
            endpoint,
            network,
            port,
            interface,
            masquerade,
            api_url,
            token_hours,
            force,
            no_apply,
            config,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")


def _init_impl(
    endpoint: Optional[str],
    network: Optional[str],
    port: Optional[int],
    interface: str,
    masquerade: Optional[str],
    api_url: Optional[str],
    token_hours: int,
    force: bool,
    no_apply: bool,
    config: str,
) -> None:
    """Implementation of init."""
    config_file = Path(config)
    cfg = _load_config(config)

    try:
        cfg = _with_hub_settings(cfg, endpoint, network, port, interface)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error

    clash = _interface_clash(cfg.wireguard.interface)
    if clash is not None:
        console.print(f"[red]{clash}[/red]")
        raise typer.Exit(1)

    if endpoint is None and not cfg.wireguard.hub_endpoint:
        if not _terminal_is_interactive():
            console.print(
                "[red]--endpoint is required when wg init is not running in an interactive "
                "terminal.[/red]"
            )
            raise typer.Exit(1)
        from ..wizards.wireguard_setup import _prompt_endpoint

        prompted = _prompt_endpoint(cfg)
        if prompted is None:
            console.print("[yellow]Cancelled. Nothing was written.[/yellow]")
            raise typer.Exit(1)
        cfg.wireguard.hub_endpoint = prompted

    with lock_file(hub_key_path()):
        outward = masquerade or _stored_masquerade_interface(cfg.wireguard.interface)
        existing = load_hub_private_key()
        if existing is not None and not force:
            # Naming the peers that would actually break is the difference between a
            # warning an operator can act on and one that just sounds frightening. A
            # half-finished setup leaves a key behind with nothing enrolled against it,
            # which is the common case for hitting this at all.
            enrolled = sorted(
                credential.username
                for credential in _auth_manager(cfg).list_credentials()
                if peer_from_credential(credential) is not None
            )
            console.print("[yellow]This host already has a WireGuard hub key.[/yellow]")
            if enrolled:
                console.print(
                    f"[dim]{len(enrolled)} peer(s) name it and would have to rejoin: "
                    f"{', '.join(enrolled)}. Replace it with --force.[/dim]"
                )
            else:
                console.print(
                    "[dim]No peers are enrolled against it, so replacing it costs "
                    "nothing. Re-run with --force.[/dim]"
                )
            raise typer.Exit(1)

        keypair = generate_keypair()
        try:
            key_file = save_hub_private_key(keypair.private_key)
        except OSError as error:
            console.print(f"[red]Could not write the hub key: {error}[/red]")
            raise typer.Exit(1) from error

        auth_manager = _auth_manager(cfg)
        auth_manager.reload_credentials()

        try:
            topology = load_topology(
                cfg, auth_manager.list_credentials(), keypair.public_key, outward
            )
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
            raise typer.Exit(1) from error

        try:
            rendered = regenerate_configs(
                topology, keypair.private_key, auth_manager.list_credentials()
            )
        except OSError as error:
            console.print(f"[red]Could not write the hub config: {error}[/red]")
            raise typer.Exit(1) from error

        _save_config(cfg, config_file)

    console.print(
        Panel(
            f"[bold green]WireGuard hub ready[/bold green]\n\n"
            f"Tunnel network: [cyan]{topology.tunnel_network}[/cyan]\n"
            f"Hub address:    [cyan]{topology.hub.address}[/cyan]\n"
            f"Listen port:    [cyan]{topology.listen_port}/udp[/cyan]\n"
            f"Endpoint:       [cyan]{topology.hub.endpoint or 'not set'}[/cyan]\n"
            f"Public key:     [cyan]{keypair.public_key}[/cyan]",
            title="shadow9 wg init",
            border_style="green",
        )
    )

    console.print(f"[green]Hub key:[/green] {key_file}")
    console.print(f"[green]Hub config:[/green] {rendered.written[0]}")
    # The rendered config carries the private key too, and it is the file wg-quick reads,
    # so the notice names that one. hub.key sits in the same directory under the same mode
    console.print(f"[yellow]{key_protection_notice(rendered.written[0])}[/yellow]")
    console.print(f"[dim]{key_file} holds the same key and the same protection.[/dim]")

    if no_apply:
        activation = _manual_activation(rendered.written[0], topology.tunnel_network.version)
    else:
        activation = _activate_hub(rendered.written[0], topology.tunnel_network.version)

    if not topology.hub.endpoint:
        console.print(
            "\n[yellow]No endpoint is set, so no peer config can be rendered yet.[/yellow]"
        )
        console.print("[dim]Set it with: shadow9 wg hub set-endpoint <address:port>[/dim]")
    elif not is_public_endpoint_host(topology.hub.endpoint):
        console.print(
            f"\n[yellow]{topology.hub.endpoint} is not an address the internet routes to, "
            f"so only peers that can already reach it will connect.[/yellow]"
        )

    if outward is None:
        console.print(
            "\n[dim]No masquerade interface set. Full-tunnel peers will reach the tunnel "
            "but not the internet. Rerun with --masquerade-interface <name> if you want "
            "them to.[/dim]"
        )

    _print_activation_summary(activation)
    _print_cleartext_notice()
    _print_join_command(cfg, keypair.public_key, api_url, token_hours)


@wg_app.command("token")
def token(
    hours: Annotated[
        int, typer.Option("--hours", help="How long the token lasts")
    ] = DEFAULT_TOKEN_HOURS,
    api_url: Annotated[
        Optional[str], typer.Option("--api-url", help="The enrollment URL nodes should call")
    ] = None,
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Issue another join token and print the command a node should run.

    A token is good for one join and then refused, so every node needs its own.
    """
    cfg = _load_config(config)
    public_key = _require_hub_public_key()

    try:
        _print_join_command(cfg, public_key, api_url, hours)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error
    except OSError as error:
        console.print(f"[red]Could not record the token: {error}[/red]")
        raise typer.Exit(1) from error

    _print_cleartext_notice()


@wg_app.command("join")
def join(
    url: Annotated[str, typer.Option("--url", "-u", help="The hub's enrollment URL")],
    join_token: Annotated[str, typer.Option("--token", "-t", help="The join token")],
    route: Annotated[
        Optional[list[str]],
        typer.Option("--route", "-r", help="A subnet behind this node, repeatable"),
    ] = None,
    name: Annotated[
        Optional[str], typer.Option("--name", help="Peer name, defaults to this host's name")
    ] = None,
    interface: Annotated[
        str, typer.Option("--interface", "-i", help="Interface name for the config file")
    ] = DEFAULT_INTERFACE,
    no_apply: Annotated[
        bool, typer.Option("--no-apply", help="Write the config but do not bring it up")
    ] = False,
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Join this machine to a hub's tunnel.

    This machine generates its own keypair and sends only the public half, so the hub never
    holds this node's private key. The answer is checked against the hub public key in the
    token before the final config replaces the saved key.

    Examples:
        shadow9 wg join --url http://203.0.113.10:8081 --token <token>
        shadow9 wg join -u http://203.0.113.10:8081 -t <token> --route 192.168.1.0/24
    """
    try:
        _join_impl(url, join_token, route or [], name, interface, no_apply, config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")


def _join_impl(
    url: str,
    join_token: str,
    routes: list[str],
    name: Optional[str],
    interface: str,
    no_apply: bool,
    config: str,
) -> None:
    """Implementation of join."""
    cfg = _load_config(config)

    try:
        token_id, secret, expected_hub_key = split_join_token(join_token)
    except TokenRejected as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error

    try:
        peer_name = checked_peer_name(name or socket.gethostname())
        parsed_routes = tuple(parse_network(entry) for entry in routes)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error

    path = config_path(interface)
    try:
        keypair, staged_key = _join_keypair(path)
    except (OSError, ValueError) as error:
        console.print(f"[red]Could not save the node's private key: {error}[/red]")
        raise typer.Exit(1) from error

    console.print(f"[cyan]Joining {url} as '{peer_name}'...[/cyan]")
    sent_routes = [str(entry) for entry in parsed_routes]
    nonce = secrets.token_urlsafe(32)
    mac_key = join_mac_key(secret)
    try:
        status, answer = post_enrollment(
            url,
            {
                "token_id": token_id,
                "name": peer_name,
                "public_key": keypair.public_key,
                "routes": sent_routes,
                "nonce": nonce,
                "mac": request_mac(
                    mac_key,
                    token_id,
                    peer_name,
                    keypair.public_key,
                    sent_routes,
                    nonce,
                ),
            },
        )
    except OSError as error:
        console.print(f"[red]{error}[/red]")
        console.print(f"[dim]The private key is saved at {staged_key}; rerun this command.[/dim]")
        raise typer.Exit(1) from error

    if status != 200:
        console.print(f"[red]The hub refused the join ({status}): {_detail(answer)}[/red]")
        console.print(f"[dim]The private key is saved at {staged_key}; rerun this command.[/dim]")
        raise typer.Exit(1)

    try:
        answered_key, hub_endpoint, tunnel_network, address, mtu, keepalive, answered_mac = (
            _enrollment_answer(answer)
        )
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        console.print(f"[dim]The private key is saved at {staged_key}; rerun this command.[/dim]")
        raise typer.Exit(1) from error

    expected_mac = response_mac(
        mac_key,
        nonce,
        cast(str, answer["address"]),
        cast(str, answer["hub_public_key"]),
        cast(str, answer["hub_endpoint"]),
        cast(str, answer["tunnel_network"]),
        cast(int, answer["mtu"]),
        cast(int, answer["keepalive"]),
        cast(int, answer["protocol"]),
    )
    if not hmac.compare_digest(answered_mac, expected_mac):
        console.print(
            f"[bold red]The hub's answer has an invalid MAC. The private key is saved at "
            f"{staged_key}, but no tunnel config was written.[/bold red]"
        )
        raise typer.Exit(1)

    if answered_key != expected_hub_key:
        console.print(
            Panel(
                "[bold red]This is not the hub the token names.[/bold red]\n\n"
                f"The token expects: [cyan]{expected_hub_key}[/cyan]\n"
                f"The answer came from: [red]{answered_key}[/red]\n\n"
                f"The private key is saved at {staged_key}, but no tunnel config was written. "
                "This hub is a bare address over plain HTTP, so "
                "the public key in the join token is the only thing that says which hub is "
                "the real one, and this answer is not it. Either something is in the path "
                "between this machine and the hub, or the token belongs to a different hub.",
                title="Join refused",
                border_style="red",
            )
        )
        raise typer.Exit(1)

    self_peer = Peer(
        name=peer_name,
        public_key=keypair.public_key,
        address=address,
        role=PeerRole.NODE,
        routes=parsed_routes,
        keepalive=keepalive or None,
    )
    topology = Topology(
        tunnel_network=tunnel_network,
        hub=Peer(
            name=HUB_PEER_NAME,
            public_key=answered_key,
            address=hub_address(tunnel_network),
            role=PeerRole.HUB,
            endpoint=hub_endpoint,
            keepalive=None,
        ),
        spokes=(self_peer,),
        listen_port=cfg.wireguard.listen_port,
        mtu=mtu,
        dns=", ".join(cfg.wireguard.dns) if cfg.wireguard.dns else None,
        interface=interface,
    )

    try:
        text = render_peer_config(topology, self_peer, keypair.private_key)
        write_config(path, text)
        if staged_key.exists():
            staged_key.unlink()
    except (OSError, ValueError) as error:
        console.print(f"[red]Could not write the config: {error}[/red]")
        raise typer.Exit(1) from error

    console.print(
        Panel(
            f"[bold green]Joined[/bold green]\n\n"
            f"Peer name:      [cyan]{peer_name}[/cyan]\n"
            f"Tunnel address: [cyan]{address}[/cyan]\n"
            f"Hub endpoint:   [cyan]{hub_endpoint}[/cyan]\n"
            f"Advertising:    [cyan]{', '.join(routes) if routes else 'nothing'}[/cyan]",
            title="shadow9 wg join",
            border_style="green",
        )
    )
    console.print(f"[green]Config:[/green] {path}")
    console.print(f"[yellow]{key_protection_notice(path)}[/yellow]")

    if no_apply:
        console.print(f"\n[dim]Bring it up with: wg-quick up {path}[/dim]")
    else:
        _apply_config(path)
    _print_cleartext_notice()


def _join_keypair(path: Path) -> tuple[Keypair, Path]:
    """Load or save a node key before enrollment can commit its public half."""
    staged = path.with_suffix(".join.key")
    if staged.exists():
        private_key = staged.read_text(encoding="utf-8").strip()
        if not is_valid_key(private_key):
            raise ValueError(f"{staged} does not hold a WireGuard private key")
        return Keypair(private_key, derive_public_key(private_key)), staged

    stored = read_stored_config(path)
    if stored is not None:
        return Keypair(stored.private_key, derive_public_key(stored.private_key)), staged

    keypair = generate_keypair()
    write_config(staged, keypair.private_key + "\n")
    return keypair, staged


@device_app.command("add")
def device_add(
    name: Annotated[str, typer.Argument(help="A name for the device, e.g. phone")],
    full_tunnel: Annotated[
        bool, typer.Option("--full-tunnel", help="Send all this device's traffic through the hub")
    ] = False,
    obfuscate: Annotated[
        bool,
        typer.Option("--obfuscate", help="Add AmneziaWG junk packets, needs an AmneziaWG client"),
    ] = False,
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Add a device that cannot run shadow9, such as a phone.

    The hub generates this device's keypair, because a QR code has to carry the private key
    for the device to scan. That is the opposite of a node join, where the node makes its
    own key and the hub never sees the private half.

    Examples:
        shadow9 wg device add phone
        shadow9 wg device add laptop --full-tunnel
    """
    try:
        _device_add_impl(name, full_tunnel, obfuscate, config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")


def _device_add_impl(name: str, full_tunnel: bool, obfuscate: bool, config: str) -> None:
    """Implementation of device add."""
    cfg = _load_config(config)

    try:
        peer_name = checked_peer_name(name)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error

    with lock_file(hub_key_path()):
        hub_private_key = _require_hub_private_key()
        auth_manager = _auth_manager(cfg)
        auth_manager.reload_credentials()
        topology = _topology(cfg, auth_manager, derive_public_key(hub_private_key))

        if topology.find_peer(peer_name) is not None:
            console.print(f"[red]'{peer_name}' is already a peer on this hub.[/red]")
            console.print(f"[dim]Remove it first: shadow9 wg remove {peer_name}[/dim]")
            raise typer.Exit(1)

        if not topology.hub.endpoint:
            console.print(
                "[red]This hub has no endpoint, so a device would have nothing to dial.[/red]"
            )
            console.print("[dim]Set it with: shadow9 wg hub set-endpoint <address:port>[/dim]")
            raise typer.Exit(1)

        try:
            claim = claim_address(topology.tunnel_network, address_claims(topology), peer_name)
        except (AddressTaken, NetworkFull) as error:
            console.print(f"[red]{error}[/red]")
            raise typer.Exit(1) from error

        keypair = generate_keypair()
        peer = Peer(
            name=peer_name,
            public_key=keypair.public_key,
            address=claim.address,
            role=PeerRole.DEVICE,
            keepalive=cfg.wireguard.keepalive or None,
        )

        try:
            save_peer(
                auth_manager,
                peer,
                private_key=keypair.private_key,
                full_tunnel=full_tunnel,
                obfuscated=obfuscate,
            )
        except (PeerFieldsMissing, ValueError) as error:
            console.print(f"[red]{error}[/red]")
            raise typer.Exit(1) from error

        topology = topology.with_peer(peer)

        try:
            text = render_peer_config(
                topology,
                peer,
                keypair.private_key,
                full_tunnel=full_tunnel,
                obfuscate=obfuscate,
            )
            path = config_path(peer_name)
            write_config(path, text)
            rendered = regenerate_configs(
                topology, hub_private_key, auth_manager.list_credentials()
            )
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
            raise typer.Exit(1) from error
        except OSError as error:
            console.print(f"[red]Could not write the config: {error}[/red]")
            raise typer.Exit(1) from error

    console.print(
        Panel(
            f"[bold green]Device added[/bold green]\n\n"
            f"Name:           [cyan]{peer_name}[/cyan]\n"
            f"Tunnel address: [cyan]{peer.address}[/cyan]\n"
            f"Tunnel mode:    [cyan]{'full' if full_tunnel else 'split'}[/cyan]\n"
            f"Obfuscation:    [cyan]{'on' if obfuscate else 'off'}[/cyan]",
            title="shadow9 wg device add",
            border_style="green",
        )
    )

    console.print(
        "[bold yellow]The hub generated this device's private key and wrote it into the "
        "config below.[/bold yellow]"
    )
    console.print(
        "[dim]That is unlike a node join, where the node makes its own key and the hub "
        "never sees it. A QR code has to carry the private key for a phone to scan it, so "
        "for a device there is no way round it. The phone must scan the new QR before a "
        "later topology change takes effect.[/dim]"
    )
    console.print(f"[green]Config:[/green] {path}")
    console.print(f"[yellow]{key_protection_notice(path)}[/yellow]")

    _report_qr(text, peer_name)

    if full_tunnel and topology.masquerade_interface is None:
        console.print(
            "\n[yellow]This device routes everything through the hub, but the hub is not "
            "set to NAT that traffic out, so it will reach the tunnel and nothing "
            "else.[/yellow]"
        )
        console.print(
            "[dim]Fix it with: shadow9 wg init --force --masquerade-interface <name>[/dim]"
        )

    _report_rendered(rendered)
    _print_cleartext_notice()


@wg_app.command("list")
def list_peers(
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Show every peer with its role, address and the subnets it advertises.
    """
    cfg = _load_config(config)
    public_key = _require_hub_public_key()
    auth_manager = _auth_manager(cfg)
    topology = _topology(cfg, auth_manager, public_key)

    handshakes = _latest_handshakes(topology.interface)

    table = Table(title="WireGuard peers", show_header=True)
    table.add_column("Name", style="cyan")
    table.add_column("Role", style="magenta")
    table.add_column("Address", style="green")
    table.add_column("Routes")
    table.add_column("State")
    table.add_column("Last handshake")

    for peer in (topology.hub, *topology.spokes):
        table.add_row(
            peer.name,
            peer.role.value,
            str(peer.address),
            ", ".join(str(route) for route in peer.routes) or "-",
            "enabled" if peer.enabled else "disabled",
            handshakes.get(peer.public_key, "unknown"),
        )

    console.print(table)
    console.print(
        f"[dim]Tunnel network {topology.tunnel_network}, hub endpoint "
        f"{topology.hub.endpoint or 'not set'}[/dim]"
    )
    _print_cleartext_notice()


@wg_app.command("remove")
def remove(
    name: Annotated[str, typer.Argument(help="The peer to remove")],
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Do not ask first")] = False,
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Remove a peer and reissue every config it appeared in.

    The user record stays. Only the peer fields and the peer's own config file go, so a
    user who was also a proxy login keeps that login.
    """
    cfg = _load_config(config)
    hub_private_key = _require_hub_private_key()

    if not yes and not typer.confirm(f"Remove peer '{name}'?", default=False):
        console.print("[yellow]Cancelled[/yellow]")
        return

    with lock_file(hub_key_path()):
        auth_manager = _auth_manager(cfg)
        auth_manager.reload_credentials()
        topology = _topology(cfg, auth_manager, derive_public_key(hub_private_key))

        peer = topology.find_peer(name)
        if peer is None or peer.role is PeerRole.HUB:
            console.print(f"[red]'{name}' is not a peer on this hub.[/red]")
            raise typer.Exit(1)

        clear_peer(auth_manager, name)

        removed_files: list[Path] = []
        for path in (config_path(name), config_path(name).with_suffix(".svg")):
            if path.exists():
                path.unlink()
                removed_files.append(path)

        try:
            rendered = regenerate_configs(
                topology.without_peer(name),
                hub_private_key,
                auth_manager.list_credentials(),
            )
        except OSError as error:
            console.print(
                f"[red]The peer was removed but a config could not be written: {error}[/red]"
            )
            raise typer.Exit(1) from error

    console.print(f"[green]Removed peer '{name}'.[/green] The user record was kept.")
    for path in removed_files:
        console.print(f"[dim]Deleted {path}[/dim]")

    _report_rendered(rendered)
    _print_cleartext_notice()


@hub_app.command("set-endpoint")
def hub_set_endpoint(
    address: Annotated[str, typer.Argument(help="host:port peers should dial")],
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Change the address peers dial, and reissue every config that names it.

    The hub is an address with no name in front of it, so there is no indirection to change
    somewhere else. Without this command an address change means hand-editing every peer.
    """
    cfg = _load_config(config)
    hub_private_key = _require_hub_private_key()

    try:
        endpoint = checked_endpoint(address)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error

    with lock_file(hub_key_path()):
        previous = cfg.wireguard.hub_endpoint or "not set"
        cfg.wireguard.hub_endpoint = endpoint

        auth_manager = _auth_manager(cfg)
        auth_manager.reload_credentials()
        topology = _topology(cfg, auth_manager, derive_public_key(hub_private_key))

        try:
            rendered = regenerate_configs(
                topology, hub_private_key, auth_manager.list_credentials()
            )
        except OSError as error:
            console.print(f"[red]Could not write a config: {error}[/red]")
            raise typer.Exit(1) from error

        _save_config(cfg, Path(config))

    console.print(f"[green]Hub endpoint is now {endpoint}[/green] [dim](was {previous})[/dim]")
    if not is_public_endpoint_host(endpoint):
        console.print(
            f"[yellow]{endpoint} is not an address the internet routes to, so only peers "
            f"that can already reach it will connect.[/yellow]"
        )

    _report_rendered(rendered)
    _print_cleartext_notice()


@wg_app.command("setup")
def setup(
    config: Annotated[
        str, typer.Option("--config", "-c", help="Path to configuration file")
    ] = DEFAULT_CONFIG_FILE,
) -> None:
    """
    Walk through hub setup with prompts instead of flags.
    """
    from ..wizards.wireguard_setup import run_wireguard_setup_wizard

    try:
        run_wireguard_setup_wizard(config)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
    except typer.Abort:
        pass


def register_wireguard_commands(app: typer.Typer) -> None:
    """
    Register the WireGuard command group with the main app.

    Args:
        app: The top-level Typer application
    """
    app.add_typer(wg_app, name="wg")


def _load_config(config: str) -> Config:
    """
    Load configuration the way every other command group does.

    Args:
        config: The path given on the command line

    Returns:
        The loaded configuration, or the defaults when there is no file
    """
    path = Path(config)
    return Config.load(path) if path.exists() else Config()


def _save_config(cfg: Config, config_file: Path) -> None:
    """
    Write the configuration back, reporting rather than raising when it cannot be written.

    Args:
        cfg: The configuration to save
        config_file: Where to write it
    """
    try:
        cfg.save(config_file)
    except OSError as error:
        console.print(f"[yellow]Could not save {config_file}: {error}[/yellow]")
        console.print("[dim]The settings apply to this run but were not kept.[/dim]")


def _terminal_is_interactive() -> bool:
    """Whether init can safely ask for a missing answer."""
    return sys.stdin.isatty()


def _interface_clash(interface: str, host: Host | None = None) -> str | None:
    """Explain what already owns an interface name, or return None when it is free."""
    machine = host or _host
    if machine.is_windows():
        return None

    interfaces = machine.interfaces()
    if interfaces is not None and interface in interfaces:
        return (
            f"WireGuard interface '{interface}' already exists on this host. "
            "Choose another name with --interface."
        )

    system_config = WIREGUARD_SYSTEM_DIR / f"{interface}.conf"
    try:
        occupied = system_config.exists() or system_config.is_symlink()
    except OSError:
        occupied = False
    if occupied:
        return f"{system_config} already exists. Choose another name with --interface."
    return None


def _with_hub_settings(
    cfg: Config,
    endpoint: Optional[str],
    network: Optional[str],
    port: Optional[int],
    interface: str,
) -> Config:
    """
    Apply the settings `init` was given, refusing a value the config system rejects.

    Args:
        cfg: The loaded configuration
        endpoint: The endpoint peers dial, or None to keep what is configured
        network: The tunnel network, or None to keep what is configured
        port: The UDP listen port, or None to keep what is configured
        interface: The WireGuard interface name

    Returns:
        The configuration with the hub turned on

    Raises:
        ValueError: If any value is not one the hub can use
    """
    if endpoint is not None:
        cfg.wireguard.hub_endpoint = checked_endpoint(
            endpoint, port if port is not None else cfg.wireguard.listen_port
        )
    if network is not None:
        parse_network(network)
        cfg.wireguard.tunnel_network = network
    if port is not None:
        cfg.wireguard.listen_port = port
    cfg.wireguard.interface = checked_interface(interface)

    cfg.wireguard.enabled = True

    errors = cfg.validate()
    wireguard_errors = [error for error in errors if "wireguard" in error.lower()]
    if wireguard_errors:
        raise ValueError("; ".join(wireguard_errors))

    return cfg


def _auth_manager(cfg: Config) -> AuthManager:
    """
    Open the credential store the same way the other command groups do.

    Args:
        cfg: The loaded configuration

    Returns:
        The store
    """
    return open_store(
        cfg, "Peers are kept on the user records, so this cannot read them without the key."
    )


def _topology(cfg: Config, auth_manager: AuthManager, public_key: str) -> Topology:
    """
    Build the star, reporting a bad stored value rather than raising a traceback.

    Args:
        cfg: The loaded configuration
        auth_manager: The credential store
        public_key: The hub's public key

    Returns:
        The topology
    """
    try:
        return load_topology(
            cfg,
            auth_manager.list_credentials(),
            public_key,
            _stored_masquerade_interface(cfg.wireguard.interface),
        )
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(1) from error


def _stored_masquerade_interface(interface: str) -> Optional[str]:
    """
    Recover the hub's outward interface from the config it wrote last time.

    Returns:
        The interface name, or None when the hub does not NAT anything out
    """
    path = config_path(interface)
    if not path.exists():
        return None
    try:
        return masquerade_interface_from_config(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def _require_hub_private_key() -> str:
    """
    The hub's private key, or a message and a non-zero exit.

    Returns:
        The base64 private key
    """
    private_key = load_hub_private_key()
    if private_key is None:
        console.print("[red]This host is not a WireGuard hub yet.[/red]")
        console.print("[dim]Run: shadow9 wg init --endpoint <address:port>[/dim]")
        raise typer.Exit(1)
    return private_key


def _require_hub_public_key() -> str:
    """
    The hub's public key, or a message and a non-zero exit.

    Returns:
        The base64 public key
    """
    public_key = hub_public_key()
    if public_key is None:
        console.print("[red]This host is not a WireGuard hub yet.[/red]")
        console.print("[dim]Run: shadow9 wg init --endpoint <address:port>[/dim]")
        raise typer.Exit(1)
    return public_key


def _print_join_command(cfg: Config, public_key: str, api_url: Optional[str], hours: int) -> None:
    """
    Issue a token and print the whole command a node should run.

    Args:
        cfg: The loaded configuration
        public_key: The hub's public key, which becomes the token's last part
        api_url: The enrollment URL, or None to work one out
        hours: How long the token lasts

    Raises:
        ValueError: If the lifetime is not positive
        OSError: If the token could not be recorded
    """
    issued = create_join_token(public_key, hours)
    url = api_url or _api_url(cfg)

    _print_firewall_notice(cfg)
    _print_node_download(url)

    console.print("\n[bold]Run this on the machine that should join:[/bold]")
    # soft_wrap keeps the token on one line. A token rich has folded across a terminal
    # width is a token that gets copied wrong, and the error it produces is "not
    # recognised by this hub", which points nowhere near the real cause
    console.print(f"  [cyan]shadow9 wg join --url {url} --token {issued}[/cyan]", soft_wrap=True)
    console.print(
        f"[dim]Add --route 192.168.1.0/24 if that machine is a gateway for a LAN. "
        f"The token is good for one join and expires in {hours} hours.[/dim]"
    )
    console.print(
        "[dim]The last part of the token is the hub's public key, which is not a "
        "secret. It is there so the joining machine can tell this hub from anything else "
        "answering that address.[/dim]"
    )


def _print_node_download(url: str) -> None:
    """
    Show package installation when the full package set is stored on this hub.

    A git clone has no CI packages. In that case the command names the release instead of
    printing a hub URL that cannot work. Raw binaries remain a labelled fallback, and are
    offered only when every supported architecture is present.

    Args:
        url: The enrollment URL a node should call
    """
    package_checksums = node_package_checksums()
    package_names = {name for packages in NODE_PACKAGE_FILES.values() for name in packages.values()}
    packages_complete = set(package_checksums) == package_names

    binary_checksums = node_binary_checksums()
    binaries_complete = set(binary_checksums) == set(NODE_ARCHITECTURES)

    if packages_complete:
        console.print(
            "\n[bold]Install the OpenWrt package before joining. The pasted commands "
            "detect this router's release and architecture:[/bold]"
        )
        console.print("\n[bold]1. Pick and download the package, on the router[/bold]")
        console.print('  [cyan]release="$(. /etc/openwrt_release; echo "$DISTRIB_RELEASE")"[/cyan]')
        console.print('  [cyan]machine="$(uname -m)"[/cyan]')
        console.print('  [cyan]case "$machine" in[/cyan]')
        console.print("  [cyan]  x86_64) architecture=amd64 ;;[/cyan]")
        console.print("  [cyan]  aarch64) architecture=arm64 ;;[/cyan]")
        console.print("  [cyan]  mips*) architecture=mipsle ;;[/cyan]")
        console.print('  [cyan]  *) echo "No shadow9 package matches $machine"; exit 1 ;;[/cyan]')
        console.print("  [cyan]esac[/cyan]")
        console.print('  [cyan]case "$release" in[/cyan]')
        console.print("  [cyan]  24.10.*) package=ipk ;;[/cyan]")
        console.print("  [cyan]  25.12.*) package=apk ;;[/cyan]")
        console.print(
            '  [cyan]  *) echo "No shadow9 package matches OpenWrt $release"; exit 1 ;;[/cyan]'
        )
        console.print("  [cyan]esac[/cyan]")
        console.print(
            f'  [cyan]wget -O "/tmp/shadow9-node.$package" '
            f'"{url}/api/wireguard/node/package/$package/$architecture"[/cyan]',
            soft_wrap=True,
        )

        console.print("\n[bold]2. Check the package before installing it[/bold]")
        console.print('  [cyan]sha256sum "/tmp/shadow9-node.$package"[/cyan]')
        console.print("  [bold]Its checksum has to match the selected package below:[/bold]")
        for package in ("ipk", "apk"):
            for architecture in NODE_ARCHITECTURES:
                name = NODE_PACKAGE_FILES[package][architecture]
                console.print(
                    f"    [dim]{package}/{architecture}[/dim]  {package_checksums[name]}",
                    soft_wrap=True,
                )

        console.print("\n[bold]3. Install the downloaded package[/bold]")
        console.print('  [cyan]case "$package" in[/cyan]')
        console.print("  [cyan]  ipk) opkg install /tmp/shadow9-node.ipk ;;[/cyan]")
        console.print("  [cyan]  apk) apk add --allow-untrusted /tmp/shadow9-node.apk ;;[/cyan]")
        console.print("  [cyan]esac[/cyan]")
        console.print(f"[yellow]{BINARY_DOWNLOAD_NOTICE}[/yellow]")
    else:
        console.print(
            "\n[yellow]This hub does not hold the complete OpenWrt package set, so a "
            "package command pointing at it would fail. Download the package that exactly "
            "matches the router from:[/yellow]"
        )
        console.print(f"  [cyan]{NODE_RELEASE_URL}[/cyan]", soft_wrap=True)

    if not binaries_complete:
        return

    console.print(
        "\n[bold]Raw binary fallback only when the release has no package for this "
        "router's architecture:[/bold]"
    )
    console.print('  [cyan]case "$(uname -m)" in[/cyan]')
    console.print("  [cyan]  x86_64) architecture=amd64 ;;[/cyan]")
    console.print("  [cyan]  aarch64) architecture=arm64 ;;[/cyan]")
    console.print("  [cyan]  mips*) architecture=mipsle ;;[/cyan]")
    console.print('  [cyan]  *) echo "No shadow9 binary matches $(uname -m)"; exit 1 ;;[/cyan]')
    console.print("  [cyan]esac[/cyan]")
    console.print(
        f"  [cyan]wget -O /tmp/shadow9-node "
        f'"{url}/api/wireguard/node/linux-$architecture"[/cyan]',
        soft_wrap=True,
    )
    console.print("  [cyan]sha256sum /tmp/shadow9-node[/cyan]")
    console.print("  [bold]It has to print the checksum for the selected architecture:[/bold]")
    for architecture in NODE_ARCHITECTURES:
        console.print(
            f"    [dim]linux-{architecture}[/dim]  {binary_checksums[architecture]}",
            soft_wrap=True,
        )
    console.print("  [cyan]mv /tmp/shadow9-node /usr/sbin/shadow9-node[/cyan]")
    console.print("  [cyan]chmod +x /usr/sbin/shadow9-node[/cyan]")
    console.print(
        "[yellow]This fallback does not install WireGuard tools, the LuCI protocol, the "
        "boot service, or the conffile that preserves node identity across sysupgrade. "
        "Use a package whenever one exists.[/yellow]"
    )
    if not packages_complete:
        console.print(f"[yellow]{BINARY_DOWNLOAD_NOTICE}[/yellow]")


def _api_url(cfg: Config) -> str:
    """
    Work out the enrollment URL a node should call.

    Args:
        cfg: The loaded configuration

    Returns:
        A URL, with a placeholder host when nothing better is known
    """
    host = "HUB-ADDRESS"
    if cfg.wireguard.hub_endpoint:
        host = cfg.wireguard.hub_endpoint.rsplit(":", 1)[0]

    return f"http://{host}:{cfg.wireguard.enrollment_port}"


def _api_port() -> int:
    """
    The port the admin API is configured to listen on.

    Returns:
        The configured port, or the API's own default when nothing is configured
    """
    try:
        from ..core.api_config import load_api_config
        from ..paths import get_config_dir

        path = get_config_dir() / "api.yaml"
        if not path.exists():
            return DEFAULT_API_PORT
        configured = load_api_config(path).get("port")
        return int(configured) if configured else DEFAULT_API_PORT
    except (OSError, ValueError, TypeError, ImportError):
        return DEFAULT_API_PORT


def _print_cleartext_notice() -> None:
    """Say that the enrollment token crosses the network in the clear."""
    console.print(f"\n[yellow]{CLEARTEXT_API_NOTICE}[/yellow]")


def _print_firewall_notice(cfg: Config) -> None:
    """Print the two inbound openings a joining node needs."""
    api_port = _api_port()
    firewall = (
        "ip6tables" if parse_network(cfg.wireguard.tunnel_network).version == 6 else "iptables"
    )
    console.print(
        "\n[bold]Open these inbound ports in both the host firewall and the cloud "
        "firewall or security group:[/bold]"
    )
    console.print(
        f"  [cyan]TCP {cfg.wireguard.enrollment_port}[/cyan] for enrollment, refresh, "
        "and node downloads"
    )
    console.print(f"  [cyan]UDP {cfg.wireguard.listen_port}[/cyan] for the WireGuard tunnel")
    console.print(
        f"[bold]Keep TCP {api_port}, the admin API port, closed to the internet.[/bold]"
    )
    console.print(
        f"[dim]The generated hub config requires {firewall} for forwarding and NAT rules.[/dim]"
    )


def _report_rendered(rendered: RenderedConfigs) -> None:
    """
    Say what was reissued and who the hub cannot reach.

    Args:
        rendered: What `regenerate_configs` did
    """
    console.print(f"\n[green]Reissued {len(rendered.written)} config file(s).[/green]")
    for path in rendered.written:
        console.print(f"[dim]  {path}[/dim]")

    if rendered.unmanaged:
        console.print(
            f"\n[yellow]These peers hold their own config, so this hub could not update "
            f"them: {', '.join(rendered.unmanaged)}[/yellow]"
        )
        console.print(
            "[dim]A node generates its own key, so the hub has never held one. Each node "
            "picks this up on its next refresh or boot. To apply it now, run "
            "'/usr/sbin/shadow9-node refresh' on that node.[/dim]"
        )


def _report_qr(config_text: str, name: str) -> None:
    """
    Write a QR of this config, or say what is missing.

    Args:
        config_text: The config the device should scan
        name: The peer name, which names the QR file
    """
    art = qr_terminal_art(config_text)
    if art is None:
        console.print("\n[yellow]No QR code: the 'qr' extra is not installed.[/yellow]")
        # The extra's name is in square brackets, which rich reads as markup and eats
        console.print(
            "[dim]The config above is complete and can be moved to the device by hand. "
            r"For a scannable code: pip install 'shadow9-manager\[qr]'[/dim]"
        )
        return

    path = config_path(name).with_suffix(".svg")
    try:
        written = write_qr(config_text, path)
    except OSError as error:
        console.print(f"[yellow]Could not write the QR file: {error}[/yellow]")
        written = None

    console.print("\n[bold]Scan this with the WireGuard app:[/bold]")
    console.print(art)
    if written is not None:
        console.print(f"[green]QR:[/green] {written}")
        console.print(
            f"[yellow]That image carries the private key just as the config does. "
            f"{key_protection_notice(written)}[/yellow]"
        )


def qr_terminal_art(text: str) -> Optional[str]:
    """
    Draw a QR code as text, for scanning straight off the terminal.

    Args:
        text: What the code should carry

    Returns:
        The drawing, or None when the optional `qr` extra is not installed
    """
    try:
        import io

        import qrcode
    except ImportError:
        return None

    code = qrcode.QRCode(border=1)
    code.add_data(text)
    code.make(fit=True)
    buffer = io.StringIO()
    code.print_ascii(out=buffer)
    return buffer.getvalue()


def write_qr(text: str, path: Path) -> Optional[Path]:
    """
    Write a QR code as an SVG, at 0600 because it carries the same key the config does.

    Args:
        text: What the code should carry
        path: Where the SVG goes

    Returns:
        The file written, or None when the optional `qr` extra is not installed

    Raises:
        OSError: If the file could not be written
    """
    try:
        import io

        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None

    code = qrcode.QRCode(border=1)
    code.add_data(text)
    code.make(fit=True)
    image = code.make_image(image_factory=qrcode.image.svg.SvgPathImage)

    buffer = io.BytesIO()
    image.save(buffer)
    write_config(path, buffer.getvalue().decode("utf-8"))
    return path


def _root_command(command: str, host: Host) -> str:
    """Add sudo only when the current process is not already root."""
    return command if host.is_root() else f"sudo {command}"


def _manual_activation(
    path: Path, network_version: int, host: Host | None = None
) -> ActivationResult:
    """Print every host command skipped by ``--no-apply``."""
    machine = host or _host
    interface = path.stem
    target = WIREGUARD_SYSTEM_DIR / path.name
    setting = (
        "net.ipv6.conf.all.forwarding=1"
        if network_version == 6
        else "net.ipv4.ip_forward=1"
    )
    firewall = "ip6tables" if network_version == 6 else "iptables"
    up_command = _root_command(f"wg-quick up {shlex.quote(str(path))}", machine)
    mkdir_command = _root_command(f"mkdir -p {WIREGUARD_SYSTEM_DIR}", machine)
    link_command = _root_command(shlex.join(["ln", "-s", str(path), str(target)]), machine)
    boot_command = _root_command(f"systemctl enable wg-quick@{interface}", machine)
    forward_command = _root_command(f"sysctl -w {setting}", machine)
    persist_command = f"echo '{setting}' | {_root_command(f'tee {FORWARDING_CONFIG}', machine)}"
    check_command = _root_command(
        f"{firewall} -C FORWARD -i {interface} -o {interface} -j ACCEPT", machine
    )
    add_command = _root_command(
        f"{firewall} -A FORWARD -i {interface} -o {interface} -j ACCEPT", machine
    )

    console.print("\n[yellow]Host activation was skipped by --no-apply.[/yellow]")
    console.print(f"[dim]Bring it up with: {up_command}[/dim]")
    console.print(f"[dim]Create the boot link: {mkdir_command}[/dim]")
    console.print(f"[dim]Then: {link_command}[/dim]")
    console.print(f"[dim]Then: {boot_command}[/dim]")
    console.print(f"[dim]Turn forwarding on: {forward_command}[/dim]")
    console.print(f"[dim]Persist it: {persist_command}[/dim]")
    console.print(f"[dim]Allow spoke traffic: {check_command} || {add_command}[/dim]")

    skipped = "not changed (--no-apply)"
    return ActivationResult(
        interface=ActivationStep("Interface up", False, skipped),
        boot=ActivationStep("Starts at boot", False, skipped),
        forwarding=ActivationStep("Forwarding on", False, skipped),
        forward_rule=ActivationStep("FORWARD rule present", False, skipped),
    )


def _activate_hub(
    path: Path, network_version: int, host: Host | None = None
) -> ActivationResult:
    """Apply the four independent host changes needed by a hub."""
    machine = host or _host
    interface = path.stem
    return ActivationResult(
        interface=_apply_config(path, machine),
        boot=_enable_at_boot(path, machine),
        forwarding=_enable_forwarding(network_version, machine),
        forward_rule=_allow_forwarding(interface, network_version, machine),
    )


def _apply_config(path: Path, host: Host | None = None) -> ActivationStep:
    """
    Bring the tunnel up, or say exactly what to run when this host cannot.

    Args:
        path: The config to bring up
        host: Checked host operations, replaced by a stand-in in tests

    Returns:
        Whether the interface was brought up
    """
    machine = host or _host
    if machine.is_windows():
        console.print(
            f"\n[dim]Windows has no wg-quick. Import {path} into the WireGuard client.[/dim]"
        )
        return ActivationStep("Interface up", False, "import it in the WireGuard client")

    binary = machine.which("wg-quick")
    if binary is None:
        command = _root_command(f"wg-quick up {shlex.quote(str(path))}", machine)
        console.print("\n[yellow]wg-quick was not found, so the tunnel was not started.[/yellow]")
        console.print(f"[dim]Install wireguard-tools, then: {command}[/dim]")
        return ActivationStep("Interface up", False, "wg-quick was not found")

    console.print(f"\n[cyan]Bringing the tunnel up: wg-quick up {path}[/cyan]")
    try:
        result = machine.run([binary, "up", str(path)])
    except (OSError, subprocess.SubprocessError) as error:
        command = _root_command(f"wg-quick up {shlex.quote(str(path))}", machine)
        console.print(f"[yellow]Could not run wg-quick: {error}[/yellow]")
        console.print(f"[dim]Run it yourself: {command}[/dim]")
        return ActivationStep("Interface up", False, str(error))

    if result.returncode == 0:
        console.print("[green]Tunnel is up.[/green]")
        return ActivationStep("Interface up", True, "yes")

    detail = (
        result.stderr.strip() or result.stdout.strip() or f"wg-quick exited {result.returncode}"
    )
    console.print(f"[yellow]wg-quick exited {result.returncode}: {detail}[/yellow]")
    if not machine.is_root():
        command = _root_command(f"wg-quick up {shlex.quote(str(path))}", machine)
        console.print(f"[dim]Root may be needed. Try: {command}[/dim]")
    return ActivationStep("Interface up", False, detail)


def _enable_at_boot(path: Path, host: Host) -> ActivationStep:
    """Link the rendered config into systemd's location and enable its unit."""
    interface = path.stem
    target = WIREGUARD_SYSTEM_DIR / path.name
    mkdir_command = _root_command(f"mkdir -p {WIREGUARD_SYSTEM_DIR}", host)
    link_command = _root_command(shlex.join(["ln", "-s", str(path), str(target)]), host)
    enable_command = _root_command(f"systemctl enable wg-quick@{interface}", host)

    if host.is_windows():
        console.print("[yellow]Windows cannot enable the Linux wg-quick service.[/yellow]")
        console.print(f"[dim]On the Linux hub: {mkdir_command}[/dim]")
        console.print(f"[dim]Then: {link_command}[/dim]")
        console.print(f"[dim]Then: {enable_command}[/dim]")
        return ActivationStep("Starts at boot", False, "Linux systemd is not available")

    if target.exists() or target.is_symlink():
        if target.is_symlink() and target.resolve(strict=False) == path.resolve(strict=False):
            console.print(f"[green]Boot config link already points to {path}.[/green]")
        else:
            if target.is_symlink():
                try:
                    existing = f"a symbolic link to {target.readlink()}"
                except OSError:
                    existing = "an unreadable symbolic link"
            elif target.is_dir():
                existing = "a directory"
            else:
                existing = "a file"
            console.print(f"[yellow]{target} is already {existing}; it was left alone.[/yellow]")
            console.print(
                f"[dim]Start shadow9's config without replacing it: "
                f"{_root_command(f'wg-quick up {shlex.quote(str(path))}', host)}[/dim]"
            )
            return ActivationStep("Starts at boot", False, f"{target} already exists")
    elif not host.is_root():
        console.print("[yellow]Root is needed to install the boot config link.[/yellow]")
        console.print(f"[dim]Run: {mkdir_command}[/dim]")
        console.print(f"[dim]Then: {link_command}[/dim]")
        console.print(f"[dim]Then: {enable_command}[/dim]")
        return ActivationStep("Starts at boot", False, "root is required")
    else:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(path.resolve())
            console.print(f"[green]Boot config link:[/green] {target} -> {path.resolve()}")
        except OSError as error:
            console.print(f"[yellow]Could not create {target}: {error}[/yellow]")
            console.print(f"[dim]Run: {mkdir_command}[/dim]")
            console.print(f"[dim]Then: {link_command}[/dim]")
            console.print(f"[dim]Then: {enable_command}[/dim]")
            return ActivationStep("Starts at boot", False, "the config link was not created")

    binary = host.which("systemctl")
    if binary is None:
        console.print("[yellow]systemctl was not found, so start-at-boot was not enabled.[/yellow]")
        console.print(f"[dim]When systemd is available, run: {enable_command}[/dim]")
        return ActivationStep("Starts at boot", False, "systemctl was not found")

    try:
        result = host.run([binary, "enable", f"wg-quick@{interface}"])
    except (OSError, subprocess.SubprocessError) as error:
        console.print(f"[yellow]Could not run systemctl: {error}[/yellow]")
        console.print(f"[dim]Run it yourself: {enable_command}[/dim]")
        return ActivationStep("Starts at boot", False, "systemctl could not run")

    if result.returncode == 0:
        console.print(f"[green]wg-quick@{interface} will start at boot.[/green]")
        return ActivationStep("Starts at boot", True, "yes")

    console.print(f"[yellow]systemctl exited {result.returncode}: {result.stderr.strip()}[/yellow]")
    console.print(f"[dim]Try: {enable_command}[/dim]")
    return ActivationStep("Starts at boot", False, "systemd did not enable the unit")


def _persist_forwarding(setting: str, host: Host) -> ActivationStep:
    """Put the selected forwarding setting in shadow9's sysctl file."""
    key = setting.partition("=")[0]
    try:
        if FORWARDING_CONFIG.is_symlink() or FORWARDING_CONFIG.is_dir():
            raise OSError(f"{FORWARDING_CONFIG} is not a regular file")
        lines = (
            FORWARDING_CONFIG.read_text(encoding="utf-8").splitlines()
            if FORWARDING_CONFIG.exists()
            else []
        )
        replacement = False
        updated: list[str] = []
        for line in lines:
            if line.partition("=")[0].strip() == key:
                if not replacement:
                    updated.append(setting)
                    replacement = True
            else:
                updated.append(line)
        if not replacement:
            updated.append(setting)
        text = "\n".join(updated).rstrip() + "\n"
        if not FORWARDING_CONFIG.exists() or FORWARDING_CONFIG.read_text(
            encoding="utf-8"
        ) != text:
            FORWARDING_CONFIG.parent.mkdir(parents=True, exist_ok=True)
            write_file_safely(FORWARDING_CONFIG, text.encode("utf-8"), mode=0o644)
        console.print(f"[green]Forwarding persists through:[/green] {FORWARDING_CONFIG}")
        return ActivationStep("Forwarding persistence", True, "yes")
    except (OSError, UnicodeError) as error:
        console.print(f"[yellow]Could not persist forwarding: {error}[/yellow]")
        command = f"echo '{setting}' | {_root_command(f'tee {FORWARDING_CONFIG}', host)}"
        console.print(f"[dim]Run: {command}[/dim]")
        return ActivationStep("Forwarding persistence", False, "the sysctl file was not written")


def _enable_forwarding(network_version: int, host: Host) -> ActivationStep:
    """Turn on forwarding now and make that setting survive reboot."""
    setting = (
        "net.ipv6.conf.all.forwarding=1"
        if network_version == 6
        else "net.ipv4.ip_forward=1"
    )
    command = _root_command(f"sysctl -w {setting}", host)
    persist_command = f"echo '{setting}' | {_root_command(f'tee {FORWARDING_CONFIG}', host)}"

    if host.is_windows():
        console.print("[yellow]Windows cannot set the Linux hub forwarding sysctl.[/yellow]")
        console.print(f"[dim]On the Linux hub run: {command}[/dim]")
        console.print(f"[dim]Then: {persist_command}[/dim]")
        return ActivationStep("Forwarding on", False, "Linux sysctl is not available")

    if not host.is_root():
        console.print("[yellow]Root is needed to turn on and persist forwarding.[/yellow]")
        console.print(f"[dim]Run: {command}[/dim]")
        console.print(f"[dim]Then: {persist_command}[/dim]")
        return ActivationStep("Forwarding on", False, "root is required")

    binary = host.which("sysctl")
    current = False
    if binary is None:
        console.print("[yellow]sysctl was not found, so forwarding was not turned on.[/yellow]")
        console.print(f"[dim]When sysctl is installed, run: {command}[/dim]")
    else:
        try:
            result = host.run([binary, "-w", setting])
        except (OSError, subprocess.SubprocessError) as error:
            console.print(f"[yellow]Could not run sysctl: {error}[/yellow]")
            console.print(f"[dim]Run it yourself: {command}[/dim]")
        else:
            if result.returncode == 0:
                current = True
                console.print("[green]IP forwarding is on.[/green]")
            else:
                console.print(
                    f"[yellow]sysctl exited {result.returncode}: {result.stderr.strip()}[/yellow]"
                )
                console.print(f"[dim]Try: {command}[/dim]")

    persistent = _persist_forwarding(setting, host)
    if current and persistent.ready:
        return ActivationStep("Forwarding on", True, "yes, and it persists")
    if current:
        return ActivationStep("Forwarding on", True, "yes, but persistence needs attention")
    return ActivationStep("Forwarding on", False, "the live sysctl was not set")


def _allow_forwarding(interface: str, network_version: int, host: Host) -> ActivationStep:
    """Check for the spoke-to-spoke rule before adding it."""
    firewall = "ip6tables" if network_version == 6 else "iptables"
    check = [firewall, "-C", "FORWARD", "-i", interface, "-o", interface, "-j", "ACCEPT"]
    add = [firewall, "-A", "FORWARD", "-i", interface, "-o", interface, "-j", "ACCEPT"]
    manual = f"{_root_command(shlex.join(check), host)} || {_root_command(shlex.join(add), host)}"

    if host.is_windows():
        console.print(f"[yellow]Windows has no {firewall} FORWARD chain.[/yellow]")
        console.print(f"[dim]On the Linux hub run: {manual}[/dim]")
        return ActivationStep("FORWARD rule present", False, f"{firewall} is not available")

    if not host.is_root():
        console.print("[yellow]Root is needed to check or add the FORWARD rule.[/yellow]")
        console.print(f"[dim]Run: {manual}[/dim]")
        return ActivationStep("FORWARD rule present", False, "root is required")

    binary = host.which(firewall)
    if binary is None:
        console.print(
            f"[yellow]{firewall} was not found, so the FORWARD rule was not added.[/yellow]"
        )
        console.print(f"[dim]When {firewall} is installed, run: {manual}[/dim]")
        return ActivationStep("FORWARD rule present", False, f"{firewall} was not found")

    check[0] = binary
    add[0] = binary
    try:
        result = host.run(check)
    except (OSError, subprocess.SubprocessError) as error:
        console.print(f"[yellow]Could not check the FORWARD rule: {error}[/yellow]")
        console.print(f"[dim]Run it yourself: {manual}[/dim]")
        return ActivationStep("FORWARD rule present", False, "the rule check could not run")

    if result.returncode == 0:
        console.print("[green]The spoke-to-spoke FORWARD rule is already present.[/green]")
        return ActivationStep("FORWARD rule present", True, "yes")
    if result.returncode != 1:
        console.print(
            f"[yellow]{firewall} could not check the rule: {result.stderr.strip()}[/yellow]"
        )
        console.print(f"[dim]Try: {manual}[/dim]")
        return ActivationStep("FORWARD rule present", False, "the rule check failed")

    try:
        added = host.run(add)
    except (OSError, subprocess.SubprocessError) as error:
        console.print(f"[yellow]Could not add the FORWARD rule: {error}[/yellow]")
        console.print(f"[dim]Run it yourself: {_root_command(shlex.join(add), host)}[/dim]")
        return ActivationStep("FORWARD rule present", False, "the rule was not added")

    if added.returncode == 0:
        console.print("[green]Added the spoke-to-spoke FORWARD rule.[/green]")
        return ActivationStep("FORWARD rule present", True, "yes")

    console.print(f"[yellow]{firewall} exited {added.returncode}: {added.stderr.strip()}[/yellow]")
    console.print(f"[dim]Try: {_root_command(shlex.join(add), host)}[/dim]")
    return ActivationStep("FORWARD rule present", False, "the rule was not added")


def _print_activation_summary(result: ActivationResult) -> None:
    """Print the four activation facts without hiding partial work."""
    lines = []
    for step in (result.interface, result.boot, result.forwarding, result.forward_rule):
        mark = "[green]yes[/green]" if step.ready else "[yellow]no[/yellow]"
        lines.append(f"{step.label}: {mark} — {step.detail}")
    console.print(Panel("\n".join(lines), title="Hub activation", border_style="cyan"))


def _latest_handshakes(interface: str) -> dict[str, str]:
    """
    Ask a running interface when each peer was last heard from.

    Empty whenever the interface is not up, which is the case on a hub set up with
    `--no-apply` or where activation could not finish. The table says so rather than
    pretending to know.

    Args:
        interface: The interface name

    Returns:
        Public keys mapped to a readable time, empty when nothing can be asked
    """
    if os.name == "nt":
        return {}

    binary = shutil.which("wg")
    if binary is None:
        return {}

    try:
        result = subprocess.run(
            [binary, "show", interface, "latest-handshakes"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    if result.returncode != 0:
        return {}

    handshakes: dict[str, str] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            seconds = int(parts[1])
        except ValueError:
            continue
        if seconds <= 0:
            handshakes[parts[0]] = "never"
        else:
            handshakes[parts[0]] = datetime.fromtimestamp(seconds, timezone.utc).isoformat()

    return handshakes


def _enrollment_answer(
    answer: dict[str, object],
) -> tuple[str, str, TunnelNetwork, TunnelAddress, int, int, str]:
    """
    Read the fields a hub answers with.

    Args:
        answer: The parsed JSON body

    Returns:
        The hub public key, endpoint, tunnel network, peer address, MTU, keepalive and MAC

    Raises:
        ValueError: If a required field is missing, has the wrong type or does not parse
    """
    text_fields = ("address", "hub_public_key", "hub_endpoint", "tunnel_network", "mac")
    missing = [name for name in text_fields if not isinstance(answer.get(name), str)]
    for name in ("mtu", "keepalive", "protocol"):
        value = answer.get(name)
        if not isinstance(value, int) or isinstance(value, bool):
            missing.append(name)
    if missing:
        raise ValueError(
            f"The hub's answer is missing {', '.join(missing)}, so this is not a shadow9 hub."
        )

    protocol = cast(int, answer["protocol"])
    if protocol != ENROLLMENT_PROTOCOL:
        raise ValueError(
            f"The hub uses enrollment protocol {protocol}, but this node understands "
            f"protocol {ENROLLMENT_PROTOCOL}."
        )

    hub_key = str(answer["hub_public_key"])
    if not is_valid_key(hub_key):
        raise ValueError("The hub's answer does not carry a WireGuard public key.")

    return (
        hub_key,
        str(answer["hub_endpoint"]),
        parse_network(str(answer["tunnel_network"])),
        parse_address(str(answer["address"])),
        cast(int, answer["mtu"]),
        cast(int, answer["keepalive"]),
        str(answer["mac"]),
    )


def _decoded(body: bytes) -> dict[str, object]:
    """
    Parse a JSON body, treating anything else as an empty answer.

    Args:
        body: The raw response body

    Returns:
        The parsed object, or an empty dict
    """
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _detail(answer: dict[str, object]) -> str:
    """
    Pull the reason out of an error answer.

    Args:
        answer: The parsed JSON body

    Returns:
        The reason the hub gave, or a sentence saying it gave none
    """
    detail = answer.get("detail")
    if isinstance(detail, str):
        return detail
    if detail:
        return json.dumps(detail)
    return "the hub gave no reason"
