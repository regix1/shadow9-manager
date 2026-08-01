"""
Interactive WireGuard hub setup for Shadow9.

The same work `shadow9 wg init` does, with questions instead of flags, for an operator who
would rather be asked than read `--help`. The one question that has no sensible default is
the endpoint, because the hub is the side that has to be reachable from outside and nothing
here can guess the address peers will dial.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import Config
from ..services.wireguard_service import (
    DEFAULT_TOKEN_HOURS,
    checked_endpoint,
    is_public_endpoint_host,
    load_hub_private_key,
)
from ..wireguard import DEFAULT_MTU, parse_network

if TYPE_CHECKING:
    from ..commands.wireguard import Host

console = Console()

DEFAULT_CONFIG_PATH = "config/config.yaml"

# The tunnel range the hub hands addresses out of. 253 peers after the hub, and far enough
# from the ranges a home router hands out that a peer's own LAN will not collide with it.
DEFAULT_TUNNEL_NETWORK = "10.9.0.0/24"

DEFAULT_LISTEN_PORT = 51820


def run_wireguard_setup_wizard(config_path: str = DEFAULT_CONFIG_PATH) -> Optional[dict]:
    """
    Walk an operator through setting this host up as a WireGuard hub.

    Args:
        config_path: The configuration file the answers are written to

    Returns:
        The settings that were applied, or None if the operator backed out
    """
    console.print(
        Panel(
            "[bold cyan]WireGuard hub setup[/bold cyan]\n\n"
            "One hub, many peers. This host becomes the hub: the side with a fixed address "
            "that everything else dials.",
            border_style="cyan",
        )
    )

    cfg = _load_config(config_path)

    from ..commands.wireguard import _interface_clash

    clash = _interface_clash(cfg.wireguard.interface)
    if clash is not None:
        console.print(f"[red]{clash}[/red]")
        raise typer.Exit(1)

    if load_hub_private_key() is not None:
        console.print("[yellow]This host already has a WireGuard hub key.[/yellow]")
        console.print(
            "[dim]Replacing it means every existing peer has to rejoin, because their "
            "configs name the old key.[/dim]"
        )
        if not typer.confirm("Replace the existing hub key?", default=False):
            console.print("[yellow]Left as it was.[/yellow]")
            return None

    endpoint = _prompt_endpoint(cfg)
    if endpoint is None:
        console.print("[yellow]Cancelled[/yellow]")
        return None

    network = _prompt_tunnel_network(cfg)
    port = _prompt_listen_port(cfg)
    masquerade = _prompt_masquerade_interface()

    answers = {
        "endpoint": endpoint,
        "tunnel_network": network,
        "listen_port": port,
        "masquerade_interface": masquerade,
    }

    _show_summary(answers)
    if not typer.confirm("\nSet the hub up with these settings?", default=True):
        console.print("[yellow]Cancelled. Nothing was written.[/yellow]")
        return None

    from ..commands.wireguard import _init_impl

    _init_impl(
        endpoint=endpoint,
        network=network,
        port=port,
        interface=cfg.wireguard.interface,
        masquerade=masquerade,
        api_url=None,
        token_hours=DEFAULT_TOKEN_HOURS,
        force=True,
        no_apply=False,
        config=config_path,
    )

    return answers


def _load_config(config_path: str) -> Config:
    """
    Load configuration, falling back to the defaults when there is no file.

    Args:
        config_path: The configuration file

    Returns:
        The loaded configuration
    """
    path = Path(config_path)
    return Config.load(path) if path.exists() else Config()


def _prompt_endpoint(cfg: Config, host: "Host | None" = None) -> Optional[str]:
    """
    Ask for the address peers dial.

    Args:
        cfg: The loaded configuration, whose current value becomes the default
        host: The host used to find an address when no endpoint is configured

    Returns:
        The endpoint, or None if the operator gave up on it
    """
    console.print("\n[bold]Step 1: the address peers dial[/bold]")
    console.print(
        "[dim]The public address of this host and the UDP port, for example "
        "203.0.113.10:51820. Peers have no name to look up, so this is what goes into "
        "every peer config.[/dim]"
    )

    suggestion = cfg.wireguard.hub_endpoint or ""
    if suggestion:
        console.print(f"[dim]Remembered {suggestion} from the saved configuration.[/dim]")
    else:
        if host is None:
            from ..commands.wireguard import _host

            host = _host
        try:
            detected = host.outward_address()
        except Exception:
            detected = None
        if detected is not None:
            candidate = f"{detected.address}:{cfg.wireguard.listen_port}"
            if is_public_endpoint_host(candidate):
                suggestion = candidate
                console.print(f"[dim]Detected {candidate} from {detected.source}.[/dim]")
            else:
                console.print(
                    f"[yellow]Detected {detected.address} from {detected.source}, but it is "
                    "private. Peers on the internet cannot dial it.[/yellow]"
                )

    while True:
        answer = typer.prompt("Endpoint", default=suggestion).strip()
        if not answer:
            console.print("[yellow]An endpoint is needed before any peer can be built.[/yellow]")
            continue

        try:
            endpoint = checked_endpoint(answer)
        except ValueError as error:
            console.print(f"[red]{error}[/red]")
            continue

        if not is_public_endpoint_host(endpoint):
            console.print(
                f"[yellow]{endpoint} is not an address the internet routes to, so only "
                f"peers that can already reach it will connect.[/yellow]"
            )
            if not typer.confirm("Use it anyway?", default=False):
                continue

        return endpoint


def _prompt_tunnel_network(cfg: Config) -> str:
    """
    Ask which range peer addresses come from.

    Args:
        cfg: The loaded configuration, whose current value becomes the default

    Returns:
        The tunnel network in CIDR form
    """
    console.print("\n[bold]Step 2: the tunnel network[/bold]")
    console.print(
        "[dim]The private range peers get their tunnel addresses from. Pick one that no "
        "LAN behind a peer is already using, or traffic for that LAN goes down the tunnel "
        "and stops.[/dim]"
    )

    default = cfg.wireguard.tunnel_network or DEFAULT_TUNNEL_NETWORK
    while True:
        answer = typer.prompt("Tunnel network", default=default).strip()
        try:
            parse_network(answer)
            return answer
        except ValueError as error:
            console.print(f"[red]{error}[/red]")


def _prompt_listen_port(cfg: Config) -> int:
    """
    Ask which UDP port the hub listens on.

    Args:
        cfg: The loaded configuration, whose current value becomes the default

    Returns:
        The port
    """
    console.print("\n[bold]Step 3: the listen port[/bold]")
    console.print(
        "[dim]UDP, so it does not collide with the proxy or the API, which are both TCP. "
        "This is the one inbound port the whole design needs open.[/dim]"
    )

    default = cfg.wireguard.listen_port or DEFAULT_LISTEN_PORT
    while True:
        answer = typer.prompt("Listen port", default=default, type=int)
        if 1 <= answer <= 65535:
            return answer
        console.print(f"[red]{answer} is not a port. Ports run from 1 to 65535.[/red]")


def _prompt_masquerade_interface() -> Optional[str]:
    """
    Ask which interface full-tunnel traffic leaves by.

    Returns:
        The interface name, or None when no peer will use a full tunnel
    """
    console.print("\n[bold]Step 4: full-tunnel peers[/bold]")
    console.print(
        "[dim]A full-tunnel peer sends all of its traffic here, so this host has to NAT "
        "that traffic out to the internet. Without an interface name, a full-tunnel peer "
        "reaches the tunnel and nothing beyond it. Skip this if every peer only wants to "
        "reach the tunnel and the LANs on it.[/dim]"
    )

    if not typer.confirm("Will any peer route all its traffic through this hub?", default=False):
        return None

    answer = typer.prompt("Internet-facing interface", default="eth0").strip()
    return answer or None


def _show_summary(answers: dict) -> None:
    """
    Show what is about to be written.

    Args:
        answers: The collected settings
    """
    table = Table(title="About to set up", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Endpoint", str(answers["endpoint"]))
    table.add_row("Tunnel network", str(answers["tunnel_network"]))
    table.add_row("Listen port", f"{answers['listen_port']}/udp")
    table.add_row("MTU", str(DEFAULT_MTU))
    table.add_row("Masquerade interface", str(answers["masquerade_interface"] or "none"))

    console.print()
    console.print(table)
