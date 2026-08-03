"""
See which Tor bridges the proxy can use, and whether the transports for them work.

The bridge catalog and the transport detection already existed but nothing reached them
from the command line, so an operator could put a user on an obfs4 bridge without being
able to see what was available or whether obfs4proxy would actually run.
"""

import asyncio
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ..bridge_list import BUILTIN_OBFS4_BRIDGES, SNOWFLAKE_BRIDGES, Bridge, BridgeType


console = Console()

# The bridge types an operator can pick for a user. NONE is a direct connection, so it
# has no bridges and nothing to check.
CATALOG: dict[BridgeType, list[Bridge]] = {
    BridgeType.OBFS4: BUILTIN_OBFS4_BRIDGES,
    BridgeType.SNOWFLAKE: SNOWFLAKE_BRIDGES,
}


def complete_bridge_type(incomplete: str) -> list[str]:
    """Offer the bridge type names on tab, rather than letting the shell list files."""
    return [item.value for item in CATALOG if item.value.startswith(incomplete)]


def parse_bridge_type(name: str) -> BridgeType:
    """
    Turn a name typed on the command line into a bridge type.

    Args:
        name: The type as typed

    Returns:
        The matching bridge type

    Raises:
        typer.Exit: When the name is not a type that has bridges
    """
    for item in CATALOG:
        if item.value == name:
            return item

    known = ", ".join(item.value for item in CATALOG)
    console.print(f"[red]There is no bridge type called '{name}'[/red]")
    console.print(f"[dim]Known types: {known}[/dim]")
    raise typer.Exit(1)


def _transport_paths() -> dict[BridgeType, str | None]:
    """Which transport binaries are on this host, keyed by the type that needs them."""
    from ..bridges import PluggableTransportManager, get_bridge_preset

    manager = PluggableTransportManager(get_bridge_preset(BridgeType.OBFS4))
    return manager.detect_transports()


def register_bridge_commands(app: typer.Typer) -> None:
    """Register the bridge subcommands with the main app."""

    bridges_app = typer.Typer(
        help="Manage the Tor bridges available to route a user through.",
        no_args_is_help=True,
    )
    app.add_typer(bridges_app, name="bridges")

    @bridges_app.command("list")
    def bridges_list(
        bridge_type: Annotated[
            str | None,
            typer.Option(
                "--type",
                "-t",
                help="Only show one type",
                autocompletion=complete_bridge_type,
            ),
        ] = None,
    ) -> None:
        """Show the built-in bridges, and whether the transport each needs is installed."""
        wanted = [parse_bridge_type(bridge_type)] if bridge_type else list(CATALOG)
        installed = _transport_paths()

        table = Table(title="Built-in bridges", show_header=True)
        table.add_column("Type", style="cyan")
        table.add_column("Bridges", justify="right")
        table.add_column("Transport")

        for item in wanted:
            path = installed.get(item)
            transport = (
                f"[green]{path}[/green]" if path else "[red]not installed[/red]"
            )
            table.add_row(item.value, str(len(CATALOG[item])), transport)

        console.print(table)
        console.print(
            "[dim]Assign one to a user with 'shadow9 socks5 user modify', and see which each "
            "user has with 'shadow9 socks5 user list'.[/dim]"
        )

    @bridges_app.command("show")
    def bridges_show(
        bridge_type: Annotated[
            str, typer.Argument(help="Bridge type to show", autocompletion=complete_bridge_type)
        ],
    ) -> None:
        """Print the bridge lines for one type, as they go into a torrc."""
        item = parse_bridge_type(bridge_type)
        for bridge in CATALOG[item]:
            # One bridge, one line, byte for byte. These get pasted into a torrc, so a
            # wrapped line is a broken line, and an IPv6 address in square brackets would
            # otherwise be read as markup and disappear.
            console.print(bridge.to_bridge_line(), markup=False, soft_wrap=True)

    @bridges_app.command("check")
    def bridges_check(
        bridge_type: Annotated[
            str, typer.Argument(help="Bridge type to check", autocompletion=complete_bridge_type)
        ],
    ) -> None:
        """Say whether the transport this bridge type needs will actually run."""
        from ..bridges import PluggableTransportManager, get_bridge_preset

        item = parse_bridge_type(bridge_type)
        manager = PluggableTransportManager(get_bridge_preset(item))

        console.print(f"[cyan]Checking the {item.value} transport...[/cyan]")
        if not asyncio.run(manager.check_transport_available(item)):
            console.print(f"[red]The {item.value} transport is not usable on this host[/red]")
            console.print(f"[dim]{manager.get_install_instructions()}[/dim]")
            raise typer.Exit(1)

        path = manager.detect_transports().get(item)
        console.print(f"[green]The {item.value} transport works[/green]")
        if path:
            console.print(f"[dim]Using {path}[/dim]")
