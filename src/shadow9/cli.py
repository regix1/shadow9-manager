"""
Command Line Interface for Shadow9 Manager.

Provides commands for running the SOCKS5 server, managing users,
and connecting to the Tor network.

Built with Typer for automatic tab completion.
"""

import os
from pathlib import Path
from typing import Annotated


# Load .env file from common locations
def _load_env():
    """Load environment variables from .env file."""
    env_locations = [
        Path.cwd() / ".env",  # Current directory
        Path(__file__).parent.parent.parent.parent
        / ".env",  # Project root (when installed editable)
        Path.home() / ".shadow9" / ".env",  # User config directory
        Path("/etc/shadow9/.env"),  # System config (Linux)
    ]

    for env_file in env_locations:
        if env_file.exists():
            try:
                with open(env_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, _, value = line.partition("=")
                            # Don't override existing env vars
                            if key.strip() not in os.environ:
                                os.environ[key.strip()] = value.strip()
                break  # Stop after first found .env
            except Exception:
                pass


_load_env()

import typer
from rich.console import Console

from . import __version__
from .commands import (
    register_server_commands,
    register_user_commands,
    register_service_commands,
    register_util_commands,
    register_api_commands,
    register_wireguard_commands,
)
console = Console()

# Create the main app
app = typer.Typer(
    name="shadow9",
    help="Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=False,
)


def version_callback(value: bool):
    if value:
        console.print(f"shadow9-manager version {__version__}")
        raise typer.Exit()


def remove_completion_callback(value: bool) -> None:
    """Take out what --install-completion put in, and say what was left behind."""
    if not value:
        return

    from .completion import remove_completion

    result = remove_completion("shadow9")

    if result.found_anything:
        for entry in result.removed:
            console.print(f"[green]Removed[/green] {entry}")
        console.print("[dim]Open a new shell for it to take effect.[/dim]")
    else:
        console.print("[yellow]No shell completion is installed for shadow9[/yellow]")

    for note in result.notes:
        console.print(f"[dim]{note}[/dim]")

    raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
    remove_completion: Annotated[
        bool,
        typer.Option(
            "--remove-completion",
            callback=remove_completion_callback,
            is_eager=True,
            help="Remove the shell completion that --install-completion set up.",
        ),
    ] = False,
) -> None:
    """
    Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

    A security-focused SOCKS5 proxy server that supports Tor network
    connectivity for accessing .onion addresses.
    """
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


# Register all commands from submodules
register_server_commands(app)
register_user_commands(app)
register_service_commands(app)
register_util_commands(app)
register_api_commands(app)
register_wireguard_commands(app)


# Entry point for the CLI
def cli():
    """Main entry point."""
    app()


if __name__ == "__main__":
    cli()
