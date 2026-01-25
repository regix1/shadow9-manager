"""
Command Line Interface for Shadow9 Manager.

Provides commands for running the SOCKS5 server, managing users,
and connecting to the Tor network.

Built with Typer for automatic tab completion.
"""

from typing import Annotated

import typer
from rich.console import Console

from .commands import (
    register_server_commands,
    register_user_commands,
    register_util_commands,
)

console = Console()

# Create the main app
app = typer.Typer(
    name="shadow9",
    help="Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support",
    add_completion=True,
    rich_markup_mode="rich",
)


def version_callback(value: bool):
    if value:
        console.print("shadow9-manager version 1.0.0")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=version_callback, is_eager=True, help="Show version and exit.")] = False,
):
    """
    Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

    A security-focused SOCKS5 proxy server that supports Tor network
    connectivity for accessing .onion addresses.
    """
    pass


# Register all commands from submodules
register_server_commands(app)
register_user_commands(app)
register_util_commands(app)


# Entry point for the CLI
def cli():
    """Main entry point."""
    app()


if __name__ == "__main__":
    cli()
