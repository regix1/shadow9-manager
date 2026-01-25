"""
Interactive serve configuration wizard for Shadow9.

Provides an interactive menu for configuring server host/port options.
"""

from typing import Tuple, Optional

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()


def run_serve_wizard(default_host: str = "127.0.0.1", default_port: int = 1080) -> Tuple[str, int]:
    """
    Interactive mode for serve command.
    
    Args:
        default_host: Default host to bind to
        default_port: Default port to listen on
    
    Returns:
        Tuple of (host, port)
    """
    console.print(Panel(
        "[bold cyan]Server Configuration[/bold cyan]\n\n"
        "Configure the SOCKS5 proxy server binding.",
        border_style="cyan"
    ))
    
    console.print("\n[bold]Server Binding[/bold]")
    console.print("  [dim]Choose where the proxy server listens for connections.[/dim]\n")
    
    # Host selection
    console.print("  [cyan]Host options:[/cyan]")
    console.print("    [dim]127.0.0.1[/dim] - Local only (most secure)")
    console.print("    [dim]0.0.0.0[/dim]   - All interfaces (accessible from network)\n")
    
    host = typer.prompt("  Host", default=default_host)
    
    # Port selection
    console.print("\n  [cyan]Port:[/cyan]")
    console.print("    [dim]1080[/dim] - Standard SOCKS5 port")
    console.print("    [dim]Custom ports may help avoid detection[/dim]\n")
    
    port_str = typer.prompt("  Port", default=str(default_port))
    try:
        port = int(port_str)
    except ValueError:
        console.print("  [yellow]Invalid port, using default 1080[/yellow]")
        port = 1080
    
    return host, port


def show_serve_preview(host: str, port: int) -> None:
    """
    Show preview of server configuration before starting.
    
    Args:
        host: The host to bind to
        port: The port to listen on
    """
    console.print(Panel(
        f"[bold]Server Configuration[/bold]\n\n"
        f"  Listen Address: [cyan]{host}:{port}[/cyan]\n\n"
        f"[dim]User settings control Tor routing, bridges, and security levels.[/dim]",
        border_style="cyan"
    ))
