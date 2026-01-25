"""
Interactive initialization wizard for Shadow9.

Provides an interactive configuration builder for initial setup.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import Config, ServerConfig, TorConfig, LogConfig, SecurityConfig, AuthConfig
from ..config import generate_master_key

console = Console()


def run_init_wizard() -> Config:
    """
    Interactive configuration builder.
    
    Returns:
        A fully configured Config object
    """
    # Server settings
    console.print("\n[bold]Step 1:[/bold] Server Settings")
    console.print("  [dim]Configure the SOCKS5 proxy server.[/dim]\n")
    
    host = typer.prompt("  Server host", default="0.0.0.0")
    port = typer.prompt("  Server port", default="1080")
    try:
        port = int(port)
    except ValueError:
        port = 1080
    
    max_connections = typer.prompt("  Max connections", default="100")
    try:
        max_connections = int(max_connections)
    except ValueError:
        max_connections = 100

    # Daemon mode
    console.print("\n  [cyan]Run mode:[/cyan]")
    console.print("    [dim]Foreground[/dim] - See logs in terminal, stop with Ctrl+C")
    console.print("    [dim]Background[/dim] - Run as daemon, stop with 'shadow9 stop'\n")
    daemon = typer.confirm("  Run in background by default?", default=False)

    server = ServerConfig(host=host, port=port, max_connections=max_connections, daemon=daemon)
    
    # Tor settings
    console.print("\n[bold]Step 2:[/bold] Tor Connection")
    console.print("  [dim]Configure where Tor is running (routing is per-user).[/dim]\n")
    
    tor_host = "127.0.0.1"
    tor_port = 9050
    control_port = 9051
    
    if not typer.confirm("  Use default Tor ports (9050/9051)?", default=True):
        tor_host = typer.prompt("    Tor SOCKS host", default="127.0.0.1")
        tor_port_str = typer.prompt("    Tor SOCKS port", default="9050")
        control_port_str = typer.prompt("    Tor control port", default="9051")
        try:
            tor_port = int(tor_port_str)
            control_port = int(control_port_str)
        except ValueError:
            tor_port = 9050
            control_port = 9051
    
    tor = TorConfig(enabled=True, socks_host=tor_host, socks_port=tor_port, control_port=control_port)
    
    # Security settings
    console.print("\n[bold]Step 3:[/bold] Default Security Level")
    console.print("  [dim]Default evasion techniques for new users.[/dim]\n")
    
    console.print("  [cyan]1. none[/cyan] - No evasion techniques")
    console.print("  [cyan]2. basic[/cyan] [green](recommended)[/green] - Standard protection")
    console.print("  [cyan]3. moderate[/cyan] - Timing jitter, traffic padding")
    console.print("  [cyan]4. paranoid[/cyan] - Maximum evasion\n")
    
    security_choice = typer.prompt("  Select level [1-4]", default="2")
    security_map = {"1": [80, 443], "2": [80, 443, 8080, 8443], "3": [80, 443, 8080, 8443], "4": [80, 443]}
    
    security = SecurityConfig(
        allowed_ports=security_map.get(security_choice, [80, 443, 8080, 8443]),
        rate_limit_per_minute=100 if security_choice in ["1", "2"] else 60
    )
    
    # Log settings
    console.print("\n[bold]Step 4:[/bold] Logging")
    console.print("  [dim]Configure logging preferences.[/dim]\n")
    
    console.print("  [cyan]1. INFO[/cyan] [green](recommended)[/green] - Standard logging")
    console.print("  [cyan]2. DEBUG[/cyan] - Verbose output for troubleshooting")
    console.print("  [cyan]3. WARNING[/cyan] - Only warnings and errors")
    console.print("  [cyan]4. ERROR[/cyan] - Only errors\n")
    
    log_choice = typer.prompt("  Select level [1-4]", default="1")
    log_map = {"1": "INFO", "2": "DEBUG", "3": "WARNING", "4": "ERROR"}
    log_level = log_map.get(log_choice, "INFO")
    
    console.print("\n  [cyan]1. json[/cyan] [green](recommended)[/green] - Structured JSON logs")
    console.print("  [cyan]2. console[/cyan] - Human-readable console output\n")
    
    format_choice = typer.prompt("  Select format [1-2]", default="1")
    log_format = "json" if format_choice == "1" else "console"
    
    log = LogConfig(level=log_level, format=log_format)
    
    # Auth settings
    auth = AuthConfig()
    
    return Config(server=server, tor=tor, security=security, log=log, auth=auth)


def show_config_summary(config: Config) -> None:
    """
    Display configuration summary.
    
    Args:
        config: The configuration to display
    """
    table = Table(title="Configuration Summary", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Server Host", config.server.host)
    table.add_row("Server Port", str(config.server.port))
    table.add_row("Max Connections", str(config.server.max_connections))
    table.add_row("Run Mode", "Background (daemon)" if config.server.daemon else "Foreground")
    table.add_row("", "")
    table.add_row("Tor SOCKS", f"{config.tor.socks_host}:{config.tor.socks_port}")
    table.add_row("Tor Control Port", str(config.tor.control_port))
    table.add_row("Tor Routing", "Per-user (IsolateSOCKSAuth)")
    table.add_row("", "")
    table.add_row("Allowed Ports", ", ".join(map(str, config.security.allowed_ports)))
    table.add_row("Rate Limit", f"{config.security.rate_limit_per_minute}/min")
    table.add_row("", "")
    table.add_row("Log Level", config.log.level)
    table.add_row("Log Format", config.log.format)
    
    console.print("\n")
    console.print(table)


def show_master_key() -> None:
    """Display a newly generated master key."""
    key = generate_master_key()
    console.print(Panel(
        f"[bold yellow]Master Key (save this securely!):[/bold yellow]\n\n"
        f"[cyan]{key}[/cyan]\n\n"
        f"Set as environment variable:\n"
        f"[dim]export SHADOW9_MASTER_KEY=\"{key}\"[/dim]",
        title="Encryption Key",
        border_style="yellow"
    ))
