"""
Interactive serve configuration wizard for Shadow9.

Provides an interactive menu for configuring server options.
"""

from typing import Tuple

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()


def run_serve_wizard() -> Tuple[bool, str, str]:
    """
    Interactive mode for serve command.
    
    Returns:
        Tuple of (use_tor, security_level, bridge_type)
    """
    console.print(Panel(
        "[bold cyan]Server Configuration[/bold cyan]\n\n"
        "Choose how to configure the proxy server.",
        border_style="cyan"
    ))
    
    console.print("\n[bold]Quick start or custom?[/bold]\n")
    console.print("  [cyan]1. Quick start[/cyan] [green](recommended)[/green]")
    console.print("     Tor enabled, basic security, no bridges.")
    console.print("     [dim]Best for: Most users, balanced speed and privacy[/dim]\n")
    console.print("  [cyan]2. Custom configuration[/cyan]")
    console.print("     Choose Tor routing, security level, and bridges.")
    console.print("     [dim]Best for: Advanced users, specific requirements[/dim]\n")
    
    choice = typer.prompt("  Select [1-2]", default="1")
    
    if choice == "1":
        # Quick start - defaults
        return True, "basic", "none"
    
    # Custom configuration
    console.print("\n[bold]Step 1:[/bold] Tor routing")
    console.print("  [dim]Route traffic through the Tor network for anonymity.[/dim]\n")
    console.print("  [cyan]Tor[/cyan] - Routes through multiple relays.")
    console.print("     Your real IP is hidden. Slower but anonymous.")
    console.print("     [dim]Best for: Privacy-sensitive usage, .onion sites[/dim]\n")
    console.print("  [cyan]Direct[/cyan] - Traffic goes directly to destination.")
    console.print("     Faster but uses your server's IP address.")
    console.print("     [dim]Best for: Speed priority, trusted networks[/dim]\n")
    use_tor = typer.confirm("  Route traffic through Tor?", default=True)
    
    # Bridge selection (only if Tor enabled)
    bridge = "none"
    if use_tor:
        console.print("\n[bold]Step 2:[/bold] Tor bridge selection")
        console.print("  [dim]Bridges help bypass Tor blocking in restricted networks.[/dim]\n")
        
        console.print("  [cyan]1. none[/cyan] [green](default)[/green]")
        console.print("     Direct connection to Tor network.")
        console.print("     [dim]Best for: Unrestricted networks, fastest option[/dim]\n")
        
        console.print("  [cyan]2. obfs4[/cyan]")
        console.print("     Obfuscates traffic to look like random data.")
        console.print("     [dim]Best for: ISPs that block Tor, moderate censorship[/dim]\n")
        
        console.print("  [cyan]3. snowflake[/cyan]")
        console.print("     Routes through volunteer browser proxies via WebRTC.")
        console.print("     [dim]Best for: When obfs4 is blocked, dynamic endpoints[/dim]\n")
        
        console.print("  [cyan]4. meek-azure[/cyan]")
        console.print("     Tunnels through Microsoft Azure cloud.")
        console.print("     Traffic appears as normal HTTPS to Microsoft CDN.")
        console.print("     [dim]Best for: Heavily censored networks (China, Iran)[/dim]")
        console.print("     [dim]Note: Slowest option due to cloud routing overhead[/dim]\n")
        
        bridge_choice = typer.prompt("  Select bridge [1-4]", default="1")
        bridge_map = {"1": "none", "2": "obfs4", "3": "snowflake", "4": "meek"}
        bridge = bridge_map.get(bridge_choice, "none")
    
    # Security level
    console.print("\n[bold]Step 3:[/bold] Security level")
    console.print("  [dim]Controls traffic analysis evasion techniques.[/dim]\n")
    
    console.print("  [cyan]1. none[/cyan]")
    console.print("     No evasion techniques applied.")
    console.print("     [dim]Best for: Maximum speed, privacy not a concern[/dim]\n")
    
    console.print("  [cyan]2. basic[/cyan] [green](recommended)[/green]")
    console.print("     Standard headers, basic fingerprint protection.")
    console.print("     [dim]Best for: General privacy with good performance[/dim]\n")
    
    console.print("  [cyan]3. moderate[/cyan]")
    console.print("     Randomized headers, timing jitter, traffic padding.")
    console.print("     [dim]Best for: Evading DPI, corporate firewalls[/dim]\n")
    
    console.print("  [cyan]4. paranoid[/cyan]")
    console.print("     Maximum evasion: packet fragmentation, random delays,")
    console.print("     decoy traffic generation, full header randomization.")
    console.print("     [dim]Best for: High-risk environments, nation-state adversaries[/dim]")
    console.print("     [dim]Note: Significant performance impact[/dim]\n")
    
    security_choice = typer.prompt("  Select level [1-4]", default="2")
    security_map = {"1": "none", "2": "basic", "3": "moderate", "4": "paranoid"}
    security = security_map.get(security_choice, "basic")
    
    return use_tor, security, bridge


def show_serve_preview(tor: bool, security: str, bridge: str) -> None:
    """
    Show preview of server configuration before starting.
    
    Args:
        tor: Whether Tor routing is enabled
        security: The security level
        bridge: The bridge type
    """
    tor_status = "[green]Enabled[/green]" if tor else "[yellow]Disabled[/yellow]"
    bridge_status = f"[cyan]{bridge}[/cyan]" if bridge != "none" else "[dim]None[/dim]"
    security_status = f"[cyan]{security}[/cyan]"
    
    console.print(Panel(
        f"[bold]Server Configuration Preview[/bold]\n\n"
        f"  Tor Routing:    {tor_status}\n"
        f"  Bridge Type:    {bridge_status}\n"
        f"  Security Level: {security_status}\n\n"
        f"[dim]The server will start with these settings.[/dim]",
        border_style="cyan"
    ))
