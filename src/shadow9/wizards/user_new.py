"""
Interactive user creation wizard for Shadow9.

Provides a step-by-step guided process for creating new proxy users.
"""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.panel import Panel

from ..auth import AuthManager
from ..config import Config
from ..paths import load_master_key

console = Console()


def run_user_wizard(config_path: str = "config/config.yaml") -> None:
    """
    Interactive wizard to create a new user.
    
    Guides the user through:
    1. Username selection
    2. Password (generate or custom)
    3. Tor routing preference
    4. Bridge selection (if Tor enabled)
    5. Security level
    6. Port restrictions (optional)
    7. Rate limiting (optional)
    """
    console.print(Panel(
        "[bold cyan]New User Setup[/bold cyan]\n\n"
        "This wizard will guide you through creating a new proxy user.",
        border_style="cyan"
    ))
    
    cfg = Config.load(Path(config_path)) if Path(config_path).exists() else Config()
    
    master_key = load_master_key()
    
    auth_manager = AuthManager(
        credentials_file=cfg.get_credentials_file(),
        master_key=master_key
    )
    
    # Step 1: Username
    username = _prompt_username(auth_manager)
    
    # Step 2: Password
    password = _prompt_password(auth_manager)
    
    # Step 3: Routing
    use_tor = _prompt_routing()
    
    # Step 4: Bridge (if Tor enabled)
    bridge_type = _prompt_bridge() if use_tor else "none"
    
    # Step 5: Security level
    security_level = _prompt_security()
    
    # Step 6: Port restrictions (optional)
    allowed_ports = _prompt_ports()
    
    # Step 7: Rate limiting (optional)
    rate_limit = _prompt_rate_limit()
    
    # Summary and confirmation
    _show_summary(username, password, use_tor, bridge_type, security_level, allowed_ports, rate_limit)
    
    if not typer.confirm("\nCreate this user?", default=True):
        console.print("[yellow]Cancelled[/yellow]")
        raise typer.Abort()
    
    # Create the user
    _create_user(auth_manager, username, password, use_tor, bridge_type, 
                 security_level, allowed_ports, rate_limit)


def _prompt_username(auth_manager: AuthManager) -> str:
    """Prompt for and validate username."""
    console.print("\n[bold]Step 1:[/bold] Choose a username")
    
    while True:
        username = typer.prompt("  Username")
        if not username:
            console.print("  [red]Username cannot be empty[/red]")
            continue
        if username in auth_manager.list_users():
            console.print(f"  [red]User '{username}' already exists[/red]")
            continue
        return username


def _prompt_password(auth_manager: AuthManager) -> str:
    """Prompt for password or generate one."""
    console.print("\n[bold]Step 2:[/bold] Set a password")
    generate_pass = typer.confirm("  Generate a secure password?", default=True)
    
    if generate_pass:
        _, password = auth_manager.generate_credentials()
        console.print(f"  [green]Generated:[/green] [cyan]{password}[/cyan]")
        return password
    
    while True:
        password = typer.prompt("  Password", hide_input=True)
        if len(password) < 8:
            console.print("  [red]Password must be at least 8 characters[/red]")
            continue
        password_confirm = typer.prompt("  Confirm password", hide_input=True)
        if password != password_confirm:
            console.print("  [red]Passwords do not match[/red]")
            continue
        return password


def _prompt_routing() -> bool:
    """Prompt for Tor routing preference."""
    console.print("\n[bold]Step 3:[/bold] Traffic routing")
    console.print("  [dim]Choose how traffic is routed through the proxy.[/dim]\n")
    console.print("  [cyan]Tor[/cyan] - Routes through multiple relays for anonymity.")
    console.print("     Your real IP is hidden. Slower but anonymous.")
    console.print("     [dim]Best for: Privacy-sensitive browsing, .onion sites[/dim]\n")
    console.print("  [cyan]Direct[/cyan] - Traffic goes directly to destination.")
    console.print("     Faster but uses your server's IP address.")
    console.print("     [dim]Best for: Speed priority, trusted networks[/dim]\n")
    return typer.confirm("  Route traffic through Tor?", default=True)


def _prompt_bridge() -> str:
    """Prompt for Tor bridge selection."""
    console.print("\n[bold]Step 4:[/bold] Tor bridge selection")
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
    
    bridge_choice = typer.prompt("  Select bridge [1-3]", default="1")
    bridge_map = {"1": "none", "2": "obfs4", "3": "snowflake"}
    return bridge_map.get(bridge_choice, "none")


def _prompt_security() -> str:
    """Prompt for security level selection."""
    console.print("\n[bold]Step 5:[/bold] Security level")
    console.print("  [dim]Controls traffic analysis evasion techniques.[/dim]\n")
    
    console.print("  [cyan]1. none[/cyan]")
    console.print("     No evasion techniques applied.")
    console.print("     [dim]Best for: Maximum speed, privacy not a concern[/dim]\n")
    
    console.print("  [cyan]2. basic[/cyan] [green](recommended)[/green]")
    console.print("     Standard headers, basic fingerprint protection.")
    console.print("     [dim]Best for: General privacy with good performance[/dim]\n")
    
    console.print("  [cyan]3. moderate[/cyan]")
    console.print("     Randomized headers, timing jitter, traffic padding.")
    console.print("     Adds random delays to mask traffic patterns.")
    console.print("     [dim]Best for: Evading DPI, corporate firewalls[/dim]\n")
    
    console.print("  [cyan]4. paranoid[/cyan]")
    console.print("     Maximum evasion: packet fragmentation, random delays,")
    console.print("     decoy traffic generation, full header randomization.")
    console.print("     [dim]Best for: High-risk environments, nation-state adversaries[/dim]")
    console.print("     [dim]Note: Significant performance impact[/dim]\n")
    
    security_choice = typer.prompt("  Select level [1-4]", default="2")
    security_map = {"1": "none", "2": "basic", "3": "moderate", "4": "paranoid"}
    return security_map.get(security_choice, "basic")


def _prompt_ports() -> Optional[List[int]]:
    """Prompt for optional port restrictions."""
    console.print("\n[bold]Step 6:[/bold] Port restrictions [dim](optional)[/dim]")
    restrict_ports = typer.confirm("  Restrict to specific ports?", default=False)
    
    if not restrict_ports:
        return None
    
    ports_input = typer.prompt("  Enter ports (comma-separated)", default="80,443")
    try:
        return [int(p.strip()) for p in ports_input.split(',')]
    except ValueError:
        console.print("  [yellow]Invalid ports, skipping restriction[/yellow]")
        return None


def _prompt_rate_limit() -> Optional[int]:
    """Prompt for optional rate limiting."""
    console.print("\n[bold]Step 7:[/bold] Rate limiting [dim](optional)[/dim]")
    enable_rate_limit = typer.confirm("  Enable rate limiting?", default=False)
    
    if not enable_rate_limit:
        return None
    
    return typer.prompt("  Max requests per minute", default="60", type=int)


def _show_summary(username: str, password: str, use_tor: bool, bridge_type: str,
                  security_level: str, allowed_ports: Optional[List[int]], 
                  rate_limit: Optional[int]) -> None:
    """Display configuration summary."""
    console.print("\n" + "=" * 50)
    console.print("[bold]Summary:[/bold]")
    console.print(f"  Username:  [cyan]{username}[/cyan]")
    console.print(f"  Password:  [cyan]{'*' * len(password)}[/cyan]")
    console.print(f"  Routing:   [cyan]{'Tor' if use_tor else 'Direct'}[/cyan]")
    if use_tor and bridge_type != "none":
        console.print(f"  Bridge:    [cyan]{bridge_type}[/cyan]")
    console.print(f"  Security:  [cyan]{security_level}[/cyan]")
    if allowed_ports:
        console.print(f"  Ports:     [cyan]{', '.join(map(str, allowed_ports))}[/cyan]")
    if rate_limit:
        console.print(f"  Rate Limit:[cyan]{rate_limit} req/min[/cyan]")
    console.print("=" * 50)


def _create_user(auth_manager: AuthManager, username: str, password: str,
                 use_tor: bool, bridge_type: str, security_level: str,
                 allowed_ports: Optional[List[int]], rate_limit: Optional[int]) -> None:
    """Create the user with the specified settings."""
    try:
        auth_manager.add_user(
            username, password,
            use_tor=use_tor,
            bridge_type=bridge_type,
            security_level=security_level,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit
        )
        
        console.print(Panel(
            f"[bold green]User created successfully![/bold green]\n\n"
            f"Username: [cyan]{username}[/cyan]\n"
            f"Password: [cyan]{password}[/cyan]\n\n"
            f"[yellow]Save these credentials - the password won't be shown again![/yellow]",
            title="Success",
            border_style="green"
        ))
        
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
