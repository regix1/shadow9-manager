"""
Interactive user modification wizard for Shadow9.

Provides a step-by-step guided process for modifying existing proxy users.
"""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..auth import AuthManager
from ..config import Config
from ..paths import load_master_key

console = Console()


def run_user_modify_wizard(config_path: str = "config/config.yaml", preselected_username: str = None) -> None:
    """
    Interactive wizard to modify an existing user.
    
    Steps:
    1. Select user from list (if not preselected)
    2. Show current settings
    3. Choose what to modify
    4. Walk through selected option(s)
    5. Show summary and confirm changes
    """
    cfg = Config.load(Path(config_path)) if Path(config_path).exists() else Config()
    
    master_key = load_master_key()
    
    auth_manager = AuthManager(
        credentials_file=cfg.get_credentials_file(),
        master_key=master_key
    )
    
    users = auth_manager.list_users()
    
    if not users:
        console.print("[yellow]No users configured. Use 'shadow9 user new' to create one.[/yellow]")
        raise typer.Exit(0)
    
    # Step 1: Select user
    if preselected_username:
        if preselected_username not in users:
            console.print(f"[red]User '{preselected_username}' not found[/red]")
            raise typer.Exit(1)
        username = preselected_username
    else:
        username = _select_user(auth_manager, users)
    
    # Get current user info
    info = auth_manager.get_user_info(username)
    if not info:
        console.print(f"[red]Could not retrieve info for '{username}'[/red]")
        raise typer.Exit(1)
    
    # Show current settings
    _show_current_settings(info)
    
    # Main modification loop
    changes = []
    while True:
        action = _prompt_modification_menu()
        
        if action == "done":
            break
        elif action == "routing":
            change = _modify_routing(auth_manager, username, info)
            if change:
                changes.append(change)
                # Update local info
                info["use_tor"] = auth_manager.get_user_tor_preference(username)
        elif action == "bridge":
            change = _modify_bridge(auth_manager, username, info)
            if change:
                changes.append(change)
                info["bridge_type"] = auth_manager.get_user_bridge_type(username)
        elif action == "security":
            change = _modify_security(auth_manager, username, info)
            if change:
                changes.append(change)
                info["security_level"] = auth_manager.get_user_security_level(username)
        elif action == "ports":
            change = _modify_ports(auth_manager, username, info)
            if change:
                changes.append(change)
                info["allowed_ports"] = auth_manager.get_user_allowed_ports(username)
        elif action == "rate_limit":
            change = _modify_rate_limit(auth_manager, username, info)
            if change:
                changes.append(change)
                info["rate_limit"] = auth_manager.get_user_rate_limit(username)
        elif action == "status":
            change = _modify_status(auth_manager, username, info)
            if change:
                changes.append(change)
                info["enabled"] = auth_manager.get_user_enabled(username)
        elif action == "logging":
            change = _modify_logging(auth_manager, username, info)
            if change:
                changes.append(change)
                info["logging_enabled"] = auth_manager.get_user_logging_enabled(username)
    
    # Show summary
    if changes:
        console.print(Panel(
            "[bold green]Changes applied:[/bold green]\n\n" +
            "\n".join(f"  • {change}" for change in changes),
            title="Summary",
            border_style="green"
        ))
        console.print("[yellow]Restart service to apply: shadow9 service restart[/yellow]")
    else:
        console.print("[yellow]No changes were made.[/yellow]")


def _select_user(auth_manager: AuthManager, users: List[str]) -> str:
    """Display numbered list of users and let user select one."""
    console.print(Panel(
        "[bold cyan]Select User to Modify[/bold cyan]\n\n"
        "Choose a user from the list below.",
        border_style="cyan"
    ))
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("#", style="dim", width=4)
    table.add_column("Username", style="cyan")
    table.add_column("Routing", style="green")
    table.add_column("Status", style="yellow")
    
    for i, username in enumerate(users, 1):
        use_tor = auth_manager.get_user_tor_preference(username)
        enabled = auth_manager.get_user_enabled(username)
        routing = "Tor" if use_tor else "Direct"
        status = "[green]Enabled[/green]" if enabled else "[red]Disabled[/red]"
        table.add_row(str(i), username, routing, status)
    
    console.print(table)
    console.print()
    
    while True:
        choice = typer.prompt("  Select user number", default="1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(users):
                return users[idx]
            console.print(f"  [red]Please enter a number between 1 and {len(users)}[/red]")
        except ValueError:
            # Check if they entered a username directly
            if choice in users:
                return choice
            console.print("  [red]Please enter a valid number or username[/red]")


def _show_current_settings(info: dict) -> None:
    """Display current user settings."""
    console.print()
    table = Table(title=f"Current Settings: {info['username']}")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    # Status
    status = "[green]Enabled[/green]" if info["enabled"] else "[red]Disabled[/red]"
    table.add_row("Status", status)
    
    # Routing
    routing = "Tor" if info["use_tor"] else "Direct"
    table.add_row("Routing", routing)
    
    # Bridge
    bridge = info.get("bridge_type", "none")
    table.add_row("Bridge", bridge if info["use_tor"] else "[dim]N/A (Direct routing)[/dim]")
    
    # Security
    security = info.get("security_level", "basic")
    table.add_row("Security", security.upper())
    
    # Logging
    logging_enabled = info.get("logging_enabled", True)
    if logging_enabled:
        table.add_row("Logging", "[green]Enabled[/green]")
    else:
        table.add_row("Logging", "[yellow]Disabled[/yellow] (no activity tracking)")
    
    # Ports
    allowed_ports = info.get("allowed_ports")
    if allowed_ports:
        table.add_row("Allowed Ports", ", ".join(map(str, allowed_ports)))
    else:
        table.add_row("Allowed Ports", "All (no restrictions)")
    
    # Rate limit
    rate_limit = info.get("rate_limit")
    if rate_limit:
        table.add_row("Rate Limit", f"{rate_limit} req/min")
    else:
        table.add_row("Rate Limit", "Server default")
    
    console.print(table)


def _prompt_modification_menu() -> str:
    """Show menu of modification options."""
    console.print("\n[bold]What would you like to modify?[/bold]\n")
    console.print("  [cyan]1.[/cyan] Routing (Tor/Direct)")
    console.print("  [cyan]2.[/cyan] Bridge type")
    console.print("  [cyan]3.[/cyan] Security level")
    console.print("  [cyan]4.[/cyan] Port restrictions")
    console.print("  [cyan]5.[/cyan] Rate limiting")
    console.print("  [cyan]6.[/cyan] Enable/Disable account")
    console.print("  [cyan]7.[/cyan] Activity logging")
    console.print("  [cyan]8.[/cyan] [green]Done - exit wizard[/green]")
    console.print()
    
    choice = typer.prompt("  Select option [1-8]", default="8")
    
    menu_map = {
        "1": "routing",
        "2": "bridge",
        "3": "security",
        "4": "ports",
        "5": "rate_limit",
        "6": "status",
        "7": "logging",
        "8": "done",
    }
    return menu_map.get(choice, "done")


def _modify_routing(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify Tor routing preference."""
    current = "Tor" if info["use_tor"] else "Direct"
    console.print(f"\n[bold]Modify Routing[/bold] [dim](current: {current})[/dim]\n")
    console.print("  [cyan]Tor[/cyan] - Routes through multiple relays for anonymity.")
    console.print("     Your real IP is hidden. Slower but anonymous.")
    console.print("     [dim]Best for: Privacy-sensitive browsing, .onion sites[/dim]\n")
    console.print("  [cyan]Direct[/cyan] - Traffic goes directly to destination.")
    console.print("     Faster but uses your server's IP address.")
    console.print("     [dim]Best for: Speed priority, trusted networks[/dim]\n")
    
    default = info["use_tor"]
    use_tor = typer.confirm("  Route traffic through Tor?", default=default)
    
    if use_tor == info["use_tor"]:
        console.print("  [dim]No change[/dim]")
        return None
    
    auth_manager.set_user_tor_preference(username, use_tor)
    new_routing = "Tor" if use_tor else "Direct"
    console.print(f"  [green]Routing updated to: {new_routing}[/green]")
    return f"Routing: {current} → {new_routing}"


def _modify_bridge(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify Tor bridge type."""
    if not info["use_tor"]:
        console.print("\n[yellow]Bridge settings only apply when Tor routing is enabled.[/yellow]")
        enable_tor = typer.confirm("  Enable Tor routing first?", default=True)
        if enable_tor:
            auth_manager.set_user_tor_preference(username, True)
            info["use_tor"] = True
            console.print("  [green]Tor routing enabled[/green]")
        else:
            return None
    
    current = info.get("bridge_type", "none")
    
    console.print(f"\n[bold]Modify Bridge Type[/bold] [dim](current: {current})[/dim]\n")
    
    console.print("  [cyan]1. none[/cyan]")
    console.print("     Direct connection to Tor network.")
    console.print("     [dim]Best for: Unrestricted networks, fastest option[/dim]\n")
    
    console.print("  [cyan]2. obfs4[/cyan]")
    console.print("     Obfuscates traffic to look like random data.")
    console.print("     [dim]Best for: ISPs that block Tor, moderate censorship[/dim]\n")
    
    console.print("  [cyan]3. snowflake[/cyan]")
    console.print("     Routes through volunteer browser proxies via WebRTC.")
    console.print("     [dim]Best for: When obfs4 is blocked, dynamic endpoints[/dim]\n")
    
    # Determine default based on current
    default_map = {"none": "1", "obfs4": "2", "snowflake": "3"}
    default = default_map.get(current, "1")
    
    bridge_choice = typer.prompt("  Select bridge [1-3]", default=default)
    bridge_map = {"1": "none", "2": "obfs4", "3": "snowflake"}
    new_bridge = bridge_map.get(bridge_choice, current)
    
    if new_bridge == current:
        console.print("  [dim]No change[/dim]")
        return None
    
    auth_manager.set_user_bridge_type(username, new_bridge)
    console.print(f"  [green]Bridge updated to: {new_bridge}[/green]")
    return f"Bridge: {current} → {new_bridge}"


def _modify_security(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify security level."""
    current = info.get("security_level", "basic")
    
    console.print(f"\n[bold]Modify Security Level[/bold] [dim](current: {current.upper()})[/dim]\n")
    
    console.print("  [cyan]1. none[/cyan]")
    console.print("     No evasion techniques applied.")
    console.print("     [dim]Best for: Maximum speed, privacy not a concern[/dim]\n")
    
    console.print("  [cyan]2. basic[/cyan]")
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
    
    # Determine default based on current
    default_map = {"none": "1", "basic": "2", "moderate": "3", "paranoid": "4"}
    default = default_map.get(current, "2")
    
    security_choice = typer.prompt("  Select level [1-4]", default=default)
    security_map = {"1": "none", "2": "basic", "3": "moderate", "4": "paranoid"}
    new_security = security_map.get(security_choice, current)
    
    if new_security == current:
        console.print("  [dim]No change[/dim]")
        return None
    
    auth_manager.set_user_security_level(username, new_security)
    console.print(f"  [green]Security updated to: {new_security.upper()}[/green]")
    return f"Security: {current.upper()} → {new_security.upper()}"


def _modify_ports(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify port restrictions."""
    current = info.get("allowed_ports")
    current_display = ", ".join(map(str, current)) if current else "All (no restrictions)"
    
    console.print(f"\n[bold]Modify Port Restrictions[/bold] [dim](current: {current_display})[/dim]\n")
    
    console.print("  [cyan]1.[/cyan] Remove restrictions (allow all ports)")
    console.print("  [cyan]2.[/cyan] Set specific ports")
    console.print("  [cyan]3.[/cyan] Keep current setting")
    console.print()
    
    choice = typer.prompt("  Select option [1-3]", default="3")
    
    if choice == "1":
        if current is None:
            console.print("  [dim]No change (already unrestricted)[/dim]")
            return None
        auth_manager.set_user_allowed_ports(username, None)
        console.print("  [green]Port restrictions removed[/green]")
        return f"Ports: {current_display} → All (no restrictions)"
    
    elif choice == "2":
        default_ports = ", ".join(map(str, current)) if current else "80, 443"
        ports_input = typer.prompt("  Enter ports (comma-separated)", default=default_ports)
        try:
            new_ports = [int(p.strip()) for p in ports_input.split(',')]
            if current and set(new_ports) == set(current):
                console.print("  [dim]No change[/dim]")
                return None
            auth_manager.set_user_allowed_ports(username, new_ports)
            new_display = ", ".join(map(str, new_ports))
            console.print(f"  [green]Ports updated to: {new_display}[/green]")
            return f"Ports: {current_display} → {new_display}"
        except ValueError:
            console.print("  [red]Invalid port format. No changes made.[/red]")
            return None
    
    else:
        console.print("  [dim]No change[/dim]")
        return None


def _modify_rate_limit(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify rate limiting."""
    current = info.get("rate_limit")
    current_display = f"{current} req/min" if current else "Server default"
    
    console.print(f"\n[bold]Modify Rate Limit[/bold] [dim](current: {current_display})[/dim]\n")
    
    console.print("  [cyan]1.[/cyan] Remove rate limit (use server default)")
    console.print("  [cyan]2.[/cyan] Set specific rate limit")
    console.print("  [cyan]3.[/cyan] Keep current setting")
    console.print()
    
    choice = typer.prompt("  Select option [1-3]", default="3")
    
    if choice == "1":
        if current is None:
            console.print("  [dim]No change (already using server default)[/dim]")
            return None
        auth_manager.set_user_rate_limit(username, None)
        console.print("  [green]Rate limit removed (using server default)[/green]")
        return f"Rate Limit: {current_display} → Server default"
    
    elif choice == "2":
        default_limit = str(current) if current else "60"
        try:
            new_limit = typer.prompt("  Max requests per minute", default=default_limit, type=int)
            if new_limit == current:
                console.print("  [dim]No change[/dim]")
                return None
            auth_manager.set_user_rate_limit(username, new_limit)
            console.print(f"  [green]Rate limit updated to: {new_limit} req/min[/green]")
            return f"Rate Limit: {current_display} → {new_limit} req/min"
        except ValueError:
            console.print("  [red]Invalid number. No changes made.[/red]")
            return None
    
    else:
        console.print("  [dim]No change[/dim]")
        return None


def _modify_status(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify enabled/disabled status."""
    current = info["enabled"]
    current_display = "Enabled" if current else "Disabled"
    
    console.print(f"\n[bold]Modify Account Status[/bold] [dim](current: {current_display})[/dim]\n")
    
    if current:
        console.print("  This account is currently [green]enabled[/green].")
        console.print("  Disabling will prevent the user from connecting.\n")
        disable = typer.confirm("  Disable this account?", default=False)
        if disable:
            auth_manager.set_user_enabled(username, False)
            console.print("  [yellow]Account disabled[/yellow]")
            return "Status: Enabled → Disabled"
    else:
        console.print("  This account is currently [red]disabled[/red].")
        console.print("  Enabling will allow the user to connect.\n")
        enable = typer.confirm("  Enable this account?", default=True)
        if enable:
            auth_manager.set_user_enabled(username, True)
            console.print("  [green]Account enabled[/green]")
            return "Status: Disabled → Enabled"
    
    console.print("  [dim]No change[/dim]")
    return None


def _modify_logging(auth_manager: AuthManager, username: str, info: dict) -> Optional[str]:
    """Modify activity logging setting (privacy feature)."""
    current = info.get("logging_enabled", True)
    current_display = "Enabled" if current else "Disabled"
    
    console.print(f"\n[bold]Modify Activity Logging[/bold] [dim](current: {current_display})[/dim]\n")
    
    if current:
        console.print("  Activity logging is currently [green]enabled[/green].")
        console.print("  Disabling will prevent the server from recording:")
        console.print("    • Connection times and targets")
        console.print("    • IP addresses and traffic data")
        console.print("    • Any activity for this user\n")
        console.print("  [dim]This is a server-side privacy guarantee.[/dim]\n")
        disable = typer.confirm("  Disable activity logging for this user?", default=False)
        if disable:
            auth_manager.set_user_logging_enabled(username, False)
            console.print("  [yellow]Activity logging disabled[/yellow]")
            return "Logging: Enabled → Disabled (no activity tracking)"
    else:
        console.print("  Activity logging is currently [yellow]disabled[/yellow].")
        console.print("  No connection data is being recorded for this user.")
        console.print("  Enabling will allow normal logging of activity.\n")
        enable = typer.confirm("  Enable activity logging for this user?", default=False)
        if enable:
            auth_manager.set_user_logging_enabled(username, True)
            console.print("  [green]Activity logging enabled[/green]")
            return "Logging: Disabled → Enabled"
    
    console.print("  [dim]No change[/dim]")
    return None
