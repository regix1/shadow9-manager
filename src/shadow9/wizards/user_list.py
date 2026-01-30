"""
Interactive user list wizard for Shadow9.

Provides an interactive menu for browsing and managing users.
"""


import typer
from rich.console import Console

from ..auth import AuthManager
from .user_info import display_user_info

console = Console()


def run_user_list_wizard(auth_manager: AuthManager, config_path: str) -> bool | None:
    """
    Interactive user list with actions.
    
    Args:
        auth_manager: The authentication manager
        config_path: Path to the configuration file
    
    Returns:
        True on success, False on error, None on cancel.
    """
    try:
        while True:
            users = auth_manager.list_users()
            
            if not users:
                console.print("[yellow]No users configured[/yellow]")
                return True
            
            console.print("\n[bold cyan]Users[/bold cyan]")
            console.print("[dim]Select a user to perform actions[/dim]\n")
            
            # Display users with status
            for i, username in enumerate(users, 1):
                use_tor = auth_manager.get_user_tor_preference(username)
                enabled = auth_manager.get_user_enabled(username)
                security = auth_manager.get_user_security_level(username)
                
                routing = "[green]Tor[/green]" if use_tor else "[yellow]Direct[/yellow]"
                status = "" if enabled else " [red](disabled)[/red]"
                
                console.print(f"  [cyan]{i}.[/cyan] {username} ({routing}) [dim]{security}{status}[/dim]")
            
            console.print(f"\n  [dim]Enter 1-{len(users)} to select, 'n' to add new, 'q' to quit[/dim]")
            
            choice = typer.prompt("Select", default="q")
            
            if choice.lower() == 'q':
                return True
            
            if choice.lower() == 'n':
                from .user_new import run_user_wizard
                run_user_wizard(config_path)
                continue
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(users):
                    username = users[idx]
                    _user_action_menu(auth_manager, username, config_path)
                else:
                    console.print(f"  [red]Please enter a number between 1 and {len(users)}[/red]")
            except ValueError:
                console.print("  [red]Invalid selection[/red]")
        
        return True
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return False


def _user_action_menu(auth_manager: AuthManager, username: str, config_path: str) -> None:
    """
    Show action menu for a specific user.
    
    Args:
        auth_manager: The authentication manager
        username: The username to manage
        config_path: Path to the configuration file
    """
    while True:
        # Get current user info
        use_tor = auth_manager.get_user_tor_preference(username)
        enabled = auth_manager.get_user_enabled(username)
        security = auth_manager.get_user_security_level(username)
        bridge = auth_manager.get_user_bridge_type(username)
        ports = auth_manager.get_user_allowed_ports(username)
        rate_limit = auth_manager.get_user_rate_limit(username)
        
        routing = "[green]Tor[/green]" if use_tor else "[yellow]Direct[/yellow]"
        status = "[green]Enabled[/green]" if enabled else "[red]Disabled[/red]"
        
        console.print(f"\n[bold cyan]User: {username}[/bold cyan]")
        console.print(f"  Status: {status} | Routing: {routing} | Security: {security}")
        if use_tor and bridge != "none":
            console.print(f"  Bridge: {bridge}")
        
        console.print("\n[bold]Actions:[/bold]")
        console.print("  [cyan]i[/cyan] - View full info")
        console.print("  [cyan]t[/cyan] - Toggle Tor routing")
        console.print("  [cyan]e[/cyan] - " + ("Disable user" if enabled else "Enable user"))
        console.print("  [cyan]s[/cyan] - Change security level")
        console.print("  [cyan]b[/cyan] - Change bridge type")
        console.print("  [cyan]p[/cyan] - Change port restrictions")
        console.print("  [cyan]r[/cyan] - Change rate limit")
        console.print("  [cyan]d[/cyan] - [red]Delete user[/red]")
        console.print("  [cyan]q[/cyan] - Back to list\n")
        
        action = typer.prompt("Action", default="q")
        
        if action.lower() == 'q':
            return
        
        if action.lower() == 'i':
            display_user_info(auth_manager, username)
            typer.prompt("\nPress Enter to continue", default="")
            continue
        
        if action.lower() == 't':
            new_tor = not use_tor
            auth_manager.set_user_tor_preference(username, new_tor)
            routing_str = "Tor" if new_tor else "Direct"
            console.print(f"  [green]Routing changed to {routing_str}[/green]")
            continue
        
        if action.lower() == 'e':
            new_status = not enabled
            auth_manager.set_user_enabled(username, new_status)
            status_str = "enabled" if new_status else "disabled"
            console.print(f"  [green]User {status_str}[/green]")
            continue
        
        if action.lower() == 's':
            console.print("\n  [cyan]1.[/cyan] none - No evasion")
            console.print("  [cyan]2.[/cyan] basic - Standard protection")
            console.print("  [cyan]3.[/cyan] moderate - Timing jitter, padding")
            console.print("  [cyan]4.[/cyan] paranoid - Maximum evasion\n")
            level_choice = typer.prompt("  Select level [1-4]", default="2")
            level_map = {"1": "none", "2": "basic", "3": "moderate", "4": "paranoid"}
            new_level = level_map.get(level_choice, "basic")
            auth_manager.set_user_security_level(username, new_level)
            console.print(f"  [green]Security level set to {new_level}[/green]")
            continue
        
        if action.lower() == 'b':
            console.print("\n  [cyan]1.[/cyan] none - No bridge")
            console.print("  [cyan]2.[/cyan] obfs4 - Obfuscated bridge")
            console.print("  [cyan]3.[/cyan] snowflake - WebRTC-based\n")
            bridge_choice = typer.prompt("  Select bridge [1-3]", default="1")
            bridge_map = {"1": "none", "2": "obfs4", "3": "snowflake"}
            new_bridge = bridge_map.get(bridge_choice, "none")
            if new_bridge != "none" and not use_tor:
                auth_manager.set_user_tor_preference(username, True)
                console.print("  [dim]Tor enabled (required for bridge)[/dim]")
            auth_manager.set_user_bridge_type(username, new_bridge)
            console.print(f"  [green]Bridge set to {new_bridge}[/green]")
            continue
        
        if action.lower() == 'p':
            console.print(f"\n  Current: {', '.join(map(str, ports)) if ports else 'All ports allowed'}")
            console.print("  [dim]Enter comma-separated ports (e.g., 80,443,8080) or 'all' for no restrictions[/dim]\n")
            ports_input = typer.prompt("  Ports", default="all")
            if ports_input.lower() == "all":
                auth_manager.set_user_allowed_ports(username, None)
                console.print("  [green]All ports allowed[/green]")
            else:
                try:
                    new_ports = [int(p.strip()) for p in ports_input.split(",")]
                    auth_manager.set_user_allowed_ports(username, new_ports)
                    console.print(f"  [green]Ports set to {', '.join(map(str, new_ports))}[/green]")
                except ValueError:
                    console.print("  [red]Invalid port format[/red]")
            continue
        
        if action.lower() == 'r':
            console.print(f"\n  Current: {rate_limit if rate_limit else 'Server default'} req/min")
            console.print("  [dim]Enter requests per minute, or 0 for server default[/dim]\n")
            rate_input = typer.prompt("  Rate limit", default="0")
            try:
                new_rate = int(rate_input)
                if new_rate == 0:
                    auth_manager.set_user_rate_limit(username, None)
                    console.print("  [green]Rate limit set to server default[/green]")
                else:
                    auth_manager.set_user_rate_limit(username, new_rate)
                    console.print(f"  [green]Rate limit set to {new_rate} req/min[/green]")
            except ValueError:
                console.print("  [red]Invalid number[/red]")
            continue
        
        if action.lower() == 'd':
            if typer.confirm(f"  Delete user '{username}'?", default=False):
                auth_manager.remove_user(username)
                console.print(f"  [green]User '{username}' deleted[/green]")
                return  # Go back to list since user is deleted
            continue
        
        console.print("  [red]Unknown action[/red]")
