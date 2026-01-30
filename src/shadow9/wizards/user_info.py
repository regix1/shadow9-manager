"""
Interactive user info wizard for Shadow9.

Provides an interactive menu for viewing user details.
"""


import typer
from rich.console import Console
from rich.table import Table

from ..auth import AuthManager

console = Console()


def run_user_info_wizard(auth_manager: AuthManager) -> bool | None:
    """
    Interactive wizard to view user information.
    
    Args:
        auth_manager: The authentication manager
    
    Returns:
        True on success, False on error, None on cancel.
    """
    try:
        users = auth_manager.list_users()
        
        if not users:
            console.print("[yellow]No users configured[/yellow]")
            return True
        
        while True:
            console.print("\n[bold cyan]Select a user to view:[/bold cyan]\n")
            for i, user in enumerate(users, 1):
                use_tor = auth_manager.get_user_tor_preference(user)
                routing = "[green]Tor[/green]" if use_tor else "[yellow]Direct[/yellow]"
                console.print(f"  [cyan]{i}[/cyan]. {user} ({routing})")
            
            console.print(f"\n  [dim]Enter number 1-{len(users)}, or 'q' to quit[/dim]")
            
            choice = typer.prompt("  Select user", default="q")
            
            if choice.lower() == 'q':
                return True
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(users):
                    display_user_info(auth_manager, users[idx])
                    
                    if not typer.confirm("\nView another user?", default=False):
                        return True
                else:
                    console.print(f"  [red]Please enter a number between 1 and {len(users)}[/red]")
            except ValueError:
                console.print("  [red]Please enter a valid number[/red]")
        
        return True
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return False


def display_user_info(auth_manager: AuthManager, username: str) -> None:
    """
    Display detailed information for a single user.
    
    Args:
        auth_manager: The authentication manager
        username: The username to display info for
    """
    info = auth_manager.get_user_info(username)

    if not info:
        console.print(f"[red]User '{username}' not found[/red]")
        return

    table = Table(title=f"User: {username}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Username", info["username"])
    table.add_row("Status", "[green]Enabled[/green]" if info["enabled"] else "[red]Disabled[/red]")

    # Display routing with bridge info
    routing = "Tor" if info["use_tor"] else "Direct"
    bridge = info.get("bridge_type", "none")
    if bridge != "none":
        routing += f" + {bridge} bridge"
    table.add_row("Routing", routing)

    table.add_row("Security", info.get("security_level", "basic").upper())

    # Display logging status (privacy setting)
    logging_enabled = info.get("logging_enabled", True)
    if logging_enabled:
        table.add_row("Logging", "[green]Enabled[/green]")
    else:
        table.add_row("Logging", "[yellow]Disabled[/yellow] (no activity tracking)")

    # Display allowed ports
    allowed_ports = info.get("allowed_ports")
    if allowed_ports:
        table.add_row("Allowed Ports", ", ".join(map(str, allowed_ports)))
    else:
        table.add_row("Allowed Ports", "All (no restrictions)")

    # Display rate limit
    rate_limit = info.get("rate_limit")
    if rate_limit:
        table.add_row("Rate Limit", f"{rate_limit} req/min")
    else:
        table.add_row("Rate Limit", "Server default")

    # Display bind port
    bind_port = info.get("bind_port")
    if bind_port:
        table.add_row("Bind Port", f"{bind_port} (dedicated listener)")
    else:
        table.add_row("Bind Port", "Shared (server default)")

    table.add_row("Created", info["created_at"] or "Unknown")
    table.add_row("Last Used", info["last_used"] or "Never")

    console.print(table)
