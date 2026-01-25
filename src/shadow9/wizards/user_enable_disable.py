"""
Interactive user enable/disable wizards for Shadow9.

Provides interactive menus for enabling and disabling users.
"""

from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console

from ..auth import AuthManager
from ..config import Config

console = Console()


def run_user_enable_wizard(
    auth_manager: AuthManager,
    username: Optional[str] = None,
) -> bool:
    """
    Interactive wizard to enable users.
    
    Args:
        auth_manager: The authentication manager
        username: Optional specific username to enable
        
    Returns:
        True if operation was successful, False otherwise
    """
    users = auth_manager.list_users()
    if not users:
        console.print("[yellow]No users found[/yellow]")
        return False

    # Get disabled users only
    disabled_users = [u for u in users if auth_manager.get_user_enabled(u) == False]

    # Interactive mode if no username provided
    if username is None:
        if not disabled_users:
            console.print("[green]All users are already enabled[/green]")
            return True

        console.print("\n[bold]Select user(s) to enable:[/bold]\n")

        # Show numbered list of disabled users
        for i, user in enumerate(disabled_users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")

        console.print(f"  [cyan]A.[/cyan] [green]Enable ALL disabled users[/green]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")

        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")

        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return False

        if choice.upper() == "A":
            for user in disabled_users:
                auth_manager.set_user_enabled(user, True)
                console.print(f"[dim]Enabled: {user}[/dim]")
            console.print(f"[green]All {len(disabled_users)} users enabled[/green]")
            return True

        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(disabled_users):
                username = disabled_users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return False
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return False

    if auth_manager.set_user_enabled(username, True):
        console.print(f"[green]User '{username}' enabled[/green]")
        return True
    else:
        console.print(f"[red]User '{username}' not found[/red]")
        return False


def run_user_disable_wizard(
    auth_manager: AuthManager,
    username: Optional[str] = None,
) -> bool:
    """
    Interactive wizard to disable users.
    
    Args:
        auth_manager: The authentication manager
        username: Optional specific username to disable
        
    Returns:
        True if operation was successful, False otherwise
    """
    users = auth_manager.list_users()
    if not users:
        console.print("[yellow]No users found[/yellow]")
        return False

    # Get enabled users only
    enabled_users = [u for u in users if auth_manager.get_user_enabled(u) == True]

    # Interactive mode if no username provided
    if username is None:
        if not enabled_users:
            console.print("[yellow]All users are already disabled[/yellow]")
            return True

        console.print("\n[bold]Select user(s) to disable:[/bold]\n")

        # Show numbered list of enabled users
        for i, user in enumerate(enabled_users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")

        console.print(f"  [cyan]A.[/cyan] [red]Disable ALL enabled users[/red]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")

        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")

        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return False

        if choice.upper() == "A":
            for user in enabled_users:
                auth_manager.set_user_enabled(user, False)
                console.print(f"[dim]Disabled: {user}[/dim]")
            console.print(f"[yellow]All {len(enabled_users)} users disabled[/yellow]")
            return True

        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(enabled_users):
                username = enabled_users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return False
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return False

    if auth_manager.set_user_enabled(username, False):
        console.print(f"[yellow]User '{username}' disabled[/yellow]")
        return True
    else:
        console.print(f"[red]User '{username}' not found[/red]")
        return False
