"""
Interactive user removal wizard for Shadow9.

Provides an interactive menu for selecting and removing users.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from ..auth import AuthManager
from ..config import Config

console = Console()


def run_user_remove_wizard(
    auth_manager: AuthManager,
    username: Optional[str] = None,
    yes: bool = False,
    all_users: bool = False,
) -> bool:
    """
    Interactive wizard to remove users.
    
    Args:
        auth_manager: The authentication manager
        username: Optional specific username to remove
        yes: Skip confirmation prompts
        all_users: Remove all users
        
    Returns:
        True if removal was successful, False otherwise
    """
    users = auth_manager.list_users()
    
    if not users:
        console.print("[yellow]No users configured[/yellow]")
        return False

    # Handle --all flag
    if all_users:
        if not yes:
            console.print(f"[bold red]This will remove ALL {len(users)} users![/bold red]")
            confirm = typer.confirm("Are you sure?", default=False)
            if not confirm:
                return False
        
        for user in users:
            auth_manager.remove_user(user)
            console.print(f"[dim]Removed: {user}[/dim]")
        console.print(f"[green]All {len(users)} users removed[/green]")
        return True

    # Interactive mode if no username provided
    if username is None:
        console.print("\n[bold]Select user(s) to remove:[/bold]\n")
        
        # Show numbered list
        for i, user in enumerate(users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")
        
        console.print(f"  [cyan]A.[/cyan] [red]Remove ALL users[/red]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")
        
        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")
        
        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return False
        
        if choice.upper() == "A":
            if not yes:
                console.print(f"\n[bold red]This will remove ALL {len(users)} users![/bold red]")
                confirm = typer.confirm("Are you sure?", default=False)
                if not confirm:
                    return False
            
            for user in users:
                auth_manager.remove_user(user)
                console.print(f"[dim]Removed: {user}[/dim]")
            console.print(f"[green]All {len(users)} users removed[/green]")
            return True
        
        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(users):
                username = users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return False
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return False

    # Confirm and remove single user
    if not yes:
        confirm = typer.confirm(f"Remove user '{username}'?")
        if not confirm:
            return False

    if auth_manager.remove_user(username):
        console.print(f"[green]User '{username}' removed[/green]")
        return True
    else:
        console.print(f"[red]User '{username}' not found[/red]")
        return False
