"""
Shadow9 Interactive Menu System.

Provides a persistent interactive menu for managing Shadow9.
"""

import sys
import platform
from typing import Callable

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shadow9.auth import AuthManager
from shadow9.config import Config
from shadow9.paths import get_paths
from shadow9.wizards import (
    run_user_wizard,
    run_user_modify_wizard,
    run_user_list_wizard,
    run_api_setup_wizard,
    display_api_config,
    display_user_info,
)
from shadow9.wizards.user_remove import run_user_remove_wizard
from shadow9.wizards.user_enable_disable import run_user_enable_wizard, run_user_disable_wizard

console = Console()


def _is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system().lower() == "linux"


def _wait_for_enter() -> None:
    """Wait for user to press Enter to continue."""
    typer.prompt("\nPress Enter to continue", default="", show_default=False)


def _get_choice(prompt: str = "Select option") -> str:
    """Get user choice with graceful handling."""
    try:
        return typer.prompt(prompt, default="").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return "q"


def _show_main_menu() -> None:
    """Display the main menu."""
    console.clear()
    console.print(Panel(
        "[bold cyan]Shadow9 Manager[/bold cyan]\n\n"
        "[dim]Secure SOCKS5 Proxy Management System[/dim]",
        border_style="cyan",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="cyan bold")
    table.add_column("Description")
    
    table.add_row("1", "User Management")
    table.add_row("2", "Server Control")
    table.add_row("3", "API Management")
    if _is_linux():
        table.add_row("4", "Service Management")
    table.add_row("5", "Settings")
    table.add_row("q", "Quit")
    
    console.print(table)
    console.print()


def _show_user_menu() -> None:
    """Display the user management submenu."""
    console.clear()
    console.print(Panel(
        "[bold green]User Management[/bold green]\n\n"
        "[dim]Create, modify, and manage proxy users[/dim]",
        border_style="green",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="green bold")
    table.add_column("Description")
    
    table.add_row("1", "Create new user")
    table.add_row("2", "List users")
    table.add_row("3", "Modify user")
    table.add_row("4", "Remove user")
    table.add_row("5", "Enable user")
    table.add_row("6", "Disable user")
    table.add_row("7", "View user info")
    table.add_row("8", "Generate credentials")
    table.add_row("b", "Back to main menu")
    
    console.print(table)
    console.print()


def _show_server_menu() -> None:
    """Display the server control submenu."""
    console.clear()
    console.print(Panel(
        "[bold yellow]Server Control[/bold yellow]\n\n"
        "[dim]Start, stop, and configure the proxy server[/dim]",
        border_style="yellow",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="yellow bold")
    table.add_column("Description")
    
    table.add_row("1", "Start server")
    table.add_row("2", "Start server (interactive mode)")
    table.add_row("3", "Server status")
    table.add_row("4", "View active connections")
    table.add_row("b", "Back to main menu")
    
    console.print(table)
    console.print()


def _show_api_menu() -> None:
    """Display the API management submenu."""
    console.clear()
    console.print(Panel(
        "[bold magenta]API Management[/bold magenta]\n\n"
        "[dim]Configure and manage the REST API[/dim]",
        border_style="magenta",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="magenta bold")
    table.add_column("Description")
    
    table.add_row("1", "Setup API")
    table.add_row("2", "View API configuration")
    table.add_row("3", "Start API server")
    table.add_row("4", "Generate API key")
    table.add_row("b", "Back to main menu")
    
    console.print(table)
    console.print()


def _show_service_menu() -> None:
    """Display the service management submenu (Linux only)."""
    console.clear()
    console.print(Panel(
        "[bold blue]Service Management[/bold blue]\n\n"
        "[dim]Manage Shadow9 as a systemd service[/dim]",
        border_style="blue",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="blue bold")
    table.add_column("Description")
    
    table.add_row("1", "Install service")
    table.add_row("2", "Uninstall service")
    table.add_row("3", "Start service")
    table.add_row("4", "Stop service")
    table.add_row("5", "Restart service")
    table.add_row("6", "Service status")
    table.add_row("7", "View service logs")
    table.add_row("b", "Back to main menu")
    
    console.print(table)
    console.print()


def _show_settings_menu() -> None:
    """Display the settings submenu."""
    console.clear()
    console.print(Panel(
        "[bold red]Settings[/bold red]\n\n"
        "[dim]Configure Shadow9 settings[/dim]",
        border_style="red",
        padding=(1, 2)
    ))
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Option", style="red bold")
    table.add_column("Description")
    
    table.add_row("1", "View current configuration")
    table.add_row("2", "Initialize/reset configuration")
    table.add_row("3", "Show master key")
    table.add_row("4", "View paths")
    table.add_row("b", "Back to main menu")
    
    console.print(table)
    console.print()


def _safe_execute(action: Callable[[], None], action_name: str) -> None:
    """Execute an action with error handling."""
    try:
        action()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error during {action_name}: {e}[/red]")
    _wait_for_enter()


def _get_auth_manager() -> AuthManager:
    """Get or create an AuthManager instance."""
    paths = get_paths()
    master_key = paths.get_master_key()
    if not master_key:
        console.print("[red]Master key not found. Please run 'shadow9 init' first.[/red]")
        raise ValueError("Master key not configured")
    return AuthManager(master_key=master_key)


# User Management Actions

def _action_create_user() -> None:
    """Create a new user."""
    console.clear()
    run_user_wizard()


def _action_list_users() -> None:
    """List all users."""
    console.clear()
    run_user_list_wizard()


def _action_modify_user() -> None:
    """Modify an existing user."""
    console.clear()
    run_user_modify_wizard()


def _action_remove_user() -> None:
    """Remove a user."""
    console.clear()
    run_user_remove_wizard()


def _action_enable_user() -> None:
    """Enable a user."""
    console.clear()
    run_user_enable_wizard()


def _action_disable_user() -> None:
    """Disable a user."""
    console.clear()
    run_user_disable_wizard()


def _action_view_user_info() -> None:
    """View detailed user information."""
    console.clear()
    console.print(Panel("[bold]View User Info[/bold]", border_style="green"))
    username = typer.prompt("Enter username")
    if username:
        try:
            auth = _get_auth_manager()
            display_user_info(auth, username)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")


def _action_generate_credentials() -> None:
    """Generate new credentials for a user."""
    console.clear()
    console.print(Panel("[bold]Generate Credentials[/bold]", border_style="green"))
    try:
        auth = _get_auth_manager()
        users = auth.list_users()
        if not users:
            console.print("[yellow]No users found. Create a user first.[/yellow]")
            return
        
        console.print("\n[cyan]Available users:[/cyan]")
        for user in users:
            console.print(f"  • {user}")
        
        username = typer.prompt("\nEnter username")
        if username not in users:
            console.print(f"[red]User '{username}' not found.[/red]")
            return
        
        new_username, new_password = auth.generate_credentials()
        console.print("\n[green]Generated credentials:[/green]")
        console.print(f"  Username: [cyan]{new_username}[/cyan]")
        console.print(f"  Password: [cyan]{new_password}[/cyan]")
        console.print("\n[dim]Note: These are suggested credentials. Use 'Modify user' to update.[/dim]")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")


# Server Control Actions

def _action_start_server() -> None:
    """Start the proxy server."""
    console.clear()
    console.print(Panel("[bold]Starting Server[/bold]", border_style="yellow"))
    console.print("[dim]Starting server with default configuration...[/dim]\n")
    
    # Import here to avoid circular imports
    from shadow9.cli import app
    try:
        # Use typer to invoke the serve command
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "shadow9", "serve"],
            capture_output=False
        )
    except Exception as e:
        console.print(f"[red]Failed to start server: {e}[/red]")


def _action_start_server_interactive() -> None:
    """Start server in interactive mode."""
    console.clear()
    console.print(Panel("[bold]Starting Server (Interactive)[/bold]", border_style="yellow"))
    
    from shadow9.wizards import run_serve_wizard, show_serve_preview
    try:
        host, port = run_serve_wizard()
        show_serve_preview(host, port)
        
        if typer.confirm("\nStart server with these settings?", default=True):
            import subprocess
            subprocess.run(
                [sys.executable, "-m", "shadow9", "serve", "--host", host, "--port", str(port)],
                capture_output=False
            )
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _action_server_status() -> None:
    """Show server status."""
    console.clear()
    console.print(Panel("[bold]Server Status[/bold]", border_style="yellow"))
    console.print("[dim]Checking server status...[/dim]\n")
    
    # Basic status check - try to connect to default port
    import socket
    ports_to_check = [1080, 8080]
    
    for port in ports_to_check:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                console.print(f"[green]✓ Port {port}: Service running[/green]")
            else:
                console.print(f"[dim]✗ Port {port}: Not listening[/dim]")
        except Exception:
            console.print(f"[dim]✗ Port {port}: Unable to check[/dim]")


def _action_view_connections() -> None:
    """View active connections."""
    console.clear()
    console.print(Panel("[bold]Active Connections[/bold]", border_style="yellow"))
    console.print("[dim]This feature requires the server to be running with session tracking.[/dim]")
    console.print("\n[yellow]Not implemented yet.[/yellow]")


# API Management Actions

def _action_setup_api() -> None:
    """Setup the API."""
    console.clear()
    run_api_setup_wizard()


def _action_view_api_config() -> None:
    """View API configuration."""
    console.clear()
    display_api_config()


def _action_start_api() -> None:
    """Start the API server."""
    console.clear()
    console.print(Panel("[bold]Starting API Server[/bold]", border_style="magenta"))
    
    import subprocess
    try:
        subprocess.run(
            [sys.executable, "-m", "shadow9", "api", "start"],
            capture_output=False
        )
    except Exception as e:
        console.print(f"[red]Failed to start API: {e}[/red]")


def _action_generate_api_key() -> None:
    """Generate a new API key."""
    console.clear()
    console.print(Panel("[bold]Generate API Key[/bold]", border_style="magenta"))
    
    import secrets
    api_key = secrets.token_urlsafe(32)
    console.print(f"\n[green]Generated API Key:[/green]")
    console.print(f"[cyan]{api_key}[/cyan]")
    console.print("\n[dim]Save this key securely. You'll need it to authenticate API requests.[/dim]")


# Service Management Actions (Linux only)

def _action_install_service() -> None:
    """Install systemd service."""
    console.clear()
    console.print(Panel("[bold]Install Service[/bold]", border_style="blue"))
    
    import subprocess
    try:
        subprocess.run(
            [sys.executable, "-m", "shadow9", "service", "install"],
            capture_output=False
        )
    except Exception as e:
        console.print(f"[red]Failed to install service: {e}[/red]")


def _action_uninstall_service() -> None:
    """Uninstall systemd service."""
    console.clear()
    console.print(Panel("[bold]Uninstall Service[/bold]", border_style="blue"))
    
    import subprocess
    try:
        subprocess.run(
            [sys.executable, "-m", "shadow9", "service", "uninstall"],
            capture_output=False
        )
    except Exception as e:
        console.print(f"[red]Failed to uninstall service: {e}[/red]")


def _action_start_service() -> None:
    """Start systemd service."""
    console.clear()
    console.print(Panel("[bold]Starting Service[/bold]", border_style="blue"))
    
    import subprocess
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "start", "shadow9"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]Service started successfully.[/green]")
        else:
            console.print(f"[red]Failed to start service: {result.stderr}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _action_stop_service() -> None:
    """Stop systemd service."""
    console.clear()
    console.print(Panel("[bold]Stopping Service[/bold]", border_style="blue"))
    
    import subprocess
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "stop", "shadow9"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]Service stopped successfully.[/green]")
        else:
            console.print(f"[red]Failed to stop service: {result.stderr}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _action_restart_service() -> None:
    """Restart systemd service."""
    console.clear()
    console.print(Panel("[bold]Restarting Service[/bold]", border_style="blue"))
    
    import subprocess
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "restart", "shadow9"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]Service restarted successfully.[/green]")
        else:
            console.print(f"[red]Failed to restart service: {result.stderr}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _action_service_status() -> None:
    """Show systemd service status."""
    console.clear()
    console.print(Panel("[bold]Service Status[/bold]", border_style="blue"))
    
    import subprocess
    try:
        result = subprocess.run(
            ["systemctl", "status", "shadow9"],
            capture_output=True,
            text=True
        )
        console.print(result.stdout)
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


def _action_view_service_logs() -> None:
    """View systemd service logs."""
    console.clear()
    console.print(Panel("[bold]Service Logs[/bold]", border_style="blue"))
    
    import subprocess
    try:
        result = subprocess.run(
            ["journalctl", "-u", "shadow9", "-n", "50", "--no-pager"],
            capture_output=True,
            text=True
        )
        console.print(result.stdout)
        if result.stderr:
            console.print(f"[dim]{result.stderr}[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# Settings Actions

def _action_view_config() -> None:
    """View current configuration."""
    console.clear()
    console.print(Panel("[bold]Current Configuration[/bold]", border_style="red"))
    
    try:
        config = Config.load()
        
        table = Table(title="Server Configuration", show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Host", config.server.host)
        table.add_row("Port", str(config.server.port))
        table.add_row("Max Connections", str(config.server.max_connections))
        table.add_row("Connection Timeout", f"{config.server.connection_timeout}s")
        
        console.print(table)
        console.print()
        
        table2 = Table(title="Security Configuration", show_header=True)
        table2.add_column("Setting", style="cyan")
        table2.add_column("Value", style="green")
        
        table2.add_row("Min Security Level", str(config.security.min_security_level))
        table2.add_row("Max Failed Attempts", str(config.security.max_failed_attempts))
        table2.add_row("Lockout Duration", f"{config.security.lockout_duration}s")
        
        console.print(table2)
        
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")


def _action_init_config() -> None:
    """Initialize or reset configuration."""
    console.clear()
    from shadow9.wizards import run_init_wizard
    run_init_wizard()


def _action_show_master_key() -> None:
    """Show the master key."""
    console.clear()
    console.print(Panel("[bold]Master Key[/bold]", border_style="red"))
    
    paths = get_paths()
    master_key = paths.get_master_key()
    
    if master_key:
        console.print("\n[yellow]⚠ Keep this key secure! Anyone with this key can decrypt credentials.[/yellow]\n")
        console.print(f"[cyan]{master_key}[/cyan]")
    else:
        console.print("[red]Master key not found. Run 'shadow9 init' to generate one.[/red]")


def _action_view_paths() -> None:
    """View configured paths."""
    console.clear()
    console.print(Panel("[bold]Shadow9 Paths[/bold]", border_style="red"))
    
    paths = get_paths()
    
    table = Table(show_header=True)
    table.add_column("Path Type", style="cyan")
    table.add_column("Location", style="green")
    
    table.add_row("Root Directory", str(paths.root))
    table.add_row("Config File", str(paths.config_file))
    table.add_row("Credentials File", str(paths.credentials_file))
    table.add_row("Users Directory", str(paths.users_dir))
    table.add_row("Logs Directory", str(paths.logs_dir))
    
    console.print(table)


# Submenu Handlers

def _handle_user_menu() -> bool:
    """Handle user management submenu. Returns False to exit to main menu."""
    while True:
        _show_user_menu()
        choice = _get_choice()
        
        if choice == "b" or choice == "q":
            return choice != "q"
        elif choice == "1":
            _safe_execute(_action_create_user, "user creation")
        elif choice == "2":
            _safe_execute(_action_list_users, "user listing")
        elif choice == "3":
            _safe_execute(_action_modify_user, "user modification")
        elif choice == "4":
            _safe_execute(_action_remove_user, "user removal")
        elif choice == "5":
            _safe_execute(_action_enable_user, "user enable")
        elif choice == "6":
            _safe_execute(_action_disable_user, "user disable")
        elif choice == "7":
            _safe_execute(_action_view_user_info, "view user info")
        elif choice == "8":
            _safe_execute(_action_generate_credentials, "credential generation")
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")
            _wait_for_enter()


def _handle_server_menu() -> bool:
    """Handle server control submenu. Returns False to exit to main menu."""
    while True:
        _show_server_menu()
        choice = _get_choice()
        
        if choice == "b" or choice == "q":
            return choice != "q"
        elif choice == "1":
            _safe_execute(_action_start_server, "server start")
        elif choice == "2":
            _safe_execute(_action_start_server_interactive, "interactive server start")
        elif choice == "3":
            _safe_execute(_action_server_status, "server status")
        elif choice == "4":
            _safe_execute(_action_view_connections, "view connections")
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")
            _wait_for_enter()


def _handle_api_menu() -> bool:
    """Handle API management submenu. Returns False to exit to main menu."""
    while True:
        _show_api_menu()
        choice = _get_choice()
        
        if choice == "b" or choice == "q":
            return choice != "q"
        elif choice == "1":
            _safe_execute(_action_setup_api, "API setup")
        elif choice == "2":
            _safe_execute(_action_view_api_config, "view API config")
        elif choice == "3":
            _safe_execute(_action_start_api, "API server start")
        elif choice == "4":
            _safe_execute(_action_generate_api_key, "API key generation")
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")
            _wait_for_enter()


def _handle_service_menu() -> bool:
    """Handle service management submenu (Linux only). Returns False to exit to main menu."""
    while True:
        _show_service_menu()
        choice = _get_choice()
        
        if choice == "b" or choice == "q":
            return choice != "q"
        elif choice == "1":
            _safe_execute(_action_install_service, "service installation")
        elif choice == "2":
            _safe_execute(_action_uninstall_service, "service uninstallation")
        elif choice == "3":
            _safe_execute(_action_start_service, "service start")
        elif choice == "4":
            _safe_execute(_action_stop_service, "service stop")
        elif choice == "5":
            _safe_execute(_action_restart_service, "service restart")
        elif choice == "6":
            _safe_execute(_action_service_status, "service status")
        elif choice == "7":
            _safe_execute(_action_view_service_logs, "view logs")
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")
            _wait_for_enter()


def _handle_settings_menu() -> bool:
    """Handle settings submenu. Returns False to exit to main menu."""
    while True:
        _show_settings_menu()
        choice = _get_choice()
        
        if choice == "b" or choice == "q":
            return choice != "q"
        elif choice == "1":
            _safe_execute(_action_view_config, "view configuration")
        elif choice == "2":
            _safe_execute(_action_init_config, "configuration initialization")
        elif choice == "3":
            _safe_execute(_action_show_master_key, "show master key")
        elif choice == "4":
            _safe_execute(_action_view_paths, "view paths")
        else:
            console.print("[yellow]Invalid option. Please try again.[/yellow]")
            _wait_for_enter()


def run_interactive_menu() -> None:
    """
    Run the interactive menu system.
    
    This is the main entry point for the interactive menu.
    It displays the main menu and handles navigation to submenus.
    """
    try:
        while True:
            _show_main_menu()
            choice = _get_choice()
            
            if choice == "q":
                console.clear()
                console.print("[cyan]Goodbye![/cyan]")
                break
            elif choice == "1":
                if not _handle_user_menu():
                    break
            elif choice == "2":
                if not _handle_server_menu():
                    break
            elif choice == "3":
                if not _handle_api_menu():
                    break
            elif choice == "4":
                if _is_linux():
                    if not _handle_service_menu():
                        break
                else:
                    console.print("[yellow]Service management is only available on Linux.[/yellow]")
                    _wait_for_enter()
            elif choice == "5":
                if not _handle_settings_menu():
                    break
            else:
                console.print("[yellow]Invalid option. Please try again.[/yellow]")
                _wait_for_enter()
                
    except KeyboardInterrupt:
        console.print("\n[cyan]Goodbye![/cyan]")
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        raise


if __name__ == "__main__":
    run_interactive_menu()
