"""
Interactive API configuration wizard for Shadow9.

Provides a step-by-step guided process for configuring the REST API settings.
"""

import secrets
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8080
DEFAULT_CONFIG_PATH = "config/api.yaml"


def run_api_setup_wizard(config_path: str = DEFAULT_CONFIG_PATH) -> dict | None:
    """
    Interactive wizard to configure API settings.
    
    Guides the user through:
    1. API key configuration (generate or custom)
    2. API host configuration
    3. API port configuration
    4. Enable/disable API on startup
    
    Args:
        config_path: Path where the API config will be saved
        
    Returns:
        Dictionary containing the configured API settings on success,
        None on cancel or error.
    """
    try:
        console.print(Panel(
            "[bold cyan]API Configuration[/bold cyan]\n\n"
            "This wizard will guide you through configuring the REST API.",
            border_style="cyan"
        ))
        
        # Load existing config if present
        existing_config = _load_existing_config(config_path)
        
        # Step 1: API Key
        api_key = _prompt_api_key(existing_config)
        
        # Step 2: API Host
        api_host = _prompt_api_host(existing_config)
        
        # Step 3: API Port
        api_port = _prompt_api_port(existing_config)
        
        # Step 4: Enable on startup
        enable_on_startup = _prompt_enable_on_startup(existing_config)
        
        # Build config
        config = {
            "api": {
                "key": api_key,
                "host": api_host,
                "port": api_port,
                "enable_on_startup": enable_on_startup,
            }
        }
        
        # Show summary and confirm
        _show_summary(config)
        
        if not typer.confirm("\nSave this configuration?", default=True):
            console.print("[yellow]Cancelled[/yellow]")
            return None
        
        # Save configuration
        if not _save_config(config, config_path):
            return None
        
        return config
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return None


def _load_existing_config(config_path: str) -> Optional[dict]:
    """Load existing API configuration if it exists."""
    path = Path(config_path)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            console.print(f"[yellow]Warning: Could not load existing config: {e}[/yellow]")
    return None


def _generate_api_key() -> str:
    """Generate a secure API key using secrets module."""
    return secrets.token_urlsafe(32)


def _prompt_api_key(existing_config: Optional[dict]) -> str:
    """Prompt for API key configuration."""
    console.print("\n[bold]Step 1:[/bold] API Key")
    console.print("  [dim]The API key is used to authenticate requests to the REST API.[/dim]\n")
    
    existing_key = None
    if existing_config and "api" in existing_config:
        existing_key = existing_config["api"].get("key")
    
    if existing_key:
        console.print(f"  [dim]Current key:[/dim] [cyan]{existing_key[:8]}...{existing_key[-4:]}[/cyan]")
        if typer.confirm("  Keep existing API key?", default=True):
            return existing_key
    
    console.print("\n  [cyan]1. Generate[/cyan] [green](recommended)[/green]")
    console.print("     Generate a cryptographically secure API key.\n")
    console.print("  [cyan]2. Custom[/cyan]")
    console.print("     Enter your own API key.\n")
    
    choice = typer.prompt("  Select option [1-2]", default="1")
    
    if choice == "1":
        api_key = _generate_api_key()
        console.print(f"\n  [green]Generated API key:[/green]")
        console.print(f"  [cyan]{api_key}[/cyan]")
        console.print("  [yellow]Save this key - you'll need it to authenticate API requests![/yellow]")
        return api_key
    else:
        while True:
            api_key = typer.prompt("  Enter API key", hide_input=True)
            if len(api_key) < 16:
                console.print("  [red]API key must be at least 16 characters[/red]")
                continue
            api_key_confirm = typer.prompt("  Confirm API key", hide_input=True)
            if api_key != api_key_confirm:
                console.print("  [red]API keys do not match[/red]")
                continue
            return api_key


def _prompt_api_host(existing_config: Optional[dict]) -> str:
    """Prompt for API host configuration."""
    console.print("\n[bold]Step 2:[/bold] API Host")
    console.print("  [dim]The network interface the API server will bind to.[/dim]\n")
    
    console.print("  [cyan]127.0.0.1[/cyan] [green](default)[/green]")
    console.print("     Only accessible from this machine (localhost).\n")
    console.print("  [cyan]0.0.0.0[/cyan]")
    console.print("     Accessible from any network interface.")
    console.print("     [yellow]Warning: Ensure proper firewall rules are in place![/yellow]\n")
    
    default_host = DEFAULT_API_HOST
    if existing_config and "api" in existing_config:
        default_host = existing_config["api"].get("host", DEFAULT_API_HOST)
    
    host = typer.prompt("  API host", default=default_host)
    return host


def _prompt_api_port(existing_config: Optional[dict]) -> int:
    """Prompt for API port configuration."""
    console.print("\n[bold]Step 3:[/bold] API Port")
    console.print("  [dim]The port number the API server will listen on.[/dim]\n")
    
    default_port = DEFAULT_API_PORT
    if existing_config and "api" in existing_config:
        default_port = existing_config["api"].get("port", DEFAULT_API_PORT)
    
    while True:
        port_str = typer.prompt("  API port", default=str(default_port))
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                console.print("  [red]Port must be between 1 and 65535[/red]")
                continue
            if port < 1024:
                console.print("  [yellow]Warning: Ports below 1024 may require elevated privileges[/yellow]")
            return port
        except ValueError:
            console.print("  [red]Invalid port number[/red]")


def _prompt_enable_on_startup(existing_config: Optional[dict]) -> bool:
    """Prompt for enable on startup configuration."""
    console.print("\n[bold]Step 4:[/bold] Enable API on Startup")
    console.print("  [dim]Whether to automatically start the API when Shadow9 starts.[/dim]\n")
    
    default_enable = False
    if existing_config and "api" in existing_config:
        default_enable = existing_config["api"].get("enable_on_startup", False)
    
    return typer.confirm("  Enable API on startup?", default=default_enable)


def _show_summary(config: dict) -> None:
    """Display configuration summary."""
    api_config = config["api"]
    
    table = Table(title="API Configuration Summary", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    # Mask API key for display
    api_key = api_config["key"]
    masked_key = f"{api_key[:8]}...{api_key[-4:]}" if len(api_key) > 12 else "****"
    
    table.add_row("API Key", masked_key)
    table.add_row("API Host", api_config["host"])
    table.add_row("API Port", str(api_config["port"]))
    table.add_row("Enable on Startup", "Yes" if api_config["enable_on_startup"] else "No")
    
    console.print("\n")
    console.print(table)


def _save_config(config: dict, config_path: str) -> bool:
    """
    Save the API configuration to a YAML file.
    
    Returns:
        True on success, False on error.
    """
    path = Path(config_path)
    
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        console.print(Panel(
            f"[bold green]API configuration saved![/bold green]\n\n"
            f"Configuration file: [cyan]{config_path}[/cyan]\n\n"
            f"[dim]To start the API server, run:[/dim]\n"
            f"[cyan]shadow9 api start[/cyan]",
            title="Success",
            border_style="green"
        ))
        return True
    except IOError as e:
        console.print(f"[red]Error saving configuration: {e}[/red]")
        return False


def display_api_config(config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """
    Display the current API configuration.
    
    Args:
        config_path: Path to the API config file
    """
    config = _load_existing_config(config_path)
    
    if not config or "api" not in config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print(f"[dim]Run the API setup wizard to configure: shadow9 api setup[/dim]")
        return
    
    _show_summary(config)
