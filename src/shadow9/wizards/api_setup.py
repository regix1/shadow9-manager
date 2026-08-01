"""
Interactive API configuration wizard for Shadow9.

Provides a step-by-step guided process for configuring the REST API settings.
"""

from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.api_config import (
    generate_api_key,
    get_api_key,
    load_api_config,
    save_api_config,
    set_api_key,
)

console = Console()

DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8080
DEFAULT_CONFIG_PATH = "config/api.yaml"


class ApiSetupResult(Enum):
    """What happened when the API setup wizard finished."""

    SAVED = "saved"
    CANCELLED = "cancelled"
    FAILED = "failed"


def run_api_setup_wizard(
    config_path: str = DEFAULT_CONFIG_PATH,
) -> ApiSetupResult:
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
        The outcome of the setup attempt.
    """
    try:
        console.print(
            Panel(
                "[bold cyan]API Configuration[/bold cyan]\n\n"
                "This wizard will guide you through configuring the REST API.",
                border_style="cyan",
            )
        )

        # Load existing config if present
        existing_config = _load_existing_config(config_path)

        # Step 1: API Key
        api_key = _prompt_api_key(existing_config, config_path)

        # Step 2: API Host
        api_host = _prompt_api_host(existing_config)

        # Step 3: API Port
        api_port = _prompt_api_port(existing_config)

        # Step 4: Enable on startup
        enable_on_startup = _prompt_enable_on_startup(existing_config)

        # Build config
        config = {
            "key": api_key,
            "host": api_host,
            "port": api_port,
            "enable_on_startup": enable_on_startup,
        }

        # Show summary and confirm
        _show_summary(config)

        if not typer.confirm("\nSave this configuration?", default=True):
            console.print("[yellow]Cancelled[/yellow]")
            return ApiSetupResult.CANCELLED

        # Save configuration
        if not _save_config(config, config_path):
            return ApiSetupResult.FAILED

        return ApiSetupResult.SAVED

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return ApiSetupResult.CANCELLED
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return ApiSetupResult.FAILED


def _load_existing_config(config_path: str) -> Optional[dict]:
    """Load existing API configuration if it exists."""
    path = Path(config_path)
    if not path.exists():
        return None
    try:
        return load_api_config(path)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load existing config: {e}[/yellow]")
        return None


def _prompt_api_key(existing_config: Optional[dict], config_path: str) -> str:
    """Prompt for API key configuration."""
    console.print("\n[bold]Step 1:[/bold] API Key")
    console.print("  [dim]The API key is used to authenticate requests to the REST API.[/dim]\n")

    existing_key = get_api_key(Path(config_path)) if existing_config else None

    if existing_key:
        console.print(
            f"  [dim]Current key:[/dim] [cyan]{existing_key[:8]}...{existing_key[-4:]}[/cyan]"
        )
        if typer.confirm("  Keep existing API key?", default=True):
            return existing_key

    console.print("\n  [cyan]1. Generate[/cyan] [green](recommended)[/green]")
    console.print("     Generate a cryptographically secure API key.\n")
    console.print("  [cyan]2. Custom[/cyan]")
    console.print("     Enter your own API key.\n")

    choice = typer.prompt("  Select option [1-2]", default="1")

    if choice == "1":
        api_key = generate_api_key()
        console.print("\n  [green]Generated API key:[/green]")
        console.print(f"  [cyan]{api_key}[/cyan]")
        console.print(
            "  [yellow]Save this key - you'll need it to authenticate API requests![/yellow]"
        )
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
    if existing_config:
        default_host = existing_config.get("host", DEFAULT_API_HOST)

    host = typer.prompt("  API host", default=default_host)
    return host


def _prompt_api_port(existing_config: Optional[dict]) -> int:
    """Prompt for API port configuration."""
    console.print("\n[bold]Step 3:[/bold] API Port")
    console.print("  [dim]The port number the API server will listen on.[/dim]\n")

    default_port = DEFAULT_API_PORT
    if existing_config:
        default_port = existing_config.get("port", DEFAULT_API_PORT)

    while True:
        port_str = typer.prompt("  API port", default=str(default_port))
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                console.print("  [red]Port must be between 1 and 65535[/red]")
                continue
            if port < 1024:
                console.print(
                    "  [yellow]Warning: Ports below 1024 may require elevated privileges[/yellow]"
                )
            return port
        except ValueError:
            console.print("  [red]Invalid port number[/red]")


def _prompt_enable_on_startup(existing_config: Optional[dict]) -> bool:
    """Prompt for enable on startup configuration."""
    console.print("\n[bold]Step 4:[/bold] Enable API on Startup")
    console.print("  [dim]Whether to automatically start the API when Shadow9 starts.[/dim]\n")

    default_enable = False
    if existing_config:
        default_enable = existing_config.get("enable_on_startup", False)

    return typer.confirm("  Enable API on startup?", default=default_enable)


def _show_summary(config: dict) -> None:
    """Display configuration summary."""
    table = Table(title="API Configuration Summary", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # Mask API key for display
    api_key = config.get("key") or ""
    if not api_key:
        masked_key = "[dim]Not configured[/dim]"
    elif len(api_key) > 12:
        masked_key = f"{api_key[:8]}...{api_key[-4:]}"
    else:
        masked_key = "****"

    table.add_row("API Key", masked_key)
    table.add_row("API Host", config.get("host", DEFAULT_API_HOST))
    table.add_row("API Port", str(config.get("port", DEFAULT_API_PORT)))
    table.add_row("Enable on Startup", "Yes" if config.get("enable_on_startup") else "No")

    console.print("\n")
    console.print(table)


def _save_config(config: dict, config_path: str) -> bool:
    """
    Save the API configuration, storing the key encrypted and the file mode 0600.

    Returns:
        True on success, False on error.
    """
    path = Path(config_path)
    api_key = config["key"]

    # everything except the key; the key only ever reaches disk through set_api_key
    settings = {k: v for k, v in config.items() if k != "key"}

    try:
        # The key is written first and the settings are merged onto what that produced.
        # Writing the settings first puts a document on disk that carries no key at all,
        # so a master key that turns out to be missing leaves the file valid, keyless, and
        # without the key that used to work, while the message below still says to re-run.
        # This order costs at worst a set of stale host and port values.
        set_api_key(api_key, path)
        stored = load_api_config(path)
        stored.update(settings)
        save_api_config(stored, path)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        console.print("[dim]Generate a master key first, then re-run 'shadow9 api setup'.[/dim]")
        return False
    except OSError as e:
        console.print(f"[red]Error saving configuration: {e}[/red]")
        return False

    console.print(
        Panel(
            f"[bold green]API configuration saved![/bold green]\n\n"
            f"Configuration file: [cyan]{config_path}[/cyan]\n"
            f"[dim]The API key is stored encrypted.[/dim]\n\n"
            f"[dim]To start the API server, run:[/dim]\n"
            f"[cyan]shadow9 api start[/cyan]",
            title="Success",
            border_style="green",
        )
    )
    return True
