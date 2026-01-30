"""
API management commands for Shadow9 CLI.

Contains commands for configuring, starting, and managing the REST API server.
"""

import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..wizards.api_setup import run_api_setup_wizard, display_api_config, DEFAULT_CONFIG_PATH

console = Console()

# Create the API command group
api_app = typer.Typer(
    name="api",
    help="API management commands",
    no_args_is_help=True,
)


def _load_api_config(config_path: str = DEFAULT_CONFIG_PATH) -> Optional[dict]:
    """Load API configuration from file."""
    path = Path(config_path)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, IOError) as e:
            console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
    return None


def _save_api_config(config: dict, config_path: str = DEFAULT_CONFIG_PATH) -> None:
    """Save API configuration to file."""
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)


def _is_api_running(host: str, port: int) -> bool:
    """Check if the API server is running on the given host:port."""
    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True,
                text=True
            )
            for line in result.stdout.splitlines():
                if f":{port}" in line and "LISTENING" in line:
                    return True
        except Exception:
            pass
    else:
        try:
            result = subprocess.run(
                ["lsof", "-t", f"-i:{port}"],
                capture_output=True,
                text=True
            )
            if result.stdout.strip():
                return True
        except FileNotFoundError:
            pass
    return False


@api_app.command("setup")
def setup(
    config_path: Annotated[str, typer.Option("--config", "-c", help="Path to API configuration file")] = DEFAULT_CONFIG_PATH,
) -> None:
    """
    Run the API setup wizard.

    Interactively configure API settings including:
    - API key (generate or custom)
    - Host and port settings
    - Startup options
    """
    try:
        run_api_setup_wizard(config_path)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
    except typer.Abort:
        pass  # User cancelled via prompt


@api_app.command("start")
def start(
    config_path: Annotated[str, typer.Option("--config", "-c", help="Path to API configuration file")] = DEFAULT_CONFIG_PATH,
    host: Annotated[Optional[str], typer.Option("--host", "-h", help="Override host from config")] = None,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="Override port from config")] = None,
    reload: Annotated[bool, typer.Option("--reload", "-r", help="Enable auto-reload")] = False,
) -> None:
    """
    Start the REST API server using saved configuration.

    Uses settings from config/api.yaml. Run 'shadow9 api setup' first to configure.

    Example:
        shadow9 api start
        shadow9 api start --reload
        shadow9 api start --host 0.0.0.0 --port 9000
    """
    try:
        _start_impl(config_path, host, port, reload)
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped[/yellow]")
    except typer.Abort:
        pass  # User cancelled via prompt


def _start_impl(config_path: str, host: Optional[str], port: Optional[int], reload: bool) -> None:
    """Implementation of start command."""
    try:
        import uvicorn
    except ImportError:
        console.print("[red]FastAPI not installed. Run: pip install fastapi uvicorn[/red]")
        raise typer.Exit(1)

    # Load configuration
    config = _load_api_config(config_path)

    if not config or "api" not in config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print(f"[dim]Run 'shadow9 api setup' to configure the API.[/dim]")
        if not typer.confirm("Start with defaults?", default=False):
            return
        api_host = host or "127.0.0.1"
        api_port = port or 8080
        api_key = None
    else:
        api_config = config["api"]
        api_host = host or api_config.get("host", "127.0.0.1")
        api_port = port or api_config.get("port", 8080)
        api_key = api_config.get("key")

    # Set API key in environment if configured
    if api_key:
        os.environ["SHADOW9_API_KEY"] = api_key
    elif not os.getenv("SHADOW9_API_KEY"):
        console.print("[yellow]Warning: No API key configured.[/yellow]")
        console.print("[dim]API endpoints will reject requests until a key is set.[/dim]")
        console.print("[dim]Run 'shadow9 api setup' to configure an API key.[/dim]\n")

    console.print(Panel(
        f"[bold green]Shadow9 REST API[/bold green]\n\n"
        f"Server:    [cyan]http://{api_host}:{api_port}[/cyan]\n"
        f"API Docs:  [cyan]http://{api_host}:{api_port}/api/docs[/cyan]\n"
        f"OpenAPI:   [cyan]http://{api_host}:{api_port}/api/openapi.json[/cyan]\n\n"
        f"[dim]Press Ctrl+C to stop.[/dim]",
        title="API Server",
        border_style="green"
    ))

    uvicorn.run(
        "shadow9.api.app:app",
        host=api_host,
        port=api_port,
        reload=reload,
        log_level="info"
    )


@api_app.command("status")
def status(
    config_path: Annotated[str, typer.Option("--config", "-c", help="Path to API configuration file")] = DEFAULT_CONFIG_PATH,
) -> None:
    """
    Show current API configuration and whether the server is running.

    Displays:
    - Current configuration settings
    - Server running status
    """
    config = _load_api_config(config_path)

    if not config or "api" not in config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print(f"[dim]Run 'shadow9 api setup' to configure the API.[/dim]")
        return

    api_config = config["api"]
    api_host = api_config.get("host", "127.0.0.1")
    api_port = api_config.get("port", 8080)
    api_key = api_config.get("key", "")
    enable_on_startup = api_config.get("enable_on_startup", False)

    # Check if running
    is_running = _is_api_running(api_host, api_port)

    # Build status table
    table = Table(title="API Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    # Mask API key for display
    if api_key and len(api_key) > 12:
        masked_key = f"{api_key[:8]}...{api_key[-4:]}"
    elif api_key:
        masked_key = "****"
    else:
        masked_key = "[dim]Not configured[/dim]"

    table.add_row("API Key", masked_key)
    table.add_row("Host", api_host)
    table.add_row("Port", str(api_port))
    table.add_row("Enable on Startup", "Yes" if enable_on_startup else "No")
    table.add_row("Config File", config_path)

    if is_running:
        table.add_row("Status", "[green]Running[/green]")
    else:
        table.add_row("Status", "[yellow]Not Running[/yellow]")

    console.print(table)

    if is_running:
        console.print(f"\n[dim]API docs available at:[/dim] [cyan]http://{api_host}:{api_port}/api/docs[/cyan]")


@api_app.command("key")
def key(
    config_path: Annotated[str, typer.Option("--config", "-c", help="Path to API configuration file")] = DEFAULT_CONFIG_PATH,
    regenerate: Annotated[bool, typer.Option("--regenerate", "-r", help="Generate a new API key")] = False,
    show: Annotated[bool, typer.Option("--show", "-s", help="Show the full API key")] = False,
) -> None:
    """
    Show or regenerate the API key.

    By default, shows a masked version of the key. Use --show to display the full key.
    Use --regenerate to create a new API key.

    Examples:
        shadow9 api key           # Show masked key
        shadow9 api key --show    # Show full key
        shadow9 api key -r        # Regenerate key
    """
    try:
        _key_impl(config_path, regenerate, show)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
    except typer.Abort:
        pass  # User cancelled via prompt


def _key_impl(config_path: str, regenerate: bool, show: bool) -> None:
    """Implementation of key command."""
    config = _load_api_config(config_path)

    if regenerate:
        # Generate new key
        new_key = secrets.token_urlsafe(32)

        if config is None:
            config = {}
        if "api" not in config:
            config["api"] = {}

        config["api"]["key"] = new_key

        try:
            _save_api_config(config, config_path)
            console.print("[green]New API key generated![/green]\n")
            console.print(f"[cyan]{new_key}[/cyan]\n")
            console.print("[yellow]Save this key - you'll need it to authenticate API requests![/yellow]")
            console.print("[dim]Restart the API server for the new key to take effect.[/dim]")
        except IOError as e:
            console.print(f"[red]Error saving configuration: {e}[/red]")
            raise typer.Exit(1)
        return

    # Show current key
    if not config or "api" not in config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print(f"[dim]Run 'shadow9 api setup' to configure an API key.[/dim]")
        return

    api_key = config["api"].get("key", "")

    if not api_key:
        console.print("[yellow]No API key configured.[/yellow]")
        console.print("[dim]Use --regenerate to generate a new key.[/dim]")
        return

    if show:
        console.print(f"[cyan]{api_key}[/cyan]")
    else:
        if len(api_key) > 12:
            masked_key = f"{api_key[:8]}...{api_key[-4:]}"
        else:
            masked_key = "****"
        console.print(f"API Key: [cyan]{masked_key}[/cyan]")
        console.print("[dim]Use --show to display the full key.[/dim]")


def register_api_commands(app: typer.Typer) -> None:
    """Register API command group with the main app."""
    app.add_typer(api_app, name="api")
