"""
API management commands for Shadow9 CLI.

Contains commands for configuring, starting, and managing the REST API server.
"""

import asyncio
import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import probe
from ..config import Config, listener_port_errors
from ..core.api_config import generate_api_key, get_api_key, load_api_config, set_api_key
from ..paths import get_config_dir
from ..wizards.api_setup import run_api_setup_wizard, DEFAULT_CONFIG_PATH

console = Console()

# Create the API command group
api_app = typer.Typer(
    name="api",
    help="API management commands",
    no_args_is_help=True,
)


def _read_api_config(config_path: str = DEFAULT_CONFIG_PATH) -> Optional[dict]:
    """Load API configuration from file, or None when nothing is configured yet."""
    path = Path(config_path)
    if not path.exists():
        return None
    try:
        return load_api_config(path)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")
        return None


def _docs_are_published() -> bool:
    """Whether a running API serves its docs, so the CLI does not advertise a 404."""
    try:
        from ..api.app import docs_enabled
    except ImportError:
        return False
    return docs_enabled()




@api_app.command("setup")
def setup(
    config_path: Annotated[
        str, typer.Option("--config", "-c", help="Path to API configuration file")
    ] = DEFAULT_CONFIG_PATH,
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
    config_path: Annotated[
        str, typer.Option("--config", "-c", help="Path to API configuration file")
    ] = DEFAULT_CONFIG_PATH,
    host: Annotated[
        Optional[str], typer.Option("--host", "-h", help="Override host from config")
    ] = None,
    port: Annotated[
        Optional[int], typer.Option("--port", "-p", help="Override port from config")
    ] = None,
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
        from ..api.app import run_server
    except ImportError as e:
        console.print("[red]FastAPI not installed. Run: pip install fastapi uvicorn[/red]")
        raise typer.Exit(1) from e

    # Load configuration
    config = _read_api_config(config_path)

    if not config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print("[dim]Run 'shadow9 api setup' to configure the API.[/dim]")
        if not typer.confirm("Start with defaults?", default=False):
            return
        api_host = host or "127.0.0.1"
        api_port = port or 8080
        api_key = None
    else:
        api_host = host or config.get("host", "127.0.0.1")
        api_port = port or config.get("port", 8080)
        api_key = get_api_key(Path(config_path))

    listener_config = Config.load(get_config_dir() / "config.yaml")
    port_errors = listener_port_errors(
        api_port,
        listener_config.wireguard.enrollment_port,
        listener_config.server.port,
    )
    if port_errors:
        for error in port_errors:
            console.print(f"[red]{error}[/red]")
        raise typer.Exit(1)

    # Set API key in environment if configured
    if api_key:
        os.environ["SHADOW9_API_KEY"] = api_key
    elif not os.getenv("SHADOW9_API_KEY"):
        console.print("[yellow]Warning: No API key configured.[/yellow]")
        console.print("[dim]API endpoints will reject requests until a key is set.[/dim]")
        console.print("[dim]Run 'shadow9 api setup' to configure an API key.[/dim]\n")

    # Through the helper, not a second import: importing shadow9.api.app inside the try
    # above meant any ImportError raised while loading it, a bad model or a missing
    # sub-dependency, printed "FastAPI not installed" and pointed the operator at the
    # wrong problem
    if _docs_are_published():
        docs_lines = (
            f"API Docs:  [cyan]http://{api_host}:{api_port}/api/docs[/cyan]\n"
            f"OpenAPI:   [cyan]http://{api_host}:{api_port}/api/openapi.json[/cyan]\n"
        )
    else:
        docs_lines = "[dim]API Docs:  off (set SHADOW9_API_DOCS=1 to publish them)[/dim]\n"

    console.print(
        Panel(
            f"[bold green]Shadow9 REST API[/bold green]\n\n"
            f"Admin:      [cyan]http://{api_host}:{api_port}[/cyan]\n"
            f"Enrollment: [cyan]http://{listener_config.wireguard.enrollment_host}:"
            f"{listener_config.wireguard.enrollment_port}[/cyan]\n"
            f"{docs_lines}\n"
            f"[dim]Press Ctrl+C to stop.[/dim]",
            title="API Server",
            border_style="green",
        )
    )

    run_server(
        host=api_host,
        port=api_port,
        reload=reload,
        enrollment_host=listener_config.wireguard.enrollment_host,
        enrollment_port=listener_config.wireguard.enrollment_port,
        socks_port=listener_config.server.port,
    )


@api_app.command("status")
def status(
    config_path: Annotated[
        str, typer.Option("--config", "-c", help="Path to API configuration file")
    ] = DEFAULT_CONFIG_PATH,
) -> None:
    """
    Show current API configuration and whether the server is running.

    Displays:
    - Current configuration settings
    - Server running status
    """
    config = _read_api_config(config_path)

    if not config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print("[dim]Run 'shadow9 api setup' to configure the API.[/dim]")
        return

    api_host = config.get("host", "127.0.0.1")
    api_port = config.get("port", 8080)
    api_key = get_api_key(Path(config_path)) or ""
    enable_on_startup = config.get("enable_on_startup", False)

    # The same probe the top-level status uses, so both answer about the address they
    # print. The old check asked the operating system for any listener on the port and
    # ignored the host entirely, so an unrelated service on another interface read as the
    # API running, and on Windows a listener on 10801 matched a question about 1080.
    is_running = asyncio.run(probe._something_is_listening(api_host, api_port))

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

    if is_running and _docs_are_published():
        console.print(
            f"\n[dim]API docs available at:[/dim] [cyan]http://{api_host}:{api_port}/api/docs[/cyan]"
        )


@api_app.command("key")
def key(
    config_path: Annotated[
        str, typer.Option("--config", "-c", help="Path to API configuration file")
    ] = DEFAULT_CONFIG_PATH,
    regenerate: Annotated[
        bool, typer.Option("--regenerate", "-r", help="Generate a new API key")
    ] = False,
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
    path = Path(config_path)
    config = _read_api_config(config_path)

    if regenerate:
        new_key = generate_api_key()

        try:
            # set_api_key writes the file through load/save, so a missing file is fine
            set_api_key(new_key, path)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1) from e
        except OSError as e:
            console.print(f"[red]Error saving configuration: {e}[/red]")
            raise typer.Exit(1) from e

        console.print("[green]New API key generated![/green]\n")
        console.print(f"[cyan]{new_key}[/cyan]\n")
        console.print(
            "[yellow]Save this key - you'll need it to authenticate API requests![/yellow]"
        )
        console.print("[dim]Restart the API server for the new key to take effect.[/dim]")
        return

    # Show current key
    if not config:
        console.print("[yellow]No API configuration found.[/yellow]")
        console.print("[dim]Run 'shadow9 api setup' to configure an API key.[/dim]")
        return

    api_key = get_api_key(path) or ""

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
