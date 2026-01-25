"""
Utility commands for Shadow9 CLI.

Contains init, check-tor, fetch, setup, status, and update commands.
"""

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..config import Config, generate_default_config
from ..tor_connector import TorConnector, TorConfig
from ..wizards import run_init_wizard, show_config_summary, show_master_key

console = Console()


def register_util_commands(app: typer.Typer):
    """Register utility commands with the main app."""

    @app.command()
    def init(
        output: Annotated[str, typer.Option("--output", "-o", help="Output path for configuration file")] = "config/config.yaml",
        quick: Annotated[bool, typer.Option("--quick", "-q", help="Use defaults without prompts")] = False,
    ):
        """Initialize a new configuration file (interactive wizard if no flags provided)."""
        output_path = Path(output)

        if output_path.exists():
            if not typer.confirm(f"Configuration file {output} already exists. Overwrite?"):
                raise typer.Abort()

        # Quick mode: just generate defaults
        if quick:
            generate_default_config(output_path)
            console.print(f"[green]Configuration file created: {output}[/green]")
            show_master_key()
            return

        # Interactive wizard
        console.print(Panel(
            "[bold cyan]Configuration Setup[/bold cyan]\n\n"
            "This wizard will help you configure Shadow9 Manager.",
            border_style="cyan"
        ))

        console.print("\n[bold]Setup Mode:[/bold]\n")
        console.print("  [cyan]1.[/cyan] Quick start [green](recommended)[/green]")
        console.print("     Use sensible defaults for all settings.")
        console.print("     [dim]Best for: Getting started quickly[/dim]\n")
        console.print("  [cyan]2.[/cyan] Custom configuration")
        console.print("     Configure each setting manually.")
        console.print("     [dim]Best for: Fine-tuning for specific needs[/dim]\n")

        mode = typer.prompt("Select mode [1-2]", default="1")

        if mode == "1":
            # Quick start - just use defaults
            generate_default_config(output_path)
            console.print(f"\n[green]Configuration file created: {output}[/green]")
            show_master_key()
            return

        # Custom configuration
        config = run_init_wizard()
        
        # Show summary
        show_config_summary(config)
        
        if not typer.confirm("\nSave this configuration?", default=True):
            console.print("[yellow]Cancelled[/yellow]")
            raise typer.Abort()

        config.save(output_path)
        console.print(f"\n[green]Configuration file created: {output}[/green]")
        show_master_key()

    @app.command("check-tor")
    def check_tor(
        tor_port: Annotated[int, typer.Option("--tor-port", "-p", help="Tor SOCKS port")] = 9050,
    ):
        """Check Tor connectivity status."""
        asyncio.run(_check_tor(tor_port))

    @app.command()
    def fetch(
        url: Annotated[str, typer.Argument(help="URL to fetch (supports .onion)")],
        tor_port: Annotated[int, typer.Option("--tor-port", "-p", help="Tor SOCKS port")] = 9050,
    ):
        """Fetch a URL through Tor (supports .onion)."""
        asyncio.run(_fetch(url, tor_port))

    @app.command()
    def setup(
        skip_optional: Annotated[bool, typer.Option("--skip-optional", help="Skip optional dependencies (bridges)")] = False,
        check_only: Annotated[bool, typer.Option("--check-only", help="Only check status, do not install")] = False,
    ):
        """
        Automated setup - installs Tor, bridges, and configures the system.

        This will:
        - Detect your operating system
        - Install Tor daemon
        - Install pluggable transports (obfs4proxy, snowflake)
        - Configure and start Tor service
        """
        from ..setup import SystemSetup, run_setup, check_setup, get_manual_install_instructions

        if check_only:
            console.print("[cyan]Checking current setup status...[/cyan]\n")
            status = check_setup()

            table = Table(title="Dependency Status")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Required", style="yellow")

            for name, info in status.items():
                status_text = "[green]Installed[/green]" if info["installed"] else "[red]Not Installed[/red]"
                required_text = "Yes" if info["required"] else "No"
                table.add_row(name, status_text, required_text)

            console.print(table)
            return

        console.print(Panel(
            "[bold cyan]Shadow9 Automated Setup[/bold cyan]\n\n"
            "This will install and configure:\n"
            "- Tor daemon\n"
            "- obfs4proxy (for obfs4 and meek-azure bridges)\n"
            "- snowflake-client (for snowflake bridges)\n\n"
            "[dim]Some operations require sudo privileges[/dim]",
            title="Setup",
            border_style="cyan"
        ))

        if not typer.confirm("\nProceed with installation?", default=True):
            console.print("[yellow]Setup cancelled[/yellow]")
            return

        success = run_setup(verbose=True, include_optional=not skip_optional)

        if success:
            console.print(Panel(
                "[bold green]Setup Complete![/bold green]\n\n"
                "Next steps:\n"
                "  [cyan]shadow9 user generate[/cyan]    # Create a user\n"
                "  [cyan]shadow9 serve[/cyan]            # Start the server",
                title="Ready",
                border_style="green"
            ))
        else:
            setup_obj = SystemSetup(verbose=False)
            instructions = get_manual_install_instructions(setup_obj.os_type)
            console.print(Panel(
                f"[yellow]Some components need manual installation:[/yellow]\n\n{instructions}",
                title="Manual Steps Required",
                border_style="yellow"
            ))

    @app.command()
    def status():
        """Show current system status and configuration."""
        from ..setup import check_setup

        console.print("[cyan]Shadow9 Manager Status[/cyan]\n")

        # Check dependencies
        dep_status = check_setup()

        # Use ASCII characters for compatibility
        check_mark = "[OK]"
        x_mark = "[X]"
        circle = "[?]"

        table = Table(title="System Components")
        table.add_column("Component", style="cyan")
        table.add_column("Status")
        table.add_column("Description", style="dim")

        for name, info in dep_status.items():
            if info["installed"]:
                status_text = f"[green]{check_mark} Installed[/green]"
            elif info["required"]:
                status_text = f"[red]{x_mark} Missing (Required)[/red]"
            else:
                status_text = f"[yellow]{circle} Not Installed[/yellow]"

            table.add_row(name, status_text, info["description"])

        console.print(table)

        # Check Tor connectivity
        console.print("\n[cyan]Tor Connectivity:[/cyan]")
        tor_config = TorConnector.detect_tor_service()
        if tor_config:
            console.print(f"  [green]{check_mark} Tor detected on port {tor_config.socks_port}[/green]")
        else:
            console.print(f"  [red]{x_mark} Tor not running[/red]")
            console.print("  [dim]Run 'shadow9 setup' to install and start Tor[/dim]")

    @app.command()
    def update():
        """
        Update Shadow9 to the latest version from GitHub.

        This will force pull the latest changes and restart the server if running.
        """
        import subprocess
        import time

        console.print("[cyan]Updating Shadow9 Manager...[/cyan]\n")

        # Get the script directory (project root)
        script_dir = Path(__file__).parent.parent.parent.parent

        # Check if we're in a git repository
        git_dir = script_dir / ".git"
        if not git_dir.exists():
            console.print("[red]Error: Not a git repository.[/red]")
            console.print("[dim]Clone from: https://github.com/regix1/shadow9-manager[/dim]")
            return

        # Check if server is running (look for shadow9 serve process)
        server_was_running = False
        server_pid = None
        try:
            result = subprocess.run(
                ["pgrep", "-f", "shadow9.*serve"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                server_was_running = True
                server_pid = result.stdout.strip().split('\n')[0]
                console.print(f"[>] Stopping running server (PID: {server_pid})...")
                subprocess.run(["kill", server_pid], capture_output=True)
                # Wait for process to stop
                time.sleep(2)
        except FileNotFoundError:
            # pgrep not available (Windows), skip server detection
            pass

        try:
            # Fetch latest
            console.print("[>] Fetching latest changes...")
            result = subprocess.run(
                ["git", "fetch", "--all"],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                console.print(f"[red]Error fetching: {result.stderr}[/red]")
                return

            # Force reset to origin/main
            console.print("[>] Applying updates...")
            result = subprocess.run(
                ["git", "reset", "--hard", "origin/main"],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                console.print(f"[red]Error updating: {result.stderr}[/red]")
                return

            # Make scripts executable
            console.print("[>] Setting permissions...")
            for script in ["setup", "shadow9"]:
                script_path = script_dir / script
                if script_path.exists():
                    script_path.chmod(0o755)

            # Reinstall package using venv pip
            console.print("[>] Reinstalling package...")
            venv_dir = script_dir / "venv"
            if sys.platform == "win32":
                venv_pip = venv_dir / "Scripts" / "pip.exe"
            else:
                venv_pip = venv_dir / "bin" / "pip"

            if venv_pip.exists():
                result = subprocess.run(
                    [str(venv_pip), "install", "-e", ".", "-q"],
                    cwd=script_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    console.print(f"[yellow]Warning: pip install failed: {result.stderr}[/yellow]")
            else:
                console.print("[yellow]Warning: Virtual environment not found, skipping reinstall[/yellow]")
                console.print("[dim]Run ./setup to create the virtual environment[/dim]")

            console.print("\n[green][OK] Shadow9 updated successfully![/green]")

            # Restart server if it was running
            if server_was_running:
                console.print("[>] Restarting server...")
                # Start server in background
                shadow9_script = script_dir / "shadow9"
                subprocess.Popen(
                    [str(shadow9_script), "serve"],
                    cwd=script_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True
                )
                console.print("[green][OK] Server restarted![/green]")
            else:
                console.print("[dim]Server was not running. Start with: ./shadow9 serve[/dim]")

        except FileNotFoundError:
            console.print("[red]Error: git not found. Please install git.[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


async def _check_tor(tor_port: int):
    """Async Tor check implementation."""
    console.print("[cyan]Checking Tor connectivity...[/cyan]")

    # Check if Tor service is detected
    detected_config = TorConnector.detect_tor_service()

    if detected_config:
        console.print(f"[green]Tor service detected on port {detected_config.socks_port}[/green]")

        tor = TorConnector(detected_config)
        if await tor.connect():
            circuit_info = tor.circuit_info
            console.print(Panel(
                f"[bold green]Tor Connection Successful[/bold green]\n\n"
                f"Exit IP: [cyan]{circuit_info.exit_ip if circuit_info else 'Unknown'}[/cyan]\n"
                f"SOCKS Port: [cyan]{detected_config.socks_port}[/cyan]",
                title="Tor Status",
                border_style="green"
            ))
            await tor.disconnect()
        else:
            console.print("[red]Could not establish Tor connection[/red]")
    else:
        console.print("[red]Tor service not detected[/red]")
        console.print(f"\n{TorConnector.get_tor_install_instructions()}")


async def _fetch(url: str, tor_port: int):
    """Async fetch implementation."""
    config = TorConfig(socks_port=tor_port)
    tor = TorConnector(config)

    try:
        console.print(f"[cyan]Connecting to Tor...[/cyan]")
        if not await tor.connect():
            console.print("[red]Failed to connect to Tor[/red]")
            return

        console.print(f"[cyan]Fetching {url}...[/cyan]")
        text = await tor.fetch_text(url)

        console.print(Panel(
            text[:2000] + ("..." if len(text) > 2000 else ""),
            title=f"Response from {url}",
            border_style="green"
        ))

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        await tor.disconnect()
