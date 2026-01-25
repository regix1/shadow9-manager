"""
Utility commands for Shadow9 CLI.

Contains init, check-tor, fetch, setup, status, and update commands.
"""

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..config import generate_default_config
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
        skip_optional: Annotated[bool, typer.Option("--skip-optional", help="Skip optional bridge transports")] = False,
        check_only: Annotated[bool, typer.Option("--check-only", help="Only check status, do not install")] = False,
    ):
        """
        Setup Tor and proxy components for Shadow9.

        Installs:
        - Tor daemon (required)
        - obfs4proxy, snowflake (optional bridges)
        """
        from ..setup import SystemSetup, run_setup, check_setup

        if check_only:
            console.print("[cyan]Checking proxy components...[/cyan]\n")
            status = check_setup()

            table = Table(title="Proxy Components")
            table.add_column("Component", style="cyan")
            table.add_column("Status")
            table.add_column("Required")

            for name, info in status.items():
                status_text = "[green]Installed[/green]" if info["installed"] else "[red]Missing[/red]"
                required_text = "[yellow]Yes[/yellow]" if info["required"] else "No"
                table.add_row(name, status_text, required_text)

            console.print(table)
            return

        console.print(Panel(
            "[bold cyan]Shadow9 Proxy Setup[/bold cyan]\n\n"
            "Installing Tor and bridge transports for\n"
            "anonymous SOCKS5 proxy routing.\n\n"
            "[dim]sudo may be required[/dim]",
            title="Proxy Setup",
            border_style="cyan"
        ))

        if not typer.confirm("\nProceed with installation?", default=True):
            console.print("[yellow]Setup cancelled[/yellow]")
            return

        success = run_setup(verbose=True, include_optional=not skip_optional)

        if success:
            # Check if systemd service exists and offer to reinstall/install it
            service_file = Path("/etc/systemd/system/shadow9.service")
            if sys.platform == "linux":
                if service_file.exists():
                    console.print("\n[yellow]Existing systemd service detected.[/yellow]")
                    console.print("[dim]Reinstalling ensures the service uses the current master key.[/dim]")
                    if typer.confirm("Reinstall the systemd service?", default=True):
                        import subprocess
                        console.print("[cyan]Reinstalling service...[/cyan]")
                        result = subprocess.run(
                            ["shadow9", "service", "install", "--host", "0.0.0.0", "--port", "1080"],
                            capture_output=True,
                            text=True
                        )
                        if result.returncode == 0:
                            console.print("[green]Service reinstalled successfully![/green]")
                            # Start the service
                            if typer.confirm("Start the service now?", default=True):
                                subprocess.run(["shadow9", "service", "start"])
                                subprocess.run(["shadow9", "service", "status"])
                        else:
                            console.print(f"[red]Service install failed: {result.stderr}[/red]")
                else:
                    # No service exists, offer to install it
                    console.print("\n[dim]No systemd service installed yet.[/dim]")
                    if typer.confirm("Install Shadow9 as a systemd service (for background operation)?", default=True):
                        import subprocess
                        console.print("[cyan]Installing service...[/cyan]")
                        result = subprocess.run(
                            ["shadow9", "service", "install", "--host", "0.0.0.0", "--port", "1080"],
                            capture_output=True,
                            text=True
                        )
                        if result.returncode == 0:
                            console.print("[green]Service installed successfully![/green]")
                            if typer.confirm("Enable service to start on boot?", default=True):
                                subprocess.run(["shadow9", "service", "enable"])
                            if typer.confirm("Start the service now?", default=True):
                                subprocess.run(["shadow9", "service", "start"])
                                subprocess.run(["shadow9", "service", "status"])
                        else:
                            console.print(f"[red]Service install failed: {result.stderr}[/red]")
            
            console.print(Panel(
                "[bold green]Proxy Setup Complete![/bold green]\n\n"
                "Start the proxy:\n"
                "  [cyan]shadow9 user generate[/cyan]  # Create user credentials\n"
                "  [cyan]shadow9 serve[/cyan]          # Start SOCKS5 proxy",
                title="Ready",
                border_style="green"
            ))
        else:
            console.print(Panel(
                "[yellow]Some components could not be installed.[/yellow]\n\n"
                "Please install Tor and pluggable transports manually for your system.",
                title="Setup Incomplete",
                border_style="yellow"
            ))

    @app.command()
    def status():
        """Show proxy status and Tor connectivity."""
        from ..setup import check_setup

        console.print("[cyan]Shadow9 Proxy Status[/cyan]\n")

        # Check dependencies
        dep_status = check_setup()

        table = Table(title="Proxy Components")
        table.add_column("Component", style="cyan")
        table.add_column("Status")
        table.add_column("Description", style="dim")

        for name, info in dep_status.items():
            if info["installed"]:
                status_text = "[green][OK] Ready[/green]"
            elif info["required"]:
                status_text = "[red][X] Missing[/red]"
            else:
                status_text = "[yellow][?] Optional[/yellow]"

            table.add_row(name, status_text, info["description"])

        console.print(table)

        # Check Tor connectivity
        console.print("\n[cyan]Tor Connection:[/cyan]")
        tor_config = TorConnector.detect_tor_service()
        if tor_config:
            console.print(f"  [green][OK][/green] Tor on port {tor_config.socks_port}")
        else:
            console.print("  [red][X][/red] Tor not running")
            console.print("  [dim]Run 'shadow9 setup' to install Tor[/dim]")

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

        # Check if server is running - first check systemd service, then fallback to PID
        server_was_running = False
        running_as_service = False
        server_pid = None
        
        # Check if running as systemd service first
        if shutil.which("systemctl"):
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "shadow9"],
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0 and result.stdout.strip() == "active":
                    server_was_running = True
                    running_as_service = True
                    console.print("[>] Stopping shadow9 service...")
                    subprocess.run(["sudo", "systemctl", "stop", "shadow9"], capture_output=True)
                    # Wait for service to fully stop and release resources
                    time.sleep(3)
            except Exception:
                pass
        
        # Fallback: check for standalone process if not running as service
        if not running_as_service:
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
                    # Wait for process to stop and release socket
                    time.sleep(3)
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

            # Check if setup script will change (before reset)
            setup_changed = False
            try:
                result = subprocess.run(
                    ["git", "diff", "HEAD", "origin/main", "--name-only"],
                    cwd=script_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    changed_files = result.stdout.strip().split('\n')
                    setup_changed = 'setup' in changed_files
            except Exception:
                pass

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

            # Reinstall package using system pip
            console.print("[>] Reinstalling package...")
            
            # Determine pip command and args
            pip_cmd = "pip3" if shutil.which("pip3") else "pip"
            pip_args = ["--break-system-packages"] if sys.version_info >= (3, 11) else []
            
            result = subprocess.run(
                [pip_cmd, "install"] + pip_args + ["-e", ".", "-q"],
                cwd=script_dir,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                # Try without --break-system-packages if it failed
                result = subprocess.run(
                    [pip_cmd, "install", "-e", ".", "-q"],
                    cwd=script_dir,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    console.print(f"[yellow]Warning: pip install failed: {result.stderr}[/yellow]")

            console.print("\n[green][OK] Shadow9 updated successfully![/green]")

            # Restart server if it was running
            if server_was_running:
                console.print("[>] Restarting server...")
                if running_as_service:
                    # Restart via systemctl
                    result = subprocess.run(
                        ["sudo", "systemctl", "start", "shadow9"],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        console.print("[green][OK] Service restarted![/green]")
                    else:
                        console.print(f"[yellow]Warning: Failed to restart service: {result.stderr}[/yellow]")
                        console.print("[dim]Try: sudo systemctl start shadow9[/dim]")
                else:
                    # Start server in background (standalone mode)
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
                console.print("[dim]Server was not running. Start with: shadow9 serve[/dim]")

            # Ask if user wants to run setup script
            console.print("")
            if setup_changed:
                console.print("[green](recommended - setup script changed)[/green]")
                run_setup_confirm = typer.confirm("Would you like to run the setup script?", default=True)
            else:
                run_setup_confirm = typer.confirm("Would you like to run the setup script?", default=False)
            
            run_setup = "y" if run_setup_confirm else "n"
            
            if run_setup.lower() in ('y', 'yes'):
                console.print("\n[cyan]Running setup script...[/cyan]\n")
                setup_script = script_dir / "setup"
                if setup_script.exists():
                    # Use os.system to ensure proper terminal/stdin handling for interactive prompts
                    import os
                    os.chdir(script_dir)
                    os.system(str(setup_script))
                else:
                    console.print("[red]Error: setup script not found[/red]")
            else:
                console.print("")
                run_again = typer.confirm("Would you like to run shadow9 setup?", default=False)
                if run_again:
                    console.print("\n[cyan]Running setup...[/cyan]\n")
                    import subprocess
                    subprocess.run(["shadow9", "setup"])

        except FileNotFoundError:
            console.print("[red]Error: git not found. Please install git.[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

    # Key management subcommand group
    key_app = typer.Typer(help="Manage encryption keys")
    app.add_typer(key_app, name="key")

    @key_app.command("generate")
    def key_generate(
        force: Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation prompts")] = False,
    ):
        """
        Generate or regenerate the master encryption key.

        This key encrypts the credentials file. If a key already exists,
        you will be prompted before regenerating (which invalidates existing credentials).
        """
        import secrets
        import subprocess
        
        # Find project root (where .env should be)
        project_root = Path(__file__).parent.parent.parent.parent
        env_file = project_root / ".env"
        config_dir = project_root / "config"
        credentials_file = config_dir / "credentials.enc"
        salt_file = config_dir / ".salt"
        
        # Check if key already exists
        key_exists = False
        if env_file.exists():
            try:
                with open(env_file) as f:
                    content = f.read()
                    if "SHADOW9_MASTER_KEY" in content:
                        key_exists = True
            except Exception:
                pass
        
        if key_exists:
            console.print("[yellow]Existing master key found in .env[/yellow]")
            console.print("[red]WARNING: Regenerating the key will make existing credentials unreadable![/red]")
            
            if not force:
                if not typer.confirm("Generate a new master key?", default=False):
                    console.print("[dim]Keeping existing key[/dim]")
                    return
            
            # Stop service if running to prevent key mismatch errors
            if shutil.which("systemctl"):
                try:
                    result = subprocess.run(
                        ["systemctl", "is-active", "--quiet", "shadow9.service"],
                        capture_output=True
                    )
                    if result.returncode == 0:
                        console.print("[yellow]Stopping shadow9 service before key regeneration...[/yellow]")
                        subprocess.run(["systemctl", "stop", "shadow9.service"], capture_output=True)
                except Exception:
                    pass
            
            # Backup old .env
            backup_env = project_root / ".env.backup"
            try:
                shutil.copy2(env_file, backup_env)
                console.print(f"[dim]Old .env backed up to {backup_env}[/dim]")
            except Exception:
                pass
            
            # Remove old credentials (encrypted with old key)
            if credentials_file.exists():
                backup_creds = config_dir / "credentials.enc.backup"
                try:
                    shutil.copy2(credentials_file, backup_creds)
                    credentials_file.unlink()
                    console.print("[dim]Old credentials removed (backup: config/credentials.enc.backup)[/dim]")
                    console.print("[yellow]You will need to create new users after this[/yellow]")
                except Exception as e:
                    console.print(f"[red]Error removing credentials: {e}[/red]")
            
            # Remove old salt file
            if salt_file.exists():
                try:
                    salt_file.unlink()
                    console.print("[dim]Old salt file removed[/dim]")
                except Exception:
                    pass
        
        # Generate new key
        master_key = secrets.token_urlsafe(32)
        
        # Ensure config directory exists
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Save to .env file
        env_content = f"""# Shadow9 Master Key - Keep this secret!
# This key encrypts your credentials file
SHADOW9_MASTER_KEY={master_key}
"""
        
        try:
            with open(env_file, "w") as f:
                f.write(env_content)
            
            # Set restrictive permissions (Unix only)
            try:
                env_file.chmod(0o600)
            except Exception:
                pass
            
            console.print("[green]Master key generated and saved to .env[/green]")
            
            # Also set in current environment for immediate use
            import os
            os.environ["SHADOW9_MASTER_KEY"] = master_key
            
        except Exception as e:
            console.print(f"[red]Error saving key: {e}[/red]")
            raise typer.Exit(1)

    @key_app.command("check")
    def key_check():
        """Check if a master key is configured."""
        import os
        
        # Check environment variable first
        if os.environ.get("SHADOW9_MASTER_KEY"):
            console.print("[green]Master key is set in environment[/green]")
            return
        
        # Check .env file
        project_root = Path(__file__).parent.parent.parent.parent
        env_file = project_root / ".env"
        
        if env_file.exists():
            try:
                with open(env_file) as f:
                    content = f.read()
                    if "SHADOW9_MASTER_KEY" in content:
                        console.print(f"[green]Master key found in {env_file}[/green]")
                        return
            except Exception:
                pass
        
        console.print("[red]No master key configured[/red]")
        console.print("[dim]Run 'shadow9 key generate' to create one[/dim]")
        raise typer.Exit(1)


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
        console.print("[cyan]Connecting to Tor...[/cyan]")
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
