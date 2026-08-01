"""
Utility commands for Shadow9 CLI.

Contains init, check-tor, fetch, setup, status, and update commands.
"""

import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, NamedTuple

import typer
from rich.table import Table
from rich.panel import Panel

from ..config import Config, generate_default_config
from ..paths import write_file_safely
from ..tor_connector import TorConnector, TorConfig
from ..wizards import run_init_wizard, show_config_summary, show_master_key
from ..ui import console, header, dependency_table
from ..ui import success as ui_success, error as ui_error
from .service import SERVICE_NAME


def register_util_commands(app: typer.Typer):
    """Register utility commands with the main app."""

    @app.command()
    def init(
        output: Annotated[
            str, typer.Option("--output", "-o", help="Output path for configuration file")
        ] = "config/config.yaml",
        quick: Annotated[
            bool, typer.Option("--quick", "-q", help="Use defaults without prompts")
        ] = False,
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
        console.print(
            Panel(
                "[bold cyan]Configuration Setup[/bold cyan]\n\n"
                "This wizard will help you configure Shadow9 Manager.",
                border_style="cyan",
            )
        )

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
        skip_optional: Annotated[
            bool, typer.Option("--skip-optional", help="Skip optional bridge transports")
        ] = False,
        check_only: Annotated[
            bool, typer.Option("--check-only", help="Only check status, do not install")
        ] = False,
    ) -> None:
        """
        Setup Tor and proxy components for Shadow9.

        Installs:
        - Tor daemon (required)
        - obfs4proxy, snowflake (optional bridges)
        """
        from ..setup import run_setup, check_setup

        if check_only:
            console.print("[cyan]Checking proxy components...[/cyan]\n")
            status = check_setup()

            table = Table(title="Proxy Components")
            table.add_column("Component", style="cyan")
            table.add_column("Status")
            table.add_column("Required")

            for name, info in status.items():
                status_text = (
                    "[green]Installed[/green]" if info["installed"] else "[red]Missing[/red]"
                )
                required_text = "[yellow]Yes[/yellow]" if info["required"] else "No"
                table.add_row(name, status_text, required_text)

            console.print(table)
            return

        console.print(
            header(
                "Shadow9 Proxy Setup",
                "Installing Tor and bridge transports for\nanonymous SOCKS5 proxy routing.\n\n[dim]sudo may be required[/dim]",
            )
        )

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
                    console.print(
                        "[dim]Reinstalling ensures the service uses the current master key.[/dim]"
                    )
                    if typer.confirm("Reinstall the systemd service?", default=True):
                        import subprocess

                        console.print("[cyan]Reinstalling service...[/cyan]")
                        result = subprocess.run(
                            ["shadow9", "service", "install"], capture_output=True, text=True
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
                    if typer.confirm(
                        "Install Shadow9 as a systemd service (for background operation)?",
                        default=True,
                    ):
                        import subprocess

                        console.print("[cyan]Installing service...[/cyan]")
                        result = subprocess.run(
                            ["shadow9", "service", "install"], capture_output=True, text=True
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

            console.print(
                Panel(
                    "[bold green]Proxy Setup Complete![/bold green]\n\n"
                    "Start the proxy:\n"
                    "  [cyan]shadow9 user generate[/cyan]  # Create user credentials\n"
                    "  [cyan]shadow9 serve[/cyan]          # Start SOCKS5 proxy",
                    title="Ready",
                    border_style="green",
                )
            )
        else:
            console.print(
                Panel(
                    "[yellow]Some components could not be installed.[/yellow]\n\n"
                    "Please install Tor and pluggable transports manually for your system.",
                    title="Setup Incomplete",
                    border_style="yellow",
                )
            )

    @app.command()
    def status():
        """Show proxy status and Tor connectivity."""
        from ..setup import check_setup

        console.print("\n[bold cyan]Shadow9 Proxy Status[/bold cyan]\n")

        # Check dependencies
        dep_status = check_setup()

        # Build dependency list for table
        deps_list = [
            {
                "name": name,
                "installed": dep_info["installed"],
                "required": dep_info["required"],
                "description": dep_info["description"],
            }
            for name, dep_info in dep_status.items()
        ]

        console.print(dependency_table(deps_list, title="Proxy Components"))

        # Check Tor connectivity
        console.print("\n[bold cyan]Tor Connection[/bold cyan]")
        tor_config = TorConnector.detect_tor_service()
        if tor_config:
            ui_success(f"Tor running on port {tor_config.socks_port}")
        else:
            ui_error("Tor not running")
            console.print("  [dim]Run 'shadow9 setup' to install Tor[/dim]")
        console.print()

    @app.command()
    def update(
        check: Annotated[
            bool,
            typer.Option("--check", help="Report what an update would bring and change nothing"),
        ] = False,
        force: Annotated[
            bool,
            typer.Option("--force", "-f", help="Reset to the remote branch, discarding local work"),
        ] = False,
        rollback: Annotated[
            bool,
            typer.Option("--rollback", help="Go back to the commit from before the last update"),
        ] = False,
    ) -> None:
        """
        Update Shadow9 to the latest version from GitHub.

        Fast forwards to the tracked branch, reinstalls the package and restarts the
        server if it was running. An update that fails, or that leaves the proxy not
        serving, is put back on the commit the install was on before it started.

        Use --check to see what is waiting, and --force to reset to the remote branch
        and discard local commits and changes.
        """
        if rollback and (check or force):
            console.print("[red]--rollback cannot be combined with --check or --force.[/red]")
            raise typer.Exit(1)

        repo_root = _find_repo_root()
        if repo_root is None:
            console.print("[red]Error: this install has no git checkout to pull from.[/red]")
            console.print(f"[dim]Package location: {Path(__file__).resolve().parent}[/dim]")
            console.print("[dim]Update by cloning the repository and installing from it:[/dim]")
            console.print("[dim]  git clone https://github.com/regix1/shadow9-manager[/dim]")
            console.print("[dim]  cd shadow9-manager[/dim]")
            console.print("[dim]  ./setup[/dim]")
            raise typer.Exit(1)

        if shutil.which("git") is None:
            console.print("[red]Error: git not found. Please install git.[/red]")
            raise typer.Exit(1)

        if rollback:
            _run_rollback(repo_root)
            return

        if check:
            console.print("[cyan]Checking for updates...[/cyan]\n")
        else:
            console.print("[cyan]Updating Shadow9 Manager...[/cyan]\n")

        # Fetch before stopping anything, so a network failure costs no downtime.
        console.print("[>] Fetching latest changes...")
        result = _git(repo_root, "fetch", "--all")
        if result.returncode != 0:
            console.print(f"[red]Error fetching: {result.stderr.strip()}[/red]")
            console.print("[dim]Nothing was changed and the server was not touched.[/dim]")
            raise typer.Exit(1)

        target = _upstream_branch(repo_root)
        current_commit = _git(repo_root, "rev-parse", "HEAD").stdout.strip()
        target_commit = _git(repo_root, "rev-parse", target).stdout.strip()
        version = _project_version(repo_root)

        if not current_commit or not target_commit:
            console.print(f"[red]Error: cannot read this checkout or {target}.[/red]")
            console.print(f"[dim]Check it by hand: git -C {repo_root} status[/dim]")
            raise typer.Exit(1)

        if current_commit == target_commit:
            console.print(
                f"[green]Already up to date: {version} ({_short(current_commit)})[/green]"
            )
            return

        # What the operator is about to take, before anything is rewritten.
        incoming = _git(
            repo_root, "log", f"{current_commit}..{target_commit}", "--oneline"
        ).stdout.splitlines()
        if incoming:
            console.print(f"\n[bold]{len(incoming)} commit(s) from {target}:[/bold]")
            for line in incoming[:15]:
                console.print(f"  [dim]{line}[/dim]")
            if len(incoming) > 15:
                console.print(f"  [dim]... and {len(incoming) - 15} more[/dim]")
        else:
            console.print(f"\n[yellow]This checkout has diverged from {target}.[/yellow]")

        changed_paths = _git(
            repo_root, "diff", "--name-only", current_commit, target_commit
        ).stdout.split()
        setup_changed = "setup" in changed_paths
        if "pyproject.toml" in changed_paths:
            console.print("[yellow]Dependencies changed in this update.[/yellow]")

        if check:
            console.print(
                f"\n[dim]On {version} ({_short(current_commit)}). "
                f"Run 'shadow9 update' to apply.[/dim]"
            )
            return

        # An update deletes uncommitted work only when asked to, and only after the
        # operator has seen what would go.
        status = _git(repo_root, "status", "--porcelain")
        if status.returncode != 0:
            console.print(f"[red]Error reading repository status: {status.stderr.strip()}[/red]")
            raise typer.Exit(1)

        changed = [line for line in status.stdout.splitlines() if line.strip()]
        if changed:
            console.print(
                f"\n[yellow]{len(changed)} uncommitted change(s) in {repo_root}:[/yellow]"
            )
            for line in changed[:10]:
                console.print(f"  [dim]{line}[/dim]")
            if len(changed) > 10:
                console.print(f"  [dim]... and {len(changed) - 10} more[/dim]")
            if not force:
                console.print(
                    "[dim]Commit or stash them, or run 'shadow9 update --force' to "
                    "discard them.[/dim]"
                )
                raise typer.Exit(1)
            console.print("[red]--force deletes these changes permanently.[/red]")
            if not typer.confirm("Discard them and update?", default=False):
                console.print("[dim]Update cancelled. Nothing was changed.[/dim]")
                raise typer.Exit(1)

        running = _stop_running_server()

        # Written outside the working tree before anything moves, so the commit to go
        # back to is still there for a later run after this process exits.
        _write_update_record(repo_root, current_commit, version)

        console.print("[>] Applying updates...")
        if force:
            result = _git(repo_root, "reset", "--hard", target)
        else:
            result = _git(repo_root, "merge", "--ff-only", target)
        if result.returncode != 0:
            console.print(f"[red]Error updating: {result.stderr.strip()}[/red]")
            if not force:
                console.print(
                    f"[dim]This checkout cannot fast forward to {target}. "
                    f"Run 'shadow9 update --force' to reset to it.[/dim]"
                )
            console.print("[dim]Nothing was applied, so the old version is still installed.[/dim]")
            _start_and_check(repo_root, running)
            raise typer.Exit(1)

        console.print("[>] Setting permissions...")
        for script in ("setup", "shadow9"):
            script_path = repo_root / script
            if script_path.exists():
                script_path.chmod(0o755)

        # New code routinely needs new package versions, and a pull installs none of
        # them, so the install is part of the update rather than a step afterwards.
        console.print("[>] Reinstalling package...")
        if not _install_package(repo_root):
            console.print("[yellow]Going back to the version that was installed before.[/yellow]")
            _roll_back(repo_root, current_commit)
            _start_and_check(repo_root, running)
            raise typer.Exit(1)

        new_version = _project_version(repo_root)
        console.print(
            f"\n[green][OK] Updated {version} ({_short(current_commit)}) to "
            f"{new_version} ({_short(target_commit)})[/green]"
        )

        if not _start_and_check(repo_root, running):
            console.print("[yellow]Going back to the version that was serving before.[/yellow]")
            if _roll_back(repo_root, current_commit) and _start_and_check(repo_root, running):
                console.print(f"[green][OK] Back on {version} ({_short(current_commit)})[/green]")
            else:
                console.print("[red]The server is not running. Start it with: shadow9 serve[/red]")
            raise typer.Exit(1)

        setup_script = repo_root / "setup"
        if setup_script.exists() and sys.stdin.isatty():
            console.print("")
            if setup_changed:
                console.print("[green](recommended - setup script changed)[/green]")
            if typer.confirm("Would you like to run the setup script?", default=setup_changed):
                console.print("\n[cyan]Running setup script...[/cyan]\n")
                # The setup script prompts, so it needs this terminal rather than pipes.
                subprocess.run([str(setup_script)], cwd=repo_root)

    # Key management subcommand group
    key_app = typer.Typer(help="Manage encryption keys")
    app.add_typer(key_app, name="key")

    @key_app.command("generate")
    def key_generate(
        force: Annotated[
            bool, typer.Option("--force", "-f", help="Skip confirmation prompts")
        ] = False,
    ) -> None:
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
            console.print(
                "[red]WARNING: Regenerating the key will make existing credentials unreadable![/red]"
            )

            if not force:
                if not typer.confirm("Generate a new master key?", default=False):
                    console.print("[dim]Keeping existing key[/dim]")
                    return

            # Stop service if running to prevent key mismatch errors
            if shutil.which("systemctl"):
                try:
                    result = subprocess.run(
                        ["systemctl", "is-active", "--quiet", "shadow9.service"],
                        capture_output=True,
                    )
                    if result.returncode == 0:
                        console.print(
                            "[yellow]Stopping shadow9 service before key regeneration...[/yellow]"
                        )
                        subprocess.run(
                            ["systemctl", "stop", "shadow9.service"], capture_output=True
                        )
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
                    console.print(
                        "[dim]Old credentials removed (backup: config/credentials.enc.backup)[/dim]"
                    )
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
            # This is the one file whose truncation cannot be recovered from: half a
            # master key means credentials.enc will never decrypt again, for every user.
            # write_file_safely renames a complete file into place and applies 0600
            # before any content exists, rather than after
            write_file_safely(env_file, env_content.encode())

            console.print("[green]Master key generated and saved to .env[/green]")

            # Also set in current environment for immediate use
            import os

            os.environ["SHADOW9_MASTER_KEY"] = master_key

        except Exception as e:
            console.print(f"[red]Error saving key: {e}[/red]")
            raise typer.Exit(1) from e

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
            console.print(
                Panel(
                    f"[bold green]Tor Connection Successful[/bold green]\n\n"
                    f"Exit IP: [cyan]{circuit_info.exit_ip if circuit_info else 'Unknown'}[/cyan]\n"
                    f"SOCKS Port: [cyan]{detected_config.socks_port}[/cyan]",
                    title="Tor Status",
                    border_style="green",
                )
            )
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

        console.print(
            Panel(
                text[:2000] + ("..." if len(text) > 2000 else ""),
                title=f"Response from {url}",
                border_style="green",
            )
        )

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
    finally:
        await tor.disconnect()


# a probe must answer quickly even when the proxy host drops packets
SERVING_PROBE_TIMEOUT = 1.0

# the file holding the commit to go back to, kept inside .git so a reset cannot
# remove it and git status never reports it
UPDATE_RECORD_NAME = "shadow9-update.json"


class RunningServer(NamedTuple):
    """How the proxy was running before the update stopped it."""

    was_running: bool
    as_service: bool


class UpdateRecord(NamedTuple):
    """What the install was on before the last update started."""

    commit: str
    version: str
    recorded_at: str


def _find_repo_root() -> Path | None:
    """
    Find the git checkout this package was installed from.

    Returns None when the package lives somewhere without a repository, such as a
    plain wheel install into site-packages, where there is nothing to pull.
    """
    # A worktree or submodule checkout has .git as a file rather than a directory.
    for candidate in Path(__file__).resolve().parents:
        if (candidate / ".git").exists():
            return candidate
    return None


def _git(repo_root: Path, *args: str) -> "subprocess.CompletedProcess[str]":
    """Run a git command in the checkout and capture what it says."""
    return subprocess.run(["git", *args], cwd=repo_root, capture_output=True, text=True)


def _short(commit: str) -> str:
    """The first eight characters of a commit, which is what people read."""
    return commit[:8] if commit else "unknown"


def _upstream_branch(repo_root: Path) -> str:
    """The branch this checkout tracks, falling back to origin/main."""
    result = _git(repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    branch = result.stdout.strip()
    if result.returncode == 0 and branch:
        return branch
    return "origin/main"


def _project_version(repo_root: Path) -> str:
    """
    Read a checkout's version so the operator can see what moved.

    VERSION is the one the Release workflow writes. pyproject.toml is still read as
    a fallback, because this runs against the checkout as it was *before* a pull:
    updating from a commit that predates the VERSION file has to report the number
    that commit actually carried, not "unknown".
    """
    try:
        recorded = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
        if recorded:
            return recorded
    except OSError:
        pass
    try:
        text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return found.group(1) if found else "unknown"


def _privileged(command: list[str]) -> list[str]:
    """Prefix a system command with sudo unless the caller is already root."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return command
    if shutil.which("sudo") is None:
        return command
    # The output of these calls is captured, so a password prompt would be invisible
    # and would hang the update. -n makes sudo fail immediately instead.
    return ["sudo", "-n", *command]


def _wait_for_service_stop(timeout_seconds: float = 15.0) -> bool:
    """Wait for the systemd service to leave the active state, False if it never does."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True
        )
        if result.stdout.strip() != "active":
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def _wait_for_pid_exit(pid: int, timeout_seconds: float = 15.0) -> bool:
    """Wait for a process to exit, False if it is still alive when the time runs out."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            # Signal refused means the process is alive under another user.
            pass
        except OSError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


def _configured_address(repo_root: Path) -> tuple[str, int]:
    """The host and port the proxy is configured to bind."""
    config_file = repo_root / "config" / "config.yaml"
    try:
        cfg = Config.load(config_file) if config_file.exists() else Config()
    except Exception:
        # A config this command cannot read is the serve command's problem to report.
        cfg = Config()
    return cfg.server.host, cfg.server.port


def _something_is_listening(host: str, port: int) -> bool:
    """
    Check whether a TCP connection to the proxy address is accepted.

    This observes one thing: some process accepted a connection at that host and
    port. It does not prove the listener is the proxy, but a refused connection does
    prove the proxy is not serving.
    """
    # a wildcard bind is not a connectable address, so probe the loopback it covers
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    try:
        with socket.create_connection((probe_host, port), timeout=SERVING_PROBE_TIMEOUT):
            return True
    except OSError:
        return False


def _wait_until_serving(host: str, port: int, timeout_seconds: float = 20.0) -> bool:
    """Wait for the proxy to accept connections again after a restart."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _something_is_listening(host, port):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def _server_launcher(repo_root: Path) -> list[str]:
    """Build the command that starts the proxy from a checkout on this platform."""
    script = repo_root / ("shadow9.bat" if sys.platform == "win32" else "shadow9")
    if script.exists():
        return [str(script), "serve"]
    return [sys.executable, "-m", "shadow9", "serve"]


def _start_server(repo_root: Path, as_service: bool) -> bool:
    """Start the proxy again in the mode it was stopped in."""
    if as_service:
        result = subprocess.run(
            _privileged(["systemctl", "start", SERVICE_NAME]), capture_output=True, text=True
        )
        if result.returncode == 0:
            return True
        console.print(
            f"[yellow]Warning: failed to restart service: {result.stderr.strip()}[/yellow]"
        )
        console.print(f"[dim]Try: sudo systemctl start {SERVICE_NAME}[/dim]")
        return False

    try:
        subprocess.Popen(
            _server_launcher(repo_root),
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        console.print(f"[yellow]Warning: failed to restart server: {e}[/yellow]")
        console.print("[dim]Start it with: shadow9 serve[/dim]")
        return False
    return True


def _stop_running_server() -> RunningServer:
    """Stop the proxy if it is running, and report how it was running."""
    if shutil.which("systemctl"):
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True
        )
        if result.stdout.strip() == "active":
            console.print(f"[>] Stopping {SERVICE_NAME} service...")
            stop = subprocess.run(
                _privileged(["systemctl", "stop", SERVICE_NAME]), capture_output=True, text=True
            )
            # The port stays bound until the unit is really gone, so a fixed sleep
            # either wastes time or restarts into an address already in use.
            if stop.returncode != 0 or not _wait_for_service_stop():
                console.print(
                    f"[red]Error: the {SERVICE_NAME} service did not stop: "
                    f"{stop.stderr.strip()}[/red]"
                )
                console.print(
                    f"[dim]Nothing was changed and the service is still running. "
                    f"Try: sudo systemctl stop {SERVICE_NAME}[/dim]"
                )
                raise typer.Exit(1)
            return RunningServer(True, True)

    # pgrep is absent on Windows, where there is no standalone process to find either.
    if shutil.which("pgrep"):
        result = subprocess.run(["pgrep", "-f", "shadow9.*serve"], capture_output=True, text=True)
        pids = [entry for entry in result.stdout.split() if entry.isdigit()]
        if pids:
            server_pid = int(pids[0])
            console.print(f"[>] Stopping running server (PID: {server_pid})...")
            subprocess.run(["kill", str(server_pid)], capture_output=True)
            if not _wait_for_pid_exit(server_pid):
                console.print(f"[red]Error: server process {server_pid} is still running.[/red]")
                console.print(
                    f"[dim]Nothing was changed. Stop it and try again: kill -9 {server_pid}[/dim]"
                )
                raise typer.Exit(1)
            return RunningServer(True, False)

    return RunningServer(False, False)


def _start_and_check(repo_root: Path, running: RunningServer) -> bool:
    """Start the proxy again and report whether it is really serving."""
    if not running.was_running:
        console.print("[dim]Server was not running. Start with: shadow9 serve[/dim]")
        return True

    console.print("[>] Restarting server...")
    if not _start_server(repo_root, running.as_service):
        return False

    # systemctl returning zero only means the unit was asked to start. A connection
    # that is accepted is the difference between updated and updated and serving.
    host, port = _configured_address(repo_root)
    if _wait_until_serving(host, port):
        console.print(f"[green][OK] Serving on {host}:{port}[/green]")
        return True

    console.print(f"[red]The server started but nothing is listening on {host}:{port}.[/red]")
    return False


def _install_package(repo_root: Path) -> bool:
    """Install the checkout into the interpreter that will run the server."""
    install = [sys.executable, "-m", "pip", "install", "-e", ".", "-q"]
    result = subprocess.run(install, cwd=repo_root, capture_output=True, text=True)
    if result.returncode != 0:
        # A distro-managed interpreter refuses every install without this.
        result = subprocess.run(
            [*install, "--break-system-packages"], cwd=repo_root, capture_output=True, text=True
        )
    if result.returncode == 0:
        return True

    console.print(f"[red]Error: dependency install failed: {result.stderr.strip()}[/red]")
    console.print(f"[dim]Run in {repo_root}: {' '.join(install)}[/dim]")
    return False


def _update_record_path(repo_root: Path) -> Path:
    """Where the commit from before the update is kept."""
    git_dir = repo_root / ".git"
    if git_dir.is_dir():
        return git_dir / UPDATE_RECORD_NAME
    return repo_root / f".{UPDATE_RECORD_NAME}"


def _write_update_record(repo_root: Path, commit: str, version: str) -> None:
    """Record the commit to go back to if this update goes wrong."""
    record = UpdateRecord(
        commit=commit,
        version=version,
        recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    try:
        write_file_safely(_update_record_path(repo_root), json.dumps(record._asdict()).encode())
    except OSError as e:
        # Losing the record costs the rollback, not the update, so say so and go on.
        console.print(f"[yellow]Warning: could not record the current commit: {e}[/yellow]")


def _read_update_record(repo_root: Path) -> UpdateRecord | None:
    """Read the commit recorded before the last update, None if there is not one."""
    try:
        stored = json.loads(_update_record_path(repo_root).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    commit = stored.get("commit") if isinstance(stored, dict) else None
    if not commit:
        return None
    return UpdateRecord(
        commit=str(commit),
        version=str(stored.get("version", "unknown")),
        recorded_at=str(stored.get("recorded_at", "unknown")),
    )


def _roll_back(repo_root: Path, commit: str) -> bool:
    """Put the checkout back on a commit and install it again."""
    console.print(f"[>] Rolling back to {_short(commit)}...")
    result = _git(repo_root, "reset", "--hard", commit)
    if result.returncode != 0:
        console.print(f"[red]Rollback failed: {result.stderr.strip()}[/red]")
        console.print(f"[dim]By hand: git -C {repo_root} reset --hard {commit}[/dim]")
        return False
    if not _install_package(repo_root):
        console.print("[red]The code went back but the install did not.[/red]")
        return False
    console.print(f"[green][OK] Rolled back to {_short(commit)}[/green]")
    return True


def _run_rollback(repo_root: Path) -> None:
    """Put the install back on the commit recorded before the last update."""
    record = _read_update_record(repo_root)
    if record is None:
        console.print(
            "[red]No update has been recorded here, so there is nothing to go back to.[/red]"
        )
        console.print(f"[dim]Pick a commit by hand: git -C {repo_root} log --oneline[/dim]")
        raise typer.Exit(1)

    console.print(
        f"[cyan]Going back to {record.version} ({_short(record.commit)}), "
        f"recorded {record.recorded_at}[/cyan]\n"
    )

    running = _stop_running_server()
    if not _roll_back(repo_root, record.commit):
        _start_and_check(repo_root, running)
        raise typer.Exit(1)
    if not _start_and_check(repo_root, running):
        raise typer.Exit(1)
