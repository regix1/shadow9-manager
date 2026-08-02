"""
Utility commands for Shadow9 CLI.

Contains init, check-tor, fetch, setup, status, and update commands.
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import tomllib
from datetime import datetime, UTC
from pathlib import Path
from typing import Annotated, NamedTuple

import typer
from rich.table import Table
from rich.panel import Panel

from ..config import Config, generate_default_config, generate_master_key
from ..core.api_config import clear_api_key, get_api_key, load_api_config, set_api_key
from ..paths import Shadow9Paths, get_paths, load_master_key, lock_file, write_file_safely
from ..tor_connector import TorConnector, TorConfig
from ..wizards import run_init_wizard, show_config_summary, show_master_key
from ..ui import console, header, dependency_table
from ..ui import success as ui_success, error as ui_error
from .service import SERVICE_FILE, SERVICE_NAME
from . import probe

# How old a half-written backup has to be before the next rotation clears it away. It is
# not zero because another rotation may be writing one right now.
ABANDONED_BACKUP_AGE_SECONDS = 3600.0


class KeyFile(NamedTuple):
    """One live file that belongs to a master key."""

    name: str
    path: Path


class BackupEntry(NamedTuple):
    """One file recorded in a key backup manifest."""

    name: str
    present: bool
    sha256: str | None = None
    byte_count: int | None = None
    content: bytes | None = None


def _key_files(paths: Shadow9Paths) -> tuple[KeyFile, ...]:
    """Return the complete set of files tied to the current master key."""
    return (
        KeyFile(".env", paths.env_file),
        KeyFile("credentials.enc", paths.credentials_file),
        KeyFile(".salt", paths.salt_file),
        KeyFile("api.yaml", paths.config_dir / "api.yaml"),
        KeyFile(".api_salt", paths.config_dir / ".api_salt"),
    )


def _env_text_with_key(existing: str | None, master_key: str) -> str:
    """
    The text of a .env file that records this master key, keeping anything else it holds.

    load_master_key reads the environment before it reads the file, so an exported key is
    the one the credentials were encrypted with even when the file says something else or
    is not there at all. A backup that copied the file as it stands would hold a stale key
    or no key, and could never be restored, which is the same way a missing salt makes a
    backup worthless.
    """
    if existing is None:
        return (
            "# Shadow9 Master Key - Keep this secret!\n"
            "# This key encrypts your credentials file\n"
            f"SHADOW9_MASTER_KEY={master_key}\n"
        )

    lines = existing.splitlines()
    for index, line in enumerate(lines):
        # the first line wins, because that is the one load_master_key stops at
        if line.strip().startswith("SHADOW9_MASTER_KEY="):
            lines[index] = f"SHADOW9_MASTER_KEY={master_key}"
            break
    else:
        lines.append(f"SHADOW9_MASTER_KEY={master_key}")

    return "\n".join(lines) + "\n"


def _remove_abandoned_backups(backups_dir: Path) -> None:
    """
    Delete the staging directories a killed rotation left behind.

    They hold copies of the master key and the credential store, and nothing ever reads
    them again, because a restore only looks at directories that were renamed into their
    final name. The age check is there because a rotation running in another process has a
    staging directory of its own open right now, and taking that one away would make its
    backup fail.
    """
    try:
        entries = list(backups_dir.iterdir())
    except OSError:
        return

    cutoff = time.time() - ABANDONED_BACKUP_AGE_SECONDS
    for entry in entries:
        if not entry.name.startswith(".incomplete-") or not entry.is_dir():
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                shutil.rmtree(entry, ignore_errors=True)
        except OSError:
            continue


def _save_key_backup(root: Path, files: tuple[KeyFile, ...], env_text: str) -> Path:
    """Copy a complete key backup into place with an atomic final rename."""
    backups_dir = root / "key-backups"
    staging_dir: Path | None = None

    try:
        backups_dir.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(backups_dir, 0o700)
        _remove_abandoned_backups(backups_dir)

        while staging_dir is None:
            candidate = backups_dir / f".incomplete-{secrets.token_hex(8)}"
            try:
                candidate.mkdir(mode=0o700 if os.name != "nt" else 0o777)
            except FileExistsError:
                continue
            staging_dir = candidate

        created = datetime.now(UTC)
        entries: list[BackupEntry] = []
        for key_file in files:
            stored_file = staging_dir / key_file.name

            if key_file.name == Shadow9Paths.ENV_FILE:
                # written rather than copied, so the backup carries the key that was really
                # in force rather than whatever text the file happened to hold
                write_file_safely(stored_file, env_text.encode("utf-8"))
            elif key_file.path.exists():
                shutil.copy2(key_file.path, stored_file)
            else:
                entries.append(BackupEntry(key_file.name, False))
                continue

            copied = stored_file.read_bytes()
            entries.append(
                BackupEntry(
                    key_file.name,
                    True,
                    hashlib.sha256(copied).hexdigest(),
                    len(copied),
                )
            )

        recorded_files: list[dict[str, object]] = []
        for entry in entries:
            recorded: dict[str, object] = {"name": entry.name, "present": entry.present}
            if entry.present:
                recorded["sha256"] = entry.sha256
                recorded["bytes"] = entry.byte_count
            recorded_files.append(recorded)

        manifest = {
            "created": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "files": recorded_files,
        }
        manifest_text = json.dumps(manifest, indent=2) + "\n"
        write_file_safely(staging_dir / "manifest.json", manifest_text.encode("utf-8"))

        base_name = created.strftime("%Y%m%d-%H%M%S")
        suffix = 0
        while True:
            name = base_name if suffix == 0 else f"{base_name}-{suffix:06d}"
            backup_dir = backups_dir / name
            try:
                os.rename(staging_dir, backup_dir)
                return backup_dir
            except OSError:
                if not backup_dir.exists():
                    raise
                suffix += 1
    except BaseException:
        if staging_dir is not None and staging_dir.exists():
            try:
                staging_dir.relative_to(backups_dir)
            except ValueError:
                pass
            else:
                shutil.rmtree(staging_dir, ignore_errors=True)
        raise


def _read_key_backup(backup_dir: Path, files: tuple[KeyFile, ...]) -> tuple[BackupEntry, ...]:
    """Read and verify every entry in a completed key backup."""
    manifest_file = backup_dir / "manifest.json"
    if not manifest_file.is_file():
        raise ValueError(f"{manifest_file} is missing, so the backup is incomplete")

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{manifest_file} could not be read: {error}") from error

    if not isinstance(manifest, dict) or set(manifest) != {"created", "files"}:
        raise ValueError("manifest.json does not have the required shape")
    if not isinstance(manifest["created"], str) or not isinstance(manifest["files"], list):
        raise ValueError("manifest.json does not have the required shape")

    expected_names = {key_file.name for key_file in files}
    raw_entries = manifest["files"]
    if len(raw_entries) != len(expected_names):
        raise ValueError("manifest.json does not list the complete five-file key set")

    entries: list[BackupEntry] = []
    seen: set[str] = set()
    for raw_entry in raw_entries:
        if not isinstance(raw_entry, dict):
            raise ValueError("manifest.json contains an invalid file entry")

        name = raw_entry.get("name")
        present = raw_entry.get("present")
        if not isinstance(name, str) or name not in expected_names or name in seen:
            raise ValueError("manifest.json contains an unknown or repeated file name")
        if not isinstance(present, bool):
            raise ValueError(f"manifest.json has an invalid present value for {name}")

        expected_fields = (
            {"name", "present", "sha256", "bytes"}
            if present
            else {
                "name",
                "present",
            }
        )
        if set(raw_entry) != expected_fields:
            raise ValueError(f"manifest.json has invalid fields for {name}")

        if not present:
            entries.append(BackupEntry(name, False))
            seen.add(name)
            continue

        checksum = raw_entry["sha256"]
        byte_count = raw_entry["bytes"]
        if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
            raise ValueError(f"manifest.json has an invalid checksum for {name}")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ValueError(f"manifest.json has an invalid byte count for {name}")

        copied_file = backup_dir / name
        if not copied_file.is_file():
            raise ValueError(f"the backup is missing {name}")
        copied = copied_file.read_bytes()
        if hashlib.sha256(copied).hexdigest() != checksum:
            raise ValueError(f"the checksum for {name} does not match manifest.json")
        if len(copied) != byte_count:
            raise ValueError(f"the byte count for {name} does not match manifest.json")

        entries.append(BackupEntry(name, True, checksum, byte_count, copied))
        seen.add(name)

    if seen != expected_names:
        raise ValueError("manifest.json does not list the complete five-file key set")

    by_name = {entry.name: entry for entry in entries}
    return tuple(by_name[key_file.name] for key_file in files)


def _offer_first_user() -> None:
    """
    Offer to create a user when the store is empty, before the service is started.

    The proxy exits at startup when nobody can authenticate, and the unit restarts it
    forever, so a service started against an empty store is a permanent crash loop that
    looks installed and healthy from the setup screen.
    """
    from .user import open_store

    try:
        if open_store(Config.load()).list_users():
            return
    except Exception:
        pass

    console.print(
        "\n[yellow]No proxy users exist yet, and the service exits until one can log in.[/yellow]"
    )
    if typer.confirm("Create the first user now?", default=True):
        subprocess.run(["shadow9", "socks5", "user", "generate"])


def register_util_commands(app: typer.Typer, socks5_app: typer.Typer) -> None:
    """Register utility commands: proxy ones on the socks5 group, the rest on the main app."""

    show_app = typer.Typer(help="Show current settings and paths.")
    app.add_typer(show_app, name="show")

    @show_app.command("config")
    def show_config() -> None:
        """Show the server, security, and WireGuard configuration."""
        paths = get_paths()
        try:
            config = Config.load(paths.config_file)
        except Exception as error:
            console.print(f"[red]Error loading configuration: {error}[/red]")
            raise typer.Exit(1) from error
        show_config_summary(config)

    @show_app.command("paths")
    def show_paths() -> None:
        """Show the files and directories used by Shadow9."""
        paths = get_paths()
        table = Table(title="Shadow9 Paths", show_header=True)
        table.add_column("Path Type", style="cyan")
        table.add_column("Location", style="green")
        table.add_row("Root Directory", str(paths.root))
        table.add_row("Config File", str(paths.config_file))
        table.add_row("Credentials File", str(paths.credentials_file))
        table.add_row("Users Directory", str(paths.users_dir))
        table.add_row("Logs Directory", str(paths.logs_dir))
        console.print(table)

    def _write_new_config(output: str, quick: bool) -> None:
        """Write a configuration file, asking what to put in it unless quick is set."""
        output_path = Path(output)

        if output_path.exists() and not typer.confirm(
            f"Configuration file {output} already exists. Overwrite?"
        ):
            raise typer.Abort()

        # Quick mode: just generate defaults
        if quick:
            generate_default_config(output_path)
            console.print(f"[green]Configuration file created: {output}[/green]")
            show_master_key(generate_master_key())
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
            show_master_key(generate_master_key())
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
        show_master_key(generate_master_key())

    @socks5_app.command("check-tor")
    def check_tor(
        tor_port: Annotated[
            int | None,
            typer.Option(
                "--tor-port",
                "-p",
                help="Tor SOCKS port to test. Autodetects the running service when not given.",
            ),
        ] = None,
    ) -> None:
        """Check Tor connectivity status."""
        if not asyncio.run(_check_tor(tor_port)):
            raise typer.Exit(1)

    @app.command()
    def setup(
        skip_optional: Annotated[
            bool, typer.Option("--skip-optional", help="Skip optional bridge transports")
        ] = False,
        check_only: Annotated[
            bool, typer.Option("--check-only", help="Only check status, do not install")
        ] = False,
        config_only: Annotated[
            bool,
            typer.Option(
                "--config-only",
                help="Only write a configuration file, install nothing",
            ),
        ] = False,
        output: Annotated[
            str, typer.Option("--output", "-o", help="Where to write the configuration file")
        ] = "config/config.yaml",
        quick: Annotated[
            bool, typer.Option("--quick", "-q", help="Take the defaults without prompting")
        ] = False,
    ) -> None:
        """
        Set Shadow9 up: write a configuration file, and install what the proxy needs.

        With --config-only it writes the configuration and stops. Otherwise it installs:
        - Tor daemon (required)
        - obfs4proxy, snowflake (optional bridges)
        """
        from ..setup import run_setup, check_setup

        if config_only:
            _write_new_config(output, quick)
            return

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
                "Installing Tor and bridge transports for\n"
                "anonymous SOCKS5 proxy routing.\n\n"
                "[dim]sudo may be required[/dim]",
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
                            ["shadow9", "socks5", "service", "install"],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode == 0:
                            console.print("[green]Service reinstalled successfully![/green]")
                            _offer_first_user()
                            # Start the service
                            if typer.confirm("Start the service now?", default=True):
                                subprocess.run(["shadow9", "socks5", "service", "start"])
                                subprocess.run(["shadow9", "socks5", "service", "status"])
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
                            ["shadow9", "socks5", "service", "install"],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode == 0:
                            console.print("[green]Service installed successfully![/green]")
                            _offer_first_user()
                            if typer.confirm("Enable service to start on boot?", default=True):
                                subprocess.run(["shadow9", "socks5", "service", "enable"])
                            if typer.confirm("Start the service now?", default=True):
                                subprocess.run(["shadow9", "socks5", "service", "start"])
                                subprocess.run(["shadow9", "socks5", "service", "status"])
                        else:
                            console.print(f"[red]Service install failed: {result.stderr}[/red]")

            console.print(
                Panel(
                    "[bold green]Proxy Setup Complete![/bold green]\n\n"
                    "Start the proxy:\n"
                    "  [cyan]shadow9 socks5 user generate[/cyan]  # Create user credentials\n"
                    "  [cyan]shadow9 socks5 serve[/cyan]          # Start SOCKS5 proxy",
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

    @socks5_app.command()
    def status() -> None:
        """Show proxy status, listening ports, and Tor connectivity."""
        from ..setup import check_setup
        from .api import _read_api_config

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

        paths = get_paths()
        config = Config.load(paths.config_file)
        api_config = _read_api_config(str(paths.config_dir / "api.yaml")) or {}
        services: list[tuple[str, str, int]] = [
            ("Proxy", config.server.host, config.server.port),
            (
                "API",
                str(api_config.get("host", "127.0.0.1")),
                int(api_config.get("port", 8080)),
            ),
        ]

        console.print("\n[bold cyan]Listening Ports[/bold cyan]")
        for name, host, port in services:
            listening = asyncio.run(probe._something_is_listening(host, port))
            if listening:
                ui_success(f"{name} listening on {host}:{port}")
            else:
                ui_error(f"{name} not listening on {host}:{port}")

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

        python_error = _target_python_error(repo_root, target)
        if python_error is not None:
            console.print(f"[red]Error: {python_error}[/red]")
            console.print("[dim]Nothing was changed and the server was not touched.[/dim]")
            raise typer.Exit(1)

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

        running = stop_running_server()
        wireguard_running = _wireguard_service_is_running()

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

        if not _use_checkout_for_service(repo_root):
            console.print("[yellow]Going back to the version that was installed before.[/yellow]")
            _roll_back(repo_root, current_commit)
            _start_and_check(repo_root, running)
            raise typer.Exit(1)

        if not _restart_wireguard_service(wireguard_running):
            console.print("[yellow]Going back to the version that was installed before.[/yellow]")
            rolled_back = _roll_back(repo_root, current_commit)
            if rolled_back:
                _restart_wireguard_service(wireguard_running)
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
                console.print(
                    "[red]The server is not running. Start it with: shadow9 socks5 serve[/red]"
                )
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

    # The key that encrypts the credential store. Named in full because "api key" is a
    # different secret entirely, and an unqualified "key" gave no way to tell them apart.
    key_app = typer.Typer(help="Manage the master key that encrypts stored credentials")
    app.add_typer(key_app, name="master-key")

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
        paths = get_paths()
        project_root = paths.root
        config_dir = paths.config_dir
        env_file = paths.env_file
        credentials_file = paths.credentials_file
        salt_file = paths.salt_file
        api_config_file = config_dir / "api.yaml"
        files = _key_files(paths)

        # Whether there is a key to lose is asked of load_master_key rather than of the
        # text of .env, because an exported SHADOW9_MASTER_KEY beats the file and is what
        # the init wizard tells operators to set up. Reading only the file missed that
        # install completely, so it got no backup, no service stop, and a new key written
        # beside a credential store and a salt belonging to the old one.
        old_master_key = load_master_key()
        key_was_exported = os.environ.get("SHADOW9_MASTER_KEY") is not None

        had_api_key = False
        old_api_key: str | None = None
        backup_dir: Path | None = None

        if old_master_key is not None:
            found_in = "the environment" if key_was_exported else str(env_file)
            console.print(f"[yellow]Existing master key found in {found_in}[/yellow]")
            console.print(
                "[red]WARNING: Regenerating the key will make existing "
                "credentials unreadable![/red]"
            )

            if not force and not typer.confirm("Generate a new master key?", default=False):
                console.print("[dim]Keeping existing key[/dim]")
                return

            stop_running_server()

            try:
                api_state = load_api_config(api_config_file)
                had_api_key = bool(api_state.get("api_key_encrypted") or api_state.get("key"))
                if had_api_key:
                    old_api_key = get_api_key(api_config_file)
            except Exception as error:
                console.print(f"[red]Could not read the current API key state: {error}[/red]")
                console.print("[dim]No key files were changed.[/dim]")
                raise typer.Exit(1) from error

            try:
                existing_env = env_file.read_text(encoding="utf-8") if env_file.exists() else None
                backup_dir = _save_key_backup(
                    project_root, files, _env_text_with_key(existing_env, old_master_key)
                )
            except Exception as error:
                console.print(f"[red]Could not create a complete key backup: {error}[/red]")
                console.print("[dim]No key files were changed.[/dim]")
                raise typer.Exit(1) from error

            credentials_were_present = credentials_file.exists()
            try:
                with lock_file(credentials_file):
                    credentials_file.unlink(missing_ok=True)
                    salt_file.unlink(missing_ok=True)
            except Exception as error:
                console.print(f"[red]Error removing old key material: {error}[/red]")
                console.print(
                    "[dim]Restore the matched backup with: "
                    f'shadow9 master-key restore "{backup_dir}"[/dim]'
                )
                raise typer.Exit(1) from error

            if credentials_were_present:
                console.print("[yellow]You will need to create new users after this[/yellow]")

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
            os.environ["SHADOW9_MASTER_KEY"] = master_key

        except Exception as e:
            console.print(f"[red]Error saving key: {e}[/red]")
            raise typer.Exit(1) from e

        if had_api_key:
            try:
                if old_api_key is not None:
                    set_api_key(old_api_key)
                    console.print(
                        "[green]The existing API key was re-encrypted and API access "
                        "still works.[/green]"
                    )
                else:
                    clear_api_key()
                    console.print(
                        "[yellow]The old API key could not be read and has been removed. "
                        "Run 'shadow9 api setup' to create another.[/yellow]"
                    )
            except Exception as error:
                if old_api_key is not None:
                    try:
                        clear_api_key()
                    except Exception as clear_error:
                        console.print(
                            f"[red]The API key could not be re-encrypted or removed: "
                            f"{clear_error}[/red]"
                        )
                        raise typer.Exit(1) from clear_error
                    console.print(
                        "[yellow]The API key could not be re-encrypted and has been removed. "
                        "Run 'shadow9 api setup' to create another.[/yellow]"
                    )
                else:
                    console.print(
                        f"[red]The unreadable API key could not be removed: {error}[/red]"
                    )
                raise typer.Exit(1) from error

        if key_was_exported:
            # only this process picked up the new key, and an exported one beats .env, so
            # the operator's next command would read the old key against the new store
            console.print(
                "[yellow]Your shell still exports the old SHADOW9_MASTER_KEY. Export the "
                "new one or start a new shell, or the next command will use the old "
                "key.[/yellow]"
            )

        if backup_dir is not None:
            console.print(f"[dim]Matched key backup saved to {backup_dir}[/dim]")
            console.print(f'[dim]Restore it with: shadow9 master-key restore "{backup_dir}"[/dim]')

    @key_app.command("restore")
    def key_restore(
        backup: Annotated[
            Path | None,
            typer.Argument(help="Backup directory to restore (newest if omitted)"),
        ] = None,
        force: Annotated[
            bool, typer.Option("--force", "-f", help="Skip confirmation prompts")
        ] = False,
    ) -> None:
        """Restore the master key and every file captured with it."""
        paths = get_paths()
        project_root = paths.root
        credentials_file = paths.credentials_file
        files = _key_files(paths)
        backups_dir = project_root / "key-backups"

        if backup is None:
            if not backups_dir.is_dir():
                console.print(f"[red]No key backups were found in {backups_dir}[/red]")
                raise typer.Exit(1)
            try:
                candidates = sorted(
                    entry
                    for entry in backups_dir.iterdir()
                    if entry.is_dir()
                    and re.fullmatch(r"\d{8}-\d{6}(?:-\d+)?", entry.name) is not None
                )
            except OSError as error:
                console.print(f"[red]Could not read key backups in {backups_dir}: {error}[/red]")
                raise typer.Exit(1) from error

            if not candidates:
                console.print(f"[red]No key backups were found in {backups_dir}[/red]")
                raise typer.Exit(1)
            backup_dir = candidates[-1]
        else:
            backup_dir = backup.expanduser().resolve()

        if not backup_dir.is_dir():
            console.print(f"[red]Key backup directory not found: {backup_dir}[/red]")
            raise typer.Exit(1)

        try:
            entries = _read_key_backup(backup_dir, files)
        except (OSError, ValueError) as error:
            console.print(f"[red]Refusing to restore {backup_dir}: {error}[/red]")
            raise typer.Exit(1) from error

        by_name = {entry.name: entry for entry in entries}
        env_entry = by_name[".env"]
        restored_master_key: str | None = None
        if env_entry.present:
            try:
                env_text = (env_entry.content or b"").decode("utf-8")
            except UnicodeError as error:
                console.print(f"[red]Refusing to restore an unreadable .env file: {error}[/red]")
                raise typer.Exit(1) from error
            for line in env_text.splitlines():
                if line.strip().startswith("SHADOW9_MASTER_KEY="):
                    restored_master_key = line.split("=", 1)[1].strip()
                    break
            if not restored_master_key:
                console.print("[red]Refusing to restore a .env file with no master key[/red]")
                raise typer.Exit(1)

        console.print(
            f"[yellow]Restoring {backup_dir} replaces the current key material. "
            "Users created since this backup will be gone.[/yellow]"
        )
        if not force and not typer.confirm("Restore this key backup?", default=False):
            console.print("[dim]Keeping the current key material[/dim]")
            return

        stop_running_server()

        # The environment file goes last so an interrupted restore never advertises the
        # old key while some live files still belong to the newer one.
        restore_order = files[1:] + files[:1]
        try:
            with lock_file(credentials_file):
                for key_file in restore_order:
                    entry = by_name[key_file.name]
                    if entry.present:
                        if entry.content is None:
                            raise ValueError(f"verified content is missing for {entry.name}")
                        write_file_safely(key_file.path, entry.content)
                    else:
                        key_file.path.unlink(missing_ok=True)
        except Exception as error:
            console.print(f"[red]Key restore did not complete: {error}[/red]")
            console.print(f"[dim]The backup at {backup_dir} was not changed.[/dim]")
            raise typer.Exit(1) from error

        exported_key = os.environ.get("SHADOW9_MASTER_KEY")
        if restored_master_key is None:
            os.environ.pop("SHADOW9_MASTER_KEY", None)
        else:
            os.environ["SHADOW9_MASTER_KEY"] = restored_master_key

        if exported_key is not None and exported_key != restored_master_key:
            # the same trap as after a rotation, in the other direction
            console.print(
                "[yellow]Your shell still exports a different SHADOW9_MASTER_KEY. An "
                "exported key beats .env, so export the restored one or start a new "
                "shell.[/yellow]"
            )

        restored = ", ".join(entry.name for entry in entries if entry.present)
        removed = ", ".join(entry.name for entry in entries if not entry.present)
        console.print(f"[green]Key material restored from {backup_dir}[/green]")
        if restored:
            console.print(f"[dim]Restored: {restored}[/dim]")
        if removed:
            console.print(f"[dim]Removed because they were absent in the backup: {removed}[/dim]")
        console.print(
            "[yellow]The Shadow9 service is stopped. Start it again with "
            "'shadow9 socks5 service start'.[/yellow]"
        )

    @key_app.command("check")
    def key_check(
        show: Annotated[
            bool,
            typer.Option("--show", help="Print the key itself, not just where it came from"),
        ] = False,
    ) -> None:
        """
        Say whether a master key is configured, and with --show print it.

        The answer comes from load_master_key rather than from reading .env, so it matches
        the key the rest of the program will actually use. An exported SHADOW9_MASTER_KEY
        beats the file, and a check that only read the file would call that install
        unconfigured.
        """
        master_key = load_master_key()

        if master_key is None:
            console.print("[red]No master key configured[/red]")
            console.print("[dim]Run 'shadow9 master-key generate' to create one[/dim]")
            raise typer.Exit(1)

        if show:
            show_master_key(master_key)
            return

        if os.environ.get("SHADOW9_MASTER_KEY"):
            console.print("[green]Master key is set in the environment[/green]")
        else:
            console.print(f"[green]Master key found in {get_paths().env_file}[/green]")


async def _check_tor(tor_port: int | None = None) -> bool:
    """
    Report whether Tor answers, and say so through the return value.

    A port given on the command line is the one tested. Autodetection only fills in a port
    the caller did not choose, because a check that quietly tests a different port than the
    one asked about answers a question nobody asked.

    Args:
        tor_port: The SOCKS port to test, or None to autodetect the running service

    Returns:
        True if Tor answered on the port that was tested
    """
    console.print("[cyan]Checking Tor connectivity...[/cyan]")

    config: TorConfig | None
    if tor_port is not None:
        config = TorConfig(socks_port=tor_port)
        console.print(f"[cyan]Testing the requested port {tor_port}[/cyan]")
    else:
        config = TorConnector.detect_tor_service()
        if config is None:
            console.print("[red]Tor service not detected[/red]")
            console.print(f"\n{TorConnector.get_tor_install_instructions()}")
            return False
        console.print(f"[green]Tor service detected on port {config.socks_port}[/green]")

    tor = TorConnector(config)
    if not await tor.connect():
        console.print(f"[red]Could not establish Tor connection on port {config.socks_port}[/red]")
        return False

    circuit_info = tor.circuit_info
    console.print(
        Panel(
            f"[bold green]Tor Connection Successful[/bold green]\n\n"
            f"Exit IP: [cyan]{circuit_info.exit_ip if circuit_info else 'Unknown'}[/cyan]\n"
            f"SOCKS Port: [cyan]{config.socks_port}[/cyan]",
            title="Tor Status",
            border_style="green",
        )
    )
    await tor.disconnect()
    return True


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


def privileged(command: list[str]) -> list[str]:
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


async def _serving_within(host: str, port: int, timeout_seconds: float) -> bool:
    """Wait for the address to accept a connection, or give up at the deadline."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        if await probe._something_is_listening(host, port):
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(1)


def _wait_until_serving(host: str, port: int, timeout_seconds: float = 20.0) -> bool:
    """
    Wait for the proxy to accept connections again after a restart.

    The check itself is commands.probe, the one the status commands use, so there is a
    single answer to "is something listening there" rather than a second copy that could
    disagree about a wildcard bind or a timeout. One event loop covers the whole wait
    instead of one per attempt.
    """
    return asyncio.run(_serving_within(host, port, timeout_seconds))


def _server_launcher(repo_root: Path) -> list[str]:
    """Build the command that starts the proxy from a checkout on this platform."""
    script = repo_root / ("shadow9.bat" if sys.platform == "win32" else "shadow9")
    if script.exists():
        return [str(script), "socks5", "serve"]
    return [sys.executable, "-m", "shadow9", "socks5", "serve"]


def _start_server(repo_root: Path, as_service: bool) -> bool:
    """Start the proxy again in the mode it was stopped in."""
    if as_service:
        result = subprocess.run(
            privileged(["systemctl", "start", SERVICE_NAME]), capture_output=True, text=True
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
        console.print("[dim]Start it with: shadow9 socks5 serve[/dim]")
        return False
    return True


def stop_running_server() -> RunningServer:
    """
    Stop the proxy if it is running, and report how it was running.

    Finds the server by identity rather than by whoever holds a port: the service unit
    first, then shadow9's own process. `shadow9 socks5 stop` uses this for the same reason the
    updater does, because killing the holder of a port has stopped unrelated programs.
    """
    if shutil.which("systemctl"):
        result = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True
        )
        if result.stdout.strip() == "active":
            console.print(f"[>] Stopping {SERVICE_NAME} service...")
            stop = subprocess.run(
                privileged(["systemctl", "stop", SERVICE_NAME]), capture_output=True, text=True
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
        console.print("[dim]Server was not running. Start with: shadow9 socks5 serve[/dim]")
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


def _venv_python(repo_root: Path) -> Path:
    """The interpreter owned by this checkout."""
    if sys.platform == "win32":
        return repo_root / "venv" / "Scripts" / "python.exe"
    return repo_root / "venv" / "bin" / "python"


def _target_python_error(repo_root: Path, target: str) -> str | None:
    """Explain when this interpreter is below the incoming package's declared floor."""
    result = _git(repo_root, "show", f"{target}:pyproject.toml")
    if result.returncode != 0 or not result.stdout:
        return None
    try:
        project = tomllib.loads(result.stdout)["project"]
        requirement = str(project["requires-python"])
    except (KeyError, TypeError, tomllib.TOMLDecodeError):
        return None

    floors = [
        tuple(int(part) for part in match.groups(default="0"))
        for match in re.finditer(r"(?:^|,)\s*>=\s*(\d+)\.(\d+)(?:\.(\d+))?", requirement)
    ]
    if not floors or sys.version_info[:3] >= max(floors):
        return None
    current = ".".join(str(part) for part in sys.version_info[:3])
    return f"the update requires Python {requirement}, but this install uses Python {current}"


def _create_venv(repo_root: Path) -> bool:
    """Create the checkout environment, adding Debian's split-out venv support if needed."""
    python = _venv_python(repo_root)
    if python.exists():
        return True

    create = [sys.executable, "-m", "venv", str(repo_root / "venv")]
    result = subprocess.run(create, cwd=repo_root, capture_output=True, text=True)
    if (
        result.returncode != 0
        and "ensurepip is not available" in f"{result.stdout}\n{result.stderr}".lower()
        and shutil.which("apt-get")
    ):
        console.print("[>] Installing Python virtual-environment support...")
        package = subprocess.run(
            privileged(["apt-get", "install", "-y", "python3-venv"]),
            capture_output=True,
            text=True,
        )
        if package.returncode == 0:
            result = subprocess.run(create, cwd=repo_root, capture_output=True, text=True)
        else:
            result = package
    if result.returncode == 0:
        return True

    console.print(
        f"[red]Error: could not create {repo_root / 'venv'}: {result.stderr.strip()}[/red]"
    )
    console.print(f"[dim]Install Python's venv support, then run: {' '.join(create)}[/dim]")
    return False


def _install_package(repo_root: Path) -> bool:
    """Install the checkout into its virtual environment."""
    if not _create_venv(repo_root):
        return False

    install = [str(_venv_python(repo_root)), "-m", "pip", "install", "-e", ".", "-q"]
    result = subprocess.run(install, cwd=repo_root, capture_output=True, text=True)
    if result.returncode == 0:
        return True

    console.print(f"[red]Error: dependency install failed: {result.stderr.strip()}[/red]")
    console.print(f"[dim]Run in {repo_root}: {' '.join(install)}[/dim]")
    return False


def _wireguard_service_is_running() -> bool:
    """Report whether the enrollment listener needs to be restarted after installation."""
    if shutil.which("systemctl") is None:
        return False

    from .wireguard import ENROLLMENT_SERVICE_NAME

    active = subprocess.run(
        ["systemctl", "is-active", ENROLLMENT_SERVICE_NAME],
        capture_output=True,
        text=True,
    )
    return active.stdout.strip() == "active"


def _restart_wireguard_service(was_running: bool) -> bool:
    """Restart the active enrollment listener so it loads and applies the installed code."""
    if not was_running:
        return True

    from .wireguard import ENROLLMENT_SERVICE_NAME

    console.print(f"[>] Restarting {ENROLLMENT_SERVICE_NAME}...")
    restarted = subprocess.run(
        privileged(["systemctl", "restart", ENROLLMENT_SERVICE_NAME]),
        capture_output=True,
        text=True,
    )
    if restarted.returncode == 0:
        return True

    console.print(
        f"[red]Error: {ENROLLMENT_SERVICE_NAME} did not restart: "
        f"{restarted.stderr.strip()}[/red]"
    )
    console.print(f"[dim]Try: sudo systemctl restart {ENROLLMENT_SERVICE_NAME}[/dim]")
    return False


def _use_checkout_for_service(repo_root: Path) -> bool:
    """Make an installed service enter through the wrapper that selects the checkout venv."""
    service_file = Path(SERVICE_FILE)
    if not service_file.exists():
        return True

    try:
        content = service_file.read_text(encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Error: cannot read {service_file}: {e}[/red]")
        return False

    old = next(
        (
            line
            for line in content.splitlines()
            if line.startswith("ExecStart=") and " serve" in line
        ),
        None,
    )
    wrapper = str(repo_root / "shadow9")
    if old is None or old.startswith(f"ExecStart={wrapper} socks5 serve"):
        return True

    serve_args = old.split(" serve", 1)[1]
    replacement = f"ExecStart={wrapper} socks5 serve{serve_args}"
    try:
        write_file_safely(
            service_file,
            content.replace(old, replacement, 1).encode("utf-8"),
            mode=0o644,
        )
    except OSError as e:
        console.print(f"[red]Error: cannot update {service_file}: {e}[/red]")
        return False

    result = subprocess.run(
        privileged(["systemctl", "daemon-reload"]), capture_output=True, text=True
    )
    if result.returncode == 0:
        return True
    console.print(f"[red]Error reloading the service unit: {result.stderr.strip()}[/red]")
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
        recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
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

    running = stop_running_server()
    if not _roll_back(repo_root, record.commit):
        _start_and_check(repo_root, running)
        raise typer.Exit(1)
    if not _start_and_check(repo_root, running):
        raise typer.Exit(1)
