"""
Service management commands for Shadow9 CLI.

Manages Shadow9 as a systemd service on Linux.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from ..paths import get_paths, write_file_safely

console = Console()

SERVICE_NAME = "shadow9"
SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}.service"


def register_service_commands(app: typer.Typer):
    """Register service commands with the main app."""

    service_app = typer.Typer(
        help="Manage Shadow9 as a systemd service (Linux only).",
        invoke_without_command=True,
        no_args_is_help=True,
    )
    app.add_typer(service_app, name="service")

    @service_app.command("install")
    def service_install(
        host: Annotated[str, typer.Option("--host", "-h", help="Host to bind to")] = "127.0.0.1",
        port: Annotated[int, typer.Option("--port", "-p", help="Port to listen on")] = 1080,
        global_cmd: Annotated[
            bool,
            typer.Option(
                "--global", "-g", help="Install 'shadow9' command globally in /usr/local/bin"
            ),
        ] = True,
    ):
        """Install Shadow9 as a systemd service."""
        _check_linux()
        _check_root()

        # Use the paths module to get consistent install path
        paths = get_paths()
        install_path = str(paths.root)

        # Find Python executable - prefer venv if it exists, otherwise use system Python
        venv_python = Path(install_path) / "venv" / "bin" / "python"
        if venv_python.exists():
            python_exec = str(venv_python)
            python_path = f"{install_path}/venv/bin:/usr/local/bin:/usr/bin:/bin"
        else:
            # Use system Python
            python_exec = shutil.which("python3") or shutil.which("python") or sys.executable
            python_path = "/usr/local/bin:/usr/bin:/bin"

        # Get master key from paths module (checks env var and .env file)
        from ..paths import load_master_key

        master_key = load_master_key()

        if master_key:
            console.print(f"[dim]Using master key from: {paths.env_file}[/dim]")

        # This is the one file whose truncation cannot be recovered from: half a master
        # key means credentials.enc will never decrypt again, for every user.
        # write_file_safely renames a complete file into place and applies 0600 before
        # any content exists, rather than after
        if not master_key:
            import secrets

            master_key = secrets.token_urlsafe(32)
            env_file = Path(install_path) / ".env"
            write_file_safely(env_file, f"SHADOW9_MASTER_KEY={master_key}\n".encode())
            console.print(f"[green]Generated master key and saved to {env_file}[/green]")

        # Ensure .env file exists in install path for the service
        target_env = Path(install_path) / ".env"
        if not target_env.exists():
            write_file_safely(target_env, f"SHADOW9_MASTER_KEY={master_key}\n".encode())
            console.print(f"[dim]Saved master key to: {target_env}[/dim]")

        # A flat RestartSec retries forever at one rate, which fills the journal on a
        # service that cannot start at all. The decaying interval needs systemd 254.
        if _systemd_version() >= 254:
            restart_backoff = (
                "# back the retry interval off to 5s, 11s, 25s, 55s, 2m, then 5m\n"
                "RestartSteps=5\n"
                "RestartMaxDelaySec=300\n"
            )
        else:
            restart_backoff = ""

        # Create systemd service file
        # Set SHADOW9_HOME to ensure consistent path resolution
        service_content = f"""[Unit]
Description=Shadow9 SOCKS5 Proxy Server
Documentation=https://github.com/regix1/shadow9-manager
After=network.target tor.service
Wants=tor.service
# Without this, five quick failures leave the unit failed until somebody logs in.
# It belongs in [Unit]; systemd ignores it under [Service].
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
WorkingDirectory={install_path}
Environment="PATH={python_path}"
Environment="PYTHONPATH={install_path}/src"
Environment="SHADOW9_HOME={install_path}"
Environment="SHADOW9_MASTER_KEY={master_key}"
ExecStart={python_exec} -m shadow9.cli serve --host {host} --port {port}
# a clean exit must also come back, so on-failure is not enough
Restart=always
RestartSec=5
{restart_backoff}# the relay holds two descriptors per connection and the default 1024 runs out
LimitNOFILE=65535
# A share of the machine rather than a fixed number of megabytes. 768M was the same
# figure on a 1 GB VPS and a 64 GB host, and systemd works a percentage out from
# installed RAM every time it loads the unit, so a resized machine gets the new figure
# on the next daemon-reload with nothing to edit here. The proxy reads these two files
# back out of its own cgroup at startup and picks how many password hashes it will run
# at once so that it fits underneath them.
# MemoryHigh is the working ceiling and the one the process is expected to live under;
# MemoryMax is the backstop, which is the order systemd's own documentation recommends.
MemoryHigh=60%
MemoryMax=75%
# continue, not stop, because stop can leave the proxy down for good. When systemd
# attributes a kill to the OOM killer it applies OOMPolicy, and stop means it stops the
# unit itself, which Restart=always does not undo. Measured on systemd 249: a unit under
# stop that took a kill systemd recorded as oom-kill went to inactive (dead) with
# Result=success and NRestarts=0 and stayed there. Whether a given kill is recorded that
# way or as a plain signal is a race, so stop is a service that usually comes back and
# sometimes does not, which is the worst of the two. Under continue the same probe
# restarted every time, 16 and 20 times in 25 seconds across two runs.
# Nothing is lost by not using stop: the kill is still on the record as Result=signal
# with ExecMainStatus=9 and the OOM lines in the journal, while a unit latched dead by
# stop reports itself as a success and says nothing at all.
OOMPolicy=continue
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={install_path}/config {install_path}/users
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""

        # systemd reads this back on daemon-reload, so a half-written unit is a unit that
        # will not parse. 0644 rather than the helper's default, because systemd and any
        # operator running systemctl status have to be able to read it
        write_file_safely(Path(SERVICE_FILE), service_content.encode(), mode=0o644)

        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        # Install global command symlink
        global_note = ""
        if global_cmd:
            shadow9_script = Path(install_path) / "shadow9"
            symlink_path = Path("/usr/local/bin/shadow9")

            # Remove existing symlink if it exists
            if symlink_path.is_symlink():
                symlink_path.unlink()
            elif symlink_path.exists():
                console.print(
                    f"[yellow]Warning: {symlink_path} exists and is not a symlink, skipping[/yellow]"
                )
                global_cmd = False

            if global_cmd:
                symlink_path.symlink_to(shadow9_script)
                console.print(f"[green]Installed global command: {symlink_path}[/green]")
                global_note = "\n\nGlobal command: [cyan]shadow9[/cyan] (available system-wide)"

        console.print(
            Panel(
                f"[bold green]Service installed![/bold green]\n\n"
                f"Service file: [cyan]{SERVICE_FILE}[/cyan]\n"
                f"Install path: [cyan]{install_path}[/cyan]\n"
                f"Listen: [cyan]{host}:{port}[/cyan]{global_note}\n\n"
                f"[bold]Next steps:[/bold]\n"
                f"  shadow9 service start    - Start the service\n"
                f"  shadow9 service enable   - Enable auto-start on boot\n"
                f"  shadow9 service status   - Check service status",
                title="Shadow9 Service",
                border_style="green",
            )
        )

    @service_app.command("uninstall")
    def service_uninstall(
        yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
    ):
        """Uninstall Shadow9 systemd service."""
        _check_linux()
        _check_root()

        if not Path(SERVICE_FILE).exists():
            console.print("[yellow]Service is not installed[/yellow]")
            raise typer.Exit(0)

        if not yes:
            if not typer.confirm("Uninstall Shadow9 service?"):
                raise typer.Abort()

        # Stop and disable service
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)

        # Remove service file
        Path(SERVICE_FILE).unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=True)

        # Remove global symlink if it exists
        symlink_path = Path("/usr/local/bin/shadow9")
        if symlink_path.is_symlink():
            symlink_path.unlink()
            console.print("[green]Removed global command symlink[/green]")

        console.print("[green]Service uninstalled[/green]")

    @service_app.command("start")
    def service_start():
        """Start the Shadow9 service."""
        _check_linux()
        _check_root()
        _check_installed()

        result = subprocess.run(
            ["systemctl", "start", SERVICE_NAME], capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print("[green]Service started[/green]")
        else:
            console.print("[red]Failed to start service[/red]")
            console.print(f"[dim]{result.stderr}[/dim]")
            raise typer.Exit(1)

    @service_app.command("stop")
    def service_stop():
        """Stop the Shadow9 service."""
        _check_linux()
        _check_root()
        _check_installed()

        result = subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True, text=True)
        if result.returncode == 0:
            console.print("[green]Service stopped[/green]")
        else:
            console.print("[red]Failed to stop service[/red]")
            raise typer.Exit(1)

    @service_app.command("restart")
    def service_restart():
        """Restart the Shadow9 service."""
        _check_linux()
        _check_root()
        _check_installed()

        result = subprocess.run(
            ["systemctl", "restart", SERVICE_NAME], capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print("[green]Service restarted[/green]")
        else:
            console.print("[red]Failed to restart service[/red]")
            raise typer.Exit(1)

    @service_app.command("enable")
    def service_enable():
        """Enable Shadow9 to start on boot."""
        _check_linux()
        _check_root()
        _check_installed()

        result = subprocess.run(
            ["systemctl", "enable", SERVICE_NAME], capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print("[green]Service enabled (will start on boot)[/green]")
        else:
            console.print("[red]Failed to enable service[/red]")
            raise typer.Exit(1)

    @service_app.command("disable")
    def service_disable():
        """Disable Shadow9 from starting on boot."""
        _check_linux()
        _check_root()
        _check_installed()

        result = subprocess.run(
            ["systemctl", "disable", SERVICE_NAME], capture_output=True, text=True
        )
        if result.returncode == 0:
            console.print("[green]Service disabled (won't start on boot)[/green]")
        else:
            console.print("[red]Failed to disable service[/red]")
            raise typer.Exit(1)

    @service_app.command("status")
    def service_status():
        """Show Shadow9 service status."""
        _check_linux()
        _check_installed()

        result = subprocess.run(
            ["systemctl", "status", SERVICE_NAME, "--no-pager"], capture_output=True, text=True
        )

        # Parse status
        is_active = "active (running)" in result.stdout
        is_enabled = (
            subprocess.run(
                ["systemctl", "is-enabled", SERVICE_NAME], capture_output=True, text=True
            ).stdout.strip()
            == "enabled"
        )

        status_color = "green" if is_active else "red"
        status_text = "Running" if is_active else "Stopped"
        boot_text = "Enabled" if is_enabled else "Disabled"

        console.print(
            Panel(
                f"[bold]Status:[/bold] [{status_color}]{status_text}[/{status_color}]\n"
                f"[bold]Boot:[/bold]   {boot_text}\n\n"
                f"[dim]{result.stdout}[/dim]",
                title="Shadow9 Service Status",
                border_style=status_color,
            )
        )

    @service_app.command("logs")
    def service_logs(
        follow: Annotated[bool, typer.Option("--follow", "-f", help="Follow log output")] = False,
        lines: Annotated[int, typer.Option("--lines", "-n", help="Number of lines to show")] = 50,
        current: Annotated[
            bool, typer.Option("--current", "-c", help="Only show logs from current service run")
        ] = False,
    ):
        """View Shadow9 service logs."""
        _check_linux()
        _check_installed()

        cmd = ["journalctl", "-u", SERVICE_NAME, "--no-pager"]

        # If --current, get logs only since the service last started
        if current:
            # Get the timestamp when the service was last activated
            result = subprocess.run(
                ["systemctl", "show", SERVICE_NAME, "--property=ActiveEnterTimestamp", "--value"],
                capture_output=True,
                text=True,
            )
            timestamp = result.stdout.strip()
            if timestamp:
                cmd.extend(["--since", timestamp])
                console.print(f"[dim]Showing logs since service start: {timestamp}[/dim]\n")
        else:
            cmd.append(f"-n{lines}")

        if follow:
            cmd.append("-f")
            if not current:
                console.print("[dim]Following logs (Ctrl+C to exit)...[/dim]\n")
            subprocess.run(cmd)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
            console.print(result.stdout)


def _systemd_version() -> int:
    """Read the running systemd's major version, or 0 if it cannot be determined."""
    try:
        result = subprocess.run(
            ["systemctl", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return 0

    # The first line reads "systemd 255 (255.4-1ubuntu8.4)"
    parts = result.stdout.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def _check_linux():
    """Check if running on Linux."""
    if sys.platform != "linux":
        console.print("[red]Service management is only available on Linux[/red]")
        console.print("[dim]On Windows/macOS, use: shadow9 serve --background[/dim]")
        raise typer.Exit(1)


def _check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        console.print("[red]This command requires root privileges[/red]")
        console.print("[dim]Run with: sudo shadow9 service ...[/dim]")
        raise typer.Exit(1)


def _check_installed():
    """Check if service is installed."""
    if not Path(SERVICE_FILE).exists():
        console.print("[red]Service is not installed[/red]")
        console.print("[dim]Run: sudo shadow9 service install[/dim]")
        raise typer.Exit(1)
