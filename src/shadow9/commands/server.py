"""
Server commands for Shadow9 CLI.

Contains serve and stop commands for managing the SOCKS5 proxy server.
"""

import asyncio
import signal
import subprocess
import sys
import traceback
from pathlib import Path
from typing import NamedTuple, Optional, Annotated

import structlog
import typer
from rich.console import Console
from rich.panel import Panel

from ..config import Config, setup_logging
from ..auth import AuthManager, MissingMasterKey
from ..memory_budget import MemoryCeilingTooLow
from ..paths import load_master_key
from ..socks5_server import Socks5Server, ConnectionInfo
from ..tor_connector import TorConnector, TorConfig
from ..bridges import TorBridgeConnector, BridgeConfig, BridgeType
from ..wizards import run_serve_wizard, show_serve_preview

console = Console()
logger = structlog.get_logger(__name__)


def register_server_commands(app: typer.Typer) -> None:
    """Register server commands with the main app."""

    @app.command()
    def serve(
        config: Annotated[
            str, typer.Option("--config", "-c", help="Path to configuration file")
        ] = "config/config.yaml",
        host: Annotated[Optional[str], typer.Option("--host", "-h", help="Host to bind to")] = None,
        port: Annotated[
            Optional[int], typer.Option("--port", "-p", help="Port to listen on")
        ] = None,
        interactive: Annotated[
            bool, typer.Option("--interactive", "-i", help="Run interactive configuration")
        ] = False,
    ) -> None:
        """Start the SOCKS5 proxy server.

        User settings control Tor routing, bridges, and security levels.
        For background operation, use: shadow9 service install && shadow9 service start
        """
        # Config.load whether or not the file is there. It handles a missing one itself,
        # and it is also the only path that applies the SHADOW9_ environment variables, so
        # constructing Config() directly on a machine with no config.yaml left every one
        # of them silently ignored.
        cfg = Config.load(Path(config))

        # Run interactive mode if requested or no host/port provided
        if interactive or (host is None and port is None):
            if not interactive:
                console.print(
                    "\n[dim]No options specified. Use -i for interactive or provide --host/--port.[/dim]"
                )
                if not typer.confirm("Run with defaults?", default=True):
                    interactive = True

            if interactive:
                host, port = run_serve_wizard()
                show_serve_preview(host, port)
                if not typer.confirm("\nStart server?", default=True):
                    console.print("[yellow]Cancelled[/yellow]")
                    raise typer.Abort()

        # Apply defaults from config if not set
        if host is None:
            host = cfg.server.host
        if port is None:
            port = cfg.server.port

        try:
            asyncio.run(_serve(config, host, port))
        except (typer.Exit, typer.Abort):
            raise
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted[/yellow]")
        except MemoryCeilingTooLow as e:
            # Not a crash, and a traceback would bury the one thing worth reading. The
            # machine cannot hold a single password verification under the limit it was
            # given, and the message names the arithmetic and every way out of it.
            logger.error("Refusing to start", error=str(e))
            console.print(f"[red]{e}[/red]")
            raise typer.Exit(1) from e
        except Exception as e:
            # Without this the traceback goes to stderr and the unit just fails again in
            # five seconds until systemd's start limit gives up on it for good. The
            # traceback is formatted here rather than passed as exc_info because the
            # console renderer expands local variables, and the master key is one.
            logger.error(
                "Server exited with an unhandled error",
                error=str(e),
                traceback=traceback.format_exc(),
            )
            console.print(f"[red]Server failed: {e}[/red]")
            console.print("[dim]Full traceback written to the log.[/dim]")
            raise typer.Exit(1) from e

    @app.command()
    def stop(
        port: Annotated[
            int,
            typer.Option(
                "--port",
                "-p",
                help="Port to look on when neither the service nor a shadow9 process is found",
            ),
        ] = 1080,
        yes: Annotated[
            bool,
            typer.Option("--yes", "-y", help="Do not ask before stopping an unrecognised process"),
        ] = False,
    ) -> None:
        """
        Stop a running Shadow9 server.

        Looks for the server by identity first, the service unit and then shadow9's own
        process, because killing whoever happens to hold a port has stopped unrelated
        programs. The port is a last resort, and a process this cannot recognise is named
        and confirmed before anything is sent to it.
        """
        from .utils import stop_running_server

        if stop_running_server().was_running:
            console.print("[green]Server stopped[/green]")
            return

        holder = _listener_on_port(port)
        if holder is None:
            console.print(
                f"[yellow]No Shadow9 service or process found, and nothing is listening "
                f"on port {port}[/yellow]"
            )
            return

        if not holder.looks_like_shadow9:
            console.print(
                f"[yellow]Port {port} is held by PID {holder.pid} ({holder.name}), which "
                f"does not look like Shadow9.[/yellow]"
            )
            if not yes and not typer.confirm("Stop it anyway?", default=False):
                console.print("[yellow]Left it running[/yellow]")
                raise typer.Exit(1)

        if not _terminate(holder.pid):
            console.print(f"[red]Could not stop PID {holder.pid}[/red]")
            raise typer.Exit(1)
        console.print(f"[green]Stopped PID {holder.pid} ({holder.name}) on port {port}[/green]")


class PortHolder(NamedTuple):
    """The process listening on a port, and whether it looks like ours."""

    pid: int
    name: str
    looks_like_shadow9: bool


def _listener_on_port(port: int) -> PortHolder | None:
    """
    Find the process listening on exactly this port.

    The port is compared as a number rather than as text. Matching the string ":1080"
    against a netstat line also matches ":10801", which is a different service.

    Args:
        port: The TCP port to look for

    Returns:
        The listening process, or None when nothing holds the port
    """
    pid = _listening_pid(port)
    if pid is None:
        return None
    name = _process_name(pid)
    return PortHolder(pid, name, "shadow9" in name.lower() or "python" in name.lower())


def _listening_pid(port: int) -> int | None:
    """Ask the platform which process is listening on a port."""
    if sys.platform == "win32":
        try:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError):
            return None
        for line in result.stdout.splitlines():
            parts = line.split()
            # proto, local address, foreign address, state, pid
            if len(parts) < 5 or parts[3] != "LISTENING":
                continue
            _, _, local_port = parts[1].rpartition(":")
            if local_port.isdigit() and int(local_port) == port and parts[4].isdigit():
                return int(parts[4])
        return None

    try:
        result = subprocess.run(["lsof", "-t", f"-i:{port}"], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return None
    found = [entry for entry in result.stdout.split() if entry.isdigit()]
    return int(found[0]) if found else None


def _process_name(pid: int) -> str:
    """Best effort name for a pid, so the operator is told what they are about to stop."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
            )
            first = result.stdout.strip().splitlines()[:1]
            return first[0].split(",")[0].strip('"') if first else "unknown"
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unknown"


def _terminate(pid: int) -> bool:
    """Ask a process to stop, and say whether the request was accepted."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True
            )
        else:
            result = subprocess.run(["kill", str(pid)], capture_output=True, text=True)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


async def _serve(config_path: str, host: Optional[str], port: Optional[int]) -> None:
    """Async implementation of serve command."""
    config_file = Path(config_path)

    server: Optional[Socks5Server] = None
    # Tracked from the start so the cleanup below runs whatever startup step failed
    tor_connectors: list[TorConnector] = []
    bridge_connectors: list[TorBridgeConnector] = []

    try:
        # Load or create configuration. Config.load is called either way: it already
        # handles a missing file, and it is the only path that applies the SHADOW9_
        # environment variables. Constructing Config() directly here meant that on a host
        # with no config.yaml, SHADOW9_AUTH_MAX_CONCURRENT_AUTH, SHADOW9_HOST,
        # SHADOW9_PORT, SHADOW9_TOR_ENABLED, SHADOW9_TOR_PORT and SHADOW9_LOG_LEVEL were
        # all read by nobody, and the proxy sized its own password hashing while an
        # operator believed they had capped it.
        if not config_file.exists():
            console.print("[yellow]No config file found, using defaults[/yellow]")
        cfg = Config.load(config_file)

        # Apply CLI overrides
        if host:
            cfg.server.host = host
        if port:
            cfg.server.port = port

        # Setup logging
        setup_logging(cfg.log)

        # Initialize authentication. Built here rather than through commands.user.open_store
        # because AuthManager and load_master_key are substituted on this module by name to
        # drive _serve without a real store, and reaching them through another module's
        # namespace would step around that.
        master_key = load_master_key()

        try:
            auth_manager = AuthManager(
                credentials_file=cfg.get_credentials_file(),
                master_key=master_key,
                tunnel_network=cfg.wireguard.tunnel_network,
            )
        except MissingMasterKey as missing:
            console.print(f"[red]{missing}[/red]")
            console.print(
                "[dim]The proxy checks every login against that store, so it will not "
                "start without the key that reads it.[/dim]"
            )
            raise typer.Exit(1) from missing

        # Check if any users exist
        if not auth_manager.list_users():
            console.print("[red]No users configured.[/red]")
            console.print("\nCreate a user first:")
            console.print("  [cyan]shadow9 user generate[/cyan]")
            return

        # Group users by bridge type (only those needing Tor)
        users = auth_manager.list_users()
        bridge_type_users: dict[str, list[str]] = {}
        direct_users: list[str] = []

        for username in users:
            if auth_manager.get_user_tor_preference(username):
                bridge_type = auth_manager.get_user_bridge_type(username) or "none"
                if bridge_type not in bridge_type_users:
                    bridge_type_users[bridge_type] = []
                bridge_type_users[bridge_type].append(username)
            else:
                direct_users.append(username)

        # Mapping of bridge_type -> (socks_host, socks_port)
        upstream_proxies: dict[str, tuple[str, int]] = {}
        default_proxy: Optional[tuple[str, int]] = None

        # Start Tor instances for each bridge type in use
        if bridge_type_users:
            console.print("[cyan]Starting Tor instances for configured bridge types...[/cyan]")

            for bridge_type, usernames in bridge_type_users.items():
                console.print(f"\n[dim]Bridge type '{bridge_type}': {', '.join(usernames)}[/dim]")

                if bridge_type == "none":
                    # Use system Tor (TorConnector)
                    tor_config = TorConfig(
                        socks_host=cfg.tor.socks_host,
                        socks_port=cfg.tor.socks_port,
                        control_port=cfg.tor.control_port,
                        control_password=cfg.tor.control_password,
                        retry_attempts=cfg.tor.retry_attempts,
                        retry_delay=cfg.tor.retry_delay,
                    )
                    tor_connector = TorConnector(tor_config)

                    if await tor_connector.connect():
                        proxy = tor_connector.get_socks_proxy()
                        upstream_proxies["none"] = proxy
                        default_proxy = proxy  # Use as default for backward compatibility
                        tor_connectors.append(tor_connector)
                        console.print(f"  [green]✓[/green] System Tor: {proxy[0]}:{proxy[1]}")
                    else:
                        console.print("  [red]✗[/red] Failed to connect to system Tor")
                        console.print(
                            f"    [dim]{TorConnector.get_tor_install_instructions()}[/dim]"
                        )
                else:
                    # Use bridge connector (starts separate Tor process)
                    try:
                        bridge_enum = BridgeType(bridge_type)
                    except ValueError:
                        console.print(f"  [red]✗[/red] Unknown bridge type: {bridge_type}")
                        continue

                    # Allocate unique port for each bridge type (starting from 9051)
                    bridge_socks_port = 9051 + len(bridge_connectors)

                    bridge_config = BridgeConfig(
                        enabled=True,
                        bridge_type=bridge_enum,
                        use_builtin_bridges=True,
                    )
                    bridge_connector = TorBridgeConnector(
                        bridge_config, socks_port=bridge_socks_port
                    )

                    try:
                        socks_host, socks_port = await bridge_connector.start_tor_with_bridges()
                        upstream_proxies[bridge_type] = (socks_host, socks_port)
                        bridge_connectors.append(bridge_connector)
                        console.print(
                            f"  [green]✓[/green] {bridge_type}: {socks_host}:{socks_port}"
                        )
                    except Exception as e:
                        console.print(f"  [red]✗[/red] Failed to start {bridge_type}: {e}")
                        # A bootstrap that times out on a censored network still leaves
                        # the Tor process running and its SOCKS port bound. The connector
                        # was never recorded, so the cleanup at the end of _serve does not
                        # see it and the next serve tries to bind the same number again.
                        try:
                            await bridge_connector.stop()
                        except Exception as stop_error:
                            console.print(
                                f"  [dim]Could not stop the {bridge_type} Tor process: "
                                f"{stop_error}[/dim]"
                            )

            if upstream_proxies:
                console.print(
                    Panel(
                        "[bold green]Tor Instances Running[/bold green]\n\n"
                        + "\n".join(
                            [
                                f"[cyan]{bt}[/cyan]: {h}:{p}"
                                for bt, (h, p) in upstream_proxies.items()
                            ]
                        )
                        + "\n\n[dim]Each user routes through their configured bridge type[/dim]",
                        title="Tor Status",
                        border_style="green",
                    )
                )
            else:
                console.print(
                    "\n[yellow]Warning: No Tor instances available - Tor users will fail![/yellow]"
                )

        # Calculate base port for dynamic bridge creation (after static bridges)
        # Static bridges start at 9051, so dynamic ones start after them
        dynamic_bridge_base_port = 9051 + len(bridge_connectors) + 10  # +10 buffer

        # Create SOCKS5 server with per-bridge proxies and dynamic creation support
        server = Socks5Server(
            host=cfg.server.host,
            port=cfg.server.port,
            auth_manager=auth_manager,
            upstream_proxy=default_proxy,
            upstream_proxies=upstream_proxies,
            bridge_base_port=dynamic_bridge_base_port,
            max_connections=cfg.server.max_connections,
            max_concurrent_auth=cfg.auth.max_concurrent_auth,
            block_private_ranges=cfg.security.block_private_ranges,
            allow_localhost=cfg.security.allow_localhost,
            blocked_hosts=cfg.security.blocked_hosts,
            max_failed_attempts=cfg.auth.max_failed_attempts,
            lockout_duration_minutes=cfg.auth.lockout_duration_minutes,
            rate_limit_per_minute=cfg.security.rate_limit_per_minute,
        )

        # Connection monitoring callback
        async def on_connection(info: ConnectionInfo) -> None:
            # Respect user's logging preference
            if info.username:
                logging_enabled = auth_manager.get_user_logging_enabled(info.username)
                if logging_enabled is False:
                    return  # Skip logging for users with logging disabled

            if info.use_tor:
                bridge = info.bridge_type or "none"
                route = f"[green]Tor/{bridge}[/green]"
            else:
                route = "[yellow]Direct[/yellow]"
            console.print(
                f"[dim]{info.username}[/dim] ({route}) -> "
                f"[cyan]{info.target_addr}:{info.target_port}[/cyan]"
            )

        server.set_connection_callback(on_connection)

        # Handle shutdown gracefully
        shutdown_event = asyncio.Event()

        def signal_handler() -> None:
            console.print("\n[yellow]Shutting down...[/yellow]")
            shutdown_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                # Windows has no add_signal_handler, and the handler there runs on its own
                # thread, so hand the wakeup back to the loop instead of touching the
                # Event directly.
                signal.signal(sig, lambda s, f: loop.call_soon_threadsafe(signal_handler))

        # Start server
        await server.start()

        # Start user-specific listeners for users with custom bind ports
        custom_port_users = auth_manager.get_users_with_custom_ports()
        user_listener_lines = []

        for username, bind_port in custom_port_users.items():
            if bind_port == cfg.server.port:
                console.print(
                    f"[yellow]Warning: {username}'s bind port {bind_port} conflicts with main port, skipping[/yellow]"
                )
                continue

            success = await server.start_user_listener(username, bind_port)
            if success:
                user_listener_lines.append(f"  [cyan]:{bind_port}[/cyan] -> [dim]{username}[/dim]")
            else:
                console.print(
                    f"[yellow]Warning: Failed to start listener for {username} on port {bind_port}[/yellow]"
                )

        # Build user routing summary with bridge types
        routing_lines = []
        for bridge_type, usernames in bridge_type_users.items():
            bridge_label = f"Tor/{bridge_type}" if bridge_type != "none" else "Tor"
            available = bridge_type in upstream_proxies
            color = "green" if available else "red"
            status = "" if available else " (unavailable)"
            routing_lines.append(
                f"[{color}]{bridge_label}[/{color}]: {', '.join(usernames)}{status}"
            )

        if direct_users:
            routing_lines.append(f"[yellow]Direct[/yellow]: {', '.join(direct_users)}")

        routing_summary = (
            "\n".join(routing_lines) if routing_lines else "[dim]No users configured[/dim]"
        )

        # DPI protection note
        bridge_types_active = [
            bt for bt in bridge_type_users.keys() if bt in upstream_proxies and bt != "none"
        ]
        if bridge_types_active:
            dpi_note = f"\n[dim]DPI protection active: {', '.join(bridge_types_active)}[/dim]"
        else:
            dpi_note = ""

        # User-specific ports section
        if user_listener_lines:
            port_section = "\n\n[bold]Per-User Ports:[/bold]\n" + "\n".join(user_listener_lines)
        else:
            port_section = ""

        console.print(
            Panel(
                f"[bold green]SOCKS5 Server Running[/bold green]\n"
                f"Listen: [cyan]{cfg.server.host}:{cfg.server.port}[/cyan] (shared)\n"
                f"Auth:   [cyan]Username/Password[/cyan]\n\n"
                f"[bold]User Routing:[/bold]\n{routing_summary}{dpi_note}{port_section}\n\n"
                f"[dim]Press Ctrl+C to stop.[/dim]",
                title="Shadow9 Manager",
                border_style="green",
            )
        )

        # Wait for shutdown signal
        await shutdown_event.wait()

    finally:
        # Reached however startup ended, so every resource that did get created is
        # released even when a later step raised.
        if server is not None:
            await server.stop()

        # Stop all Tor connectors
        for connector in tor_connectors:
            await connector.disconnect()

        # Stop all bridge connectors
        for connector in bridge_connectors:
            await connector.stop()

        if server is not None:
            console.print("[green]Server stopped[/green]")
