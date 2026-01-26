"""
Server commands for Shadow9 CLI.

Contains serve and stop commands for managing the SOCKS5 proxy server.
"""

import asyncio
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional, Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from ..config import Config, setup_logging
from ..auth import AuthManager
from ..paths import load_master_key
from ..socks5_server import Socks5Server, ConnectionInfo
from ..tor_connector import TorConnector, TorConfig
from ..bridges import TorBridgeConnector, BridgeConfig, BridgeType
from ..wizards import run_serve_wizard, show_serve_preview

console = Console()


def register_server_commands(app: typer.Typer):
    """Register server commands with the main app."""

    @app.command()
    def serve(
        config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
        host: Annotated[Optional[str], typer.Option("--host", "-h", help="Host to bind to")] = None,
        port: Annotated[Optional[int], typer.Option("--port", "-p", help="Port to listen on")] = None,
        interactive: Annotated[bool, typer.Option("--interactive", "-i", help="Run interactive configuration")] = False,
    ):
        """Start the SOCKS5 proxy server.

        User settings control Tor routing, bridges, and security levels.
        For background operation, use: shadow9 service install && shadow9 service start
        """
        # Load config to get defaults
        cfg = Config.load(Path(config)) if Path(config).exists() else Config()

        # Run interactive mode if requested or no host/port provided
        if interactive or (host is None and port is None):
            if not interactive:
                console.print("\n[dim]No options specified. Use -i for interactive or provide --host/--port.[/dim]")
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

        asyncio.run(_serve(config, host, port))

    @app.command()
    def stop(
        port: Annotated[int, typer.Option("--port", "-p", help="Port the server is running on")] = 1080,
    ):
        """Stop a running Shadow9 server."""
        if sys.platform == "win32":
            # Windows: find and kill process by port
            try:
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True
                )
                for line in result.stdout.splitlines():
                    if f":{port}" in line and "LISTENING" in line:
                        parts = line.split()
                        pid = parts[-1]
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)
                        console.print(f"[green]Stopped server on port {port} (PID {pid})[/green]")
                        return
                console.print(f"[yellow]No server found on port {port}[/yellow]")
            except Exception as e:
                console.print(f"[red]Error stopping server: {e}[/red]")
        else:
            # Unix: use lsof/fuser to find and kill
            try:
                result = subprocess.run(
                    ["lsof", "-t", f"-i:{port}"],
                    capture_output=True,
                    text=True
                )
                if result.stdout.strip():
                    pid = result.stdout.strip().split()[0]
                    subprocess.run(["kill", pid])
                    console.print(f"[green]Stopped server on port {port} (PID {pid})[/green]")
                else:
                    console.print(f"[yellow]No server found on port {port}[/yellow]")
            except FileNotFoundError:
                # lsof not available, try fuser
                try:
                    subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True)
                    console.print(f"[green]Stopped server on port {port}[/green]")
                except Exception as e:
                    console.print(f"[red]Error stopping server: {e}[/red]")


async def _serve(config_path: str, host: Optional[str], port: Optional[int]):
    """Async implementation of serve command."""
    config_file = Path(config_path)

    # Load or create configuration
    if config_file.exists():
        cfg = Config.load(config_file)
    else:
        console.print("[yellow]No config file found, using defaults[/yellow]")
        cfg = Config()

    # Apply CLI overrides
    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port

    # Setup logging
    setup_logging(cfg.log)

    # Initialize authentication
    master_key = load_master_key()

    auth_manager = AuthManager(
        credentials_file=cfg.get_credentials_file(),
        master_key=master_key
    )

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

    # Track all Tor connectors for cleanup
    tor_connectors: list[TorConnector] = []
    bridge_connectors: list[TorBridgeConnector] = []
    
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
                    console.print(f"    [dim]{TorConnector.get_tor_install_instructions()}[/dim]")
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
                bridge_connector = TorBridgeConnector(bridge_config, socks_port=bridge_socks_port)
                
                try:
                    socks_host, socks_port = await bridge_connector.start_tor_with_bridges()
                    upstream_proxies[bridge_type] = (socks_host, socks_port)
                    bridge_connectors.append(bridge_connector)
                    console.print(f"  [green]✓[/green] {bridge_type}: {socks_host}:{socks_port}")
                except Exception as e:
                    console.print(f"  [red]✗[/red] Failed to start {bridge_type}: {e}")
        
        if upstream_proxies:
            console.print(Panel(
                "[bold green]Tor Instances Running[/bold green]\n\n" +
                "\n".join([
                    f"[cyan]{bt}[/cyan]: {h}:{p}" 
                    for bt, (h, p) in upstream_proxies.items()
                ]) +
                "\n\n[dim]Each user routes through their configured bridge type[/dim]",
                title="Tor Status",
                border_style="green"
            ))
        else:
            console.print("\n[yellow]Warning: No Tor instances available - Tor users will fail![/yellow]")

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
    )

    # Connection monitoring callback
    async def on_connection(info: ConnectionInfo):
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

    def signal_handler():
        console.print("\n[yellow]Shutting down...[/yellow]")
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda s, f: signal_handler())

    # Start server
    try:
        await server.start()

        # Start user-specific listeners for users with custom bind ports
        custom_port_users = auth_manager.get_users_with_custom_ports()
        user_listener_lines = []
        
        for username, bind_port in custom_port_users.items():
            if bind_port == cfg.server.port:
                console.print(f"[yellow]Warning: {username}'s bind port {bind_port} conflicts with main port, skipping[/yellow]")
                continue
            
            success = await server.start_user_listener(username, bind_port)
            if success:
                user_listener_lines.append(f"  [cyan]:{bind_port}[/cyan] -> [dim]{username}[/dim]")
            else:
                console.print(f"[yellow]Warning: Failed to start listener for {username} on port {bind_port}[/yellow]")

        # Build user routing summary with bridge types
        routing_lines = []
        for bridge_type, usernames in bridge_type_users.items():
            bridge_label = f"Tor/{bridge_type}" if bridge_type != "none" else "Tor"
            available = bridge_type in upstream_proxies
            color = "green" if available else "red"
            status = "" if available else " (unavailable)"
            routing_lines.append(f"[{color}]{bridge_label}[/{color}]: {', '.join(usernames)}{status}")
        
        if direct_users:
            routing_lines.append(f"[yellow]Direct[/yellow]: {', '.join(direct_users)}")
        
        routing_summary = "\n".join(routing_lines) if routing_lines else "[dim]No users configured[/dim]"
        
        # DPI protection note
        bridge_types_active = [bt for bt in bridge_type_users.keys() if bt in upstream_proxies and bt != "none"]
        if bridge_types_active:
            dpi_note = f"\n[dim]DPI protection active: {', '.join(bridge_types_active)}[/dim]"
        else:
            dpi_note = ""
        
        # User-specific ports section
        if user_listener_lines:
            port_section = "\n\n[bold]Per-User Ports:[/bold]\n" + "\n".join(user_listener_lines)
        else:
            port_section = ""
        
        console.print(Panel(
            f"[bold green]SOCKS5 Server Running[/bold green]\n"
            f"Listen: [cyan]{cfg.server.host}:{cfg.server.port}[/cyan] (shared)\n"
            f"Auth:   [cyan]Username/Password[/cyan]\n\n"
            f"[bold]User Routing:[/bold]\n{routing_summary}{dpi_note}{port_section}\n\n"
            f"[dim]Press Ctrl+C to stop.[/dim]",
            title="Shadow9 Manager",
            border_style="green"
        ))

        # Wait for shutdown signal
        await shutdown_event.wait()

    finally:
        await server.stop()
        
        # Stop all Tor connectors
        for connector in tor_connectors:
            await connector.disconnect()
        
        # Stop all bridge connectors
        for connector in bridge_connectors:
            await connector.stop()

        console.print("[green]Server stopped[/green]")
