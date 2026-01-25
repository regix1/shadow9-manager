"""
Server commands for Shadow9 CLI.

Contains serve and stop commands for managing the SOCKS5 proxy server.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional, Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from ..config import Config, setup_logging
from ..auth import AuthManager
from ..socks5_server import Socks5Server, ConnectionInfo
from ..tor_connector import TorConnector, TorConfig
from ..wizards import run_serve_wizard, show_serve_preview

console = Console()


def register_server_commands(app: typer.Typer):
    """Register server commands with the main app."""
    
    @app.command()
    def serve(
        config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
        host: Annotated[Optional[str], typer.Option("--host", "-h", help="Host to bind to")] = None,
        port: Annotated[Optional[int], typer.Option("--port", "-p", help="Port to listen on")] = None,
        background: Annotated[Optional[bool], typer.Option("--background/--foreground", "-d/-f", help="Run in background or foreground")] = None,
        interactive: Annotated[bool, typer.Option("--interactive", "-i", help="Run interactive configuration")] = False,
    ):
        """Start the SOCKS5 proxy server.
        
        User settings control Tor routing, bridges, and security levels.
        """
        # Load config to get defaults
        cfg = Config.load(Path(config)) if Path(config).exists() else Config()
        
        # Use config daemon setting if not specified on command line
        run_background = background if background is not None else cfg.server.daemon
        
        # Run interactive mode if requested or no host/port provided
        if interactive or (host is None and port is None and background is None):
            if not interactive:
                console.print("\n[dim]No options specified. Use -i for interactive or provide --host/--port.[/dim]")
                if not typer.confirm("Run with defaults?", default=True):
                    interactive = True
            
            if interactive:
                host, port, run_background = run_serve_wizard()
                show_serve_preview(host, port, run_background)
                if not typer.confirm("\nStart server?", default=True):
                    console.print("[yellow]Cancelled[/yellow]")
                    raise typer.Abort()
        
        # Apply defaults from config if not set
        if host is None:
            host = cfg.server.host
        if port is None:
            port = cfg.server.port
        
        # Handle background mode
        if run_background:
            import subprocess
            
            # Build command without --background flag
            cmd = [sys.executable, "-m", "shadow9", "serve", "--foreground"]
            if config != "config/config.yaml":
                cmd.extend(["--config", config])
            cmd.extend(["--host", host])
            cmd.extend(["--port", str(port)])
            
            # Start detached process
            if sys.platform == "win32":
                # Windows: use CREATE_NEW_PROCESS_GROUP
                subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                # Unix: use nohup-style daemonization
                subprocess.Popen(
                    cmd,
                    start_new_session=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            
            console.print(f"[green]Server started in background[/green]")
            console.print(f"[dim]Listen: {host}:{port}[/dim]")
            console.print(f"[dim]To stop: shadow9 stop[/dim]")
            return
        
        asyncio.run(_serve(config, host, port))

    @app.command()
    def stop(
        port: Annotated[int, typer.Option("--port", "-p", help="Port the server is running on")] = 1080,
    ):
        """Stop a running Shadow9 server."""
        import subprocess
        
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
    master_key = None
    if cfg.auth.master_key_env:
        import os
        master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    # Check if any users exist
    if not auth_manager.list_users():
        console.print("[yellow]No users configured. Creating default user...[/yellow]")
        username, password = auth_manager.generate_credentials()
        try:
            auth_manager.add_user(username, password)
            console.print(Panel(
                f"[bold green]Default credentials created:[/bold green]\n\n"
                f"Username: [cyan]{username}[/cyan]\n"
                f"Password: [cyan]{password}[/cyan]\n\n"
                f"[yellow]Save these credentials! They won't be shown again.[/yellow]",
                title="New User Created",
                border_style="green"
            ))
        except ValueError as e:
            console.print(f"[red]Failed to create default user: {e}[/red]")
            return

    # Initialize Tor connector if any users need Tor routing
    tor_connector = None
    users_need_tor = any(
        auth_manager.get_user_tor_preference(u) 
        for u in auth_manager.list_users()
    )

    if users_need_tor:
        console.print("[cyan]Users with Tor enabled detected. Connecting to Tor...[/cyan]")
        tor_config = TorConfig(
            socks_host=cfg.tor.socks_host,
            socks_port=cfg.tor.socks_port,
            control_port=cfg.tor.control_port,
            control_password=cfg.tor.control_password,
        )
        tor_connector = TorConnector(tor_config)

        if await tor_connector.connect():
            circuit_info = tor_connector.circuit_info
            console.print(Panel(
                f"[bold green]Connected to Tor Network[/bold green]\n\n"
                f"Tor SOCKS: [cyan]{cfg.tor.socks_host}:{cfg.tor.socks_port}[/cyan]\n"
                f"Isolation: [cyan]Per-user circuits (IsolateSOCKSAuth)[/cyan]",
                title="Tor Status",
                border_style="green"
            ))
        else:
            console.print("[yellow]Warning: Could not connect to Tor network[/yellow]")
            console.print(f"[dim]{TorConnector.get_tor_install_instructions()}[/dim]")
            console.print("\n[yellow]Users with Tor routing enabled will fall back to direct.[/yellow]")
            tor_connector = None

    # Create SOCKS5 server
    upstream_proxy = None
    if tor_connector and tor_connector.is_connected:
        upstream_proxy = tor_connector.get_socks_proxy()

    server = Socks5Server(
        host=cfg.server.host,
        port=cfg.server.port,
        auth_manager=auth_manager,
        upstream_proxy=upstream_proxy,
    )

    # Connection monitoring callback
    async def on_connection(info: ConnectionInfo):
        route = "[green]Tor[/green]" if info.use_tor else "[yellow]Direct[/yellow]"
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

        tor_status = "Available (per-user circuits)" if upstream_proxy else "Not connected"
        console.print(Panel(
            f"[bold green]SOCKS5 Server Running[/bold green]\n"
            f"Listen: [cyan]{cfg.server.host}:{cfg.server.port}[/cyan]\n"
            f"Tor:    [cyan]{tor_status}[/cyan]\n"
            f"Auth:   [cyan]Username/Password[/cyan]\n\n"
            f"[dim]Each user gets isolated Tor circuit. Routing per user settings.[/dim]\n"
            f"[dim]Press Ctrl+C to stop.[/dim]",
            title="Shadow9 Manager",
            border_style="green"
        ))

        # Wait for shutdown signal
        await shutdown_event.wait()

    finally:
        await server.stop()
        if tor_connector:
            await tor_connector.disconnect()

        console.print("[green]Server stopped[/green]")
