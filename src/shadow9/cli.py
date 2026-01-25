"""
Command Line Interface for Shadow9 Manager.

Provides commands for running the SOCKS5 server, managing users,
and connecting to the Tor network.

Built with Typer for automatic tab completion.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional, Annotated
from enum import Enum

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .config import Config, setup_logging, generate_master_key, generate_default_config
from .auth import AuthManager
from .socks5_server import Socks5Server, ConnectionInfo
from .tor_connector import TorConnector, TorConfig, TorStatus
from .security import (
    SecurityLevel, SecurityConfig, SecureServer,
    get_security_preset, FIREWALL_FRIENDLY_PORTS
)
from .bridges import (
    BridgeType, BridgeConfig, TorBridgeConnector,
    get_bridge_preset, print_bridge_info, PluggableTransportManager
)
from .wizards import (
    run_user_wizard, run_user_modify_wizard,
    run_user_list_wizard, display_user_info,
    run_serve_wizard, show_serve_preview,
    run_init_wizard, show_config_summary, show_master_key
)

console = Console()

# Create the main app
app = typer.Typer(
    name="shadow9",
    help="Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support",
    add_completion=True,
    rich_markup_mode="rich",
)

# Create user subcommand group
user_app = typer.Typer(help="Manage proxy users.")
app.add_typer(user_app, name="user")


# Enums for choices
class SecurityChoice(str, Enum):
    none = "none"
    basic = "basic"
    moderate = "moderate"
    paranoid = "paranoid"


class BridgeChoice(str, Enum):
    none = "none"
    obfs4 = "obfs4"
    snowflake = "snowflake"
    meek = "meek"


def version_callback(value: bool):
    if value:
        console.print("shadow9-manager version 1.0.0")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=version_callback, is_eager=True, help="Show version and exit.")] = False,
):
    """
    Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

    A security-focused SOCKS5 proxy server that supports Tor network
    connectivity for accessing .onion addresses.
    """
    pass




@app.command()
def serve(
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
    host: Annotated[Optional[str], typer.Option("--host", "-h", help="Host to bind to")] = None,
    port: Annotated[Optional[int], typer.Option("--port", "-p", help="Port to listen on")] = None,
    interactive: Annotated[bool, typer.Option("--interactive", "-i", help="Run interactive configuration")] = False,
):
    """Start the SOCKS5 proxy server.
    
    User settings control Tor routing, bridges, and security levels.
    """
    # Run interactive mode if requested or no host/port provided
    if interactive or (host is None and port is None):
        if not interactive:
            console.print("\n[dim]No host/port specified. Use -i for interactive or provide --host/--port.[/dim]")
            if not typer.confirm("Run with defaults (127.0.0.1:1080)?", default=True):
                interactive = True
        
        if interactive:
            host, port = run_serve_wizard()
            show_serve_preview(host, port)
            if not typer.confirm("\nStart server?", default=True):
                console.print("[yellow]Cancelled[/yellow]")
                raise typer.Abort()
    
    asyncio.run(_serve(config, host, port))


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

    if users_need_tor or cfg.tor.enabled:
        console.print("[cyan]Connecting to Tor network...[/cyan]")
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
                f"Exit IP: [cyan]{circuit_info.exit_ip if circuit_info else 'Unknown'}[/cyan]\n"
                f"Tor SOCKS: [cyan]{cfg.tor.socks_host}:{cfg.tor.socks_port}[/cyan]",
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
        console.print(
            f"[dim]{info.username}[/dim] -> "
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

        tor_status = "Available" if upstream_proxy else "Not connected"
        console.print(Panel(
            f"[bold green]SOCKS5 Server Running[/bold green]\n\n"
            f"Listen: [cyan]{cfg.server.host}:{cfg.server.port}[/cyan]\n"
            f"Tor: [cyan]{tor_status}[/cyan]\n"
            f"Auth: [cyan]Username/Password Required[/cyan]\n\n"
            f"[dim]Routing and security controlled by user settings.[/dim]\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
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


# ============== User Commands ==============

@user_app.command("add")
def user_add(
    username: Annotated[Optional[str], typer.Argument(help="Username for the new user")] = None,
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="User password")] = None,
    use_tor: Annotated[Optional[bool], typer.Option("--tor/--no-tor", help="Route traffic through Tor")] = None,
    bridge: Annotated[BridgeChoice, typer.Option("--bridge", "-b", help="Tor bridge type")] = BridgeChoice.none,
    security: Annotated[SecurityChoice, typer.Option("--security", "-s", help="Security/evasion level")] = SecurityChoice.basic,
    ports: Annotated[Optional[str], typer.Option("--ports", help="Comma-separated list of allowed ports")] = None,
    rate_limit: Annotated[Optional[int], typer.Option("--rate-limit", help="Max requests per minute")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Add a new user with customizable settings."""
    # If no username provided, offer to run interactive wizard
    if username is None:
        console.print("[yellow]No username provided.[/yellow]")
        run_wizard = typer.confirm("Run interactive wizard?", default=True)
        if run_wizard:
            from .user_wizard import run_user_wizard
            run_user_wizard(config)
            return
        else:
            console.print("[dim]Usage: shadow9 user add <username> [OPTIONS][/dim]")
            console.print("[dim]Or run: shadow9 user new[/dim]")
            raise typer.Exit(0)

    # Prompt for password if not provided
    if password is None:
        password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    # Prompt for Tor preference if not specified
    if use_tor is None:
        use_tor = typer.confirm(
            "Route this user's traffic through Tor? (No = direct proxy)",
            default=True
        )

    # If using bridges, Tor must be enabled
    if bridge != BridgeChoice.none and not use_tor:
        console.print("[yellow]Note: Bridges require Tor. Enabling Tor routing.[/yellow]")
        use_tor = True

    # Parse ports
    allowed_ports = None
    if ports:
        try:
            allowed_ports = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            console.print("[red]Error: Invalid port format. Use comma-separated numbers.[/red]")
            raise typer.Exit(1)

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    try:
        if auth_manager.add_user(
            username, password,
            use_tor=use_tor,
            bridge_type=bridge.value,
            security_level=security.value,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit
        ):
            routing = "Tor" if use_tor else "Direct"
            if bridge != BridgeChoice.none:
                routing += f" + {bridge.value} bridge"
            console.print(f"[green]User '{username}' added successfully[/green]")
            console.print(f"[dim]Routing: {routing}[/dim]")
            console.print(f"[dim]Security: {security.value}[/dim]")
            if allowed_ports:
                console.print(f"[dim]Allowed ports: {', '.join(map(str, allowed_ports))}[/dim]")
            if rate_limit:
                console.print(f"[dim]Rate limit: {rate_limit} req/min[/dim]")
        else:
            console.print(f"[red]User '{username}' already exists[/red]")
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@user_app.command("remove")
def user_remove(
    username: Annotated[Optional[str], typer.Argument(help="Username to remove (interactive if omitted)")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation")] = False,
    all_users: Annotated[bool, typer.Option("--all", help="Remove all users")] = False,
):
    """Remove a user (interactive menu if no username provided)."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    users = auth_manager.list_users()
    
    if not users:
        console.print("[yellow]No users configured[/yellow]")
        return

    # Handle --all flag
    if all_users:
        if not yes:
            console.print(f"[bold red]This will remove ALL {len(users)} users![/bold red]")
            confirm = typer.confirm("Are you sure?", default=False)
            if not confirm:
                raise typer.Abort()
        
        for user in users:
            auth_manager.remove_user(user)
            console.print(f"[dim]Removed: {user}[/dim]")
        console.print(f"[green]All {len(users)} users removed[/green]")
        return

    # Interactive mode if no username provided
    if username is None:
        console.print("\n[bold]Select user(s) to remove:[/bold]\n")
        
        # Show numbered list
        for i, user in enumerate(users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")
        
        console.print(f"  [cyan]A.[/cyan] [red]Remove ALL users[/red]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")
        
        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")
        
        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        if choice.upper() == "A":
            if not yes:
                console.print(f"\n[bold red]This will remove ALL {len(users)} users![/bold red]")
                confirm = typer.confirm("Are you sure?", default=False)
                if not confirm:
                    raise typer.Abort()
            
            for user in users:
                auth_manager.remove_user(user)
                console.print(f"[dim]Removed: {user}[/dim]")
            console.print(f"[green]All {len(users)} users removed[/green]")
            return
        
        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(users):
                username = users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return

    # Confirm and remove single user
    if not yes:
        confirm = typer.confirm(f"Remove user '{username}'?")
        if not confirm:
            raise typer.Abort()

    if auth_manager.remove_user(username):
        console.print(f"[green]User '{username}' removed[/green]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")




@user_app.command("list")
def user_list(
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
    interactive: Annotated[bool, typer.Option("--interactive", "-i", help="Interactive mode with actions")] = False,
):
    """List all users (use -i for interactive mode with actions)."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    users = auth_manager.list_users()

    if not users:
        console.print("[yellow]No users configured[/yellow]")
        return

    if not interactive:
        # Standard table view
        table = Table(title="Configured Users")
        table.add_column("Username", style="cyan")
        table.add_column("Routing", style="green")

        for username in users:
            use_tor = auth_manager.get_user_tor_preference(username)
            routing = "Tor" if use_tor else "Direct"
            table.add_row(username, routing)

        console.print(table)
        console.print("\n[dim]Tip: Use 'shadow9 user list -i' for interactive mode with actions[/dim]")
        return

    # Interactive mode
    run_user_list_wizard(auth_manager, config)


@user_app.command("generate")
def user_generate(
    use_tor: Annotated[Optional[bool], typer.Option("--tor/--no-tor", help="Route traffic through Tor")] = None,
    bridge: Annotated[Optional[BridgeChoice], typer.Option("--bridge", "-b", help="Tor bridge type")] = None,
    security: Annotated[Optional[SecurityChoice], typer.Option("--security", "-s", help="Security/evasion level")] = None,
    ports: Annotated[Optional[str], typer.Option("--ports", help="Comma-separated list of allowed ports")] = None,
    rate_limit: Annotated[Optional[int], typer.Option("--rate-limit", help="Max requests per minute")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Generate a random user with secure credentials."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    # Prompt for Tor preference if not specified
    if use_tor is None:
        console.print("\n[bold]Traffic Routing:[/bold]")
        console.print("  [dim]Tor provides anonymity by routing through multiple relays.[/dim]")
        console.print("  [dim]Direct mode is faster but uses your real IP.[/dim]\n")
        use_tor = typer.confirm(
            "Route traffic through Tor?",
            default=True
        )

    # Prompt for bridge if using Tor and not specified
    if use_tor and bridge is None:
        console.print("\n[bold]Tor Bridge Selection:[/bold]")
        console.print("  [dim]Bridges help bypass Tor blocking in restricted networks.[/dim]\n")
        
        console.print("  [cyan]1. none[/cyan] [green](default)[/green]")
        console.print("     Direct connection to Tor network.")
        console.print("     [dim]Best for: Unrestricted networks, fastest option[/dim]\n")
        
        console.print("  [cyan]2. obfs4[/cyan]")
        console.print("     Obfuscates traffic to look like random data.")
        console.print("     [dim]Best for: ISPs that block Tor, moderate censorship[/dim]\n")
        
        console.print("  [cyan]3. snowflake[/cyan]")
        console.print("     Routes through volunteer browser proxies via WebRTC.")
        console.print("     [dim]Best for: When obfs4 is blocked, dynamic endpoints[/dim]\n")
        
        console.print("  [cyan]4. meek-azure[/cyan]")
        console.print("     Tunnels through Microsoft Azure cloud (ajax.aspnetcdn.com).")
        console.print("     Traffic appears as normal HTTPS to Microsoft CDN.")
        console.print("     [dim]Best for: Heavily censored networks (China, Iran)[/dim]")
        console.print("     [dim]Note: Slowest option due to cloud routing overhead[/dim]\n")
        
        bridge_choice = typer.prompt("Select bridge [1-4]", default="1")
        bridge_map = {"1": BridgeChoice.none, "2": BridgeChoice.obfs4, 
                      "3": BridgeChoice.snowflake, "4": BridgeChoice.meek}
        bridge = bridge_map.get(bridge_choice, BridgeChoice.none)
    elif bridge is None:
        bridge = BridgeChoice.none

    # If using bridges, Tor must be enabled
    if bridge != BridgeChoice.none and not use_tor:
        console.print("[yellow]Note: Bridges require Tor. Enabling Tor routing.[/yellow]")
        use_tor = True

    # Prompt for security level if not specified
    if security is None:
        console.print("\n[bold]Security Level:[/bold]")
        console.print("  [dim]Controls traffic analysis evasion techniques.[/dim]\n")
        
        console.print("  [cyan]1. none[/cyan]")
        console.print("     No evasion techniques applied.")
        console.print("     [dim]Best for: Maximum speed, privacy not a concern[/dim]\n")
        
        console.print("  [cyan]2. basic[/cyan] [green](recommended)[/green]")
        console.print("     Standard headers, basic fingerprint protection.")
        console.print("     [dim]Best for: General privacy with good performance[/dim]\n")
        
        console.print("  [cyan]3. moderate[/cyan]")
        console.print("     Randomized headers, timing jitter, traffic padding.")
        console.print("     Adds random delays to mask traffic patterns.")
        console.print("     [dim]Best for: Evading DPI, corporate firewalls[/dim]\n")
        
        console.print("  [cyan]4. paranoid[/cyan]")
        console.print("     Maximum evasion: packet fragmentation, random delays,")
        console.print("     decoy traffic generation, full header randomization.")
        console.print("     [dim]Best for: High-risk environments, nation-state adversaries[/dim]")
        console.print("     [dim]Note: Significant performance impact[/dim]\n")
        
        security_choice = typer.prompt("Select level [1-4]", default="2")
        security_map = {"1": SecurityChoice.none, "2": SecurityChoice.basic,
                        "3": SecurityChoice.moderate, "4": SecurityChoice.paranoid}
        security = security_map.get(security_choice, SecurityChoice.basic)

    # Parse ports
    allowed_ports = None
    if ports:
        try:
            allowed_ports = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            console.print("[red]Error: Invalid port format. Use comma-separated numbers.[/red]")
            raise typer.Exit(1)

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    username, password = auth_manager.generate_credentials()
    routing = "Tor" if use_tor else "Direct"
    if bridge != BridgeChoice.none:
        bridge_display = "meek-azure" if bridge == BridgeChoice.meek else bridge.value
        routing += f" + {bridge_display}"

    try:
        auth_manager.add_user(
            username, password,
            use_tor=use_tor,
            bridge_type=bridge.value,
            security_level=security.value,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit
        )

        # Build info string
        info_lines = [
            f"[bold green]New user created:[/bold green]\n",
            f"Username: [cyan]{username}[/cyan]",
            f"Password: [cyan]{password}[/cyan]",
            f"Routing: [cyan]{routing}[/cyan]",
            f"Security: [cyan]{security.value}[/cyan]",
        ]
        if allowed_ports:
            info_lines.append(f"Ports: [cyan]{', '.join(map(str, allowed_ports))}[/cyan]")
        if rate_limit:
            info_lines.append(f"Rate Limit: [cyan]{rate_limit} req/min[/cyan]")
        info_lines.append("\n[yellow]Save these credentials! They won't be shown again.[/yellow]")

        console.print(Panel(
            "\n".join(info_lines),
            title="Generated Credentials",
            border_style="green"
        ))
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@user_app.command("info")
def user_info(
    username: Annotated[Optional[str], typer.Argument(help="Username to show info for (interactive if omitted)")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Show detailed information about a user."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    # Interactive mode if no username provided
    if username is None:
        users = auth_manager.list_users()
        
        if not users:
            console.print("[yellow]No users configured[/yellow]")
            raise typer.Exit(0)
        
        while True:
            console.print("\n[bold cyan]Select a user to view:[/bold cyan]\n")
            for i, user in enumerate(users, 1):
                use_tor = auth_manager.get_user_tor_preference(user)
                routing = "[green]Tor[/green]" if use_tor else "[yellow]Direct[/yellow]"
                console.print(f"  [cyan]{i}[/cyan]. {user} ({routing})")
            
            console.print(f"\n  [dim]Enter number 1-{len(users)}, or 'q' to quit[/dim]")
            
            choice = typer.prompt("  Select user", default="q")
            
            if choice.lower() == 'q':
                return
            
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(users):
                    display_user_info(auth_manager, users[idx])
                    
                    if not typer.confirm("\nView another user?", default=False):
                        return
                else:
                    console.print(f"  [red]Please enter a number between 1 and {len(users)}[/red]")
            except ValueError:
                console.print("  [red]Please enter a valid number[/red]")
    else:
        display_user_info(auth_manager, username)


@user_app.command("modify")
def user_modify(
    username: Annotated[Optional[str], typer.Argument(help="Username to modify (omit for interactive selection)")] = None,
    use_tor: Annotated[Optional[bool], typer.Option("--tor/--no-tor", help="Enable or disable Tor routing")] = None,
    bridge: Annotated[Optional[BridgeChoice], typer.Option("--bridge", "-b", help="Tor bridge type")] = None,
    enabled: Annotated[Optional[bool], typer.Option("--enable/--disable", help="Enable or disable account")] = None,
    security: Annotated[Optional[SecurityChoice], typer.Option("--security", "-s", help="Security/evasion level")] = None,
    ports: Annotated[Optional[str], typer.Option("--ports", help="Allowed ports (comma-separated or 'all')")] = None,
    rate_limit: Annotated[Optional[int], typer.Option("--rate-limit", help="Max requests per minute (0 for default)")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Modify settings for an existing user.
    
    Run without arguments for interactive mode, or specify username and flags for direct modification.
    """
    # Check if any modification flags were provided
    has_flags = any([use_tor is not None, bridge is not None, enabled is not None, 
                     security is not None, ports is not None, rate_limit is not None])
    
    # Launch interactive wizard if no username or no flags
    if username is None or (username is not None and not has_flags):
        run_user_modify_wizard(config, preselected_username=username)
        return
    
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    # Check user exists
    if username not in auth_manager.list_users():
        console.print(f"[red]User '{username}' not found[/red]")
        raise typer.Exit(1)

    changes = []

    # Update Tor preference
    if use_tor is not None:
        auth_manager.set_user_tor_preference(username, use_tor)
        routing = "Tor" if use_tor else "Direct"
        changes.append(f"Routing: {routing}")

    # Update bridge type
    if bridge is not None:
        # If setting a bridge, ensure Tor is enabled
        if bridge != BridgeChoice.none:
            current_tor = auth_manager.get_user_tor_preference(username)
            if not current_tor:
                auth_manager.set_user_tor_preference(username, True)
                changes.append("Routing: Tor (required for bridge)")
        auth_manager.set_user_bridge_type(username, bridge.value)
        changes.append(f"Bridge: {bridge.value}")

    # Update enabled status
    if enabled is not None:
        auth_manager.set_user_enabled(username, enabled)
        status = "Enabled" if enabled else "Disabled"
        changes.append(f"Status: {status}")

    # Update security level
    if security is not None:
        auth_manager.set_user_security_level(username, security.value)
        changes.append(f"Security: {security.value}")

    # Update allowed ports
    if ports is not None:
        if ports.lower() == "all":
            auth_manager.set_user_allowed_ports(username, None)
            changes.append("Ports: All (no restrictions)")
        else:
            try:
                allowed_ports = [int(p.strip()) for p in ports.split(',')]
                auth_manager.set_user_allowed_ports(username, allowed_ports)
                changes.append(f"Ports: {', '.join(map(str, allowed_ports))}")
            except ValueError:
                console.print("[red]Error: Invalid port format. Use comma-separated numbers or 'all'.[/red]")
                raise typer.Exit(1)

    # Update rate limit
    if rate_limit is not None:
        if rate_limit == 0:
            auth_manager.set_user_rate_limit(username, None)
            changes.append("Rate Limit: Server default")
        else:
            auth_manager.set_user_rate_limit(username, rate_limit)
            changes.append(f"Rate Limit: {rate_limit} req/min")

    if changes:
        console.print(f"[green]User '{username}' updated:[/green]")
        for change in changes:
            console.print(f"  - {change}")
    else:
        console.print("[yellow]No changes specified.[/yellow]")
        console.print("[dim]Options: --tor/--no-tor, --bridge, --enable/--disable, --security, --ports, --rate-limit[/dim]")


@user_app.command("enable")
def user_enable(
    username: Annotated[Optional[str], typer.Argument(help="Username to enable")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Enable a user account."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    users = auth_manager.list_users()
    if not users:
        console.print("[yellow]No users found[/yellow]")
        return

    # Get disabled users only
    disabled_users = [u for u in users if auth_manager.get_user_enabled(u) == False]

    # Interactive mode if no username provided
    if username is None:
        if not disabled_users:
            console.print("[green]All users are already enabled[/green]")
            return

        console.print("\n[bold]Select user(s) to enable:[/bold]\n")

        # Show numbered list of disabled users
        for i, user in enumerate(disabled_users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")

        console.print(f"  [cyan]A.[/cyan] [green]Enable ALL disabled users[/green]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")

        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")

        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return

        if choice.upper() == "A":
            for user in disabled_users:
                auth_manager.set_user_enabled(user, True)
                console.print(f"[dim]Enabled: {user}[/dim]")
            console.print(f"[green]All {len(disabled_users)} users enabled[/green]")
            return

        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(disabled_users):
                username = disabled_users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return

    if auth_manager.set_user_enabled(username, True):
        console.print(f"[green]User '{username}' enabled[/green]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")


@user_app.command("disable")
def user_disable(
    username: Annotated[Optional[str], typer.Argument(help="Username to disable")] = None,
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Disable a user account (prevents login)."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    users = auth_manager.list_users()
    if not users:
        console.print("[yellow]No users found[/yellow]")
        return

    # Get enabled users only
    enabled_users = [u for u in users if auth_manager.get_user_enabled(u) == True]

    # Interactive mode if no username provided
    if username is None:
        if not enabled_users:
            console.print("[yellow]All users are already disabled[/yellow]")
            return

        console.print("\n[bold]Select user(s) to disable:[/bold]\n")

        # Show numbered list of enabled users
        for i, user in enumerate(enabled_users, 1):
            use_tor = auth_manager.get_user_tor_preference(user)
            routing = "Tor" if use_tor else "Direct"
            console.print(f"  [cyan]{i}.[/cyan] {user} [dim]({routing})[/dim]")

        console.print(f"  [cyan]A.[/cyan] [red]Disable ALL enabled users[/red]")
        console.print(f"  [cyan]Q.[/cyan] Cancel\n")

        choice = typer.prompt("Enter selection (number, A for all, Q to cancel)")

        if choice.upper() == "Q":
            console.print("[yellow]Cancelled[/yellow]")
            return

        if choice.upper() == "A":
            for user in enabled_users:
                auth_manager.set_user_enabled(user, False)
                console.print(f"[dim]Disabled: {user}[/dim]")
            console.print(f"[yellow]All {len(enabled_users)} users disabled[/yellow]")
            return

        # Handle number selection
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(enabled_users):
                username = enabled_users[idx]
            else:
                console.print("[red]Invalid selection[/red]")
                return
        except ValueError:
            console.print("[red]Invalid selection[/red]")
            return

    if auth_manager.set_user_enabled(username, False):
        console.print(f"[yellow]User '{username}' disabled[/yellow]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")


@user_app.command("new")
def user_new(
    config: Annotated[str, typer.Option("--config", "-c", help="Path to configuration file")] = "config/config.yaml",
):
    """Interactive wizard to create a new user."""
    run_user_wizard(config)


# ============== Utility Commands ==============


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


@app.command()
def fetch(
    url: Annotated[str, typer.Argument(help="URL to fetch (supports .onion)")],
    tor_port: Annotated[int, typer.Option("--tor-port", "-p", help="Tor SOCKS port")] = 9050,
):
    """Fetch a URL through Tor (supports .onion)."""
    asyncio.run(_fetch(url, tor_port))


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
    from .setup import SystemSetup, run_setup, check_setup, get_manual_install_instructions

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
        "- obfs4proxy (for obfs4 bridges)\n"
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
            "You can now run:\n"
            "  [cyan]shadow9 serve[/cyan]                    # Basic proxy\n"
            "  [cyan]shadow9 serve --bridge obfs4[/cyan]     # With stealth bridges\n"
            "  [cyan]shadow9 serve --security paranoid[/cyan] # With DPI bypass",
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
    from .setup import check_setup

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
    import os
    import time

    console.print("[cyan]Updating Shadow9 Manager...[/cyan]\n")

    # Get the script directory (project root)
    script_dir = Path(__file__).parent.parent.parent

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

        # Reinstall package
        console.print("[>] Reinstalling package...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", ".", "-q"],
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


# Entry point for the CLI
def cli():
    """Main entry point."""
    app()


if __name__ == "__main__":
    cli()
