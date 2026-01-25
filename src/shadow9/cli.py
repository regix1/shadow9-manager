"""
Command Line Interface for Shadow9 Manager.

Provides commands for running the SOCKS5 server, managing users,
and connecting to the Tor network.
"""

import asyncio
import signal
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

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

console = Console()


def async_command(f):
    """Decorator to run async commands."""
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapper


@click.group()
@click.version_option(version="1.0.0", prog_name="shadow9-manager")
def main():
    """
    Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

    A security-focused SOCKS5 proxy server that supports Tor network
    connectivity for accessing .onion addresses.
    """
    pass


@main.command()
@click.option('--config', '-c', type=click.Path(exists=False), default='config/config.yaml',
              help='Path to configuration file')
@click.option('--host', '-h', default=None, help='Host to bind to')
@click.option('--port', '-p', type=int, default=None, help='Port to listen on')
@click.option('--tor/--no-tor', default=True, help='Enable/disable Tor routing')
@click.option('--tor-port', type=int, default=None, help='Tor SOCKS port (default: 9050)')
@click.option('--security', '-s', type=click.Choice(['none', 'basic', 'moderate', 'paranoid']),
              default='none', help='Security/evasion level for firewall bypass')
@click.option('--bridge', '-b', type=click.Choice(['none', 'obfs4', 'snowflake', 'meek']),
              default='none', help='Tor bridge type for stealth (hides Tor usage from server ISP)')
def serve(config: str, host: Optional[str], port: Optional[int],
          tor: bool, tor_port: Optional[int], security: str, bridge: str):
    """Start the SOCKS5 proxy server."""
    asyncio.run(_serve(config, host, port, tor, tor_port, security, bridge))


async def _serve(config_path: str, host: Optional[str], port: Optional[int],
                 enable_tor: bool, tor_port: Optional[int], security: str = "none",
                 bridge: str = "none"):
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
    if tor_port:
        cfg.tor.socks_port = tor_port
    cfg.tor.enabled = enable_tor

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

    # Initialize Tor connector if enabled
    tor_connector = None
    bridge_connector = None
    bridge_type = BridgeType(bridge) if bridge != "none" else BridgeType.NONE

    if cfg.tor.enabled:
        # Check if using bridges for stealth Tor connection
        if bridge_type != BridgeType.NONE:
            console.print(f"[cyan]Initializing Tor with {bridge_type.value} bridges...[/cyan]")

            bridge_config = get_bridge_preset(bridge_type)
            console.print(Panel(
                print_bridge_info(bridge_config),
                title="Bridge Configuration",
                border_style="cyan"
            ))

            # Check if pluggable transport is available
            pt_manager = PluggableTransportManager(bridge_config)
            transports = pt_manager.detect_transports()

            if bridge_type not in transports:
                console.print(f"[red]Pluggable transport '{bridge_type.value}' not found![/red]")
                console.print(f"[dim]{pt_manager.get_install_instructions()}[/dim]")
                console.print("\n[yellow]Falling back to direct Tor connection...[/yellow]")
                bridge_type = BridgeType.NONE
            else:
                console.print(f"[green]Found {bridge_type.value}: {transports[bridge_type]}[/green]")
                bridge_connector = TorBridgeConnector(bridge_config)

                try:
                    socks_host, socks_port = await bridge_connector.start_tor_with_bridges()
                    cfg.tor.socks_host = socks_host
                    cfg.tor.socks_port = socks_port
                    console.print(Panel(
                        f"[bold green]Tor with Bridges Started[/bold green]\n\n"
                        f"Bridge Type: [cyan]{bridge_type.value}[/cyan]\n"
                        f"SOCKS: [cyan]{socks_host}:{socks_port}[/cyan]\n\n"
                        f"[dim]Your Tor connection is now hidden from network observers[/dim]",
                        title="Stealth Tor",
                        border_style="green"
                    ))
                except Exception as e:
                    console.print(f"[red]Failed to start Tor with bridges: {e}[/red]")
                    console.print("\n[yellow]Falling back to direct Tor connection...[/yellow]")
                    bridge_connector = None
                    bridge_type = BridgeType.NONE

        # Connect to Tor (either with bridges already started, or direct)
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
            stealth_info = f"\nBridge: [cyan]{bridge_type.value}[/cyan]" if bridge_type != BridgeType.NONE else ""
            console.print(Panel(
                f"[bold green]Connected to Tor Network[/bold green]\n\n"
                f"Exit IP: [cyan]{circuit_info.exit_ip if circuit_info else 'Unknown'}[/cyan]\n"
                f"Tor SOCKS: [cyan]{cfg.tor.socks_host}:{cfg.tor.socks_port}[/cyan]"
                f"{stealth_info}",
                title="Tor Status",
                border_style="green"
            ))
        else:
            console.print("[yellow]Warning: Could not connect to Tor network[/yellow]")
            console.print(f"[dim]{TorConnector.get_tor_install_instructions()}[/dim]")
            console.print("\n[yellow]Starting without Tor support...[/yellow]")
            tor_connector = None
            if bridge_connector:
                await bridge_connector.stop()
                bridge_connector = None

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

    # Apply security settings
    security_level = SecurityLevel(security)
    security_config = get_security_preset(security_level)

    # Wrap with secure server if security is enabled
    if security_level != SecurityLevel.NONE:
        from .security import SecureServer, print_security_info
        secure_server = SecureServer(server, security_config)
        console.print(Panel(
            print_security_info(security_config),
            title="Security Configuration",
            border_style="cyan"
        ))

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
        # Use secure server if security is enabled
        if security_level != SecurityLevel.NONE:
            await secure_server.start()
        else:
            await server.start()

        security_info = f"Security: [cyan]{security_level.value.upper()}[/cyan]\n" if security_level != SecurityLevel.NONE else ""

        console.print(Panel(
            f"[bold green]SOCKS5 Server Running[/bold green]\n\n"
            f"Listen: [cyan]{cfg.server.host}:{cfg.server.port}[/cyan]\n"
            f"Tor Routing: [cyan]{'Enabled' if upstream_proxy else 'Disabled'}[/cyan]\n"
            f"{security_info}"
            f"Auth: [cyan]Username/Password Required[/cyan]\n\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            title="Shadow9 Manager",
            border_style="green"
        ))

        # Wait for shutdown signal
        await shutdown_event.wait()

    finally:
        if security_level != SecurityLevel.NONE:
            await secure_server.stop()
        else:
            await server.stop()
        if tor_connector:
            await tor_connector.disconnect()
        if bridge_connector:
            await bridge_connector.stop()

        console.print("[green]Server stopped[/green]")


@main.group()
def user():
    """Manage proxy users."""
    pass


@user.command('add')
@click.argument('username')
@click.option('--password', '-p', prompt=True, hide_input=True,
              confirmation_prompt=True, help='User password')
@click.option('--tor/--no-tor', 'use_tor', default=None,
              help='Route traffic through Tor (prompts if not specified)')
@click.option('--bridge', '-b', type=click.Choice(['none', 'obfs4', 'snowflake', 'meek']),
              default='none', help='Tor bridge type (hides Tor usage from ISP)')
@click.option('--security', '-s', type=click.Choice(['none', 'basic', 'moderate', 'paranoid']),
              default='basic', help='Security/evasion level for this user')
@click.option('--ports', help='Comma-separated list of allowed ports (e.g., "80,443,8080")')
@click.option('--rate-limit', type=int, help='Max requests per minute for this user')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_add(username: str, password: str, use_tor: Optional[bool], bridge: str,
             security: str, ports: Optional[str], rate_limit: Optional[int], config: str):
    """Add a new user with customizable settings."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    # Prompt for Tor preference if not specified
    if use_tor is None:
        use_tor = click.confirm(
            "Route this user's traffic through Tor? (No = direct proxy)",
            default=True
        )

    # If using bridges, Tor must be enabled
    if bridge != "none" and not use_tor:
        console.print("[yellow]Note: Bridges require Tor. Enabling Tor routing.[/yellow]")
        use_tor = True

    # Parse ports
    allowed_ports = None
    if ports:
        try:
            allowed_ports = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            console.print("[red]Error: Invalid port format. Use comma-separated numbers.[/red]")
            return

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
            bridge_type=bridge,
            security_level=security,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit
        ):
            routing = "Tor" if use_tor else "Direct"
            if bridge != "none":
                routing += f" + {bridge} bridge"
            console.print(f"[green]User '{username}' added successfully[/green]")
            console.print(f"[dim]Routing: {routing}[/dim]")
            console.print(f"[dim]Security: {security}[/dim]")
            if allowed_ports:
                console.print(f"[dim]Allowed ports: {', '.join(map(str, allowed_ports))}[/dim]")
            if rate_limit:
                console.print(f"[dim]Rate limit: {rate_limit} req/min[/dim]")
        else:
            console.print(f"[red]User '{username}' already exists[/red]")
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")


@user.command('remove')
@click.argument('username')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
@click.confirmation_option(prompt='Are you sure you want to remove this user?')
def user_remove(username: str, config: str):
    """Remove a user."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    if auth_manager.remove_user(username):
        console.print(f"[green]User '{username}' removed[/green]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")


@user.command('list')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_list(config: str):
    """List all users."""
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

    table = Table(title="Configured Users")
    table.add_column("Username", style="cyan")
    table.add_column("Routing", style="green")

    for username in users:
        use_tor = auth_manager.get_user_tor_preference(username)
        routing = "Tor" if use_tor else "Direct"
        table.add_row(username, routing)

    console.print(table)


@user.command('generate')
@click.option('--tor/--no-tor', 'use_tor', default=None,
              help='Route traffic through Tor (prompts if not specified)')
@click.option('--bridge', '-b', type=click.Choice(['none', 'obfs4', 'snowflake', 'meek']),
              default='none', help='Tor bridge type (hides Tor usage from ISP)')
@click.option('--security', '-s', type=click.Choice(['none', 'basic', 'moderate', 'paranoid']),
              default='basic', help='Security/evasion level for this user')
@click.option('--ports', help='Comma-separated list of allowed ports (e.g., "80,443,8080")')
@click.option('--rate-limit', type=int, help='Max requests per minute for this user')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_generate(use_tor: Optional[bool], bridge: str, security: str, ports: Optional[str],
                  rate_limit: Optional[int], config: str):
    """Generate a random user with secure credentials."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    # Prompt for Tor preference if not specified
    if use_tor is None:
        use_tor = click.confirm(
            "Route this user's traffic through Tor? (No = direct proxy)",
            default=True
        )

    # If using bridges, Tor must be enabled
    if bridge != "none" and not use_tor:
        console.print("[yellow]Note: Bridges require Tor. Enabling Tor routing.[/yellow]")
        use_tor = True

    # Parse ports
    allowed_ports = None
    if ports:
        try:
            allowed_ports = [int(p.strip()) for p in ports.split(',')]
        except ValueError:
            console.print("[red]Error: Invalid port format. Use comma-separated numbers.[/red]")
            return

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    username, password = auth_manager.generate_credentials()
    routing = "Tor" if use_tor else "Direct"
    if bridge != "none":
        routing += f" + {bridge}"

    try:
        auth_manager.add_user(
            username, password,
            use_tor=use_tor,
            bridge_type=bridge,
            security_level=security,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit
        )
        
        # Build info string
        info_lines = [
            f"[bold green]New user created:[/bold green]\n",
            f"Username: [cyan]{username}[/cyan]",
            f"Password: [cyan]{password}[/cyan]",
            f"Routing: [cyan]{routing}[/cyan]",
            f"Security: [cyan]{security}[/cyan]",
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


@user.command('info')
@click.argument('username')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_info(username: str, config: str):
    """Show detailed information about a user."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    info = auth_manager.get_user_info(username)

    if not info:
        console.print(f"[red]User '{username}' not found[/red]")
        return

    table = Table(title=f"User: {username}")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Username", info["username"])
    table.add_row("Status", "[green]Enabled[/green]" if info["enabled"] else "[red]Disabled[/red]")
    
    # Display routing with bridge info
    routing = "Tor" if info["use_tor"] else "Direct"
    bridge = info.get("bridge_type", "none")
    if bridge != "none":
        routing += f" + {bridge} bridge"
    table.add_row("Routing", routing)
    
    table.add_row("Security", info.get("security_level", "basic").upper())
    
    # Display allowed ports
    allowed_ports = info.get("allowed_ports")
    if allowed_ports:
        table.add_row("Allowed Ports", ", ".join(map(str, allowed_ports)))
    else:
        table.add_row("Allowed Ports", "All (no restrictions)")
    
    # Display rate limit
    rate_limit = info.get("rate_limit")
    if rate_limit:
        table.add_row("Rate Limit", f"{rate_limit} req/min")
    else:
        table.add_row("Rate Limit", "Server default")
    
    table.add_row("Created", info["created_at"] or "Unknown")
    table.add_row("Last Used", info["last_used"] or "Never")

    console.print(table)


@user.command('modify')
@click.argument('username')
@click.option('--tor/--no-tor', 'use_tor', default=None,
              help='Enable or disable Tor routing for this user')
@click.option('--bridge', '-b', type=click.Choice(['none', 'obfs4', 'snowflake', 'meek']),
              default=None, help='Tor bridge type (hides Tor usage from ISP)')
@click.option('--enable/--disable', 'enabled', default=None,
              help='Enable or disable this user account')
@click.option('--security', '-s', type=click.Choice(['none', 'basic', 'moderate', 'paranoid']),
              default=None, help='Security/evasion level for this user')
@click.option('--ports', help='Comma-separated list of allowed ports, or "all" for no restrictions')
@click.option('--rate-limit', type=int, help='Max requests per minute (0 for server default)')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_modify(username: str, use_tor: Optional[bool], bridge: Optional[str],
                enabled: Optional[bool], security: Optional[str], ports: Optional[str],
                rate_limit: Optional[int], config: str):
    """Modify settings for an existing user."""
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
        return

    changes = []

    # Update Tor preference
    if use_tor is not None:
        auth_manager.set_user_tor_preference(username, use_tor)
        routing = "Tor" if use_tor else "Direct"
        changes.append(f"Routing: {routing}")

    # Update bridge type
    if bridge is not None:
        # If setting a bridge, ensure Tor is enabled
        if bridge != "none":
            current_tor = auth_manager.get_user_tor_preference(username)
            if not current_tor:
                auth_manager.set_user_tor_preference(username, True)
                changes.append("Routing: Tor (required for bridge)")
        auth_manager.set_user_bridge_type(username, bridge)
        changes.append(f"Bridge: {bridge}")

    # Update enabled status
    if enabled is not None:
        auth_manager.set_user_enabled(username, enabled)
        status = "Enabled" if enabled else "Disabled"
        changes.append(f"Status: {status}")

    # Update security level
    if security is not None:
        auth_manager.set_user_security_level(username, security)
        changes.append(f"Security: {security}")

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
                return

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


@user.command('enable')
@click.argument('username')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_enable(username: str, config: str):
    """Enable a user account."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    if auth_manager.set_user_enabled(username, True):
        console.print(f"[green]User '{username}' enabled[/green]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")


@user.command('disable')
@click.argument('username')
@click.option('--config', '-c', type=click.Path(), default='config/config.yaml',
              help='Path to configuration file')
def user_disable(username: str, config: str):
    """Disable a user account (prevents login)."""
    cfg = Config.load(Path(config)) if Path(config).exists() else Config()

    import os
    master_key = os.getenv(cfg.auth.master_key_env)

    auth_manager = AuthManager(
        credentials_file=Path(cfg.auth.credentials_file),
        master_key=master_key
    )

    if auth_manager.set_user_enabled(username, False):
        console.print(f"[yellow]User '{username}' disabled[/yellow]")
    else:
        console.print(f"[red]User '{username}' not found[/red]")


@main.command()
@click.option('--output', '-o', type=click.Path(), default='config/config.yaml',
              help='Output path for configuration file')
def init(output: str):
    """Initialize a new configuration file."""
    output_path = Path(output)

    if output_path.exists():
        if not click.confirm(f"Configuration file {output} already exists. Overwrite?"):
            return

    generate_default_config(output_path)
    console.print(f"[green]Configuration file created: {output}[/green]")

    # Also generate a master key
    key = generate_master_key()
    console.print(Panel(
        f"[bold yellow]Master Key (save this securely!):[/bold yellow]\n\n"
        f"[cyan]{key}[/cyan]\n\n"
        f"Set as environment variable:\n"
        f"[dim]export SHADOW9_MASTER_KEY=\"{key}\"[/dim]",
        title="Encryption Key",
        border_style="yellow"
    ))


@main.command()
@click.option('--tor-port', '-p', type=int, default=9050, help='Tor SOCKS port')
def check_tor(tor_port: int):
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


@main.command()
@click.argument('url')
@click.option('--tor-port', '-p', type=int, default=9050, help='Tor SOCKS port')
def fetch(url: str, tor_port: int):
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


@main.command()
@click.option('--skip-optional', is_flag=True, help='Skip optional dependencies (bridges)')
@click.option('--check-only', is_flag=True, help='Only check status, do not install')
def setup(skip_optional: bool, check_only: bool):
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
        "• Tor daemon\n"
        "• obfs4proxy (for obfs4 bridges)\n"
        "• snowflake-client (for snowflake bridges)\n\n"
        "[dim]Some operations require sudo privileges[/dim]",
        title="Setup",
        border_style="cyan"
    ))

    if not click.confirm("\nProceed with installation?", default=True):
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


@main.command()
def status():
    """Show current system status and configuration."""
    from .setup import check_setup
    import platform

    console.print("[cyan]Shadow9 Manager Status[/cyan]\n")

    # Check dependencies
    status = check_setup()

    # Use ASCII characters for compatibility
    check_mark = "[OK]"
    x_mark = "[X]"
    circle = "[?]"

    table = Table(title="System Components")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Description", style="dim")

    for name, info in status.items():
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





@main.command()
def update():
    """
    Update Shadow9 to the latest version from GitHub.

    This will force pull the latest changes and restart the server if running.
    """
    import subprocess
    import os

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
            import time
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


if __name__ == "__main__":
    main()
