"""
Interactive initialization wizard for Shadow9.

Provides an interactive configuration builder for initial setup.
"""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..config import Config, ServerConfig, TorConfig, LogConfig, SecurityConfig, AuthConfig
from ..paths import load_master_key

console = Console()


def run_init_wizard() -> Config | None:
    """
    Interactive configuration builder.

    Returns:
        A fully configured Config object on success, None on cancel or error.
    """
    try:
        # Server settings
        console.print("\n[bold]Step 1:[/bold] Server Settings")
        console.print("  [dim]Configure the SOCKS5 proxy server.[/dim]\n")

        host = typer.prompt("  Server host", default="127.0.0.1")
        port = typer.prompt("  Server port", default="1080")
        try:
            port = int(port)
        except ValueError:
            port = 1080

        max_connections = typer.prompt("  Max connections", default="100")
        try:
            max_connections = int(max_connections)
        except ValueError:
            max_connections = 100

        console.print(
            "\n  [dim]serve runs in the foreground. For background operation,"
            " use 'shadow9 socks5 service install' and 'shadow9 socks5 service start'.[/dim]"
        )

        server = ServerConfig(host=host, port=port, max_connections=max_connections)

        # Tor settings
        console.print("\n[bold]Step 2:[/bold] Tor Connection")
        console.print("  [dim]Configure where Tor is running (routing is per-user).[/dim]\n")

        tor_host = "127.0.0.1"
        tor_port = 9050
        control_port = 9051

        if not typer.confirm("  Use default Tor ports (9050/9051)?", default=True):
            tor_host = typer.prompt("    Tor SOCKS host", default="127.0.0.1")
            tor_port_str = typer.prompt("    Tor SOCKS port", default="9050")
            control_port_str = typer.prompt("    Tor control port", default="9051")
            try:
                tor_port = int(tor_port_str)
                control_port = int(control_port_str)
            except ValueError:
                tor_port = 9050
                control_port = 9051

        tor = TorConfig(
            enabled=True, socks_host=tor_host, socks_port=tor_port, control_port=control_port
        )

        # Security settings. These two fields are all this step writes, so the choices
        # name the ports and the rate limit rather than an evasion level: evasion is a
        # per-user setting and is chosen when you add a user.
        console.print("\n[bold]Step 3:[/bold] Allowed Ports and Rate Limit")
        console.print(
            "  [dim]Where users may connect, and how many requests each may make per"
            " minute. Evasion is chosen per user when you add one.[/dim]\n"
        )

        console.print("  [cyan]1.[/cyan] Web ports only (80, 443), 100 requests/min")
        console.print(
            "  [cyan]2.[/cyan] [green](recommended)[/green] Web and proxy ports"
            " (80, 443, 8080, 8443), 100 requests/min"
        )
        console.print("  [cyan]3.[/cyan] Web and proxy ports, 60 requests/min")
        console.print("  [cyan]4.[/cyan] Web ports only (80, 443), 60 requests/min\n")

        security_choice = typer.prompt("  Select [1-4]", default="2")
        security_map = {
            "1": [80, 443],
            "2": [80, 443, 8080, 8443],
            "3": [80, 443, 8080, 8443],
            "4": [80, 443],
        }

        security = SecurityConfig(
            allowed_ports=security_map.get(security_choice, [80, 443, 8080, 8443]),
            rate_limit_per_minute=100 if security_choice in ["1", "2"] else 60,
        )

        # Log settings
        console.print("\n[bold]Step 4:[/bold] Logging")
        console.print("  [dim]Configure logging preferences.[/dim]\n")

        console.print("  [cyan]1. INFO[/cyan] [green](recommended)[/green] - Standard logging")
        console.print("  [cyan]2. DEBUG[/cyan] - Verbose output for troubleshooting")
        console.print("  [cyan]3. WARNING[/cyan] - Only warnings and errors")
        console.print("  [cyan]4. ERROR[/cyan] - Only errors\n")

        log_choice = typer.prompt("  Select level [1-4]", default="1")
        log_map = {"1": "INFO", "2": "DEBUG", "3": "WARNING", "4": "ERROR"}
        log_level = log_map.get(log_choice, "INFO")

        console.print(
            "\n  [cyan]1. json[/cyan] [green](recommended)[/green] - Structured JSON logs"
        )
        console.print("  [cyan]2. console[/cyan] - Human-readable console output\n")

        format_choice = typer.prompt("  Select format [1-2]", default="1")
        log_format = "json" if format_choice == "1" else "console"

        log = LogConfig(level=log_level, format=log_format)

        # Auth settings
        auth = AuthConfig()

        return Config(server=server, tor=tor, security=security, log=log, auth=auth)

    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled[/yellow]")
        return None
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        return None


def show_config_summary(config: Config) -> None:
    """
    Display configuration summary.

    Args:
        config: The configuration to display
    """
    table = Table(title="Server Configuration", show_header=True)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Server Host", config.server.host)
    table.add_row("Server Port", str(config.server.port))
    table.add_row("Max Connections", str(config.server.max_connections))
    table.add_row("Connection Timeout", f"{config.server.connection_timeout}s")
    table.add_row("", "")
    table.add_row("Tor SOCKS", f"{config.tor.socks_host}:{config.tor.socks_port}")
    table.add_row("Tor Control Port", str(config.tor.control_port))
    table.add_row("Tor Routing", "Per-user (IsolateSOCKSAuth)")
    table.add_row("", "")
    table.add_row("Log Level", config.log.level)
    table.add_row("Log Format", config.log.format)

    console.print("\n")
    console.print(table)

    security_table = Table(title="Security Configuration", show_header=True)
    security_table.add_column("Setting", style="cyan")
    security_table.add_column("Value", style="green")
    security_table.add_row("Max Failed Attempts", str(config.auth.max_failed_attempts))
    security_table.add_row(
        "Lockout Duration", f"{config.auth.lockout_duration_minutes} min"
    )
    security_table.add_row("Allowed Ports", ", ".join(map(str, config.security.allowed_ports)))
    security_table.add_row("Rate Limit", f"{config.security.rate_limit_per_minute}/min")

    console.print()
    console.print(security_table)

    wireguard_table = Table(title="WireGuard Configuration", show_header=True)
    wireguard_table.add_column("Setting", style="cyan")
    wireguard_table.add_column("Value", style="green")
    wireguard_table.add_row("Enabled", str(config.wireguard.enabled))
    wireguard_table.add_row("Listen Port", str(config.wireguard.listen_port))
    wireguard_table.add_row("Enrollment Host", config.wireguard.enrollment_host)
    wireguard_table.add_row("Enrollment Port", str(config.wireguard.enrollment_port))
    wireguard_table.add_row("Tunnel Network", config.wireguard.tunnel_network)
    wireguard_table.add_row("Hub Endpoint", config.wireguard.hub_endpoint)
    wireguard_table.add_row("MTU", str(config.wireguard.mtu))
    wireguard_table.add_row("DNS", ", ".join(config.wireguard.dns))
    wireguard_table.add_row("Keepalive", f"{config.wireguard.keepalive}s")

    console.print()
    console.print(wireguard_table)


def show_master_key(key: str | None = None) -> None:
    """Display a new key or the key currently used for credential encryption."""
    key = key or load_master_key()
    if key is None:
        console.print(
            "[red]Master key not found. Run 'shadow9 master-key generate' to create one.[/red]"
        )
        return

    console.print(
        Panel(
            "[bold yellow]Keep this key secure! Anyone with this key can decrypt credentials."
            "[/bold yellow]\n\n"
            f"[cyan]{key}[/cyan]\n\n"
            f"Set as environment variable:\n"
            f'[dim]export SHADOW9_MASTER_KEY="{key}"[/dim]',
            title="Encryption Key",
            border_style="yellow",
        )
    )
