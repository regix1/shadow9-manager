"""
User detail rendering for Shadow9.

Draws one user's settings as a table. The menus and the CLI each pick the user
themselves and then call in here to show them.
"""

from rich.console import Console
from rich.table import Table

from ..auth import AuthManager

console = Console()


def display_user_info(auth_manager: AuthManager, username: str) -> None:
    """
    Display detailed information for a single user.

    Args:
        auth_manager: The authentication manager
        username: The username to display info for
    """
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

    # Display logging status (privacy setting)
    logging_enabled = info.get("logging_enabled", True)
    if logging_enabled:
        table.add_row("Logging", "[green]Enabled[/green]")
    else:
        table.add_row("Logging", "[yellow]Disabled[/yellow] (no activity tracking)")

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

    # Display bind port
    bind_port = info.get("bind_port")
    if bind_port:
        table.add_row("Bind Port", f"{bind_port} (dedicated listener)")
    else:
        table.add_row("Bind Port", "Shared (server default)")

    table.add_row("Created", info["created_at"] or "Unknown")
    table.add_row("Last Used", info["last_used"] or "Never")

    console.print(table)
