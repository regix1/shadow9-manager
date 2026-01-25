"""
User management commands for Shadow9 CLI.

Contains all user subcommands: add, remove, list, generate, info, modify, enable, disable, new.
"""

from pathlib import Path
from typing import Optional, Annotated
from enum import Enum

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from ..config import Config
from ..auth import AuthManager
from ..wizards import (
    run_user_wizard, run_user_modify_wizard,
    run_user_list_wizard, display_user_info
)

console = Console()


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


def register_user_commands(app: typer.Typer):
    """Register user subcommands with the app."""
    
    user_app = typer.Typer(
        help="Manage proxy users.",
        invoke_without_command=True,
        no_args_is_help=True,
    )
    app.add_typer(user_app, name="user")

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
