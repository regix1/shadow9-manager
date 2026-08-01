"""
Manage the third-party pieces the proxy depends on.

`shadow9 status` reports on these but could not act on them, so an operator who saw Tor
listed had to know it was `tor.service` and go to systemctl. These commands close that gap.

Only Tor has a lifecycle. The two pluggable transports are binaries that Tor starts as
child processes when a user is on that kind of bridge, so there is nothing to start or
stop, and saying so is more use than pretending otherwise.
"""

import subprocess
import sys
from typing import Annotated, NamedTuple

import typer
from rich.console import Console
from rich.table import Table

from ..tor_connector import TorConnector


console = Console()

# The unit shadow9 installs for itself, which Wants=tor.service, so it will pull Tor back
# up. Stopping Tor without knowing that looks like the stop silently failed.
OWN_SERVICE = "shadow9.service"


class Component(NamedTuple):
    """One of the things `shadow9 status` lists under Proxy Components."""

    name: str
    label: str
    unit: str | None
    on_demand: str


COMPONENTS = (
    Component("tor", "Tor", "tor", ""),
    Component(
        "obfs4proxy",
        "obfs4proxy",
        None,
        "Tor starts it when a user is on an obfs4 bridge",
    ),
    Component(
        "snowflake-client",
        "snowflake-client",
        None,
        "Tor starts it when a user is on a Snowflake bridge",
    ),
)


def find_component(name: str) -> Component:
    """
    Look up a component by the name used on the command line.

    Args:
        name: The component name as typed

    Returns:
        The matching component

    Raises:
        typer.Exit: When the name is not one of the components
    """
    for component in COMPONENTS:
        if component.name == name:
            return component

    known = ", ".join(item.name for item in COMPONENTS)
    console.print(f"[red]There is no component called '{name}'[/red]")
    console.print(f"[dim]Known components: {known}[/dim]")
    raise typer.Exit(1)


def _require_systemd() -> None:
    """Stop early where there is no systemd to talk to."""
    if sys.platform != "linux":
        console.print("[red]Starting and stopping components needs systemd, so Linux only[/red]")
        console.print("[dim]'shadow9 components status' still works here[/dim]")
        raise typer.Exit(1)


def _unit_state(unit: str) -> str:
    """What systemd says about a unit, or 'unknown' when it cannot be asked."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def units_pulling_in(unit: str) -> list[str]:
    """
    Other units that start this one, so stopping it does not surprise somebody.

    Tor is a system-wide daemon. Something else on the host may depend on it, and shadow9
    has no business taking that down without saying so first.

    Args:
        unit: The systemd unit to ask about

    Returns:
        The units that pull it in, excluding the unit itself
    """
    try:
        result = subprocess.run(
            ["systemctl", "list-dependencies", "--reverse", "--plain", "--no-pager", unit],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    found = []
    for line in result.stdout.splitlines():
        entry = line.strip()
        if entry and entry.endswith(".service") and not entry.startswith(unit):
            found.append(entry)
    return found


def _run_unit_action(action: str, unit: str) -> bool:
    """Ask systemd to do something to a unit, and say whether it accepted."""
    from .utils import privileged

    try:
        result = subprocess.run(
            privileged(["systemctl", action, unit]), capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as error:
        console.print(f"[red]Could not run systemctl {action} {unit}: {error}[/red]")
        return False

    if result.returncode != 0:
        console.print(f"[red]systemctl {action} {unit} failed: {result.stderr.strip()}[/red]")
        return False
    return True


def _refuse_on_demand(component: Component) -> None:
    """Explain why a pluggable transport has nothing to start or stop."""
    console.print(
        f"[yellow]{component.label} is not a service, so there is nothing to "
        f"start or stop[/yellow]"
    )
    console.print(f"[dim]{component.on_demand}, and it exits with the connection.[/dim]")
    console.print("[dim]To stop it, stop the proxy or move that user off the bridge.[/dim]")
    raise typer.Exit(1)


def register_component_commands(app: typer.Typer) -> None:
    """Register the component subcommands with the main app."""

    components_app = typer.Typer(help="Manage Tor and the bridge transports the proxy uses.")
    app.add_typer(components_app, name="components")

    @components_app.command("status")
    def components_status() -> None:
        """Show whether each component is installed and, for Tor, whether it is running."""
        from ..setup import check_setup

        installed = check_setup()

        table = Table(title="Proxy Components", show_header=True)
        table.add_column("Component", style="cyan")
        table.add_column("Installed")
        table.add_column("State")

        for component in COMPONENTS:
            entry = installed.get(component.label, {})
            present = (
                "[green]yes[/green]" if entry.get("installed") else "[red]no[/red]"
            )

            if component.unit is None:
                state = f"[dim]on demand ({component.on_demand})[/dim]"
            elif sys.platform != "linux":
                state = "[dim]needs systemd to say[/dim]"
            else:
                unit_state = _unit_state(component.unit)
                colour = "green" if unit_state == "active" else "yellow"
                state = f"[{colour}]{unit_state}[/{colour}] ({component.unit}.service)"

            table.add_row(component.label, present, state)

        console.print(table)

        detected = TorConnector.detect_tor_service()
        if detected:
            console.print(f"[dim]Tor is answering on port {detected.socks_port}.[/dim]")

    @components_app.command("start")
    def components_start(
        name: Annotated[str, typer.Argument(help="Component to start")],
    ) -> None:
        """Start a component."""
        component = find_component(name)
        if component.unit is None:
            _refuse_on_demand(component)

        _require_systemd()
        if not _run_unit_action("start", component.unit or ""):
            raise typer.Exit(1)
        console.print(f"[green]{component.label} started[/green]")

    @components_app.command("restart")
    def components_restart(
        name: Annotated[str, typer.Argument(help="Component to restart")],
    ) -> None:
        """Restart a component."""
        component = find_component(name)
        if component.unit is None:
            _refuse_on_demand(component)

        _require_systemd()
        if not _run_unit_action("restart", component.unit or ""):
            raise typer.Exit(1)
        console.print(f"[green]{component.label} restarted[/green]")

    @components_app.command("stop")
    def components_stop(
        name: Annotated[str, typer.Argument(help="Component to stop")],
        yes: Annotated[
            bool,
            typer.Option("--yes", "-y", help="Do not ask when something else depends on it"),
        ] = False,
    ) -> None:
        """Stop a component, saying first what else on this host depends on it."""
        component = find_component(name)
        if component.unit is None:
            _refuse_on_demand(component)

        _require_systemd()
        unit = component.unit or ""
        dependents = units_pulling_in(f"{unit}.service")
        others = [entry for entry in dependents if entry != OWN_SERVICE]

        if others:
            console.print(
                f"[yellow]{component.label} is also wanted by: {', '.join(others)}[/yellow]"
            )
            console.print("[dim]Stopping it may take those down too.[/dim]")
            if not yes and not typer.confirm(f"Stop {component.label} anyway?", default=False):
                console.print("[yellow]Left it running[/yellow]")
                raise typer.Exit(1)

        if not _run_unit_action("stop", unit):
            raise typer.Exit(1)
        console.print(f"[green]{component.label} stopped[/green]")

        if OWN_SERVICE in dependents:
            console.print(
                f"[dim]The shadow9 unit has Wants={unit}.service, so starting shadow9 will "
                f"start {component.label} again. Edit the unit if you want it to stay down.[/dim]"
            )
