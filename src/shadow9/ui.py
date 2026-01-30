"""
Unified UI components for Shadow9 Manager.

Provides consistent Rich-based styling across all CLI commands.
"""

import sys
from typing import Optional, List, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.rule import Rule
from rich.text import Text
from rich import box


# Create console with force_terminal to ensure colors work
console = Console(force_terminal=True)


# Status icons - use ASCII fallbacks on Windows to avoid encoding issues
class Icons:
    """Icons for status indicators (ASCII on Windows, Unicode elsewhere)."""
    if sys.platform == "win32":
        # ASCII fallbacks for Windows cmd.exe/PowerShell encoding issues
        SUCCESS = "[OK]"
        ERROR = "[X]"
        WARNING = "[!]"
        INFO = ">"
        PENDING = "[ ]"
        RUNNING = "[*]"
    else:
        # Unicode icons for Unix-like systems
        SUCCESS = "\u2713"  # ✓
        ERROR = "\u2717"    # ✗
        WARNING = "\u26a0"  # ⚠
        INFO = "\u2192"     # →
        PENDING = "\u25cb"  # ○
        RUNNING = "\u25c9"  # ◉


# Color scheme
class Colors:
    """Consistent color scheme."""
    PRIMARY = "cyan"
    SUCCESS = "green"
    ERROR = "red"
    WARNING = "yellow"
    MUTED = "dim"
    ACCENT = "bold cyan"


def header(title: str, subtitle: Optional[str] = None, style: str = Colors.PRIMARY) -> Panel:
    """
    Create a header panel for a section or wizard.

    Args:
        title: Main title text
        subtitle: Optional description below title
        style: Border style color

    Returns:
        Rich Panel object
    """
    content = f"[bold {style}]{title}[/bold {style}]"
    if subtitle:
        content += f"\n\n{subtitle}"

    return Panel(
        content,
        border_style=style,
        padding=(1, 2),
    )


def step_header(step: int, total: int, title: str) -> Rule:
    """
    Create a step header with progress indicator.

    Args:
        step: Current step number (1-indexed)
        total: Total number of steps
        title: Step title

    Returns:
        Rich Rule object
    """
    return Rule(
        f"[bold cyan]Step {step} of {total}[/bold cyan]  {title}",
        style="dim",
        align="left",
    )


def status_line(
    message: str,
    status: str = "info",
    indent: int = 2,
) -> None:
    """
    Print a status line with appropriate icon and color.

    Args:
        message: Status message
        status: One of 'success', 'error', 'warning', 'info', 'pending'
        indent: Number of spaces to indent
    """
    icons = {
        "success": (Icons.SUCCESS, Colors.SUCCESS),
        "error": (Icons.ERROR, Colors.ERROR),
        "warning": (Icons.WARNING, Colors.WARNING),
        "info": (Icons.INFO, Colors.PRIMARY),
        "pending": (Icons.PENDING, Colors.MUTED),
    }

    icon, color = icons.get(status, (Icons.INFO, Colors.PRIMARY))
    prefix = " " * indent
    console.print(f"{prefix}[{color}]{icon}[/{color}] {message}")


def success(message: str, indent: int = 2) -> None:
    """Print a success status line."""
    status_line(message, "success", indent)


def error(message: str, indent: int = 2) -> None:
    """Print an error status line."""
    status_line(message, "error", indent)


def warning(message: str, indent: int = 2) -> None:
    """Print a warning status line."""
    status_line(message, "warning", indent)


def info(message: str, indent: int = 2) -> None:
    """Print an info status line."""
    status_line(message, "info", indent)


def muted(message: str, indent: int = 2) -> None:
    """Print a muted/dim message."""
    prefix = " " * indent
    console.print(f"{prefix}[dim]{message}[/dim]")


def completion_panel(
    title: str,
    commands: List[Tuple[str, str]],
    success: bool = True,
    note: Optional[str] = None,
) -> Panel:
    """
    Create a completion panel with command reference table.

    Args:
        title: Panel title
        commands: List of (command, description) tuples
        success: Whether this is a success (green) or warning (yellow) panel
        note: Optional note to display below the table

    Returns:
        Rich Panel object
    """
    style = Colors.SUCCESS if success else Colors.WARNING

    # Create command table
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        padding=(0, 1),
    )
    table.add_column("Command", style="cyan")
    table.add_column("Description")

    for cmd, desc in commands:
        table.add_row(cmd, desc)

    # Build content
    content_parts = [table]
    if note:
        content_parts.append(Text(f"\n{note}", style="dim"))

    return Panel(
        table,
        title=f"[bold {style}]{title}[/bold {style}]",
        border_style=style,
        padding=(1, 2),
    )


def dependency_table(
    dependencies: List[dict],
    title: str = "Components",
) -> Table:
    """
    Create a table showing dependency status.

    Args:
        dependencies: List of dicts with 'name', 'installed', 'required', 'description' keys
        title: Table title

    Returns:
        Rich Table object
    """
    table = Table(
        title=title,
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Description", style="dim")

    for dep in dependencies:
        if dep.get("installed"):
            status = f"[{Colors.SUCCESS}]{Icons.SUCCESS} Ready[/{Colors.SUCCESS}]"
        elif dep.get("required"):
            status = f"[{Colors.ERROR}]{Icons.ERROR} Missing[/{Colors.ERROR}]"
        else:
            status = f"[{Colors.WARNING}]{Icons.WARNING} Optional[/{Colors.WARNING}]"

        table.add_row(
            dep.get("name", "Unknown"),
            status,
            dep.get("description", ""),
        )

    return table


def create_progress() -> Progress:
    """
    Create a configured Progress instance for multi-step operations.

    Returns:
        Rich Progress object
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    )


class SetupUI:
    """
    UI helper for setup wizards with step tracking.

    Provides a consistent interface for multi-step setup processes.
    """

    def __init__(self, title: str, subtitle: Optional[str] = None, total_steps: int = 4):
        """
        Initialize the setup UI.

        Args:
            title: Setup wizard title
            subtitle: Optional description
            total_steps: Total number of steps in the wizard
        """
        self.title = title
        self.subtitle = subtitle
        self.total_steps = total_steps
        self.current_step = 0

    def show_header(self) -> None:
        """Display the setup header panel."""
        console.print()
        console.print(header(self.title, self.subtitle))
        console.print()

    def start_step(self, title: str) -> None:
        """
        Start a new step.

        Args:
            title: Step title
        """
        self.current_step += 1
        console.print()
        console.print(step_header(self.current_step, self.total_steps, title))

    def success(self, message: str) -> None:
        """Print success message for current step."""
        success(message)

    def error(self, message: str) -> None:
        """Print error message for current step."""
        error(message)

    def warning(self, message: str) -> None:
        """Print warning message for current step."""
        warning(message)

    def info(self, message: str) -> None:
        """Print info message for current step."""
        info(message)

    def muted(self, message: str) -> None:
        """Print muted message."""
        muted(message)

    def show_completion(
        self,
        commands: List[Tuple[str, str]],
        success_state: bool = True,
        title: Optional[str] = None,
    ) -> None:
        """
        Show the completion panel.

        Args:
            commands: List of (command, description) tuples
            success_state: Whether setup succeeded
            title: Override panel title
        """
        panel_title = title or ("Setup Complete!" if success_state else "Setup Incomplete")
        console.print()
        console.print(completion_panel(panel_title, commands, success_state))
        console.print()
