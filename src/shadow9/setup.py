"""
Automated Setup for Shadow9 Manager.

Handles installation of all dependencies:
- Tor daemon
- Pluggable transports (obfs4proxy, snowflake-client)
- System configuration
"""

import subprocess
import shutil
import platform
import os
from pathlib import Path
from typing import Tuple
from dataclasses import dataclass
from enum import Enum

import structlog

from .ui import (
    SetupUI,
    console,
    success,
    error,
    warning,
    info,
    muted,
    dependency_table,
    completion_panel,
)

logger = structlog.get_logger(__name__)


class OS(Enum):
    """Supported operating systems."""
    LINUX_DEBIAN = "debian"      # Debian, Ubuntu, Mint, etc.
    LINUX_FEDORA = "fedora"      # Fedora, RHEL, CentOS
    LINUX_ARCH = "arch"          # Arch, Manjaro
    LINUX_ALPINE = "alpine"      # Alpine Linux
    LINUX_OTHER = "linux"        # Generic Linux
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    """Represents a system dependency."""
    name: str
    check_command: str           # Command to check if installed
    install_commands: dict       # OS -> install command(s)
    binary_name: str             # Name of binary to check in PATH
    required: bool = True
    description: str = ""
    min_version: str = ""        # Minimum required version (e.g., "0.4.8")
    version_command: str = ""    # Command to get version string


# Commands to add official Tor Project repository (for latest Tor version)
# These ensure we get Tor 0.4.8+ with all modern features
TOR_REPO_SETUP_DEBIAN = [
    "sudo apt-get update",
    "sudo apt-get install -y apt-transport-https gpg",
    # Add Tor Project signing key
    "wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | sudo gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg --yes",
    # Add Tor Project repository (auto-detect distro codename)
    "echo \"deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $(lsb_release -cs) main\" | sudo tee /etc/apt/sources.list.d/tor.list",
    "sudo apt-get update",
    "sudo apt-get install -y tor deb.torproject.org-keyring",
]

TOR_REPO_SETUP_FEDORA = [
    # Fedora has reasonably up-to-date Tor in repos
    "sudo dnf install -y tor",
]

# Required dependencies
DEPENDENCIES = [
    Dependency(
        name="Tor",
        check_command="tor --version",
        binary_name="tor",
        description="Tor anonymity network daemon (from official Tor Project repo)",
        min_version="0.4.8",
        version_command="tor --version 2>&1 | head -1 | sed -n 's/.*Tor version \\([0-9.]*\\).*/\\1/p'",
        install_commands={
            OS.LINUX_DEBIAN: TOR_REPO_SETUP_DEBIAN,
            OS.LINUX_FEDORA: TOR_REPO_SETUP_FEDORA,
            OS.LINUX_ARCH: ["sudo pacman -S --noconfirm tor"],
            OS.LINUX_ALPINE: ["sudo apk add tor"],
            OS.MACOS: ["brew install tor"],
            OS.WINDOWS: [],  # Manual install required
        }
    ),
    Dependency(
        name="obfs4proxy",
        check_command="obfs4proxy -version",
        binary_name="obfs4proxy",
        description="Pluggable transport for obfs4 bridges",
        required=False,
        install_commands={
            OS.LINUX_DEBIAN: ["sudo apt-get install -y obfs4proxy"],
            OS.LINUX_FEDORA: ["sudo dnf install -y obfs4"],
            OS.LINUX_ARCH: ["sudo pacman -S --noconfirm obfs4proxy"],
            OS.LINUX_ALPINE: ["sudo apk add obfs4proxy"],
            OS.MACOS: ["brew install obfs4proxy"],
            OS.WINDOWS: [],
        }
    ),
    Dependency(
        name="snowflake-client",
        check_command="snowflake-client -version",
        binary_name="snowflake-client",
        description="Pluggable transport for Snowflake bridges",
        required=False,
        install_commands={
            OS.LINUX_DEBIAN: ["sudo apt-get install -y snowflake-client"],
            OS.LINUX_FEDORA: [],  # Not in repos, manual install
            OS.LINUX_ARCH: ["yay -S --noconfirm snowflake-pt-client"],  # AUR
            OS.LINUX_ALPINE: [],
            OS.MACOS: ["brew install snowflake"],
            OS.WINDOWS: [],
        }
    ),
]


class SystemSetup:
    """
    Automated system setup for Shadow9.

    Detects OS and installs all required dependencies.
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.os_type = self._detect_os()
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        self.ui: SetupUI | None = None

    def _detect_os(self) -> OS:
        """Detect the operating system and distribution."""
        system = platform.system().lower()

        if system == "darwin":
            return OS.MACOS
        elif system == "windows":
            return OS.WINDOWS
        elif system == "linux":
            return self._detect_linux_distro()
        else:
            return OS.UNKNOWN

    def _detect_linux_distro(self) -> OS:
        """Detect Linux distribution."""
        # Check /etc/os-release
        os_release = Path("/etc/os-release")
        if os_release.exists():
            content = os_release.read_text().lower()

            if any(d in content for d in ["debian", "ubuntu", "mint", "pop", "elementary", "kali"]):
                return OS.LINUX_DEBIAN
            elif any(d in content for d in ["fedora", "rhel", "centos", "rocky", "alma"]):
                return OS.LINUX_FEDORA
            elif any(d in content for d in ["arch", "manjaro", "endeavour"]):
                return OS.LINUX_ARCH
            elif "alpine" in content:
                return OS.LINUX_ALPINE

        # Check for package managers as fallback
        if shutil.which("apt-get"):
            return OS.LINUX_DEBIAN
        elif shutil.which("dnf") or shutil.which("yum"):
            return OS.LINUX_FEDORA
        elif shutil.which("pacman"):
            return OS.LINUX_ARCH
        elif shutil.which("apk"):
            return OS.LINUX_ALPINE

        return OS.LINUX_OTHER

    def _log(self, message: str, level: str = "info") -> None:
        """Log a message with Rich styling."""
        if not self.verbose:
            return

        log_funcs = {
            "info": info,
            "success": success,
            "warning": warning,
            "error": error,
            "step": info,
        }
        log_func = log_funcs.get(level, info)
        log_func(message)

    def _run_command(self, command: str, check: bool = True) -> Tuple[bool, str]:
        """Run a shell command."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            success_result = result.returncode == 0
            output = result.stdout + result.stderr
            return success_result, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.

        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        def parse_version(v: str) -> list:
            # Extract just the version numbers, ignore any suffix
            import re
            match = re.match(r'(\d+(?:\.\d+)*)', v)
            if match:
                return [int(x) for x in match.group(1).split('.')]
            return [0]

        parts1 = parse_version(v1)
        parts2 = parse_version(v2)

        # Pad shorter version with zeros
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        return 0

    def check_dependency(self, dep: Dependency) -> tuple[bool, bool]:
        """
        Check if a dependency is installed and meets version requirements.

        Returns:
            Tuple of (is_installed, meets_version_requirement)
        """
        # First check if binary is in PATH
        if not shutil.which(dep.binary_name):
            # Try running the check command
            success_result, _ = self._run_command(dep.check_command)
            if not success_result:
                return False, False

        # Binary exists, check version if required
        if dep.min_version and dep.version_command:
            success_result, output = self._run_command(dep.version_command)
            if success_result and output.strip():
                installed_version = output.strip()
                if self._compare_versions(installed_version, dep.min_version) < 0:
                    return True, False  # Installed but outdated

        return True, True

    def install_dependency(self, dep: Dependency) -> bool:
        """Install a dependency."""
        if self.os_type not in dep.install_commands:
            self._log(f"No install instructions for {dep.name} on {self.os_type.value}", "warning")
            return False

        commands = dep.install_commands[self.os_type]
        if not commands:
            self._log(f"{dep.name} requires manual installation on {self.os_type.value}", "warning")
            return False

        self._log(f"Installing {dep.name}...", "step")

        for cmd in commands:
            muted(f"Running: {cmd}", indent=4)
            success_result, output = self._run_command(cmd)

            if not success_result:
                self._log(f"Failed to run: {cmd}", "error")
                if self.verbose:
                    console.print(f"[dim]{output}[/dim]")
                return False

        # Verify installation
        if self.check_dependency(dep):
            self._log(f"{dep.name} installed successfully", "success")
            return True
        else:
            self._log(f"{dep.name} installation may have failed", "warning")
            return False

    def check_all_dependencies(self) -> dict:
        """Check status of all dependencies."""
        status = {}
        for dep in DEPENDENCIES:
            is_installed, meets_version = self.check_dependency(dep)
            status[dep.name] = {
                "installed": is_installed and meets_version,
                "required": dep.required,
                "description": dep.description,
            }
        return status

    def install_all_dependencies(self, include_optional: bool = True) -> bool:
        """Install all dependencies."""
        self._log(f"Detected OS: {self.os_type.value}", "info")
        self._log("Checking and installing dependencies...", "step")

        all_success = True

        for dep in DEPENDENCIES:
            if not dep.required and not include_optional:
                continue

            is_installed, meets_version = self.check_dependency(dep)

            if is_installed and meets_version:
                self._log(f"{dep.name} is already installed", "success")
            elif is_installed and not meets_version:
                self._log(f"{dep.name} is installed but outdated (need {dep.min_version}+)", "warning")
                self._log(f"Upgrading {dep.name} from official repository...", "step")
                success_result = self.install_dependency(dep)
                if not success_result and dep.required:
                    all_success = False
            else:
                self._log(f"{dep.name} is not installed", "warning")
                if dep.required or include_optional:
                    success_result = self.install_dependency(dep)
                    if not success_result and dep.required:
                        all_success = False

        return all_success

    def configure_tor(self) -> bool:
        """Configure Tor for Shadow9 usage."""
        self._log("Configuring Tor...", "step")

        # Determine torrc location
        torrc_paths = [
            Path("/etc/tor/torrc"),
            Path("/usr/local/etc/tor/torrc"),
            Path.home() / ".torrc",
        ]

        torrc_path = None
        for path in torrc_paths:
            if path.exists():
                torrc_path = path
                break

        if not torrc_path:
            self._log("Could not find torrc file", "warning")
            return False

        # Check if we need to modify torrc
        content = torrc_path.read_text()

        modifications_needed = []

        # Ensure SocksPort is set
        if "SocksPort" not in content:
            modifications_needed.append("SocksPort 9050")

        # Ensure ControlPort is set (for new identity requests)
        if "ControlPort" not in content:
            modifications_needed.append("ControlPort 9051")

        if modifications_needed:
            muted(f"Config location: {torrc_path}", indent=4)
            self._log(
                f"Please add the following to {torrc_path}:\n" +
                "\n".join(f"    {m}" for m in modifications_needed),
                "warning"
            )

        return True

    def start_tor_service(self) -> bool:
        """Start the Tor service."""
        self._log("Starting Tor service...", "step")

        # Try systemctl first (most modern Linux)
        if shutil.which("systemctl"):
            success_result, _ = self._run_command("sudo systemctl enable tor")
            success_result, _ = self._run_command("sudo systemctl start tor")
            if success_result:
                self._log("Tor service started with systemd", "success")
                return True

        # Try service command
        if shutil.which("service"):
            success_result, _ = self._run_command("sudo service tor start")
            if success_result:
                self._log("Tor service started", "success")
                return True

        # Try brew services on macOS
        if self.os_type == OS.MACOS:
            success_result, _ = self._run_command("brew services start tor")
            if success_result:
                self._log("Tor service started with Homebrew", "success")
                return True

        self._log("Could not start Tor service automatically", "warning")
        return False

    def full_setup(self, include_optional: bool = True) -> bool:
        """
        Run full automated setup.

        1. Install all dependencies
        2. Configure Tor
        3. Start Tor service
        4. Verify everything works
        """
        # Initialize UI
        self.ui = SetupUI(
            title="Shadow9 Proxy Setup",
            subtitle="Installing Tor and bridge transports for\nanonymous SOCKS5 proxy routing.",
            total_steps=4,
        )
        self.ui.show_header()

        # Check if running as root/sudo for Linux
        if self.os_type in [OS.LINUX_DEBIAN, OS.LINUX_FEDORA, OS.LINUX_ARCH, OS.LINUX_ALPINE]:
            if not self.is_root and os.geteuid() != 0:
                warning("Some operations require sudo. You may be prompted for password.")

        # Step 1: Install dependencies
        self.ui.start_step("Installing Dependencies")
        if not self.install_all_dependencies(include_optional):
            self._log("Some required dependencies failed to install", "error")
            return False

        # Step 2: Configure Tor
        self.ui.start_step("Configuring Tor")
        self.configure_tor()

        # Step 3: Start Tor
        self.ui.start_step("Starting Tor Service")
        self.start_tor_service()

        # Step 4: Verify
        self.ui.start_step("Verification")
        status = self.check_all_dependencies()

        all_good = True
        deps_list = []
        for name, dep_info in status.items():
            deps_list.append({
                "name": name,
                "installed": dep_info["installed"],
                "required": dep_info["required"],
                "description": dep_info["description"],
            })
            if not dep_info["installed"] and dep_info["required"]:
                all_good = False

        console.print()
        console.print(dependency_table(deps_list, title="Proxy Components"))

        # Show completion
        commands = [
            ("shadow9 serve", "Start the SOCKS5 proxy server"),
            ("shadow9 user generate", "Create user credentials"),
            ("shadow9 status", "Check proxy status"),
            ("shadow9 --help", "View all available commands"),
        ]

        if all_good:
            self.ui.show_completion(commands, success_state=True, title="Proxy Setup Complete!")
        else:
            self.ui.show_completion(
                commands,
                success_state=False,
                title="Setup Completed with Warnings",
            )

        return all_good



def run_setup(verbose: bool = True, include_optional: bool = True) -> bool:
    """Run the automated setup."""
    setup = SystemSetup(verbose=verbose)
    return setup.full_setup(include_optional=include_optional)


def check_setup() -> dict:
    """Check current setup status."""
    setup = SystemSetup(verbose=False)
    return setup.check_all_dependencies()
