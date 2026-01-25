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

logger = structlog.get_logger(__name__)

# ANSI colors (matching bash setup script)
CYAN = '\033[0;36m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
NC = '\033[0m'  # No color


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


# Required dependencies
DEPENDENCIES = [
    Dependency(
        name="Tor",
        check_command="tor --version",
        binary_name="tor",
        description="Tor anonymity network daemon",
        install_commands={
            OS.LINUX_DEBIAN: ["sudo apt-get update", "sudo apt-get install -y tor"],
            OS.LINUX_FEDORA: ["sudo dnf install -y tor"],
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

    def _log(self, message: str, level: str = "info"):
        """Log a message with colors matching bash setup script."""
        if self.verbose:
            prefixes = {
                "info": f"{CYAN}[INFO]{NC} ",
                "success": f"{GREEN}[OK]{NC} ",
                "warning": f"{YELLOW}[WARN]{NC} ",
                "error": f"{RED}[ERROR]{NC} ",
                "step": f"{CYAN}[>]{NC} ",
            }
            prefix = prefixes.get(level, "")
            print(f"{prefix}{message}")

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
            success = result.returncode == 0
            output = result.stdout + result.stderr
            return success, output
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def check_dependency(self, dep: Dependency) -> bool:
        """Check if a dependency is installed."""
        # First check if binary is in PATH
        if shutil.which(dep.binary_name):
            return True

        # Try running the check command
        success, _ = self._run_command(dep.check_command)
        return success

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
            self._log(f"Running: {cmd}", "info")
            success, output = self._run_command(cmd)

            if not success:
                self._log(f"Failed to run: {cmd}", "error")
                if self.verbose:
                    print(output)
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
            installed = self.check_dependency(dep)
            status[dep.name] = {
                "installed": installed,
                "required": dep.required,
                "description": dep.description,
            }
        return status

    def install_all_dependencies(self, include_optional: bool = True) -> bool:
        """Install all dependencies."""
        self._log(f"Detected OS: {self.os_type.value}", "info")
        self._log("Checking and installing dependencies...\n", "step")

        all_success = True

        for dep in DEPENDENCIES:
            if not dep.required and not include_optional:
                continue

            if self.check_dependency(dep):
                self._log(f"{dep.name} is already installed", "success")
            else:
                self._log(f"{dep.name} is not installed", "warning")
                if dep.required or include_optional:
                    success = self.install_dependency(dep)
                    if not success and dep.required:
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
            self._log(f"Adding to {torrc_path}: {modifications_needed}", "info")
            # Would need sudo to write - just inform user
            self._log(
                f"Please add the following to {torrc_path}:\n" +
                "\n".join(modifications_needed),
                "warning"
            )

        return True

    def start_tor_service(self) -> bool:
        """Start the Tor service."""
        self._log("Starting Tor service...", "step")

        # Try systemctl first (most modern Linux)
        if shutil.which("systemctl"):
            success, _ = self._run_command("sudo systemctl enable tor")
            success, _ = self._run_command("sudo systemctl start tor")
            if success:
                self._log("Tor service started with systemd", "success")
                return True

        # Try service command
        if shutil.which("service"):
            success, _ = self._run_command("sudo service tor start")
            if success:
                self._log("Tor service started", "success")
                return True

        # Try brew services on macOS
        if self.os_type == OS.MACOS:
            success, _ = self._run_command("brew services start tor")
            if success:
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
        print(f"\n{CYAN}{'=' * 60}")
        print("           Shadow9 Proxy Setup")
        print(f"{'=' * 60}{NC}\n")

        # Check if running as root/sudo for Linux
        if self.os_type in [OS.LINUX_DEBIAN, OS.LINUX_FEDORA, OS.LINUX_ARCH, OS.LINUX_ALPINE]:
            if not self.is_root and os.geteuid() != 0:
                self._log("Some operations require sudo. You may be prompted for password.", "warning")

        # Step 1: Install dependencies
        print(f"\n{CYAN}[1/4]{NC} Installing Dependencies")
        if not self.install_all_dependencies(include_optional):
            self._log("Some required dependencies failed to install", "error")
            return False

        # Step 2: Configure Tor
        print(f"\n{CYAN}[2/4]{NC} Configuring Tor")
        self.configure_tor()

        # Step 3: Start Tor
        print(f"\n{CYAN}[3/4]{NC} Starting Tor Service")
        self.start_tor_service()

        # Step 4: Verify
        print(f"\n{CYAN}[4/4]{NC} Verification")
        status = self.check_all_dependencies()

        all_good = True
        for name, info in status.items():
            if info["installed"]:
                print(f"  {GREEN}[OK]{NC} {name}")
            elif not info["required"]:
                print(f"  {YELLOW}[WARN]{NC} {name} (optional)")
            else:
                print(f"  {RED}[ERROR]{NC} {name} (required)")
                all_good = False

        print(f"\n{CYAN}{'=' * 60}{NC}")
        if all_good:
            print(f"{GREEN}[OK]{NC} Proxy setup complete!")
            print(f"\n  shadow9 serve    # Start the proxy server")
        else:
            print(f"{YELLOW}[WARN]{NC} Setup completed with warnings")
        print(f"{CYAN}{'=' * 60}{NC}\n")

        return all_good



def run_setup(verbose: bool = True, include_optional: bool = True) -> bool:
    """Run the automated setup."""
    setup = SystemSetup(verbose=verbose)
    return setup.full_setup(include_optional=include_optional)


def check_setup() -> dict:
    """Check current setup status."""
    setup = SystemSetup(verbose=False)
    return setup.check_all_dependencies()
