"""
Tor Bridge and Pluggable Transport Support for Shadow9.

Provides stealth Tor connectivity using:
- obfs4 bridges (most effective against DPI)
- meek bridges (looks like cloud traffic)
- snowflake bridges (uses WebRTC)
- webtunnel bridges (looks like HTTPS)

This hides the fact that you're using Tor from network observers.
"""

import asyncio
import subprocess
import shutil
import tempfile
import os
import platform
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class BridgeType(Enum):
    """Supported bridge/pluggable transport types."""
    NONE = "none"           # Direct Tor connection (detectable)
    OBFS4 = "obfs4"         # Obfuscated traffic (recommended)
    MEEK_AZURE = "meek"     # Looks like Azure cloud traffic
    SNOWFLAKE = "snowflake" # Uses WebRTC peers
    WEBTUNNEL = "webtunnel" # Looks like HTTPS to allowed domains


@dataclass
class Bridge:
    """Represents a Tor bridge configuration."""
    type: BridgeType
    address: str           # IP:Port or domain
    fingerprint: str       # Bridge fingerprint
    params: dict = field(default_factory=dict)  # Transport-specific params (cert, iat-mode, etc.)

    def to_bridge_line(self) -> str:
        """Convert to torrc bridge line format."""
        if self.type == BridgeType.NONE:
            return ""

        # Format: Bridge <transport> <address> <fingerprint> <params>
        parts = [self.type.value, self.address]

        if self.fingerprint:
            parts.append(self.fingerprint)

        # Add transport-specific parameters
        for key, value in self.params.items():
            parts.append(f"{key}={value}")

        return "Bridge " + " ".join(parts)


@dataclass
class BridgeConfig:
    """Configuration for Tor bridges."""
    enabled: bool = False
    bridge_type: BridgeType = BridgeType.OBFS4
    bridges: List[Bridge] = field(default_factory=list)

    # Paths to pluggable transport binaries
    obfs4proxy_path: Optional[str] = None
    snowflake_path: Optional[str] = None
    webtunnel_path: Optional[str] = None

    # Use built-in bridges (requires no configuration)
    use_builtin_bridges: bool = True


# Built-in obfs4 bridges (public bridges from Tor Project)
# These are updated periodically - for production, get fresh bridges from https://bridges.torproject.org
BUILTIN_OBFS4_BRIDGES = [
    Bridge(
        type=BridgeType.OBFS4,
        address="193.11.166.194:27025",
        fingerprint="1AE039EE0B11DB79E4B4B29ABA3C647B40B7B280",
        params={
            "cert": "4JeU2x3EsSphNCqGEMLhOGCQBsLvRPOdDmOGudvPL2qKSn+DCDJuFilndkvF0XhFOQ0qHA",
            "iat-mode": "0"
        }
    ),
    Bridge(
        type=BridgeType.OBFS4,
        address="38.229.33.83:80",
        fingerprint="0BAC39417268B96B9F514E7F63FA6FBA1A788955",
        params={
            "cert": "VwEFpk9F/UN9JED7XpG1XOjm/O8ZCXK80oPecgWnNDZDv5pdkhq1OpbAH0wNqOT6H6BmRQ",
            "iat-mode": "1"
        }
    ),
    Bridge(
        type=BridgeType.OBFS4,
        address="193.11.166.194:27020",
        fingerprint="86AC7B8D430DAC4117E9F42C9EAED18133863AAF",
        params={
            "cert": "0aKPMOYUDaYRIVddHfxRHG9q2jJsxEWLqnqCs2wMpfNSwLcJB4lGydBRL7wABs7zGcFk0Q",
            "iat-mode": "0"
        }
    ),
]

# Built-in snowflake configuration
SNOWFLAKE_BRIDGE = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.3:80",  # Dummy address, snowflake uses STUN/TURN
    fingerprint="2B280B23E1107BB62ABFC40DDCC8824814F80A72",
    params={
        "url": "https://snowflake-broker.torproject.net.global.prod.fastly.net/",
        "ampcache": "https://cdn.ampproject.org/",
        "front": "www.google.com",
        "ice": "stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478"
    }
)

# Meek Azure bridge
MEEK_AZURE_BRIDGE = Bridge(
    type=BridgeType.MEEK_AZURE,
    address="0.0.0.1:2",  # Dummy address
    fingerprint="97700DFE9F483596DDA6264C4D7DF7641E1E39CE",
    params={
        "url": "https://meek.azureedge.net/",
        "front": "ajax.aspnetcdn.com"
    }
)


class PluggableTransportManager:
    """
    Manages pluggable transport binaries and Tor bridge configuration.
    """

    def __init__(self, config: BridgeConfig):
        self.config = config
        self._obfs4proxy_proc: Optional[subprocess.Popen] = None
        self._snowflake_proc: Optional[subprocess.Popen] = None

    def detect_transports(self) -> dict[BridgeType, Optional[str]]:
        """
        Detect available pluggable transport binaries.

        Returns dict mapping transport type to binary path.
        """
        transports = {}

        # Look for obfs4proxy
        obfs4_names = ["obfs4proxy", "obfs4proxy.exe", "lyrebird", "lyrebird.exe"]
        for name in obfs4_names:
            path = shutil.which(name)
            if path:
                transports[BridgeType.OBFS4] = path
                break

        if self.config.obfs4proxy_path and Path(self.config.obfs4proxy_path).exists():
            transports[BridgeType.OBFS4] = self.config.obfs4proxy_path

        # Look for snowflake-client
        snowflake_names = ["snowflake-client", "snowflake-client.exe"]
        for name in snowflake_names:
            path = shutil.which(name)
            if path:
                transports[BridgeType.SNOWFLAKE] = path
                break

        if self.config.snowflake_path and Path(self.config.snowflake_path).exists():
            transports[BridgeType.SNOWFLAKE] = self.config.snowflake_path

        return transports

    def generate_torrc(self, data_dir: Path, socks_port: int = 9050) -> str:
        """
        Generate torrc configuration for bridges.

        Args:
            data_dir: Tor data directory
            socks_port: SOCKS port for this Tor instance

        Returns:
            torrc content string
        """
        lines = [
            f"DataDirectory {data_dir}",
            f"SocksPort {socks_port}",
            "UseBridges 1",
        ]

        # Get bridges to use
        if self.config.use_builtin_bridges and not self.config.bridges:
            if self.config.bridge_type == BridgeType.OBFS4:
                bridges = BUILTIN_OBFS4_BRIDGES
            elif self.config.bridge_type == BridgeType.SNOWFLAKE:
                bridges = [SNOWFLAKE_BRIDGE]
            elif self.config.bridge_type == BridgeType.MEEK_AZURE:
                bridges = [MEEK_AZURE_BRIDGE]
            else:
                bridges = []
        else:
            bridges = self.config.bridges

        # Add bridge lines
        for bridge in bridges:
            bridge_line = bridge.to_bridge_line()
            if bridge_line:
                lines.append(bridge_line)

        # Add transport plugin configuration
        transports = self.detect_transports()

        if BridgeType.OBFS4 in transports and self.config.bridge_type == BridgeType.OBFS4:
            lines.append(f"ClientTransportPlugin obfs4 exec {transports[BridgeType.OBFS4]}")

        if BridgeType.SNOWFLAKE in transports and self.config.bridge_type == BridgeType.SNOWFLAKE:
            lines.append(f"ClientTransportPlugin snowflake exec {transports[BridgeType.SNOWFLAKE]}")

        return "\n".join(lines)

    def get_install_instructions(self) -> str:
        """Get installation instructions for pluggable transports."""
        system = platform.system().lower()

        if system == "windows":
            return """
Pluggable Transport Installation (Windows):
1. Download Tor Browser from https://www.torproject.org/
2. The obfs4proxy.exe is included in: Tor Browser\\Browser\\TorBrowser\\Tor\\PluggableTransports\\
3. Add that path to your system PATH, or specify it in config

Alternative: Download standalone obfs4proxy from:
https://github.com/Yawning/obfs4/releases
"""
        elif system == "darwin":
            return """
Pluggable Transport Installation (macOS):
1. Using Homebrew: brew install obfs4proxy
2. Or download from Tor Browser bundle

For Snowflake:
brew install snowflake
"""
        else:  # Linux
            return """
Pluggable Transport Installation (Linux):
1. Ubuntu/Debian: sudo apt install obfs4proxy
2. Fedora: sudo dnf install obfs4
3. Arch: sudo pacman -S obfs4proxy

For Snowflake:
sudo apt install snowflake-client
"""

    async def check_transport_available(self, bridge_type: BridgeType) -> bool:
        """Check if the required pluggable transport is available."""
        transports = self.detect_transports()
        return bridge_type in transports


class TorBridgeConnector:
    """
    Connects to Tor network using bridges for stealth.

    This makes your Tor connection undetectable by:
    - Using obfs4 to obfuscate traffic patterns
    - Using meek to disguise as cloud service traffic
    - Using snowflake to use WebRTC peer connections
    """

    def __init__(self, bridge_config: BridgeConfig, socks_port: int = 9050):
        self.config = bridge_config
        self.socks_port = socks_port
        self.pt_manager = PluggableTransportManager(bridge_config)
        self._tor_process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None

    async def start_tor_with_bridges(self) -> tuple[str, int]:
        """
        Start a Tor process configured with bridges.

        Returns:
            Tuple of (socks_host, socks_port)
        """
        # Check if transport is available
        if not await self.pt_manager.check_transport_available(self.config.bridge_type):
            logger.warning(
                f"Pluggable transport {self.config.bridge_type.value} not found",
            )
            print(self.pt_manager.get_install_instructions())
            raise RuntimeError(f"Pluggable transport {self.config.bridge_type.value} not installed")

        # Create temp directory for Tor data
        self._temp_dir = tempfile.TemporaryDirectory(prefix="shadow9_tor_")
        data_dir = Path(self._temp_dir.name)

        # Generate torrc with specified port
        torrc_content = self.pt_manager.generate_torrc(data_dir, self.socks_port)
        torrc_path = data_dir / "torrc"
        torrc_path.write_text(torrc_content)

        logger.info(
            "Starting Tor with bridges",
            bridge_type=self.config.bridge_type.value,
            socks_port=self.socks_port,
            torrc=str(torrc_path)
        )

        # Find tor binary
        tor_path = shutil.which("tor")
        if not tor_path:
            raise RuntimeError("Tor not found. Please install Tor.")

        # Start Tor process
        self._tor_process = subprocess.Popen(
            [tor_path, "-f", str(torrc_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for Tor to bootstrap
        await self._wait_for_bootstrap()

        return "127.0.0.1", self.socks_port

    async def _wait_for_bootstrap(self, timeout: int = 120) -> None:
        """Wait for Tor to finish bootstrapping."""
        logger.info("Waiting for Tor to bootstrap...", socks_port=self.socks_port)

        start_time = asyncio.get_event_loop().time()

        while True:
            if asyncio.get_event_loop().time() - start_time > timeout:
                raise RuntimeError("Tor bootstrap timeout")

            if self._tor_process.poll() is not None:
                stderr = self._tor_process.stderr.read().decode() if self._tor_process.stderr else ""
                raise RuntimeError(f"Tor process died: {stderr}")

            # Check if Tor is ready by trying to connect to SOCKS port
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.socks_port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                logger.info("Tor bootstrap complete", socks_port=self.socks_port)
                return
            except (ConnectionRefusedError, asyncio.TimeoutError):
                await asyncio.sleep(2)

    async def stop(self) -> None:
        """Stop Tor process and cleanup."""
        if self._tor_process:
            self._tor_process.terminate()
            try:
                self._tor_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._tor_process.kill()
            self._tor_process = None

        if self._temp_dir:
            self._temp_dir.cleanup()
            self._temp_dir = None

        logger.info("Tor with bridges stopped")


def get_bridge_preset(bridge_type: BridgeType) -> BridgeConfig:
    """Get a bridge configuration preset."""
    if bridge_type == BridgeType.NONE:
        return BridgeConfig(enabled=False)

    return BridgeConfig(
        enabled=True,
        bridge_type=bridge_type,
        use_builtin_bridges=True,
    )


def print_bridge_info(config: BridgeConfig) -> str:
    """Generate human-readable bridge configuration summary."""
    if not config.enabled:
        return "Bridges: Disabled (Tor connection may be detectable)"

    lines = [
        f"Bridge Type: {config.bridge_type.value.upper()}",
    ]

    if config.bridge_type == BridgeType.OBFS4:
        lines.append("  → Traffic looks like random noise")
        lines.append("  → Most effective against DPI")
    elif config.bridge_type == BridgeType.MEEK_AZURE:
        lines.append("  → Traffic looks like Microsoft Azure")
        lines.append("  → Good for networks blocking Tor")
    elif config.bridge_type == BridgeType.SNOWFLAKE:
        lines.append("  → Uses WebRTC peer connections")
        lines.append("  → Hard to block, uses volunteer proxies")

    if config.use_builtin_bridges:
        lines.append("Using: Built-in public bridges")
    else:
        lines.append(f"Using: {len(config.bridges)} custom bridge(s)")

    return "\n".join(lines)
