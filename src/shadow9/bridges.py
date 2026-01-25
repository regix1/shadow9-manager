"""
Tor Bridge and Pluggable Transport Support for Shadow9.

Provides stealth Tor connectivity using:
- obfs4 bridges (most effective against DPI)

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

# Built-in snowflake configurations (multiple options for reliability)
# Updated January 2025 - fixes bootstrap issues from March 2024
# See: https://forum.torproject.org/t/fix-problems-with-snowflake-since-2024-03-01-broker-failure-unexpected-error-no-answer/11755
# See: https://github.com/net4people/bbs/issues/338

# Common STUN servers (from official Tor Browser build)
_STUN_SERVERS = ",".join([
    "stun:stun.l.google.com:19302",
    "stun:stun.antisip.com:3478",
    "stun:stun.bluesip.net:3478",
    "stun:stun.dus.net:3478",
    "stun:stun.epygi.com:3478",
    "stun:stun.sonetel.com:3478",
    "stun:stun.uls.co.za:3478",
    "stun:stun.voipgate.com:3478",
    "stun:stun.voys.nl:3478"
])

# Primary: CDN77 (official Tor Project choice as of 2025)
SNOWFLAKE_BRIDGE_CDN77 = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.3:80",  # Dummy address, snowflake uses STUN/TURN
    fingerprint="2B280B23E1107BB62ABFC40DDCC8824814F80A72",
    params={
        "url": "https://1098762253.rsc.cdn77.org/",
        "front": "www.phpmyadmin.net",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# CDN77 with alternative front domain
SNOWFLAKE_BRIDGE_CDN77_ALT = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.4:80",
    fingerprint="8838024498816A039FCBBAB14E6F40A0843051FA",
    params={
        "url": "https://1098762253.rsc.cdn77.org/",
        "front": "docs.plesk.com",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# AMP Cache with Google fronting (good alternative)
SNOWFLAKE_BRIDGE_AMP = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.5:80",
    fingerprint="2B280B23E1107BB62ABFC40DDCC8824814F80A72",
    params={
        "url": "https://snowflake-broker.torproject.net/",
        "ampcache": "https://cdn.ampproject.org/",
        "front": "www.google.com",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# Fastly with Shazam fronting
SNOWFLAKE_BRIDGE_FASTLY_SHAZAM = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.6:80",
    fingerprint="2B280B23E1107BB62ABFC40DDCC8824814F80A72",
    params={
        "url": "https://snowflake-broker.torproject.net.global.prod.fastly.net/",
        "front": "www.shazam.com",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# Fastly with Foursquare fronting
SNOWFLAKE_BRIDGE_FASTLY_FOURSQUARE = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.7:80",
    fingerprint="2B280B23E1107BB62ABFC40DDCC8824814F80A72",
    params={
        "url": "https://snowflake-broker.torproject.net.global.prod.fastly.net/",
        "front": "foursquare.com",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# Bunny CDN (Triplebit private broker - independent infrastructure)
SNOWFLAKE_BRIDGE_BUNNY = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="10.0.3.1:80",
    fingerprint="53B65F538F5E9A5FA6DFE5D75C78CB66C5515EF7",
    params={
        "url": "https://triplebit-snowflake-broker.b-cdn.net/",
        "front": "www.bunny.net",
        "ice": _STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# All snowflake bridges for fallback (ordered by reliability)
SNOWFLAKE_BRIDGES = [
    SNOWFLAKE_BRIDGE_CDN77,           # Primary - official Tor choice
    SNOWFLAKE_BRIDGE_CDN77_ALT,       # CDN77 alt front
    SNOWFLAKE_BRIDGE_AMP,             # Google AMP cache
    SNOWFLAKE_BRIDGE_FASTLY_SHAZAM,   # Fastly + Shazam
    SNOWFLAKE_BRIDGE_FASTLY_FOURSQUARE,  # Fastly + Foursquare
    SNOWFLAKE_BRIDGE_BUNNY,           # Bunny CDN (independent)
]

# Backwards compatibility alias (now points to CDN77)
SNOWFLAKE_BRIDGE = SNOWFLAKE_BRIDGE_CDN77

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

    def generate_torrc(
        self, 
        data_dir: Path, 
        socks_port: int = 9050, 
        control_port: int = 0,
        specific_bridge: Optional[Bridge] = None
    ) -> str:
        """
        Generate torrc configuration for bridges.

        Args:
            data_dir: Tor data directory
            socks_port: SOCKS port for this Tor instance
            control_port: Control port for this Tor instance (0 = auto-assign)
            specific_bridge: If provided, use only this specific bridge (for fallback testing)

        Returns:
            torrc content string
        """
        lines = [
            f"DataDirectory {data_dir}",
            f"SocksPort {socks_port}",
            "UseBridges 1",
        ]

        # Add control port for bootstrap monitoring
        if control_port > 0:
            lines.append(f"ControlPort {control_port}")
        else:
            # Use auto port assignment with a socket file
            control_socket = data_dir / "control.sock"
            lines.append(f"ControlSocket {control_socket}")

        # Get bridges to use
        if specific_bridge:
            # Use only the specific bridge for fallback testing
            bridges = [specific_bridge]
        elif self.config.use_builtin_bridges and not self.config.bridges:
            if self.config.bridge_type == BridgeType.OBFS4:
                bridges = BUILTIN_OBFS4_BRIDGES
            elif self.config.bridge_type == BridgeType.SNOWFLAKE:
                # For snowflake, just use the first bridge - fallback is handled at higher level
                bridges = [SNOWFLAKE_BRIDGES[0]] if SNOWFLAKE_BRIDGES else []
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
    
    def get_fallback_bridges(self) -> List[Bridge]:
        """Get list of bridges to try for fallback."""
        if self.config.bridge_type == BridgeType.SNOWFLAKE:
            return SNOWFLAKE_BRIDGES
        elif self.config.bridge_type == BridgeType.OBFS4:
            return BUILTIN_OBFS4_BRIDGES
        return []

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

    - Using snowflake to use WebRTC peer connections
    """

    def __init__(self, bridge_config: BridgeConfig, socks_port: int = 9050):
        self.config = bridge_config
        self.socks_port = socks_port
        self.pt_manager = PluggableTransportManager(bridge_config)
        self._tor_process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._data_dir: Optional[Path] = None
        self._log_file: Optional[Path] = None
        self._current_bridge: Optional[Bridge] = None  # Track which bridge is working

    async def start_tor_with_bridges(self) -> tuple[str, int]:
        """
        Start a Tor process configured with bridges.
        
        For snowflake bridges, this will try each bridge in SNOWFLAKE_BRIDGES
        until one successfully bootstraps.

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

        # Get list of bridges to try
        fallback_bridges = self.pt_manager.get_fallback_bridges()
        
        if not fallback_bridges:
            # No fallback list, use default behavior
            return await self._try_single_bridge(None)
        
        # Try each bridge until one works
        last_error = None
        for i, bridge in enumerate(fallback_bridges):
            bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))
            logger.info(
                f"Trying bridge {i+1}/{len(fallback_bridges)}: {bridge_name}",
                bridge_type=self.config.bridge_type.value
            )
            print(f"  Trying bridge {i+1}/{len(fallback_bridges)}: {bridge_name}")
            
            try:
                result = await self._try_single_bridge(bridge, timeout=120)  # 2 min per bridge
                self._current_bridge = bridge
                logger.info(f"Successfully connected using bridge: {bridge_name}")
                print(f"  ✓ Connected using: {bridge_name}")
                return result
            except RuntimeError as e:
                last_error = e
                logger.warning(f"Bridge {bridge_name} failed: {e}")
                print(f"  ✗ Bridge failed: {bridge_name}")
                # Cleanup before trying next bridge
                await self._cleanup_tor()
                continue
        
        # All bridges failed
        raise RuntimeError(f"All {len(fallback_bridges)} bridges failed to connect. Last error: {last_error}")

    async def _try_single_bridge(self, bridge: Optional[Bridge], timeout: int = 180) -> tuple[str, int]:
        """
        Try to start Tor with a specific bridge.
        
        Args:
            bridge: Specific bridge to use, or None for default behavior
            timeout: Bootstrap timeout in seconds
            
        Returns:
            Tuple of (socks_host, socks_port)
        """
        # Create temp directory for Tor data
        self._temp_dir = tempfile.TemporaryDirectory(prefix="shadow9_tor_")
        self._data_dir = Path(self._temp_dir.name)

        # Generate torrc with specified port and specific bridge
        torrc_content = self.pt_manager.generate_torrc(
            self._data_dir, 
            self.socks_port,
            specific_bridge=bridge
        )
        
        # Add log file to torrc for bootstrap monitoring
        self._log_file = self._data_dir / "tor.log"
        torrc_content += f"\nLog notice file {self._log_file}"
        
        torrc_path = self._data_dir / "torrc"
        torrc_path.write_text(torrc_content)

        bridge_name = "default"
        if bridge:
            bridge_name = bridge.params.get("front", bridge.params.get("url", "unknown"))

        logger.info(
            "Starting Tor with bridges",
            bridge_type=self.config.bridge_type.value,
            bridge=bridge_name,
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
        await self._wait_for_bootstrap(timeout=timeout)

        return "127.0.0.1", self.socks_port
    
    async def _cleanup_tor(self) -> None:
        """Cleanup Tor process and temp directory without logging stop message."""
        if self._tor_process:
            self._tor_process.terminate()
            try:
                self._tor_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._tor_process.kill()
            self._tor_process = None

        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception:
                pass
            self._temp_dir = None

    async def _wait_for_bootstrap(self, timeout: int = 180) -> None:
        """Wait for Tor to finish bootstrapping by monitoring the log file."""
        import re
        
        logger.info("Waiting for Tor to bootstrap...", socks_port=self.socks_port)

        start_time = asyncio.get_event_loop().time()
        last_progress = 0
        log_position = 0

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if elapsed > timeout:
                raise RuntimeError(f"Tor bootstrap timeout after {timeout}s (last progress: {last_progress}%)")

            if self._tor_process.poll() is not None:
                stderr = self._tor_process.stderr.read().decode() if self._tor_process.stderr else ""
                raise RuntimeError(f"Tor process died: {stderr}")

            # Read from log file
            if hasattr(self, '_log_file') and self._log_file.exists():
                try:
                    with open(self._log_file, 'r') as f:
                        f.seek(log_position)
                        new_content = f.read()
                        log_position = f.tell()
                        
                        for line in new_content.splitlines():
                            # Look for bootstrap progress
                            if 'Bootstrapped' in line:
                                match = re.search(r'Bootstrapped (\d+)%', line)
                                if match:
                                    progress = int(match.group(1))
                                    if progress != last_progress:
                                        last_progress = progress
                                        logger.info(f"Tor bootstrap: {progress}%")
                                    if progress >= 100:
                                        # Give it a moment to fully stabilize
                                        await asyncio.sleep(1)
                                        logger.info("Tor bootstrap complete", socks_port=self.socks_port)
                                        return
                except Exception as e:
                    logger.debug(f"Error reading log file: {e}")

            # Fallback: check if SOCKS port is actually working after some time
            if elapsed > 30:  # After 30s, try a connection test
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection("127.0.0.1", self.socks_port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    if last_progress >= 95:  # Close enough
                        logger.info("Tor bootstrap complete (connection test)", socks_port=self.socks_port)
                        return
                except (ConnectionRefusedError, asyncio.TimeoutError):
                    pass

            await asyncio.sleep(1)

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
    elif config.bridge_type == BridgeType.SNOWFLAKE:
        lines.append("  → Uses WebRTC peer connections")
        lines.append("  → Hard to block, uses volunteer proxies")

    if config.use_builtin_bridges:
        lines.append("Using: Built-in public bridges")
    else:
        lines.append(f"Using: {len(config.bridges)} custom bridge(s)")

    return "\n".join(lines)
