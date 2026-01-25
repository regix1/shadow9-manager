"""
Tor Network Connector for Shadow9.

Provides connectivity to the Tor network through the local Tor SOCKS5 proxy.
Supports .onion address resolution and circuit management.
"""

import asyncio
import socket
import struct
import platform
import shutil
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum

import structlog
from aiohttp_socks import ProxyConnector
import aiohttp

logger = structlog.get_logger(__name__)


class TorStatus(Enum):
    """Tor connection status."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class TorConfig:
    """Configuration for Tor connection."""
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050  # Default Tor SOCKS port
    control_port: int = 9051  # Default Tor control port
    control_password: Optional[str] = None
    timeout: float = 60.0


@dataclass
class TorCircuitInfo:
    """Information about current Tor circuit."""
    exit_ip: Optional[str] = None
    exit_country: Optional[str] = None
    circuit_id: Optional[str] = None


class TorConnector:
    """
    Manages connection to the Tor network.

    Features:
    - Connection to local Tor SOCKS5 proxy
    - .onion address support
    - Circuit information retrieval
    - Automatic Tor service detection
    - HTTP client with Tor routing
    """

    # Tor check URLs
    TOR_CHECK_URL = "https://check.torproject.org/api/ip"
    TOR_CHECK_URL_BACKUP = "https://check.torproject.org/"

    def __init__(self, config: Optional[TorConfig] = None):
        """
        Initialize the Tor connector.

        Args:
            config: Tor configuration (uses defaults if not provided)
        """
        self.config = config or TorConfig()
        self._status = TorStatus.DISCONNECTED
        self._circuit_info: Optional[TorCircuitInfo] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._status_callback: Optional[Callable[[TorStatus], Awaitable[None]]] = None

    @property
    def status(self) -> TorStatus:
        """Get current Tor connection status."""
        return self._status

    @property
    def is_connected(self) -> bool:
        """Check if connected to Tor network."""
        return self._status == TorStatus.CONNECTED

    @property
    def circuit_info(self) -> Optional[TorCircuitInfo]:
        """Get current circuit information."""
        return self._circuit_info

    async def _set_status(self, status: TorStatus) -> None:
        """Update status and notify callback."""
        self._status = status
        if self._status_callback:
            await self._status_callback(status)

    def set_status_callback(self, callback: Callable[[TorStatus], Awaitable[None]]) -> None:
        """Set callback for status changes."""
        self._status_callback = callback

    async def connect(self) -> bool:
        """
        Connect to the Tor network through the local proxy.

        Returns:
            True if connection successful, False otherwise
        """
        await self._set_status(TorStatus.CONNECTING)

        try:
            # First check if Tor is running
            if not await self._check_tor_running():
                logger.error("Tor service not detected")
                await self._set_status(TorStatus.ERROR)
                return False

            # Create aiohttp session with SOCKS5 proxy
            connector = ProxyConnector.from_url(
                f"socks5://{self.config.socks_host}:{self.config.socks_port}",
                rdns=True  # Enable remote DNS resolution for .onion
            )
            self._session = aiohttp.ClientSession(connector=connector)

            # Verify Tor connection by checking exit IP
            await self._verify_tor_connection()

            await self._set_status(TorStatus.CONNECTED)
            logger.info(
                "Connected to Tor network",
                exit_ip=self._circuit_info.exit_ip if self._circuit_info else "unknown"
            )
            return True

        except Exception as e:
            logger.error("Failed to connect to Tor", error=str(e))
            await self._set_status(TorStatus.ERROR)
            # Close session if it was created
            if self._session:
                await self._session.close()
                self._session = None
            return False

    async def disconnect(self) -> None:
        """Disconnect from Tor network."""
        if self._session:
            await self._session.close()
            self._session = None

        self._circuit_info = None
        await self._set_status(TorStatus.DISCONNECTED)
        logger.info("Disconnected from Tor network")

    async def _check_tor_running(self) -> bool:
        """Check if Tor service is running and accessible."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.socks_host, self.config.socks_port),
                timeout=5.0
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            return False

    async def _verify_tor_connection(self) -> None:
        """Verify we're actually connected through Tor."""
        if not self._session:
            raise RuntimeError("Session not initialized")

        try:
            async with self._session.get(
                self.TOR_CHECK_URL,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get("IsTor", False):
                        self._circuit_info = TorCircuitInfo(
                            exit_ip=data.get("IP")
                        )
                        return
                    else:
                        raise RuntimeError("Traffic not routed through Tor")
                else:
                    raise RuntimeError(f"Tor check failed: HTTP {response.status}")

        except aiohttp.ClientError as e:
            # Try backup check
            try:
                async with self._session.get(
                    self.TOR_CHECK_URL_BACKUP,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    text = await response.text()
                    if "Congratulations" in text and "Tor" in text:
                        self._circuit_info = TorCircuitInfo()
                        return
                    else:
                        raise RuntimeError("Traffic not routed through Tor")
            except Exception:
                raise RuntimeError(f"Could not verify Tor connection: {e}")

    async def get_new_circuit(self) -> bool:
        """
        Request a new Tor circuit (new identity).

        Requires Tor control port access with authentication.
        """
        if not self.config.control_password:
            logger.warning("Control password not set, cannot request new circuit")
            return False

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.socks_host, self.config.control_port),
                timeout=5.0
            )

            # Authenticate
            writer.write(f'AUTHENTICATE "{self.config.control_password}"\r\n'.encode())
            await writer.drain()
            response = await reader.readline()

            if not response.startswith(b"250"):
                logger.error("Tor control authentication failed")
                writer.close()
                return False

            # Request new circuit
            writer.write(b"SIGNAL NEWNYM\r\n")
            await writer.drain()
            response = await reader.readline()

            writer.close()
            await writer.wait_closed()

            if response.startswith(b"250"):
                logger.info("New Tor circuit requested")
                # Wait for circuit to establish
                await asyncio.sleep(10)
                # Refresh circuit info
                await self._verify_tor_connection()
                return True

            return False

        except Exception as e:
            logger.error("Failed to request new circuit", error=str(e))
            return False

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[bytes] = None,
        timeout: float = 60.0
    ) -> aiohttp.ClientResponse:
        """
        Fetch a URL through Tor.

        Args:
            url: URL to fetch (supports .onion)
            method: HTTP method
            headers: Optional headers
            data: Optional request body
            timeout: Request timeout

        Returns:
            aiohttp ClientResponse
        """
        if not self._session:
            raise RuntimeError("Not connected to Tor")

        async with self._session.request(
            method,
            url,
            headers=headers,
            data=data,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            # Read content to keep it available after context exit
            await response.read()
            return response

    async def fetch_text(self, url: str, timeout: float = 60.0) -> str:
        """Fetch URL and return text content."""
        if not self._session:
            raise RuntimeError("Not connected to Tor")

        async with self._session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            return await response.text()

    async def check_onion_available(self, onion_url: str) -> bool:
        """
        Check if an .onion address is reachable.

        Args:
            onion_url: The .onion URL to check

        Returns:
            True if reachable, False otherwise
        """
        if not self._session:
            raise RuntimeError("Not connected to Tor")

        try:
            async with self._session.head(
                onion_url,
                timeout=aiohttp.ClientTimeout(total=30),
                allow_redirects=True
            ) as response:
                return response.status < 500
        except Exception:
            return False

    def get_socks_proxy(self) -> tuple[str, int]:
        """Get the SOCKS5 proxy address for external use."""
        return self.config.socks_host, self.config.socks_port

    @staticmethod
    def detect_tor_service() -> Optional[TorConfig]:
        """
        Detect running Tor service and return configuration.

        Returns:
            TorConfig if Tor found, None otherwise
        """
        # Common Tor configurations
        configs_to_try = [
            TorConfig(socks_port=9050),  # Standard Tor daemon
            TorConfig(socks_port=9150),  # Tor Browser
            TorConfig(socks_port=9250),  # Tor Expert Bundle
        ]

        for config in configs_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((config.socks_host, config.socks_port))
                sock.close()

                if result == 0:
                    logger.info(f"Detected Tor on port {config.socks_port}")
                    return config
            except Exception:
                continue

        return None

    @staticmethod
    def check_tor_installed() -> bool:
        """Check if Tor is installed on the system."""
        return shutil.which("tor") is not None

    @staticmethod
    def get_tor_install_instructions() -> str:
        """Get Tor installation instructions for the current platform."""
        system = platform.system().lower()

        if system == "windows":
            return (
                "Tor Installation for Windows:\n"
                "1. Download Tor Browser from https://www.torproject.org/\n"
                "2. Or install Tor Expert Bundle\n"
                "3. Ensure Tor is running before using shadow9-manager"
            )
        elif system == "darwin":  # macOS
            return (
                "Tor Installation for macOS:\n"
                "1. Using Homebrew: brew install tor\n"
                "2. Start Tor: brew services start tor\n"
                "3. Or download Tor Browser from https://www.torproject.org/"
            )
        elif system == "linux":
            return (
                "Tor Installation for Linux:\n"
                "1. Ubuntu/Debian: sudo apt install tor\n"
                "2. Fedora: sudo dnf install tor\n"
                "3. Arch: sudo pacman -S tor\n"
                "4. Start Tor: sudo systemctl start tor"
            )
        else:
            return "Visit https://www.torproject.org/ for installation instructions"

    async def __aenter__(self) -> 'TorConnector':
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()


class TorProxyBridge:
    """
    Bridges the local SOCKS5 server to Tor network.

    This allows the SOCKS5 server to route connections through Tor,
    enabling .onion access for connected clients.
    """

    def __init__(self, tor_connector: TorConnector):
        """
        Initialize the Tor proxy bridge.

        Args:
            tor_connector: Active Tor connector instance
        """
        self.tor = tor_connector

    async def create_connection(
        self,
        target_host: str,
        target_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create a connection to target through Tor.

        Args:
            target_host: Target hostname (can be .onion)
            target_port: Target port

        Returns:
            Tuple of (reader, writer) for the connection
        """
        if not self.tor.is_connected:
            raise RuntimeError("Tor not connected")

        socks_host, socks_port = self.tor.get_socks_proxy()

        # Connect to Tor SOCKS5 proxy
        reader, writer = await asyncio.open_connection(socks_host, socks_port)

        # SOCKS5 handshake (no auth for local Tor)
        writer.write(struct.pack("!BBB", 0x05, 1, 0x00))
        await writer.drain()

        response = await reader.readexactly(2)
        if response[1] != 0x00:
            raise RuntimeError("Tor SOCKS5 handshake failed")

        # CONNECT request
        if target_host.endswith('.onion') or not self._is_ip(target_host):
            # Domain name
            domain_bytes = target_host.encode('utf-8')
            request = struct.pack(
                "!BBBBB",
                0x05, 0x01, 0x00, 0x03, len(domain_bytes)
            ) + domain_bytes + struct.pack("!H", target_port)
        else:
            # IP address
            addr_bytes = socket.inet_aton(target_host)
            request = struct.pack(
                "!BBBB4sH",
                0x05, 0x01, 0x00, 0x01, addr_bytes, target_port
            )

        writer.write(request)
        await writer.drain()

        # Read response
        response = await reader.readexactly(4)
        if response[1] != 0x00:
            error_codes = {
                0x01: "General SOCKS server failure",
                0x02: "Connection not allowed",
                0x03: "Network unreachable",
                0x04: "Host unreachable",
                0x05: "Connection refused",
                0x06: "TTL expired",
                0x07: "Command not supported",
                0x08: "Address type not supported",
            }
            msg = error_codes.get(response[1], f"Unknown error: {response[1]}")
            raise RuntimeError(f"Tor connection failed: {msg}")

        # Skip bound address
        atyp = response[3]
        if atyp == 0x01:  # IPv4
            await reader.readexactly(6)
        elif atyp == 0x03:  # Domain
            dlen = struct.unpack("!B", await reader.readexactly(1))[0]
            await reader.readexactly(dlen + 2)
        elif atyp == 0x04:  # IPv6
            await reader.readexactly(18)

        logger.debug("Tor connection established", target=f"{target_host}:{target_port}")
        return reader, writer

    @staticmethod
    def _is_ip(addr: str) -> bool:
        """Check if address is an IP."""
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, addr)
                return True
            except socket.error:
                return False
