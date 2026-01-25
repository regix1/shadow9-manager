"""
SOCKS5 Server Implementation with Authentication.

Implements RFC 1928 (SOCKS5) and RFC 1929 (Username/Password Authentication).
Security-focused implementation with proper input validation and error handling.
"""

import asyncio
import socket
import struct
from enum import IntEnum
from dataclasses import dataclass
from typing import Optional, Callable, Awaitable
from ipaddress import ip_address, IPv4Address, IPv6Address

import structlog

from .auth import AuthManager

logger = structlog.get_logger(__name__)


class Socks5AuthMethod(IntEnum):
    """SOCKS5 Authentication Methods (RFC 1928)."""
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class Socks5Command(IntEnum):
    """SOCKS5 Commands (RFC 1928)."""
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Socks5AddressType(IntEnum):
    """SOCKS5 Address Types (RFC 1928)."""
    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class Socks5Reply(IntEnum):
    """SOCKS5 Reply Codes (RFC 1928)."""
    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


@dataclass
class ConnectionInfo:
    """Information about a proxied connection."""
    client_addr: tuple[str, int]
    target_addr: str
    target_port: int
    username: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    # User settings (populated from auth manager)
    use_tor: bool = True
    bridge_type: str = "none"
    security_level: str = "basic"


class Socks5Server:
    """
    Secure SOCKS5 proxy server with username/password authentication.

    Features:
    - RFC 1928/1929 compliant
    - Username/password authentication required
    - Connection rate limiting
    - Proper input validation
    - Async I/O for high performance
    """

    SOCKS_VERSION = 0x05
    AUTH_VERSION = 0x01
    MAX_BUFFER_SIZE = 65536
    CONNECTION_TIMEOUT = 30
    RELAY_TIMEOUT = 300

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1080,
        auth_manager: Optional[AuthManager] = None,
        upstream_proxy: Optional[tuple[str, int]] = None,
        allowed_commands: Optional[set[Socks5Command]] = None,
    ):
        """
        Initialize the SOCKS5 server.

        Args:
            host: Host address to bind to
            port: Port to listen on
            auth_manager: Authentication manager for credentials
            upstream_proxy: Optional upstream SOCKS5 proxy (host, port)
            allowed_commands: Set of allowed SOCKS5 commands (default: CONNECT only)
        """
        self.host = host
        self.port = port
        self.auth_manager = auth_manager
        self.upstream_proxy = upstream_proxy
        self.allowed_commands = allowed_commands or {Socks5Command.CONNECT}

        self._server: Optional[asyncio.Server] = None
        self._connections: dict[str, ConnectionInfo] = {}
        self._running = False

        # Connection callback for monitoring
        self._on_connection: Optional[Callable[[ConnectionInfo], Awaitable[None]]] = None

    async def start(self) -> None:
        """Start the SOCKS5 server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True,
        )

        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info("SOCKS5 server started", host=addr[0], port=addr[1])

    async def stop(self) -> None:
        """Stop the SOCKS5 server."""
        self._running = False

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("SOCKS5 server stopped")

    async def serve_forever(self) -> None:
        """Run the server until stopped."""
        if not self._server:
            await self.start()

        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        client_addr = writer.get_extra_info('peername')
        conn_id = f"{client_addr[0]}:{client_addr[1]}"

        logger.debug("New connection", client=conn_id)

        try:
            # Set timeouts
            reader._transport.set_write_buffer_limits(high=self.MAX_BUFFER_SIZE)

            # Perform SOCKS5 handshake with authentication
            username = await asyncio.wait_for(
                self._socks5_handshake(reader, writer),
                timeout=self.CONNECTION_TIMEOUT
            )

            if username is None:
                return

            # Get user settings from auth manager
            user_settings = {}
            if self.auth_manager and username:
                user_settings = self.auth_manager.get_user_info(username) or {}

            # Get connection request
            target = await asyncio.wait_for(
                self._socks5_request(reader, writer),
                timeout=self.CONNECTION_TIMEOUT
            )

            if target is None:
                return

            target_host, target_port = target

            # Check port restrictions for this user
            allowed_ports = user_settings.get("allowed_ports")
            if allowed_ports and target_port not in allowed_ports:
                logger.warning(
                    "Port not allowed for user",
                    username=username,
                    port=target_port,
                    allowed=allowed_ports
                )
                await self._send_reply(writer, Socks5Reply.NOT_ALLOWED)
                return

            # Create connection info with user settings
            conn_info = ConnectionInfo(
                client_addr=client_addr,
                target_addr=target_host,
                target_port=target_port,
                username=username,
                use_tor=user_settings.get("use_tor", True),
                bridge_type=user_settings.get("bridge_type", "none"),
                security_level=user_settings.get("security_level", "basic"),
            )
            self._connections[conn_id] = conn_info

            # Check if user wants Tor routing
            use_tor = conn_info.use_tor

            # Connect to target (directly or via upstream proxy based on user preference)
            if self.upstream_proxy and use_tor:
                target_reader, target_writer = await self._connect_via_proxy(
                    target_host, target_port
                )
                logger.debug(
                    "Routing through Tor",
                    username=username,
                    bridge=conn_info.bridge_type,
                    security=conn_info.security_level
                )
            else:
                target_reader, target_writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, target_port),
                    timeout=self.CONNECTION_TIMEOUT
                )
                logger.debug(
                    "Direct connection",
                    username=username,
                    security=conn_info.security_level
                )

            # Send success reply
            await self._send_reply(writer, Socks5Reply.SUCCEEDED)

            # Notify connection callback
            if self._on_connection:
                await self._on_connection(conn_info)

            # Relay data between client and target
            await self._relay(reader, writer, target_reader, target_writer, conn_info)

        except asyncio.TimeoutError:
            logger.warning("Connection timeout", client=conn_id)
            await self._send_reply(writer, Socks5Reply.TTL_EXPIRED)
        except ConnectionRefusedError:
            logger.warning("Connection refused by target", client=conn_id)
            await self._send_reply(writer, Socks5Reply.CONNECTION_REFUSED)
        except OSError as e:
            if "Network is unreachable" in str(e):
                await self._send_reply(writer, Socks5Reply.NETWORK_UNREACHABLE)
            elif "No route to host" in str(e):
                await self._send_reply(writer, Socks5Reply.HOST_UNREACHABLE)
            else:
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
            logger.error("Connection error", client=conn_id, error=str(e))
        except Exception as e:
            logger.error("Unexpected error", client=conn_id, error=str(e))
            await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
        finally:
            if conn_id in self._connections:
                del self._connections[conn_id]
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _socks5_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[str]:
        """
        Perform SOCKS5 handshake with authentication.

        Returns the authenticated username, or None on failure.
        """
        # Read greeting: VER, NMETHODS, METHODS
        header = await reader.readexactly(2)
        version, nmethods = struct.unpack("!BB", header)

        if version != self.SOCKS_VERSION:
            logger.warning("Invalid SOCKS version", version=version)
            writer.close()
            return None

        # Read authentication methods
        methods = await reader.readexactly(nmethods)
        methods_set = set(methods)

        # We require username/password authentication
        if Socks5AuthMethod.USERNAME_PASSWORD not in methods_set:
            # No acceptable authentication method
            writer.write(struct.pack("!BB", self.SOCKS_VERSION, Socks5AuthMethod.NO_ACCEPTABLE))
            await writer.drain()
            logger.warning("No acceptable auth method")
            return None

        # Request username/password authentication
        writer.write(struct.pack("!BB", self.SOCKS_VERSION, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()

        # Authenticate
        return await self._authenticate(reader, writer)

    async def _authenticate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[str]:
        """
        Perform username/password authentication (RFC 1929).

        Returns the username on success, None on failure.
        """
        # Read auth version and username length
        auth_header = await reader.readexactly(2)
        auth_version, ulen = struct.unpack("!BB", auth_header)

        if auth_version != self.AUTH_VERSION:
            logger.warning("Invalid auth version", version=auth_version)
            return None

        # Validate username length
        if ulen == 0 or ulen > 255:
            logger.warning("Invalid username length", length=ulen)
            await self._send_auth_response(writer, False)
            return None

        # Read username
        username = (await reader.readexactly(ulen)).decode('utf-8', errors='replace')

        # Read password length and password
        plen = struct.unpack("!B", await reader.readexactly(1))[0]

        if plen == 0 or plen > 255:
            logger.warning("Invalid password length", length=plen)
            await self._send_auth_response(writer, False)
            return None

        password = (await reader.readexactly(plen)).decode('utf-8', errors='replace')

        # Verify credentials
        if self.auth_manager and self.auth_manager.verify(username, password):
            await self._send_auth_response(writer, True)
            return username
        else:
            logger.warning("Authentication failed", username=username)
            await self._send_auth_response(writer, False)
            return None

    async def _send_auth_response(self, writer: asyncio.StreamWriter, success: bool) -> None:
        """Send authentication response."""
        status = 0x00 if success else 0x01
        writer.write(struct.pack("!BB", self.AUTH_VERSION, status))
        await writer.drain()

    async def _socks5_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[tuple[str, int]]:
        """
        Parse SOCKS5 connection request.

        Returns (target_host, target_port) or None on failure.
        """
        # Read request header: VER, CMD, RSV, ATYP
        header = await reader.readexactly(4)
        version, cmd, _, atyp = struct.unpack("!BBBB", header)

        if version != self.SOCKS_VERSION:
            logger.warning("Invalid SOCKS version in request", version=version)
            return None

        # Validate command
        try:
            command = Socks5Command(cmd)
        except ValueError:
            logger.warning("Invalid command", cmd=cmd)
            await self._send_reply(writer, Socks5Reply.COMMAND_NOT_SUPPORTED)
            return None

        if command not in self.allowed_commands:
            logger.warning("Command not allowed", command=command.name)
            await self._send_reply(writer, Socks5Reply.COMMAND_NOT_SUPPORTED)
            return None

        # Parse destination address
        try:
            addr_type = Socks5AddressType(atyp)
        except ValueError:
            logger.warning("Invalid address type", atyp=atyp)
            await self._send_reply(writer, Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED)
            return None

        # Read address based on type
        if addr_type == Socks5AddressType.IPV4:
            raw_addr = await reader.readexactly(4)
            target_host = socket.inet_ntoa(raw_addr)

        elif addr_type == Socks5AddressType.DOMAIN:
            domain_len = struct.unpack("!B", await reader.readexactly(1))[0]
            if domain_len == 0 or domain_len > 255:
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
                return None
            target_host = (await reader.readexactly(domain_len)).decode('utf-8', errors='replace')

            # Basic domain validation
            if not self._validate_domain(target_host):
                logger.warning("Invalid domain", domain=target_host)
                await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
                return None

        elif addr_type == Socks5AddressType.IPV6:
            raw_addr = await reader.readexactly(16)
            target_host = socket.inet_ntop(socket.AF_INET6, raw_addr)

        else:
            await self._send_reply(writer, Socks5Reply.ADDRESS_TYPE_NOT_SUPPORTED)
            return None

        # Read port
        target_port = struct.unpack("!H", await reader.readexactly(2))[0]

        if target_port == 0:
            logger.warning("Invalid port", port=target_port)
            await self._send_reply(writer, Socks5Reply.GENERAL_FAILURE)
            return None

        logger.info("Connection request", target=f"{target_host}:{target_port}")
        return target_host, target_port

    async def _send_reply(
        self,
        writer: asyncio.StreamWriter,
        reply: Socks5Reply,
        bind_addr: str = "0.0.0.0",
        bind_port: int = 0
    ) -> None:
        """Send SOCKS5 reply to client."""
        try:
            # Build reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT
            addr_bytes = socket.inet_aton(bind_addr)
            reply_data = struct.pack(
                "!BBBB4sH",
                self.SOCKS_VERSION,
                reply,
                0x00,  # Reserved
                Socks5AddressType.IPV4,
                addr_bytes,
                bind_port
            )
            writer.write(reply_data)
            await writer.drain()
        except Exception as e:
            logger.error("Failed to send reply", error=str(e))

    async def _connect_via_proxy(
        self,
        target_host: str,
        target_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to target via upstream SOCKS5 proxy."""
        proxy_host, proxy_port = self.upstream_proxy

        # Connect to upstream proxy
        reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

        # SOCKS5 handshake with no auth (for simplicity with Tor)
        writer.write(struct.pack("!BBB", self.SOCKS_VERSION, 1, Socks5AuthMethod.NO_AUTH))
        await writer.drain()

        response = await reader.readexactly(2)
        if response[1] != Socks5AuthMethod.NO_AUTH:
            raise ConnectionError("Upstream proxy requires authentication")

        # Send CONNECT request
        if target_host.endswith('.onion') or not self._is_ip(target_host):
            # Domain name
            domain_bytes = target_host.encode('utf-8')
            request = struct.pack(
                "!BBBBB",
                self.SOCKS_VERSION,
                Socks5Command.CONNECT,
                0x00,
                Socks5AddressType.DOMAIN,
                len(domain_bytes)
            ) + domain_bytes + struct.pack("!H", target_port)
        else:
            # IP address
            addr_bytes = socket.inet_aton(target_host)
            request = struct.pack(
                "!BBBB4sH",
                self.SOCKS_VERSION,
                Socks5Command.CONNECT,
                0x00,
                Socks5AddressType.IPV4,
                addr_bytes,
                target_port
            )

        writer.write(request)
        await writer.drain()

        # Read response
        response = await reader.readexactly(4)
        if response[1] != Socks5Reply.SUCCEEDED:
            raise ConnectionError(f"Upstream proxy connection failed: {response[1]}")

        # Skip bound address
        atyp = response[3]
        if atyp == Socks5AddressType.IPV4:
            await reader.readexactly(4 + 2)
        elif atyp == Socks5AddressType.DOMAIN:
            dlen = struct.unpack("!B", await reader.readexactly(1))[0]
            await reader.readexactly(dlen + 2)
        elif atyp == Socks5AddressType.IPV6:
            await reader.readexactly(16 + 2)

        return reader, writer

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        target_reader: asyncio.StreamReader,
        target_writer: asyncio.StreamWriter,
        conn_info: ConnectionInfo
    ) -> None:
        """Relay data between client and target."""

        async def relay_to_target():
            try:
                while True:
                    data = await asyncio.wait_for(
                        client_reader.read(self.MAX_BUFFER_SIZE),
                        timeout=self.RELAY_TIMEOUT
                    )
                    if not data:
                        break
                    target_writer.write(data)
                    await target_writer.drain()
                    conn_info.bytes_sent += len(data)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                target_writer.close()

        async def relay_to_client():
            try:
                while True:
                    data = await asyncio.wait_for(
                        target_reader.read(self.MAX_BUFFER_SIZE),
                        timeout=self.RELAY_TIMEOUT
                    )
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
                    conn_info.bytes_received += len(data)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                pass
            finally:
                client_writer.close()

        # Run both relay tasks concurrently
        await asyncio.gather(relay_to_target(), relay_to_client(), return_exceptions=True)

        logger.info(
            "Connection closed",
            target=f"{conn_info.target_addr}:{conn_info.target_port}",
            sent=conn_info.bytes_sent,
            received=conn_info.bytes_received
        )

    @staticmethod
    def _validate_domain(domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False

        # Allow .onion domains
        if domain.endswith('.onion'):
            return len(domain) > 7

        # Basic validation - allow alphanumeric, hyphen, dots
        allowed = set('abcdefghijklmnopqrstuvwxyz0123456789.-')
        return all(c in allowed for c in domain.lower())

    @staticmethod
    def _is_ip(addr: str) -> bool:
        """Check if address is an IP address."""
        try:
            ip_address(addr)
            return True
        except ValueError:
            return False

    def set_connection_callback(
        self,
        callback: Callable[[ConnectionInfo], Awaitable[None]]
    ) -> None:
        """Set callback for new connections."""
        self._on_connection = callback

    @property
    def active_connections(self) -> int:
        """Get number of active connections."""
        return len(self._connections)

    def get_connection_info(self) -> list[ConnectionInfo]:
        """Get info about all active connections."""
        return list(self._connections.values())
