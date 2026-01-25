"""Tests for SOCKS5 server module."""

import pytest
import pytest_asyncio
import asyncio
import struct
import socket

from shadow9.socks5_server import (
    Socks5Server,
    Socks5AuthMethod,
    Socks5Command,
    Socks5AddressType,
    Socks5Reply,
)
from shadow9.auth import AuthManager


@pytest.fixture
def auth_manager(tmp_path):
    """Create auth manager with test user."""
    creds_file = tmp_path / "credentials.enc"
    auth = AuthManager(credentials_file=creds_file)
    auth.add_user("testuser", "SecurePass123!@#")
    return auth


@pytest_asyncio.fixture
async def server(auth_manager):
    """Create and start a test server."""
    server = Socks5Server(
        host="127.0.0.1",
        port=0,  # Let OS choose port
        auth_manager=auth_manager,
    )
    await server.start()
    yield server
    await server.stop()


class TestSocks5Server:
    """Tests for Socks5Server."""

    @pytest.mark.asyncio
    async def test_server_starts(self, auth_manager):
        """Test that server starts and stops correctly."""
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
        )
        await server.start()
        assert server._running is True
        await server.stop()
        assert server._running is False

    @pytest.mark.asyncio
    async def test_authentication_required(self, server):
        """Test that authentication is required."""
        # Get server port
        addr = server._server.sockets[0].getsockname()
        port = addr[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send greeting without username/password method
        writer.write(struct.pack("!BBB", 0x05, 1, Socks5AuthMethod.NO_AUTH))
        await writer.drain()

        # Should receive "no acceptable method"
        response = await reader.readexactly(2)
        version, method = struct.unpack("!BB", response)

        assert version == 0x05
        assert method == Socks5AuthMethod.NO_ACCEPTABLE

        writer.close()
        await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_successful_auth(self, server):
        """Test successful authentication."""
        addr = server._server.sockets[0].getsockname()
        port = addr[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send greeting with username/password method
        writer.write(struct.pack("!BBB", 0x05, 1, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()

        # Should receive username/password method selection
        response = await reader.readexactly(2)
        version, method = struct.unpack("!BB", response)

        assert version == 0x05
        assert method == Socks5AuthMethod.USERNAME_PASSWORD

        # Send authentication
        username = b"testuser"
        password = b"SecurePass123!@#"
        auth_request = struct.pack("!BB", 0x01, len(username)) + username
        auth_request += struct.pack("!B", len(password)) + password

        writer.write(auth_request)
        await writer.drain()

        # Should receive success
        response = await reader.readexactly(2)
        auth_version, status = struct.unpack("!BB", response)

        assert auth_version == 0x01
        assert status == 0x00  # Success

        writer.close()
        await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_failed_auth(self, server):
        """Test failed authentication."""
        addr = server._server.sockets[0].getsockname()
        port = addr[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send greeting
        writer.write(struct.pack("!BBB", 0x05, 1, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()
        await reader.readexactly(2)

        # Send wrong credentials
        username = b"testuser"
        password = b"WrongPassword123!@#"
        auth_request = struct.pack("!BB", 0x01, len(username)) + username
        auth_request += struct.pack("!B", len(password)) + password

        writer.write(auth_request)
        await writer.drain()

        # Should receive failure
        response = await reader.readexactly(2)
        auth_version, status = struct.unpack("!BB", response)

        assert auth_version == 0x01
        assert status == 0x01  # Failure

        writer.close()
        await writer.wait_closed()

    @pytest.mark.asyncio
    async def test_invalid_socks_version(self, server):
        """Test rejection of invalid SOCKS version."""
        addr = server._server.sockets[0].getsockname()
        port = addr[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Send greeting with wrong version
        writer.write(struct.pack("!BBB", 0x04, 1, Socks5AuthMethod.NO_AUTH))
        await writer.drain()

        # Connection should be closed
        try:
            await asyncio.wait_for(reader.read(100), timeout=1.0)
        except asyncio.TimeoutError:
            pass

        writer.close()


class TestSocks5Enums:
    """Tests for SOCKS5 protocol enums."""

    def test_auth_methods(self):
        """Test authentication method values."""
        assert Socks5AuthMethod.NO_AUTH == 0x00
        assert Socks5AuthMethod.USERNAME_PASSWORD == 0x02
        assert Socks5AuthMethod.NO_ACCEPTABLE == 0xFF

    def test_commands(self):
        """Test command values."""
        assert Socks5Command.CONNECT == 0x01
        assert Socks5Command.BIND == 0x02
        assert Socks5Command.UDP_ASSOCIATE == 0x03

    def test_address_types(self):
        """Test address type values."""
        assert Socks5AddressType.IPV4 == 0x01
        assert Socks5AddressType.DOMAIN == 0x03
        assert Socks5AddressType.IPV6 == 0x04

    def test_reply_codes(self):
        """Test reply code values."""
        assert Socks5Reply.SUCCEEDED == 0x00
        assert Socks5Reply.GENERAL_FAILURE == 0x01
        assert Socks5Reply.CONNECTION_REFUSED == 0x05
