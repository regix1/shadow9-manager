"""Tests for SOCKS5 server module."""

import pytest
import pytest_asyncio
import asyncio
import concurrent.futures
import ipaddress
import socket
import struct
import threading
import time
from typing import Optional

from shadow9.socks5_server import (
    Socks5Server,
    Socks5AuthMethod,
    Socks5Command,
    Socks5AddressType,
    Socks5Reply,
)
from shadow9.auth import AuthManager
from shadow9.bridges import TorBridgeConnector


@pytest.fixture
def auth_manager(tmp_path):
    """Create auth manager with test users.

    `directuser` skips Tor, which is what the destination and rate limit tests need:
    a Tor user with no upstream proxy is refused before the request ever reaches them.
    """
    creds_file = tmp_path / "credentials.enc"
    auth = AuthManager(credentials_file=creds_file)
    auth.add_user("testuser", "SecurePass123!@#")
    auth.add_user("directuser", "SecurePass123!@#", use_tor=False)
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


async def _authenticate_once(port: int, username: bytes, password: bytes) -> int:
    """Run one SOCKS5 greeting plus username/password exchange, returning the auth status byte."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(struct.pack("!BBB", 0x05, 1, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()
        await reader.readexactly(2)

        request = struct.pack("!BB", 0x01, len(username)) + username
        request += struct.pack("!B", len(password)) + password
        writer.write(request)
        await writer.drain()

        return struct.unpack("!BB", await reader.readexactly(2))[1]
    finally:
        writer.close()


class TestSocks5ServerResources:
    """Tests for connection limits, event loop responsiveness and socket cleanup."""

    @pytest.mark.asyncio
    async def test_concurrent_handlers_never_exceed_the_connection_cap(self, auth_manager):
        """More clients than the cap must not run more than the cap of handlers at once.

        Each handler holds memory for the duration of the argon2 hash, so an uncapped
        server lets N simultaneous clients hold N times that much at once.
        """
        max_connections = 3
        client_count = 12
        inside = 0
        peak = 0
        release = asyncio.Event()

        async def waiting_handshake(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> Optional[str]:
            nonlocal inside, peak
            inside += 1
            peak = max(peak, inside)
            try:
                await release.wait()
            finally:
                inside -= 1
            return None

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            max_connections=max_connections,
        )
        server._socks5_handshake = waiting_handshake
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        clients: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        try:
            for _ in range(client_count):
                clients.append(await asyncio.open_connection("127.0.0.1", port))

            await asyncio.sleep(0.3)

            assert peak == max_connections

            # Past the cap the server closes the socket instead of parking the client,
            # so the excess see EOF while the ones holding a slot stay open
            refused = 0
            for reader, _ in clients:
                try:
                    if await asyncio.wait_for(reader.read(1), timeout=0.2) == b"":
                        refused += 1
                except asyncio.TimeoutError:
                    pass

            assert refused == client_count - max_connections
        finally:
            release.set()
            for _, writer in clients:
                writer.close()
            await asyncio.sleep(0.1)
            await server.stop()

    @pytest.mark.asyncio
    async def test_authentication_keeps_the_event_loop_responsive(self, auth_manager):
        """Credential verification runs off the loop, so other tasks keep getting scheduled.

        The real cost here is argon2 at 64 MB per hash. This substitutes a plain blocking
        sleep so the assertion measures scheduling latency rather than hashing time.
        """
        block_seconds = 0.3

        def blocking_verify(username: str, password: str) -> bool:
            time.sleep(block_seconds)
            return username == "testuser"

        auth_manager.verify = blocking_verify

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        max_gap = 0.0
        stop = asyncio.Event()

        async def heartbeat() -> None:
            nonlocal max_gap
            last = time.monotonic()
            while not stop.is_set():
                await asyncio.sleep(0)
                now = time.monotonic()
                max_gap = max(max_gap, now - last)
                last = now

        beat = asyncio.create_task(heartbeat())
        try:
            await asyncio.gather(
                *(_authenticate_once(port, b"testuser", b"SecurePass123!@#") for _ in range(3))
            )
        finally:
            stop.set()
            await beat
            await server.stop()

        assert max_gap < 0.05

    @pytest.mark.asyncio
    async def test_upstream_socket_is_closed_when_the_connect_times_out(
        self, auth_manager, monkeypatch
    ):
        """A cancelled upstream connect must not leave the proxy-side socket open.

        Tor connects time out routinely, and every leaked descriptor brings the process
        closer to EMFILE, at which point asyncio stops accepting new clients. The opened
        writers are held here on purpose: that keeps the stream finalizer from closing
        them, so the assertion measures what the code closes rather than what the garbage
        collector happens to reclaim.
        """
        attempts = 5
        accepted = 0
        disconnected = 0

        async def stalled_upstream(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            nonlocal accepted, disconnected
            accepted += 1
            try:
                while await reader.read(64):
                    pass
            except (ConnectionError, OSError):
                pass
            disconnected += 1
            writer.close()

        upstream = await asyncio.start_server(stalled_upstream, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]

        opened: list[asyncio.StreamWriter] = []
        real_open_connection = asyncio.open_connection

        async def recording_open_connection(
            host: Optional[str] = None, port: Optional[int] = None, **kwargs
        ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
            reader, writer = await real_open_connection(host, port, **kwargs)
            opened.append(writer)
            return reader, writer

        monkeypatch.setattr(asyncio, "open_connection", recording_open_connection)

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            upstream_proxy=("127.0.0.1", upstream_port),
        )

        try:
            for _ in range(attempts):
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        server._connect_via_proxy(
                            "example.com",
                            443,
                            socks_username="testuser",
                            socks_password="testuser",
                        ),
                        timeout=0.2,
                    )

            assert len(opened) == attempts
            assert all(writer.is_closing() for writer in opened)

            await asyncio.sleep(0.4)

            assert accepted == attempts
            assert disconnected == attempts
        finally:
            for writer in opened:
                writer.close()
            await asyncio.sleep(0.1)
            upstream.close()
            await upstream.wait_closed()

    @pytest.mark.asyncio
    async def test_failed_bridge_start_is_not_retried_on_every_connection(
        self, auth_manager, monkeypatch
    ):
        """A bridge that fails to start is remembered, so no Tor process is spawned per client."""
        starts = 0

        async def failing_start(self) -> tuple[str, int]:
            nonlocal starts
            starts += 1
            raise RuntimeError("tor refused to bootstrap")

        monkeypatch.setattr(TorBridgeConnector, "start_tor_with_bridges", failing_start)

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        first_port = server._next_bridge_port

        for _ in range(3):
            assert await server._get_or_create_bridge_proxy("obfs4") is None

        assert starts == 1
        assert server._next_bridge_port - first_port <= 1

    @pytest.mark.asyncio
    async def test_dead_bridge_proxy_is_dropped(self, auth_manager, monkeypatch):
        """A bridge whose Tor instance stopped working is removed so the next client rebuilds it."""
        stopped = 0

        async def working_start(self) -> tuple[str, int]:
            return ("127.0.0.1", self.socks_port)

        async def counted_stop(self) -> None:
            nonlocal stopped
            stopped += 1

        monkeypatch.setattr(TorBridgeConnector, "start_tor_with_bridges", working_start)
        monkeypatch.setattr(TorBridgeConnector, "stop", counted_stop)

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)

        assert await server._get_or_create_bridge_proxy("obfs4") is not None
        assert "obfs4" in server.upstream_proxies
        assert "obfs4" in server._dynamic_connectors

        await server._drop_bridge_proxy("obfs4")

        assert stopped == 1
        assert "obfs4" not in server.upstream_proxies
        assert "obfs4" not in server._dynamic_connectors

    @pytest.mark.asyncio
    async def test_server_reports_start_time_and_active_connections(self, auth_manager):
        """The server exposes when it started and how many connections it is carrying."""
        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)

        assert server.started_at is None
        assert server.active_connections == 0

        await server.start()
        try:
            assert server.started_at is not None
        finally:
            await server.stop()


class _FakeResolver:
    """Stands in for loop.getaddrinfo so a test can say where a name points.

    Names in the table get the answer the table gives. An address literal is handed back
    unchanged, which is what keeps the test's own connection to 127.0.0.1 working while
    one name is being faked. Anything else raises the same error a name that does not
    exist raises, rather than reaching a real resolver, so a network that answers
    NXDOMAIN with an address of its own cannot change the result.
    """

    def __init__(self, answers: dict[str, str]) -> None:
        self._answers = answers

    async def __call__(
        self,
        host: str,
        port: int | str | None = None,
        *,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple]]:
        address = self._answers.get(host)
        if address is None:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                raise socket.gaierror(
                    socket.EAI_NONAME, f"Name or service not known: {host}"
                ) from None
            address = host
        resolved = ipaddress.ip_address(address)
        if resolved.version == 6:
            return [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    (address, int(port or 0), 0, 0),
                )
            ]
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                (address, int(port or 0)),
            )
        ]


async def _request_connect_once(
    port: int,
    username: bytes,
    password: bytes,
    target_host: str,
    target_port: int,
    address_type: Socks5AddressType = Socks5AddressType.DOMAIN,
) -> int:
    """Log in and send one CONNECT request, returning the SOCKS5 reply code byte."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(struct.pack("!BBB", 0x05, 1, Socks5AuthMethod.USERNAME_PASSWORD))
        await writer.drain()
        await reader.readexactly(2)

        login = struct.pack("!BB", 0x01, len(username)) + username
        login += struct.pack("!B", len(password)) + password
        writer.write(login)
        await writer.drain()
        assert struct.unpack("!BB", await reader.readexactly(2))[1] == 0x00

        request = struct.pack("!BBBB", 0x05, Socks5Command.CONNECT, 0x00, address_type)
        if address_type == Socks5AddressType.IPV4:
            request += socket.inet_aton(target_host)
        elif address_type == Socks5AddressType.IPV6:
            request += socket.inet_pton(socket.AF_INET6, target_host)
        else:
            encoded = target_host.encode()
            request += struct.pack("!B", len(encoded)) + encoded
        request += struct.pack("!H", target_port)
        writer.write(request)
        await writer.drain()

        return struct.unpack("!BBBB4sH", await reader.readexactly(10))[1]
    finally:
        writer.close()


class TestSocks5ServerAccessPolicy:
    """Tests for Tor routing, destination filtering, account lockout and rate limiting."""

    @pytest.mark.asyncio
    async def test_tor_user_is_refused_when_no_upstream_proxy_is_available(self, auth_manager):
        """A user routed through Tor must fail rather than get an unprotected connection.

        The old path fell through to a plain connect and still answered SUCCEEDED, so the
        target saw the address the user was running Tor to hide and nothing said so.
        """
        accepted = 0

        async def count_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal accepted
            accepted += 1
            writer.close()

        target = await asyncio.start_server(count_target, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            upstream_proxy=None,
            allow_localhost=True,
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            reply = await _request_connect_once(
                port,
                b"testuser",
                b"SecurePass123!@#",
                "127.0.0.1",
                target_port,
                Socks5AddressType.IPV4,
            )
            await asyncio.sleep(0.1)

            assert reply == Socks5Reply.GENERAL_FAILURE
            assert accepted == 0
        finally:
            await server.stop()
            target.close()
            await target.wait_closed()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "address,address_type",
        [
            ("127.0.0.1", Socks5AddressType.IPV4),
            ("10.0.0.1", Socks5AddressType.IPV4),
            ("169.254.169.254", Socks5AddressType.IPV4),
            ("100.64.0.1", Socks5AddressType.IPV4),
            ("::1", Socks5AddressType.IPV6),
        ],
    )
    async def test_addresses_off_the_public_internet_are_refused(
        self, auth_manager, address, address_type
    ):
        """Literal addresses that are not publicly routable are refused on both address types.

        100.64.0.1 is in here on purpose: carrier-grade NAT answers False to is_private,
        so a check written against that attribute lets it through.
        """
        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            reply = await _request_connect_once(
                port,
                b"directuser",
                b"SecurePass123!@#",
                address,
                80,
                address_type,
            )
            assert reply == Socks5Reply.NOT_ALLOWED
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_allow_localhost_permits_loopback(self, auth_manager):
        """Turning allow_localhost on lets loopback destinations through again."""

        async def idle_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while await reader.read(64):
                    pass
            except (ConnectionError, OSError):
                pass
            writer.close()

        target = await asyncio.start_server(idle_target, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]

        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, allow_localhost=True
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            reply = await _request_connect_once(
                port,
                b"directuser",
                b"SecurePass123!@#",
                "127.0.0.1",
                target_port,
                Socks5AddressType.IPV4,
            )
            assert reply == Socks5Reply.SUCCEEDED
        finally:
            await server.stop()
            target.close()
            await target.wait_closed()

    @pytest.mark.asyncio
    async def test_hostname_resolving_to_loopback_is_refused(self, auth_manager):
        """A name that resolves to loopback is refused, so the check cannot be smuggled past.

        Checking the requested string proves nothing, because the client picks the string
        and any name can be pointed at this machine.
        """
        accepted = 0

        async def count_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal accepted
            accepted += 1
            writer.close()

        target = await asyncio.start_server(count_target, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            reply = await _request_connect_once(
                port,
                b"directuser",
                b"SecurePass123!@#",
                "localhost",
                target_port,
                Socks5AddressType.DOMAIN,
            )
            await asyncio.sleep(0.1)

            assert reply == Socks5Reply.NOT_ALLOWED
            assert accepted == 0
        finally:
            await server.stop()
            target.close()
            await target.wait_closed()

    @pytest.mark.asyncio
    async def test_blocked_hosts_cover_their_subdomains(self, auth_manager):
        """An entry in the block list also refuses everything underneath it."""
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            blocked_hosts=["blocked.example"],
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            for host in ("blocked.example", "www.blocked.example"):
                reply = await _request_connect_once(
                    port,
                    b"directuser",
                    b"SecurePass123!@#",
                    host,
                    443,
                    Socks5AddressType.DOMAIN,
                )
                assert reply == Socks5Reply.NOT_ALLOWED, host
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_the_address_a_blocked_name_resolves_to_is_refused_as_a_literal(
        self, auth_manager, monkeypatch
    ):
        """The bypass the name check on its own leaves open.

        A client that looks the name up itself and sends the literal never puts the name
        in front of the server, so nothing in the name comparison can catch it. Matching
        the addresses the blocked names resolve to is what closes it.
        """
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "getaddrinfo",
            _FakeResolver({"blocked.example": "93.184.216.34"}),
        )
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            blocked_hosts=["blocked.example"],
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            assert server._blocked_addresses == frozenset({"93.184.216.34"})
            reply = await _request_connect_once(
                port,
                b"directuser",
                b"SecurePass123!@#",
                "93.184.216.34",
                443,
                Socks5AddressType.IPV4,
            )
            assert reply == Socks5Reply.NOT_ALLOWED
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_a_different_name_for_the_blocked_machine_is_refused(
        self, auth_manager, monkeypatch
    ):
        """An alias is not in the block list and points at the blocked machine anyway."""
        monkeypatch.setattr(
            asyncio.get_running_loop(),
            "getaddrinfo",
            _FakeResolver(
                {"blocked.example": "93.184.216.34", "alias.example": "93.184.216.34"}
            ),
        )
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            blocked_hosts=["blocked.example"],
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            assert not server._is_blocked_host("alias.example")
            reply = await _request_connect_once(
                port,
                b"directuser",
                b"SecurePass123!@#",
                "alias.example",
                443,
                Socks5AddressType.DOMAIN,
            )
            assert reply == Socks5Reply.NOT_ALLOWED
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_a_name_that_stops_resolving_keeps_its_last_addresses(
        self, auth_manager, monkeypatch
    ):
        """A resolver that is briefly unreachable must not quietly lift the block."""
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop, "getaddrinfo", _FakeResolver({"blocked.example": "93.184.216.34"})
        )
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            blocked_hosts=["blocked.example"],
        )
        await server.refresh_blocked_addresses()
        assert server._blocked_addresses == frozenset({"93.184.216.34"})

        monkeypatch.setattr(loop, "getaddrinfo", _FakeResolver({}))
        await server.refresh_blocked_addresses()

        assert server._blocked_addresses == frozenset({"93.184.216.34"})

    @pytest.mark.asyncio
    async def test_a_name_that_moves_stops_refusing_the_address_it_left(
        self, auth_manager, monkeypatch
    ):
        """Addresses must not pile up, or the block spreads to whoever holds them next."""
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop, "getaddrinfo", _FakeResolver({"blocked.example": "93.184.216.34"})
        )
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            blocked_hosts=["blocked.example"],
        )
        await server.refresh_blocked_addresses()

        monkeypatch.setattr(
            loop, "getaddrinfo", _FakeResolver({"blocked.example": "172.67.1.1"})
        )
        await server.refresh_blocked_addresses()

        assert server._blocked_addresses == frozenset({"172.67.1.1"})

    @pytest.mark.asyncio
    async def test_locked_out_client_is_refused_without_hashing(self, auth_manager):
        """Past the attempt limit the server answers without paying for an argon2 hash.

        Every verification reserves 64 MB, and an attacker pays that cost even for a
        username that does not exist, because the dummy hash runs for those too. A lockout
        that still hashes has not removed the cost it exists to remove.
        """
        attempts = 3
        hashes = 0
        real_verify = auth_manager.verify

        def counting_verify(username: str, password: str) -> bool:
            nonlocal hashes
            hashes += 1
            return real_verify(username, password)

        auth_manager.verify = counting_verify

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            max_failed_attempts=attempts,
            lockout_duration_minutes=0.5 / 60,
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            for _ in range(attempts):
                status = await _authenticate_once(port, b"testuser", b"WrongPass123!@#")
                assert status != 0x00

            assert hashes == attempts
            hashes_before_lockout = hashes

            status = await _authenticate_once(port, b"testuser", b"WrongPass123!@#")
            assert status != 0x00
            assert hashes == hashes_before_lockout

            await asyncio.sleep(0.6)

            status = await _authenticate_once(port, b"testuser", b"SecurePass123!@#")
            assert status == 0x00
            assert hashes == hashes_before_lockout + 1
        finally:
            await server.stop()

    @pytest.mark.asyncio
    async def test_user_rate_limit_is_shared_across_connections(self, auth_manager):
        """One user's limit covers every connection they hold, not each one separately."""
        limit = 3
        extra = 2

        async def idle_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while await reader.read(64):
                    pass
            except (ConnectionError, OSError):
                pass
            writer.close()

        target = await asyncio.start_server(idle_target, "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]

        auth_manager.add_user("limiteduser", "SecurePass123!@#", use_tor=False, rate_limit=limit)

        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, allow_localhost=True
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            replies = []
            for _ in range(limit + extra):
                replies.append(
                    await _request_connect_once(
                        port,
                        b"limiteduser",
                        b"SecurePass123!@#",
                        "127.0.0.1",
                        target_port,
                        Socks5AddressType.IPV4,
                    )
                )

            assert replies[:limit] == [Socks5Reply.SUCCEEDED] * limit
            assert replies[limit:] == [Socks5Reply.NOT_ALLOWED] * extra
        finally:
            await server.stop()
            target.close()
            await target.wait_closed()

    @pytest.mark.asyncio
    async def test_concurrent_authentications_never_exceed_the_hashing_cap(self, auth_manager):
        """Password hashing has its own cap, because the connection cap does not bound it.

        The hash runs on asyncio's default executor, whose size follows the host's core
        count, so before this cap existed the peak argon2 memory was decided by the
        machine rather than by any setting. Each permit reserves 64 MB for the length of
        one verification.
        """
        permits = 2
        clients = 8

        counter_lock = threading.Lock()
        release = threading.Event()
        inside = 0
        peak = 0

        def blocking_verify(username: str, password: str) -> bool:
            nonlocal inside, peak
            with counter_lock:
                inside += 1
                peak = max(peak, inside)
            release.wait(timeout=5)
            with counter_lock:
                inside -= 1
            return True

        auth_manager.verify = blocking_verify

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            max_concurrent_auth=permits,
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        tasks = [
            asyncio.create_task(_authenticate_once(port, b"testuser", b"SecurePass123!@#"))
            for _ in range(clients)
        ]
        try:
            await asyncio.sleep(0.5)
            observed_peak = peak
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await server.stop()

        assert observed_peak == permits

    @pytest.mark.asyncio
    async def test_timed_out_handshakes_do_not_release_the_hashing_permit_early(self, auth_manager):
        """A cancelled handshake must not free a permit while its thread is still hashing.

        The handshake runs under a timeout. Cancelling the await does not stop a thread
        that already started argon2, so a permit released as the cancellation unwinds lets
        the next connection start a second 64 MiB hash beside the abandoned one. Repeating
        that walks concurrent hashes up to the executor's worker count and puts back the
        memory the cap exists to bound.
        """
        permits = 2
        waves = 4
        clients_per_wave = 4

        counter_lock = threading.Lock()
        release = threading.Event()
        inside = 0
        peak = 0

        def blocking_verify(username: str, password: str) -> bool:
            nonlocal inside, peak
            with counter_lock:
                inside += 1
                peak = max(peak, inside)
            release.wait(timeout=20)
            with counter_lock:
                inside -= 1
            return True

        auth_manager.verify = blocking_verify

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            max_concurrent_auth=permits,
            max_connections=200,
        )
        server.CONNECTION_TIMEOUT = 0.3
        await server.start()
        port = server._server.sockets[0].getsockname()[1]

        tasks = []
        try:
            for _ in range(waves):
                tasks += [
                    asyncio.create_task(_authenticate_once(port, b"testuser", b"SecurePass123!@#"))
                    for _ in range(clients_per_wave)
                ]
                # Long enough for the handshake timeout to fire and cancel every client
                await asyncio.sleep(0.45)
            observed_peak = peak
        finally:
            release.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await server.stop()

        assert observed_peak == permits

    @pytest.mark.asyncio
    async def test_a_probe_that_connects_and_closes_is_not_logged_as_an_error(
        self, auth_manager, monkeypatch
    ):
        """The API status check opens a connection and closes it without a greeting.

        A dashboard polling every five seconds does that seventeen thousand times a day,
        and each one used to write an error line into the log an operator reads after a
        crash.
        """
        levels: list[str] = []
        real_log_if_allowed = Socks5Server._log_if_allowed

        def recording_log(self, level, event, username=None, **kwargs):
            levels.append(level)
            return real_log_if_allowed(self, level, event, username=username, **kwargs)

        monkeypatch.setattr(Socks5Server, "_log_if_allowed", recording_log)

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            _reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            await asyncio.sleep(0.2)
        finally:
            await server.stop()

        assert "error" not in levels

    @pytest.mark.asyncio
    async def test_an_ipv6_destination_is_sent_upstream_as_ipv6(self, auth_manager):
        """A v6 literal must reach the upstream proxy, not raise on the way out.

        inet_aton parses IPv4 only, so packing a v6 literal with it raised OSError and
        the client saw an unexplained failure for an address Tor reaches perfectly well.
        """
        request_bytes: list[bytes] = []

        async def fake_upstream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readexactly(3)  # greeting
            writer.write(struct.pack("!BB", 0x05, 0x00))
            await writer.drain()
            header = await reader.readexactly(4)  # VER CMD RSV ATYP
            body = await reader.readexactly(16 + 2)  # v6 address and port
            request_bytes.append(header + body)
            writer.write(struct.pack("!BBBB4sH", 0x05, 0x00, 0x00, 0x01, b"\x00" * 4, 0))
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(fake_upstream, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            upstream_proxy=("127.0.0.1", upstream_port),
        )
        try:
            _reader, writer = await asyncio.wait_for(
                server._connect_via_proxy("2606:4700:4700::1111", 443),
                timeout=5,
            )
            writer.close()
        finally:
            upstream.close()

        assert len(request_bytes) == 1
        sent = request_bytes[0]
        assert sent[3] == Socks5AddressType.IPV6
        assert sent[4:20] == ipaddress.ip_address("2606:4700:4700::1111").packed
        assert struct.unpack("!H", sent[20:22])[0] == 443

    @pytest.mark.asyncio
    async def test_every_allowed_address_for_a_name_is_kept(self, auth_manager):
        """Screening the destination must not shrink a name down to one address.

        A dual-stack name answers with more than one literal. Connecting to only the first
        makes a family this host has no route for look like an unreachable destination,
        for every such name, and asyncio walked the whole list before the screen existed.
        """
        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        loop = asyncio.get_running_loop()

        async def two_families(host, port, *args, **kwargs):
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800::1", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
            ]

        loop.getaddrinfo = two_families
        try:
            allowed = await server._resolve_allowed_address("example.test", 443, "directuser")
        finally:
            del loop.getaddrinfo

        assert allowed == ["2606:2800::1", "93.184.216.34"]

    @pytest.mark.asyncio
    async def test_an_unreachable_first_address_falls_through_to_the_next(self, auth_manager):
        """One address refusing must not refuse the whole name."""
        target = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
        target_port = target.sockets[0].getsockname()[1]

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        try:
            # Nothing is listening on the v6 loopback, so the first address errors and
            # the second is the one that answers
            reader, writer = await server._open_first_reachable(["::1", "127.0.0.1"], target_port)
            writer.close()
            await writer.wait_closed()
        finally:
            target.close()
            await target.wait_closed()

        assert reader is not None

    @pytest.mark.asyncio
    async def test_a_handshake_cancelled_before_its_hash_starts_leaves_the_permit_usable(
        self, auth_manager
    ):
        """A verification cancelled while still queued must not consume a permit.

        The hash runs on the same executor that serves loop.getaddrinfo, so a busy pool
        can leave a submitted verification waiting for a worker. If the handshake times
        out in that window the job is discarded before it runs. A permit taken outside
        the worker would have nothing left to release it, and once as many handshakes as
        there are permits time out that way no client can authenticate again.
        """
        permits = 2
        loop = asyncio.get_running_loop()
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        loop.set_default_executor(pool)

        occupied = threading.Event()

        def slow_verify(username: str, password: str) -> bool:
            time.sleep(0.2)
            return True

        auth_manager.verify = slow_verify

        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            auth_manager=auth_manager,
            max_concurrent_auth=permits,
        )

        try:
            busy = [loop.run_in_executor(None, occupied.wait) for _ in range(2)]
            await asyncio.sleep(0.1)

            for _ in range(permits):
                queued = asyncio.ensure_future(
                    server._verify_credentials("testuser", "SecurePass123!@#")
                )
                await asyncio.sleep(0.05)
                queued.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await queued

            occupied.set()
            await asyncio.gather(*busy)

            verified = await asyncio.wait_for(
                server._verify_credentials("testuser", "SecurePass123!@#"),
                timeout=5,
            )
        finally:
            occupied.set()
            pool.shutdown(wait=False)

        assert verified is True

    @pytest.mark.asyncio
    async def test_tracking_maps_stay_bounded_when_the_client_cycles_keys(self, auth_manager):
        """Cycling source addresses, usernames or both must not grow the tracking maps.

        Both are keyed by values the client picks, so an unbounded map here would be a new
        way to exhaust memory in the same process the connection cap exists to protect.
        """
        cap = 32
        cycles = 500

        server = Socks5Server(host="127.0.0.1", port=0, auth_manager=auth_manager)
        server.MAX_TRACKED_ENTRIES = cap

        for index in range(cycles):
            server._record_auth_failure(f"10.0.0.{index}", f"user{index}")
            server._rate_limit_exceeded(f"user{index}", 100)

        assert len(server._auth_failures) <= cap
        assert len(server._user_requests) <= cap

        # The most recent attacker is still tracked, so eviction dropped stale keys
        # rather than whatever arrived last
        assert (f"10.0.0.{cycles - 1}", f"user{cycles - 1}") in server._auth_failures
        assert f"user{cycles - 1}" in server._user_requests

    @pytest.mark.asyncio
    async def test_lockout_bounds_guesses_against_an_account_not_just_a_source(self, auth_manager):
        """Spreading guesses across source addresses must not buy more attempts.

        A count kept per source address hands every new address a full budget against the
        same account, so a caller with a list of addresses never runs out of guesses.
        """
        attempts = 5
        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, max_failed_attempts=attempts
        )

        for octet in range(20):
            for _ in range(attempts):
                server._record_auth_failure(f"203.0.113.{octet}", "testuser")

        # An address that has never been seen before still cannot guess this account
        assert server._is_locked_out("198.51.100.1", "testuser")

        # An account nobody has guessed is unaffected
        assert not server._is_locked_out("198.51.100.1", "directuser")

    @pytest.mark.asyncio
    async def test_a_locked_out_account_cannot_be_freed_by_inventing_usernames(self, auth_manager):
        """The capped per-source map evicts its oldest entry, which must not clear a lockout.

        Filling that map with usernames nobody owns pushes the real entry out. The account
        count is only kept for usernames the store actually holds, so it cannot be flushed
        that way and the lockout survives.
        """
        attempts = 5
        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, max_failed_attempts=attempts
        )
        attacker = "198.51.100.7"

        # One address runs out after `attempts`, so reaching the account-wide limit takes
        # a spread of them
        for octet in range(server.ACCOUNT_ATTEMPT_FACTOR):
            for _ in range(attempts):
                server._record_auth_failure(f"198.51.100.{octet}", "testuser")
        assert server._is_locked_out(attacker, "testuser")

        for index in range(server.MAX_TRACKED_ENTRIES + 10):
            server._record_auth_failure(attacker, f"nobody{index}")

        assert (attacker, "testuser") not in server._auth_failures, (
            "the eviction under test did not happen"
        )
        assert server._is_locked_out(attacker, "testuser")
        assert len(server._account_failures) == 1

    @pytest.mark.asyncio
    async def test_guessing_at_an_account_cannot_refuse_an_address_that_already_got_in(
        self, auth_manager
    ):
        """The account-wide count must not become a remote off-switch for a named user.

        Usernames are not secret: they appear in the per-user listener log lines and are
        often the customer's own handle. A count keyed by username alone means anybody who
        can name a user can refuse that user, because the lockout answers before the
        password is read and a correct password never clears it.
        """
        attempts = 5
        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, max_failed_attempts=attempts
        )
        owner = "203.0.113.44"
        server._record_auth_success(owner, "testuser")

        # Far past the account limit, from far more addresses than it takes to reach it
        for octet in range(server.ACCOUNT_ATTEMPT_FACTOR * 4):
            for _ in range(attempts):
                server._record_auth_failure(f"198.51.100.{octet}", "testuser")

        assert server._account_failures["testuser"].failures > (
            attempts * server.ACCOUNT_ATTEMPT_FACTOR
        )
        assert not server._is_locked_out(owner, "testuser")

    @pytest.mark.asyncio
    async def test_one_source_cannot_reach_the_account_limit_on_its_own(self, auth_manager):
        """A single address spends its own budget long before the account-wide one.

        This is what keeps five connections from refusing everybody else: the address that
        sent them is locked out, and every other address still has its full budget.
        """
        attempts = 5
        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, max_failed_attempts=attempts
        )
        attacker = "198.51.100.7"

        for _ in range(attempts):
            server._record_auth_failure(attacker, "testuser")

        assert server._is_locked_out(attacker, "testuser")
        assert not server._is_locked_out("203.0.113.44", "testuser")

    @pytest.mark.asyncio
    async def test_a_correct_password_clears_both_failure_counts(self, auth_manager):
        """A user who gets it right must not stay locked out by their own earlier typos."""
        server = Socks5Server(
            host="127.0.0.1", port=0, auth_manager=auth_manager, max_failed_attempts=5
        )
        await server.start()
        port = server._server.sockets[0].getsockname()[1]
        try:
            for _ in range(3):
                server._record_auth_failure("127.0.0.1", "testuser")
            assert server._account_failures["testuser"].failures == 3

            status = await _authenticate_once(port, b"testuser", b"SecurePass123!@#")
            assert status == 0x00
            assert server._account_failures == {}
            assert server._auth_failures == {}
        finally:
            await server.stop()


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


class TestOnlyOneMemoryBudgetWatchAtATime:
    """A server stopped and started again must not end up with two of them.

    Both would move _parked_auth_slots and both would release the same
    BoundedSemaphore, and the release past its initial value raises inside a daemon
    thread with nobody reading its output.
    """

    @pytest.mark.asyncio
    async def test_a_watch_still_running_is_not_joined_by_a_second_one(self, monkeypatch):
        from shadow9 import socks5_server as socks5_module
        from shadow9.memory_budget import HashPermits, MemoryBudget

        inside_resize = threading.Event()
        let_it_finish = threading.Event()

        def slow_answer(configured, relay_reserve_bytes, budget=None, cpu_count=None):
            inside_resize.set()
            let_it_finish.wait(30)
            return HashPermits(
                permits=1,
                budget=MemoryBudget(
                    limit_bytes=256 * 1024 * 1024,
                    available_bytes=256 * 1024 * 1024,
                    source="cgroup v2",
                    detail="",
                ),
                reason="test",
                set_by_operator=False,
            )

        server = Socks5Server(host="127.0.0.1", port=0, max_concurrent_auth=None)
        # Short enough that the watch reaches its first reading at once, and short enough
        # that stop() gives up on the wedged thread rather than waiting half a minute.
        monkeypatch.setattr(server, "BUDGET_RECHECK_SECONDS", 0.05)
        monkeypatch.setattr(socks5_module, "choose_hash_permits", slow_answer)

        await server.start()
        assert inside_resize.wait(10) is True
        await server.stop()

        wedged = server._budget_watch
        assert wedged is not None and wedged.is_alive()
        running_before = {
            thread.ident
            for thread in threading.enumerate()
            if thread.name == "shadow9-memory-budget"
        }

        await server.start()

        running_after = {
            thread.ident
            for thread in threading.enumerate()
            if thread.name == "shadow9-memory-budget"
        }
        assert running_after == running_before
        assert server._budget_watch is wedged

        let_it_finish.set()
        await server.stop()


class TestResolvingTheBlockListIsBounded:
    """The watch that repeats it awaits it directly, so an unbounded lookup never ends.

    Startup bounds the whole round, which is why the hang only shows up later: the server
    opens after thirty seconds with the block list half filled in, and the watch is then
    stuck on the silent name for the life of the process.
    """

    @staticmethod
    def _answers(host: str) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    @pytest.mark.asyncio
    async def test_a_name_that_never_answers_does_not_hold_up_the_rest(self, monkeypatch):
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            blocked_hosts=["silent.example", "answers.example"],
        )
        monkeypatch.setattr(server, "BLOCKED_HOST_RESOLVE_TIMEOUT", 0.2)

        async def getaddrinfo(host: str, port, *args, **kwargs):
            if host == "silent.example":
                await asyncio.sleep(3600)
            return self._answers(host)

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)

        started = time.monotonic()
        # Bounded by the test as well, so the bug reads as a failure rather than a hang.
        await asyncio.wait_for(server.refresh_blocked_addresses(), timeout=10.0)
        elapsed = time.monotonic() - started

        assert elapsed < 2.0
        # The name behind the silent one was never reached at all before this.
        assert server._is_blocked_address("93.184.216.34") is True

    @pytest.mark.asyncio
    async def test_a_later_round_still_reaches_a_name_that_went_quiet_before(
        self, monkeypatch
    ):
        """The watch has to survive the round, not just return from it."""
        server = Socks5Server(host="127.0.0.1", port=0, blocked_hosts=["moody.example"])
        monkeypatch.setattr(server, "BLOCKED_HOST_RESOLVE_TIMEOUT", 0.2)
        answering = False

        async def getaddrinfo(host: str, port, *args, **kwargs):
            if not answering:
                await asyncio.sleep(3600)
            return self._answers(host)

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)

        await asyncio.wait_for(server.refresh_blocked_addresses(), timeout=10.0)
        assert server._is_blocked_address("93.184.216.34") is False

        answering = True
        await asyncio.wait_for(server.refresh_blocked_addresses(), timeout=10.0)

        assert server._is_blocked_address("93.184.216.34") is True

    @pytest.mark.asyncio
    async def test_a_long_block_list_does_not_go_out_all_at_once(self, monkeypatch):
        """Every five minutes, so the burst would be a standing habit rather than a one-off."""
        server = Socks5Server(
            host="127.0.0.1",
            port=0,
            blocked_hosts=[f"host{index}.example" for index in range(40)],
        )
        in_flight = 0
        highest = 0

        async def getaddrinfo(host: str, port, *args, **kwargs):
            nonlocal in_flight, highest
            in_flight += 1
            highest = max(highest, in_flight)
            try:
                await asyncio.sleep(0.01)
                return self._answers(host)
            finally:
                in_flight -= 1

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", getaddrinfo)

        await server.refresh_blocked_addresses()

        assert highest <= Socks5Server.BLOCKED_HOST_RESOLVE_CONCURRENCY
        assert highest > 1, "resolving one at a time is what made a long list slow"


class TestTheTorRouteLimitIsAnnounced:
    """A control the operator turned on has a hole in it that cannot be seen from outside.

    A domain on the Tor route is handed upstream unresolved on purpose, so only the name
    is checked and a second name for a blocked machine goes through. Saying so in a
    docstring reaches nobody who is configuring the block list.
    """

    @staticmethod
    def _record_warnings(monkeypatch) -> list[tuple[str, dict]]:
        """Capture what the module warns about, leaving its other levels working."""
        from shadow9 import socks5_server as socks5_module

        said: list[tuple[str, dict]] = []

        def record_warning(event: str, **kwargs) -> None:
            said.append((event, kwargs))

        monkeypatch.setattr(socks5_module.logger, "warning", record_warning)
        return said

    @pytest.mark.asyncio
    async def test_starting_with_a_block_list_says_the_tor_route_checks_names_only(
        self, monkeypatch
    ):
        said = self._record_warnings(monkeypatch)

        server = Socks5Server(host="127.0.0.1", port=0, blocked_hosts=["blocked.example"])
        try:
            await server.start()
        finally:
            await server.stop()

        tor_note = [kwargs for event, kwargs in said if "Tor route" in event]
        assert tor_note, f"nothing said about the Tor route, only: {[e for e, _ in said]}"
        assert tor_note[0]["blocked_hosts"] == 1
        assert "another name" in tor_note[0]["not_checked"]

    @pytest.mark.asyncio
    async def test_a_server_with_no_block_list_says_nothing_about_it(self, monkeypatch):
        """The warning has to stay quiet for operators it does not concern."""
        said = self._record_warnings(monkeypatch)

        server = Socks5Server(host="127.0.0.1", port=0)
        try:
            await server.start()
        finally:
            await server.stop()

        assert not [event for event, _ in said if "Tor route" in event]
