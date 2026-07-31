"""Tests that every network wait in the Tor path is bounded.

A Tor daemon that accepts a socket and then never answers is the failure these tests
exist for: an unbounded read against it parks the coroutine for the life of the
process, and on the connect path that means the server never finishes starting.
"""

import ast
import asyncio
import inspect
import socket
import textwrap
import time
from typing import Iterator

import pytest

from shadow9 import tor_connector
from shadow9.tor_connector import TorConfig, TorConnector, TorProxyBridge, TorStatus

# Stream operations that block until the peer cooperates. Each one must be an argument
# to asyncio.wait_for rather than the thing being awaited. aiohttp reads are excluded on
# purpose: they are bounded by the aiohttp.ClientTimeout passed at each call site.
BLOCKING_STREAM_CALLS = frozenset({"open_connection", "drain", "readline", "readexactly"})


def collect_unbounded_awaits(source: str) -> list[tuple[int, str]]:
    """Return (line offset, call name) for every stream call that is awaited directly.

    A bounded call reads ``await asyncio.wait_for(reader.readline(), timeout=5.0)``, so the
    expression being awaited is ``wait_for`` and the stream call is only its argument.
    Anything this returns is awaited with nothing bounding how long it may take.
    """
    unbounded: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(textwrap.dedent(source))):
        if not isinstance(node, ast.Await) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in BLOCKING_STREAM_CALLS:
            unbounded.append((node.lineno, name))
    return unbounded


def collect_wait_for_calls(source: str) -> list[ast.Call]:
    """Return every ``asyncio.wait_for`` call in the given source."""
    return [
        node
        for node in ast.walk(ast.parse(textwrap.dedent(source)))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "wait_for"
    ]


@pytest.fixture
def silent_listener() -> Iterator[tuple[str, int]]:
    """A listening socket that is never accepted, so it answers nothing.

    The kernel completes the TCP handshake into the accept queue, so a client connects
    successfully and then waits forever for a reply. That is exactly how a wedged Tor
    daemon behaves, and it needs no handler task that could outlive the test.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    host, port = listener.getsockname()
    try:
        yield host, port
    finally:
        listener.close()


class TestTorAwaitsAreBounded:
    """Every blocking stream call in the module carries a timeout."""

    def test_no_stream_call_is_awaited_without_a_timeout(self) -> None:
        """The whole module: no bare await of connect, drain, readline or readexactly."""
        unbounded = collect_unbounded_awaits(inspect.getsource(tor_connector))
        assert unbounded == []

    def test_the_control_port_handshake_is_bounded(self) -> None:
        """The control port authenticate and NEWNYM exchange runs at startup and on demand."""
        source = inspect.getsource(TorConnector.get_new_circuit)
        assert collect_unbounded_awaits(source) == []

    def test_the_socks_handshake_is_bounded(self) -> None:
        """The bridge handshake is nine reads and writes against a daemon that may stall."""
        source = inspect.getsource(TorProxyBridge.create_connection)
        assert collect_unbounded_awaits(source) == []

    def test_every_wait_for_names_a_timeout(self) -> None:
        """asyncio.wait_for with timeout=None waits forever, which defeats the wrapper."""
        for call in collect_wait_for_calls(inspect.getsource(tor_connector)):
            timeouts = [kw for kw in call.keywords if kw.arg == "timeout"]
            assert len(timeouts) == 1
            assert not (
                isinstance(timeouts[0].value, ast.Constant) and timeouts[0].value.value is None
            )


class TestSilentTorDaemon:
    """A daemon that accepts the socket and then says nothing must not hang the caller."""

    @pytest.mark.asyncio
    async def test_create_connection_raises_instead_of_hanging(
        self, silent_listener: tuple[str, int]
    ) -> None:
        """The bridge handshake gives up on its own timeout rather than waiting forever."""
        host, port = silent_listener
        connector = TorConnector(TorConfig(socks_host=host, socks_port=port, timeout=0.25))
        connector._status = TorStatus.CONNECTED
        bridge = TorProxyBridge(connector)

        started = time.monotonic()
        with pytest.raises(TimeoutError):
            await bridge.create_connection("example.onion", 80)
        assert time.monotonic() - started < 5.0

    @pytest.mark.asyncio
    async def test_a_reachable_port_still_counts_as_tor_running(
        self, silent_listener: tuple[str, int]
    ) -> None:
        """The reachability probe writes nothing, so a silent peer is still a live port."""
        host, port = silent_listener
        connector = TorConnector(TorConfig(socks_host=host, socks_port=port))

        started = time.monotonic()
        assert await connector._check_tor_running() is True
        assert time.monotonic() - started < 5.0

    @pytest.mark.asyncio
    async def test_check_tor_running_is_false_when_nothing_listens(self) -> None:
        """A closed port fails fast instead of raising out of the connect path."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()

        connector = TorConnector(TorConfig(socks_host="127.0.0.1", socks_port=closed_port))
        assert await connector._check_tor_running() is False


class TestSilentControlPort:
    """The control port path returns rather than parking the caller."""

    @pytest.mark.asyncio
    async def test_get_new_circuit_gives_up_on_a_silent_control_port(
        self, silent_listener: tuple[str, int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The authenticate read is the first thing a wedged control port stalls."""
        host, port = silent_listener
        connector = TorConnector(
            TorConfig(socks_host=host, control_port=port, control_password="secret")
        )

        real_wait_for = asyncio.wait_for

        async def wait_for_quickly(coro: object, timeout: float | None = None) -> object:
            return await real_wait_for(coro, timeout=0.25)

        monkeypatch.setattr(asyncio, "wait_for", wait_for_quickly)

        started = time.monotonic()
        assert await connector.get_new_circuit() is False
        assert time.monotonic() - started < 5.0
