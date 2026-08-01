"""Tests for TLS fragmentation and relay buffering."""

import asyncio
import ssl
from unittest.mock import AsyncMock, Mock

import pytest

from shadow9.security import (
    DPIBypass,
    DPIBypassConfig,
    SecurityConfig,
    SecurityLevel,
    get_security_preset,
)
from shadow9.socks5_server import ConnectionInfo, Socks5Server


def _client_hello(hostname: str) -> bytes:
    """Create the bytes a TLS client sends before it receives a server response."""
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_bio(incoming, outgoing, server_hostname=hostname)

    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()

    return outgoing.read()


def _writer() -> Mock:
    """Create the StreamWriter operations used by the relay."""
    writer = Mock(spec=asyncio.StreamWriter)
    writer.drain = AsyncMock()
    writer.can_write_eof.return_value = True
    return writer


def _writes(writer: Mock) -> list[bytes]:
    """Return each byte string passed to StreamWriter.write."""
    return [call.args[0] for call in writer.write.call_args_list]


def _boundaries(fragments: list[bytes]) -> list[int]:
    """Return the byte offset after every fragment except the last one."""
    boundaries: list[int] = []
    offset = 0
    for fragment in fragments[:-1]:
        offset += len(fragment)
        boundaries.append(offset)
    return boundaries


@pytest.fixture
def server() -> Socks5Server:
    """Create a relay without starting a listener."""
    return Socks5Server(max_concurrent_auth=1, block_private_ranges=False)


def test_fragment_for_bypass_splits_complete_client_hello_at_sni() -> None:
    """Every configured split is measured against the complete ClientHello."""
    hostname = "sni-shadow9.example"
    client_hello = _client_hello(hostname)
    config = get_security_preset(SecurityLevel.MODERATE).dpi_bypass
    bypass = DPIBypass(config)
    sni_offset = bypass._find_sni_offset(client_hello)

    assert hostname.encode() in client_hello
    assert sni_offset != -1

    fragments = bypass.fragment_for_bypass(client_hello)

    assert b"".join(fragments) == client_hello
    assert _boundaries(fragments) == [
        config.split_position,
        sni_offset + config.sni_split_position,
    ]


@pytest.mark.asyncio
async def test_relay_buffers_split_client_hello_before_fragmenting(
    server: Socks5Server,
) -> None:
    """A short first read does not make the relay lose the later SNI split."""
    hostname = "sni-shadow9.example"
    client_hello = _client_hello(hostname)
    config = get_security_preset(SecurityLevel.MODERATE).dpi_bypass
    bypass = DPIBypass(config)
    sni_offset = bypass._find_sni_offset(client_hello)
    client_reader = asyncio.StreamReader()
    target_reader = asyncio.StreamReader()
    client_writer = _writer()
    target_writer = _writer()
    connection = ConnectionInfo(("127.0.0.1", 12345), hostname, 443)

    target_reader.feed_eof()
    client_reader.feed_data(client_hello[:20])
    relay = asyncio.create_task(
        server._relay(
            client_reader,
            client_writer,
            target_reader,
            target_writer,
            connection,
            bypass,
        )
    )
    await asyncio.sleep(0.01)
    client_reader.feed_data(client_hello[20:])
    client_reader.feed_eof()
    await asyncio.wait_for(relay, timeout=1)

    fragments = _writes(target_writer)
    assert b"".join(fragments) == client_hello
    assert _boundaries(fragments) == [
        config.split_position,
        sni_offset + config.sni_split_position,
    ]


@pytest.mark.asyncio
async def test_relay_releases_incomplete_tls_record_after_buffer_timeout(
    server: Socks5Server,
) -> None:
    """A client that stops during its first TLS record is not held indefinitely."""
    client_hello = _client_hello("sni-shadow9.example")
    partial_record = client_hello[:20]
    client_reader = asyncio.StreamReader()
    target_reader = asyncio.StreamReader()
    client_writer = _writer()
    target_writer = _writer()
    connection = ConnectionInfo(("127.0.0.1", 12345), "example.com", 443)
    bypass = DPIBypass(get_security_preset(SecurityLevel.MODERATE).dpi_bypass)
    server.TLS_RECORD_TIMEOUT = 0.01

    target_reader.feed_eof()
    client_reader.feed_data(partial_record)
    relay = asyncio.create_task(
        server._relay(
            client_reader,
            client_writer,
            target_reader,
            target_writer,
            connection,
            bypass,
        )
    )
    try:
        await asyncio.sleep(0.05)
        assert _writes(target_writer) == [partial_record]
    finally:
        client_reader.feed_eof()
        await asyncio.wait_for(relay, timeout=1)


@pytest.mark.asyncio
async def test_relay_does_not_buffer_tls_record_larger_than_read_limit(
    server: Socks5Server,
) -> None:
    """The configured relay buffer is also the first-record size limit."""
    client_hello = _client_hello("sni-shadow9.example")
    client_reader = asyncio.StreamReader()
    target_reader = asyncio.StreamReader()
    client_writer = _writer()
    target_writer = _writer()
    connection = ConnectionInfo(("127.0.0.1", 12345), "example.com", 443)
    bypass = DPIBypass(get_security_preset(SecurityLevel.MODERATE).dpi_bypass)
    server.MAX_BUFFER_SIZE = 20

    target_reader.feed_eof()
    client_reader.feed_data(client_hello)
    client_reader.feed_eof()
    await asyncio.wait_for(
        server._relay(
            client_reader,
            client_writer,
            target_reader,
            target_writer,
            connection,
            bypass,
        ),
        timeout=1,
    )

    fragments = _writes(target_writer)
    assert b"".join(fragments) == client_hello
    assert fragments[0] == client_hello[: server.MAX_BUFFER_SIZE]


class TestEveryPresetFieldIsApplied:
    """A preset field nothing reads is a protection an operator is promised and never gets.

    Six fields used to sit on SecurityConfig, set by the presets and read by no runtime
    path: TLS wrapping, traffic padding and its two bounds, common-port use, and DNS-leak
    prevention. A seventh, fragment_tls_records, did the same on DPIBypassConfig. Choosing
    paranoid applied none of them to a single byte. This is the check that stops another
    one being added.
    """

    def _read_somewhere(self, field_name: str) -> bool:
        """
        Whether any module under src reads this attribute off a config object.

        security.py counts, because the relay reaches these settings through
        DPIBypass.fragment_for_bypass, so a field read only in there is still applied to
        real traffic. The leading dot is what separates a read from a preset assignment:
        `split_position=1` in a constructor sets it, `self.config.split_position` uses it.
        """
        import re
        from pathlib import Path

        source_root = Path(__file__).resolve().parent.parent / "src" / "shadow9"
        reading = re.compile(rf"\.{re.escape(field_name)}\b")
        return any(
            reading.search(module.read_text(encoding="utf-8"))
            for module in source_root.rglob("*.py")
        )

    @pytest.mark.parametrize(
        "config_type",
        [SecurityConfig, DPIBypassConfig],
        ids=["SecurityConfig", "DPIBypassConfig"],
    )
    def test_no_field_is_inert(self, config_type: type) -> None:
        from dataclasses import fields as dataclass_fields

        # dpi_bypass holds the nested config rather than being a setting itself, and
        # level names which preset an object is so a caller can report it back.
        carriers = {"dpi_bypass", "level"}

        inert = [
            item.name
            for item in dataclass_fields(config_type)
            if item.name not in carriers and not self._read_somewhere(item.name)
        ]

        assert inert == [], (
            f"{config_type.__name__} has fields no runtime path reads: {inert}. "
            f"Either give each one a path that applies it, or take it out, because a "
            f"preset that sets it is promising something that never happens."
        )
