"""
Security and DPI Bypass Module for Shadow9.

Modern techniques based on GoodbyeDPI, ByeDPI, SpoofDPI, and zapret.
These tools are proven to work against Deep Packet Inspection in 2024-2025.

Techniques:
- TCP segmentation (split TLS ClientHello)
- Fake packet injection
- TTL manipulation
- SNI fragmentation
- Desync attacks
- TLS record fragmentation
"""

import secrets
from dataclasses import dataclass, field
from enum import Enum

import structlog

logger = structlog.get_logger(__name__)


class SecurityLevel(Enum):
    """Security/evasion level presets."""

    NONE = "none"  # No evasion, raw SOCKS5
    BASIC = "basic"  # TLS wrapping only
    MODERATE = "moderate"  # TLS + packet splitting
    PARANOID = "paranoid"  # Full DPI bypass techniques


@dataclass
class DPIBypassConfig:
    """
    DPI (Deep Packet Inspection) bypass configuration.

    Based on techniques from:
    - GoodbyeDPI (Windows)
    - ByeDPI (Cross-platform)
    - SpoofDPI (Go-based)
    - zapret (Linux)
    """

    enabled: bool = False

    # TCP Segmentation - Split TLS ClientHello into multiple segments
    # This confuses DPI that expects complete handshake in one packet
    split_tls_hello: bool = True
    split_position: int = 2  # Split after 2 bytes (confuses SNI detection)

    # Fake packet injection - Send decoy packets before real data
    fake_packets_enabled: bool = False

    # SNI (Server Name Indication) fragmentation
    # Split the SNI field across TCP segments
    fragment_sni: bool = True
    sni_split_position: int = 1  # Split SNI after 1 byte

    # Desync attack - Send data that breaks DPI state machine
    desync_enabled: bool = False
    desync_method: str = "split"  # split, fake, disorder

    # TLS record fragmentation
    tls_record_split_size: int = 1  # Very small records confuse DPI

    # HTTP-specific bypass (for HTTP CONNECT)
    http_space_before_method: bool = False  # " GET" instead of "GET"
    http_mixed_case_method: bool = False  # "gEt" instead of "GET"


@dataclass
class SecurityConfig:
    """
    Security and evasion configuration.

    Only settings the relay actually applies live here. Fields for TLS wrapping, traffic
    padding, common-port use and DNS-leak prevention used to sit alongside these, set by
    the presets and read by nothing, so an operator who chose paranoid was told they had
    protections that were never applied to a single byte. Anything added here needs a
    runtime path that reads it, and `test_security.py` checks that every field has one.
    """

    level: SecurityLevel = SecurityLevel.BASIC

    # DPI Bypass (modern techniques)
    dpi_bypass: DPIBypassConfig = field(default_factory=DPIBypassConfig)


class DPIBypass:
    """
    Modern DPI bypass implementation.

    Based on techniques proven to work in countries with advanced DPI:
    - Russia (Roskomnadzor)
    - China (Great Firewall)
    - Iran
    - And others
    """

    def __init__(self, config: DPIBypassConfig):
        self.config = config
        self._original_socket_send = None

    def split_tls_client_hello(self, data: bytes, position: int = 2) -> list[bytes]:
        """
        Split TLS ClientHello packet at specified position.

        DPI often expects the entire ClientHello in one packet.
        Splitting it breaks SNI detection.
        """
        if len(data) <= position:
            return [data]

        # Check if this is TLS handshake (0x16 = handshake, 0x03 = TLS version)
        if len(data) > 2 and data[0] == 0x16 and data[1] == 0x03:
            return [data[:position], data[position:]]

        return [data]

    def fragment_sni(self, data: bytes) -> list[bytes]:
        """
        Fragment the SNI (Server Name Indication) field in TLS ClientHello.

        SNI is used by DPI to determine which site you're connecting to.
        Fragmenting it makes detection harder.
        """
        if not self.config.fragment_sni:
            return [data]

        # Find SNI extension in ClientHello
        sni_offset = self._find_sni_offset(data)
        if sni_offset == -1:
            return [data]

        # Split at SNI boundary
        split_pos = sni_offset + self.config.sni_split_position
        if split_pos < len(data):
            return [data[:split_pos], data[split_pos:]]

        return [data]

    def _find_sni_offset(self, data: bytes) -> int:
        """Find the offset of SNI extension in TLS ClientHello."""
        try:
            # TLS record header is 5 bytes
            # Handshake header is 4 bytes
            # After that comes client version (2), random (32),
            # session_id length (1) + session_id, cipher_suites, etc.

            if len(data) < 43:  # Minimum TLS ClientHello size
                return -1

            # Check for TLS handshake
            if data[0] != 0x16:  # Not a handshake
                return -1

            # Look for SNI extension type (0x00 0x00)
            # This is a simplified search
            for i in range(43, len(data) - 4):
                if data[i : i + 2] == b"\x00\x00":  # SNI extension type
                    # Verify it looks like SNI
                    if i + 4 < len(data):
                        return i + 4  # Return position after extension header

            return -1
        except Exception:
            return -1

    def create_fake_packet(self, real_data: bytes) -> bytes:
        """
        Build a decoy payload the same length as the real data.

        The technique this comes from gives the decoy a TTL low enough that it dies
        before the destination, which needs a raw socket. Nothing here sets a TTL, so
        every preset leaves fake_packets_enabled off and this returns nothing.
        """
        if not self.config.fake_packets_enabled:
            return b""

        # Create packet with random payload
        fake_payload = secrets.token_bytes(len(real_data))
        return fake_payload

    def apply_desync(self, data: bytes) -> list[bytes]:
        """
        Apply desync attack to break DPI state machine.

        Methods:
        - split: Split into tiny segments
        - fake: Inject fake packets
        - disorder: Send out of order
        """
        if not self.config.desync_enabled:
            return [data]

        method = self.config.desync_method

        if method == "split":
            # Split into many small segments
            segments = []
            chunk_size = self.config.tls_record_split_size
            for i in range(0, len(data), chunk_size):
                segments.append(data[i : i + chunk_size])
            return segments

        elif method == "fake":
            # Insert fake packet before real data
            fake = self.create_fake_packet(data)
            if fake:
                return [fake, data]
            return [data]

        elif method == "disorder":
            # Send second half first (requires socket-level manipulation)
            mid = len(data) // 2
            return [data[mid:], data[:mid]]

        return [data]

    def fragment_for_bypass(self, data: bytes) -> list[bytes]:
        """
        Apply all enabled fragmentation techniques.

        Returns list of data chunks to send separately.
        """
        split_points: set[int] = set()

        # Apply TLS ClientHello splitting
        if self.config.split_tls_hello:
            tls_fragments = self.split_tls_client_hello(data, self.config.split_position)
            if len(tls_fragments) > 1:
                split_points.add(len(tls_fragments[0]))

        # Apply SNI fragmentation
        if self.config.fragment_sni:
            sni_fragments = self.fragment_sni(data)
            if len(sni_fragments) > 1:
                split_points.add(len(sni_fragments[0]))

        fragments: list[bytes] = []
        start = 0
        for split_point in sorted(split_points):
            fragments.append(data[start:split_point])
            start = split_point
        fragments.append(data[start:])

        # Apply desync if enabled
        if self.config.desync_enabled:
            new_fragments = []
            for frag in fragments:
                new_fragments.extend(self.apply_desync(frag))
            fragments = new_fragments

        return fragments

    def modify_http_request(self, data: bytes) -> bytes:
        """
        Modify HTTP request to evade DPI.

        Some DPI systems look for exact HTTP patterns.
        """
        if not data.startswith((b"GET ", b"POST ", b"CONNECT ", b"HEAD ")):
            return data

        modified = data

        # Add space before method
        if self.config.http_space_before_method:
            modified = b" " + modified

        # Mixed case method (some DPI is case-sensitive)
        if self.config.http_mixed_case_method:
            # gEt, pOsT, etc.
            for method in [b"GET", b"POST", b"CONNECT", b"HEAD", b"PUT", b"DELETE"]:
                if modified.upper().startswith(method):
                    mixed = bytes(
                        [c.lower() if i % 2 else c.upper() for i, c in enumerate(method.decode())],
                        "ascii",
                    )
                    modified = mixed + modified[len(method) :]
                    break

        return modified


def get_security_preset(level: SecurityLevel) -> SecurityConfig:
    """Get security configuration preset."""
    presets = {
        # none and basic are the same to the relay: both leave DPI bypass off. Basic is
        # kept because it is the default on every stored user record, so removing it
        # would make those records unreadable, and it is what an operator picks to say
        # "no evasion" without picking "none".
        SecurityLevel.NONE: SecurityConfig(
            level=SecurityLevel.NONE,
            dpi_bypass=DPIBypassConfig(enabled=False),
        ),
        SecurityLevel.BASIC: SecurityConfig(
            level=SecurityLevel.BASIC,
            dpi_bypass=DPIBypassConfig(enabled=False),
        ),
        SecurityLevel.MODERATE: SecurityConfig(
            level=SecurityLevel.MODERATE,
            dpi_bypass=DPIBypassConfig(
                enabled=True,
                split_tls_hello=True,
                fragment_sni=True,
                desync_enabled=False,
            ),
        ),
        SecurityLevel.PARANOID: SecurityConfig(
            level=SecurityLevel.PARANOID,
            dpi_bypass=DPIBypassConfig(
                enabled=True,
                split_tls_hello=True,
                split_position=1,
                fragment_sni=True,
                sni_split_position=1,
                desync_enabled=True,
                desync_method="split",
                tls_record_split_size=1,
                fake_packets_enabled=False,  # Requires raw sockets
            ),
        ),
    }
    return presets.get(level, presets[SecurityLevel.BASIC])


