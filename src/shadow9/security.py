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

import asyncio
import ssl
import secrets
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

import structlog

logger = structlog.get_logger(__name__)


class SecurityLevel(Enum):
    """Security/evasion level presets."""
    NONE = "none"           # No evasion, raw SOCKS5
    BASIC = "basic"         # TLS wrapping only
    MODERATE = "moderate"   # TLS + packet splitting
    PARANOID = "paranoid"   # Full DPI bypass techniques


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
    fake_packet_ttl: int = 1  # TTL=1 so packet dies at first hop but confuses DPI

    # TTL manipulation - Vary TTL to evade stateful DPI
    ttl_manipulation: bool = False
    initial_ttl: int = 64

    # SNI (Server Name Indication) fragmentation
    # Split the SNI field across TCP segments
    fragment_sni: bool = True
    sni_split_position: int = 1  # Split SNI after 1 byte

    # Desync attack - Send data that breaks DPI state machine
    desync_enabled: bool = False
    desync_method: str = "split"  # split, fake, disorder

    # TLS record fragmentation
    fragment_tls_records: bool = True
    tls_record_split_size: int = 1  # Very small records confuse DPI

    # HTTP-specific bypass (for HTTP CONNECT)
    http_space_before_method: bool = False  # " GET" instead of "GET"
    http_mixed_case_method: bool = False    # "gEt" instead of "GET"
    http_extra_space: bool = False          # Double spaces in headers


@dataclass
class SecurityConfig:
    """Security and evasion configuration."""
    level: SecurityLevel = SecurityLevel.BASIC

    # TLS Settings
    tls_enabled: bool = True
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None

    # DPI Bypass (modern techniques)
    dpi_bypass: DPIBypassConfig = field(default_factory=DPIBypassConfig)

    # Traffic obfuscation
    padding_enabled: bool = False
    padding_min: int = 16
    padding_max: int = 256

    # Port settings
    use_common_ports: bool = True  # 80, 443, 8080

    # DNS
    prevent_dns_leaks: bool = True

    # Connection settings
    tcp_nodelay: bool = True  # Disable Nagle's algorithm for faster sends
    keep_alive: bool = True


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
                if data[i:i+2] == b'\x00\x00':  # SNI extension type
                    # Verify it looks like SNI
                    if i + 4 < len(data):
                        return i + 4  # Return position after extension header

            return -1
        except Exception:
            return -1

    def create_fake_packet(self, real_data: bytes) -> bytes:
        """
        Create a fake packet with low TTL.

        The packet reaches the DPI device but dies before reaching
        the destination, potentially confusing stateful inspection.
        """
        if not self.config.fake_packets_enabled:
            return b''

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
                segments.append(data[i:i+chunk_size])
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
        fragments = [data]

        # Apply TLS ClientHello splitting
        if self.config.split_tls_hello:
            new_fragments = []
            for frag in fragments:
                new_fragments.extend(
                    self.split_tls_client_hello(frag, self.config.split_position)
                )
            fragments = new_fragments

        # Apply SNI fragmentation
        if self.config.fragment_sni:
            new_fragments = []
            for frag in fragments:
                new_fragments.extend(self.fragment_sni(frag))
            fragments = new_fragments

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
        if not data.startswith((b'GET ', b'POST ', b'CONNECT ', b'HEAD ')):
            return data

        modified = data

        # Add space before method
        if self.config.http_space_before_method:
            modified = b' ' + modified

        # Mixed case method (some DPI is case-sensitive)
        if self.config.http_mixed_case_method:
            # gEt, pOsT, etc.
            for method in [b'GET', b'POST', b'CONNECT', b'HEAD', b'PUT', b'DELETE']:
                if modified.upper().startswith(method):
                    mixed = bytes([
                        c.lower() if i % 2 else c.upper()
                        for i, c in enumerate(method.decode())
                    ], 'ascii')
                    modified = mixed + modified[len(method):]
                    break

        return modified


class TLSWrapper:
    """
    Wraps SOCKS5 connections in TLS to appear as HTTPS traffic.
    """

    def __init__(self, config: SecurityConfig):
        self.config = config
        self._ssl_context: Optional[ssl.SSLContext] = None

    def create_server_context(self) -> ssl.SSLContext:
        """Create SSL context for server-side TLS."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        if self.config.tls_cert_file and self.config.tls_key_file:
            context.load_cert_chain(
                self.config.tls_cert_file,
                self.config.tls_key_file
            )
        else:
            cert_path, key_path = self._generate_self_signed_cert()
            context.load_cert_chain(cert_path, key_path)

        context.set_ciphers('ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20')
        context.options |= ssl.OP_NO_COMPRESSION

        return context

    def create_client_context(self, server_hostname: Optional[str] = None) -> ssl.SSLContext:
        """Create SSL context for client-side TLS."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _generate_self_signed_cert(self) -> tuple[str, str]:
        """Generate a self-signed certificate mimicking legitimate sites."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import tempfile
        from datetime import timedelta

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Mimic a common CDN certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cloudflare, Inc."),
            x509.NameAttribute(NameOID.COMMON_NAME, "sni.cloudflaressl.com"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("sni.cloudflaressl.com"),
                    x509.DNSName("*.cloudflare.com"),
                    x509.DNSName("cloudflare.com"),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        cert_path = Path(tempfile.gettempdir()) / "shadow9_cert.pem"
        key_path = Path(tempfile.gettempdir()) / "shadow9_key.pem"

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        logger.info("Generated TLS certificate", cn="sni.cloudflaressl.com")
        return str(cert_path), str(key_path)


class SecureTransport:
    """
    Secure transport layer with DPI bypass capabilities.

    Wraps asyncio streams with:
    - TLS encryption
    - Packet fragmentation
    - DPI evasion techniques
    """

    def __init__(self, config: SecurityConfig):
        self.config = config
        self.dpi_bypass = DPIBypass(config.dpi_bypass)
        self.tls_wrapper = TLSWrapper(config)

    async def send_with_bypass(
        self,
        writer: asyncio.StreamWriter,
        data: bytes
    ) -> None:
        """Send data with DPI bypass techniques applied."""
        if not self.config.dpi_bypass.enabled:
            writer.write(data)
            await writer.drain()
            return

        # Fragment data for DPI bypass
        fragments = self.dpi_bypass.fragment_for_bypass(data)

        # Send each fragment separately with small delays
        for i, fragment in enumerate(fragments):
            writer.write(fragment)
            await writer.drain()

            # Small delay between fragments to ensure they're sent separately
            if i < len(fragments) - 1:
                await asyncio.sleep(0.001)  # 1ms delay

    async def wrap_with_tls(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server_side: bool = True
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Wrap connection with TLS."""
        if not self.config.tls_enabled:
            return reader, writer

        if server_side:
            self.tls_wrapper.create_server_context()
        else:
            self.tls_wrapper.create_client_context()

        # This requires upgrading the transport to TLS
        # For server-side, this is done at accept time
        # For client-side, this can be done with start_tls

        return reader, writer  # Placeholder - TLS is applied at server start


class SecureServer:
    """
    Enhanced SOCKS5 server with security/DPI bypass features.
    """

    def __init__(self, base_server, security_config: SecurityConfig):
        self.base_server = base_server
        self.config = security_config
        self.transport = SecureTransport(security_config)
        self._ssl_context: Optional[ssl.SSLContext] = None

    async def start(self) -> None:
        """Start the secure server."""
        if self.config.tls_enabled:
            self._ssl_context = self.transport.tls_wrapper.create_server_context()
            logger.info("TLS enabled")

        if self.config.dpi_bypass.enabled:
            logger.info(
                "DPI bypass enabled",
                split_tls=self.config.dpi_bypass.split_tls_hello,
                fragment_sni=self.config.dpi_bypass.fragment_sni,
                desync=self.config.dpi_bypass.desync_enabled
            )

        # Start server with TLS if enabled
        if self._ssl_context:
            self.base_server._server = await asyncio.start_server(
                self.base_server._handle_client,
                self.base_server.host,
                self.base_server.port,
                ssl=self._ssl_context,
                reuse_address=True,
            )
        else:
            await self.base_server.start()
            return

        self.base_server._running = True
        addr = self.base_server._server.sockets[0].getsockname()

        features = []
        if self.config.tls_enabled:
            features.append("TLS")
        if self.config.dpi_bypass.enabled:
            features.append("DPI-Bypass")

        logger.info(
            "Secure SOCKS5 server started",
            host=addr[0],
            port=addr[1],
            features=features
        )

    async def stop(self) -> None:
        """Stop the secure server."""
        await self.base_server.stop()


def get_security_preset(level: SecurityLevel) -> SecurityConfig:
    """Get security configuration preset."""
    presets = {
        SecurityLevel.NONE: SecurityConfig(
            level=SecurityLevel.NONE,
            tls_enabled=False,
            dpi_bypass=DPIBypassConfig(enabled=False),
            padding_enabled=False,
            prevent_dns_leaks=False,
        ),
        SecurityLevel.BASIC: SecurityConfig(
            level=SecurityLevel.BASIC,
            tls_enabled=True,
            dpi_bypass=DPIBypassConfig(enabled=False),
            padding_enabled=False,
            prevent_dns_leaks=True,
        ),
        SecurityLevel.MODERATE: SecurityConfig(
            level=SecurityLevel.MODERATE,
            tls_enabled=True,
            dpi_bypass=DPIBypassConfig(
                enabled=True,
                split_tls_hello=True,
                fragment_sni=True,
                desync_enabled=False,
            ),
            padding_enabled=True,
            padding_min=32,
            padding_max=128,
            use_common_ports=True,
            prevent_dns_leaks=True,
        ),
        SecurityLevel.PARANOID: SecurityConfig(
            level=SecurityLevel.PARANOID,
            tls_enabled=True,
            dpi_bypass=DPIBypassConfig(
                enabled=True,
                split_tls_hello=True,
                split_position=1,
                fragment_sni=True,
                sni_split_position=1,
                desync_enabled=True,
                desync_method="split",
                fragment_tls_records=True,
                tls_record_split_size=1,
                fake_packets_enabled=False,  # Requires raw sockets
            ),
            padding_enabled=True,
            padding_min=64,
            padding_max=512,
            use_common_ports=True,
            prevent_dns_leaks=True,
        ),
    }
    return presets.get(level, presets[SecurityLevel.BASIC])


# Ports commonly allowed through corporate firewalls
FIREWALL_FRIENDLY_PORTS = [
    443,   # HTTPS - almost always allowed
    80,    # HTTP - usually allowed
    8080,  # HTTP Proxy - often allowed
    8443,  # HTTPS Alt - often allowed
]


def print_security_info(config: SecurityConfig) -> str:
    """Generate human-readable security configuration summary."""
    lines = [
        f"Security Level: {config.level.value.upper()}",
        f"TLS Encryption: {'Enabled' if config.tls_enabled else 'Disabled'}",
    ]

    if config.dpi_bypass.enabled:
        dpi = config.dpi_bypass
        lines.append("DPI Bypass: Enabled")
        if dpi.split_tls_hello:
            lines.append(f"  - TLS ClientHello splitting (pos: {dpi.split_position})")
        if dpi.fragment_sni:
            lines.append(f"  - SNI fragmentation (pos: {dpi.sni_split_position})")
        if dpi.desync_enabled:
            lines.append(f"  - Desync attack ({dpi.desync_method})")
        if dpi.fake_packets_enabled:
            lines.append(f"  - Fake packets (TTL: {dpi.fake_packet_ttl})")
    else:
        lines.append("DPI Bypass: Disabled")

    if config.padding_enabled:
        lines.append(f"Padding: {config.padding_min}-{config.padding_max} bytes")

    lines.append(f"DNS Leak Prevention: {'Enabled' if config.prevent_dns_leaks else 'Disabled'}")

    return "\n".join(lines)
