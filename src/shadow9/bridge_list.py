"""
Snowflake and obfs4 bridge configurations for Shadow9.

This file contains the built-in bridge lists. These are updated periodically.
For production, get fresh bridges from https://bridges.torproject.org

Sources:
- https://forum.torproject.org/t/fix-problems-with-snowflake-since-2024-03-01-broker-failure-unexpected-error-no-answer/11755
- https://github.com/net4people/bbs/issues/338
- https://github.com/net4people/bbs/issues/197
"""

from dataclasses import dataclass, field
from typing import List
from enum import Enum


class BridgeType(Enum):
    """Supported bridge/pluggable transport types."""
    NONE = "none"           # Direct Tor connection (detectable)
    OBFS4 = "obfs4"         # Obfuscated traffic (recommended)
    SNOWFLAKE = "snowflake" # Uses WebRTC peers
    WEBTUNNEL = "webtunnel" # Looks like HTTPS to allowed domains


@dataclass
class Bridge:
    """A single Tor bridge configuration."""
    type: BridgeType
    address: str           # IP:Port or domain
    fingerprint: str       # Bridge fingerprint
    params: dict = field(default_factory=dict)  # Transport-specific params

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


# =============================================================================
# STUN Servers (for WebRTC NAT traversal)
# =============================================================================

STUN_SERVERS = ",".join([
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


# =============================================================================
# obfs4 Bridges (public bridges from Tor Project)
# =============================================================================

BUILTIN_OBFS4_BRIDGES: List[Bridge] = [
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


# =============================================================================
# Snowflake Bridges
# =============================================================================

# Fastly CDN URL (most reliable)
_FASTLY_URL = "https://snowflake-broker.torproject.net.global.prod.fastly.net/"

# Standard fingerprint for most snowflake bridges
_SNOWFLAKE_FP = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"


def _fastly_bridge(address_suffix: int, front: str) -> Bridge:
    """Helper to create Fastly-based snowflake bridge."""
    return Bridge(
        type=BridgeType.SNOWFLAKE,
        address=f"192.0.2.{address_suffix}:80",
        fingerprint=_SNOWFLAKE_FP,
        params={
            "url": _FASTLY_URL,
            "front": front,
            "ice": STUN_SERVERS,
            "utls-imitate": "hellorandomizedalpn"
        }
    )


# Fastly CDN fronts (most reliable)
SNOWFLAKE_FASTLY_SHAZAM = _fastly_bridge(3, "www.shazam.com")
SNOWFLAKE_FASTLY_FOURSQUARE = _fastly_bridge(4, "foursquare.com")
SNOWFLAKE_FASTLY_COSMO = _fastly_bridge(5, "www.cosmopolitan.com")
SNOWFLAKE_FASTLY_ESQUIRE = _fastly_bridge(6, "www.esquire.com")
SNOWFLAKE_FASTLY_JSDELIVR = _fastly_bridge(7, "fastly.jsdelivr.net")
SNOWFLAKE_FASTLY_JIMDO = _fastly_bridge(8, "www.jimdo.com")
SNOWFLAKE_FASTLY_DRUPAL = _fastly_bridge(9, "www.drupal.org")
SNOWFLAKE_FASTLY_SENTRY = _fastly_bridge(10, "js.sentry-cdn.com")
SNOWFLAKE_FASTLY_1STDIBS = _fastly_bridge(11, "www.1stdibs.com")
SNOWFLAKE_FASTLY_FILESTACK = _fastly_bridge(12, "www.filestack.com")

# AMP Cache with Google fronting
SNOWFLAKE_AMP_GOOGLE = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.13:80",
    fingerprint=_SNOWFLAKE_FP,
    params={
        "url": "https://snowflake-broker.torproject.net/",
        "ampcache": "https://cdn.ampproject.org/",
        "front": "www.google.com",
        "ice": STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# CDN77 (backup - may be slow in some regions)
SNOWFLAKE_CDN77 = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.14:80",
    fingerprint=_SNOWFLAKE_FP,
    params={
        "url": "https://1098762253.rsc.cdn77.org/",
        "front": "www.phpmyadmin.net",
        "ice": STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# Bunny CDN (Triplebit private broker - independent infrastructure)
SNOWFLAKE_BUNNY = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="10.0.3.1:80",
    fingerprint="53B65F538F5E9A5FA6DFE5D75C78CB66C5515EF7",
    params={
        "url": "https://triplebit-snowflake-broker.b-cdn.net/",
        "front": "www.bunny.net",
        "ice": STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)

# Azure CDN (good fallback, may work when others are blocked)
SNOWFLAKE_AZURE = Bridge(
    type=BridgeType.SNOWFLAKE,
    address="192.0.2.15:80",
    fingerprint=_SNOWFLAKE_FP,
    params={
        "url": "https://snowflake-broker.azureedge.net/",
        "front": "ajax.aspnetcdn.com",
        "ice": STUN_SERVERS,
        "utls-imitate": "hellorandomizedalpn"
    }
)


# =============================================================================
# Bridge Lists (speed tested and sorted at runtime)
# =============================================================================

# All snowflake bridges - Fastly fronts first (most reliable)
SNOWFLAKE_BRIDGES: List[Bridge] = [
    # Fastly CDN fronts (fastest, most reliable)
    SNOWFLAKE_FASTLY_SHAZAM,
    SNOWFLAKE_FASTLY_FOURSQUARE,
    SNOWFLAKE_FASTLY_COSMO,
    SNOWFLAKE_FASTLY_ESQUIRE,
    SNOWFLAKE_FASTLY_JSDELIVR,
    SNOWFLAKE_FASTLY_JIMDO,
    SNOWFLAKE_FASTLY_DRUPAL,
    SNOWFLAKE_FASTLY_SENTRY,
    SNOWFLAKE_FASTLY_1STDIBS,
    SNOWFLAKE_FASTLY_FILESTACK,
    # AMP cache (Google fronting)
    SNOWFLAKE_AMP_GOOGLE,
    # Alternative CDNs
    SNOWFLAKE_AZURE,
    SNOWFLAKE_CDN77,
    SNOWFLAKE_BUNNY,
]

# Default bridge (for backwards compatibility)
SNOWFLAKE_BRIDGE = SNOWFLAKE_FASTLY_SHAZAM
