"""
Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

A security-focused SOCKS5 proxy implementation with:
- Authenticated SOCKS5 server (host mode)
- SOCKS5 client with authentication
- Tor network connectivity for .onion access
"""

from importlib.metadata import PackageNotFoundError, version as installed_version
from pathlib import Path

from .socks5_server import Socks5Server
from .socks5_client import Socks5Client
from .tor_connector import TorConnector
from .auth import AuthManager
from .config import Config
from .security import SecurityLevel, SecurityConfig, get_security_preset
from .bridges import BridgeType, BridgeConfig, get_bridge_preset


def _read_version() -> str:
    """
    The version this copy reports, from installed metadata or the VERSION file.

    An installed copy carries the number in its package metadata, which the build
    takes from VERSION. A source checkout has no metadata, so the same file is read
    directly rather than reporting something a release never produced.
    """
    try:
        return installed_version("shadow9-manager")
    except PackageNotFoundError:
        pass
    try:
        source = Path(__file__).resolve().parents[2] / "VERSION"
        return source.read_text(encoding="utf-8").strip() or "unknown"
    except OSError:
        return "unknown"


__version__ = _read_version()
__author__ = "Shadow9 Team"

__all__ = [
    "Socks5Server",
    "Socks5Client",
    "TorConnector",
    "AuthManager",
    "Config",
    "SecurityLevel",
    "SecurityConfig",
    "get_security_preset",
    "BridgeType",
    "BridgeConfig",
    "get_bridge_preset",
]
