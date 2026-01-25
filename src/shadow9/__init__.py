"""
Shadow9 Manager - Secure SOCKS5 Proxy with Tor Support

A security-focused SOCKS5 proxy implementation with:
- Authenticated SOCKS5 server (host mode)
- SOCKS5 client with authentication
- Tor network connectivity for .onion access
"""

__version__ = "1.0.0"
__author__ = "Shadow9 Team"

from .socks5_server import Socks5Server
from .socks5_client import Socks5Client
from .tor_connector import TorConnector
from .auth import AuthManager
from .config import Config
from .security import SecurityLevel, SecurityConfig, get_security_preset
from .bridges import BridgeType, BridgeConfig, get_bridge_preset

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
