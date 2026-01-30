"""
Shadow9 Domain Models

Strongly typed Pydantic models for the Shadow9 proxy manager.
"""

from .user import (
    SecurityLevel,
    BridgeType,
    UserBase,
    User,
    Credential,
)
from .server import (
    Socks5AuthMethod,
    Socks5Command,
    Socks5AddressType,
    Socks5Reply,
    ConnectionInfo,
)

__all__ = [
    # User models
    "SecurityLevel",
    "BridgeType",
    "UserBase",
    "User",
    "Credential",
    # Server models
    "Socks5AuthMethod",
    "Socks5Command",
    "Socks5AddressType",
    "Socks5Reply",
    "ConnectionInfo",
]
