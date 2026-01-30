"""
Server domain models with strong typing using Pydantic.

These models define SOCKS5 protocol types and connection information.
"""

from datetime import datetime
from enum import IntEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Socks5AuthMethod(IntEnum):
    """SOCKS5 authentication methods (RFC 1928)."""
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


class Socks5Command(IntEnum):
    """SOCKS5 commands (RFC 1928)."""
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Socks5AddressType(IntEnum):
    """SOCKS5 address types (RFC 1928)."""
    IPV4 = 0x01
    DOMAIN = 0x03
    IPV6 = 0x04


class Socks5Reply(IntEnum):
    """SOCKS5 reply codes (RFC 1928)."""
    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_NOT_SUPPORTED = 0x08


class ConnectionInfo(BaseModel):
    """Information about an active proxy connection."""
    
    model_config = ConfigDict(from_attributes=True)
    
    client_address: str = Field(
        ...,
        description="Client IP address"
    )
    client_port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Client port"
    )
    username: Optional[str] = Field(
        default=None,
        description="Authenticated username"
    )
    target_host: Optional[str] = Field(
        default=None,
        description="Target host being connected to"
    )
    target_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Target port being connected to"
    )
    use_tor: bool = Field(
        default=False,
        description="Whether connection uses Tor"
    )
    connected_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the connection was established"
    )
    bytes_sent: int = Field(
        default=0,
        ge=0,
        description="Bytes sent to target"
    )
    bytes_received: int = Field(
        default=0,
        ge=0,
        description="Bytes received from target"
    )


class ServerStatus(BaseModel):
    """Server status information."""
    
    model_config = ConfigDict(from_attributes=True)
    
    running: bool = Field(
        ...,
        description="Whether the server is running"
    )
    host: str = Field(
        ...,
        description="Server bind address"
    )
    port: int = Field(
        ...,
        ge=1,
        le=65535,
        description="Server bind port"
    )
    active_connections: int = Field(
        default=0,
        ge=0,
        description="Number of active connections"
    )
    total_users: int = Field(
        default=0,
        ge=0,
        description="Total registered users"
    )
    tor_enabled: bool = Field(
        default=False,
        description="Whether Tor routing is enabled"
    )
    uptime_seconds: Optional[float] = Field(
        default=None,
        ge=0,
        description="Server uptime in seconds"
    )
