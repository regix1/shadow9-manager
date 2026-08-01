"""
User domain models with strong typing using Pydantic.

These models provide runtime validation and type safety for user-related data.
"""

from datetime import datetime, UTC
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..wireguard.addresses import parse_address, parse_network
from ..wireguard.keys import is_valid_key
from ..wireguard.render import PeerRole


def utc_now() -> datetime:
    """The current time, carrying UTC rather than leaving the zone to be guessed."""
    return datetime.now(UTC)


def _stored_time(value: datetime) -> str:
    """
    Render a time the way the credentials file has always held it.

    The store's timestamps are naive UTC and an existing install's file is full of
    them, so writing an offset here would change every string in that file. The zone
    is dropped on the way out and put back by `_loaded_time` on the way in, which
    keeps the bytes on disk identical while the models stay zone-aware.
    """
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value.isoformat()


def _loaded_time(value: str) -> datetime:
    """Read a stored timestamp back, reading a missing zone as the UTC it always was."""
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


class SecurityLevel(StrEnum):
    """Security/evasion levels for traffic analysis protection."""

    NONE = "none"
    BASIC = "basic"
    MODERATE = "moderate"
    PARANOID = "paranoid"


class BridgeType(StrEnum):
    """Tor bridge types for bypassing censorship."""

    NONE = "none"
    OBFS4 = "obfs4"
    SNOWFLAKE = "snowflake"


class UserBase(BaseModel):
    """Base user model with common fields."""

    model_config = ConfigDict(
        from_attributes=True,
        str_strip_whitespace=True,
    )

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique username (alphanumeric, underscore, hyphen)",
    )
    use_tor: bool = Field(default=True, description="Whether to route traffic through Tor")
    bridge_type: BridgeType = Field(
        default=BridgeType.NONE, description="Tor bridge type for censorship circumvention"
    )
    security_level: SecurityLevel = Field(
        default=SecurityLevel.BASIC,
        description="Security/evasion level for traffic analysis protection",
    )
    allowed_ports: Optional[list[int]] = Field(
        default=None, description="List of allowed destination ports (None = all ports)"
    )
    rate_limit: Optional[int] = Field(
        default=None, ge=1, description="Max requests per minute (None = server default)"
    )
    bind_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Custom bind port for this user (None = shared server port)",
    )
    logging_enabled: bool = Field(
        default=True, description="Whether to log activity for this user (privacy setting)"
    )
    enabled: bool = Field(default=True, description="Whether the user account is enabled")

    # WireGuard peer settings, the same seven the credential store holds and checked the
    # same way. All of them absent means this user is not a peer. The checks below call
    # into the wireguard package rather than restating the rules, so the API and the CLI
    # cannot come to disagree about what a valid key or a valid route is.
    wg_public_key: Optional[str] = Field(
        default=None, description="Base64 X25519 public key (44 characters)"
    )
    wg_address: Optional[str] = Field(
        default=None, description="This peer's address inside the tunnel, without a prefix"
    )
    wg_routes: Optional[list[str]] = Field(
        default=None, description="Subnets reachable through this peer, in CIDR form"
    )
    wg_role: Optional[PeerRole] = Field(
        default=None, description="What this peer is in the star: hub, node or device"
    )
    wg_endpoint: Optional[str] = Field(
        default=None, description="host:port other peers dial. Only the hub has one"
    )
    wg_keepalive: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Seconds between keepalives this peer sends (None = send none)",
    )
    wg_expires_at: Optional[datetime] = Field(
        default=None, description="When this peer stops being allowed in"
    )

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        """Validate all ports are in valid range."""
        if v is not None:
            for port in v:
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}. Must be 1-65535")
        return v

    @field_validator("wg_public_key")
    @classmethod
    def validate_wg_public_key(cls, v: Optional[str]) -> Optional[str]:
        """Apply the check the renderer applies, so a key the tunnel would reject never stores."""
        if v is not None and not is_valid_key(v):
            raise ValueError(f"Not a WireGuard public key: {v!r}")
        return v

    @field_validator("wg_address")
    @classmethod
    def validate_wg_address(cls, v: Optional[str]) -> Optional[str]:
        """A single host inside the tunnel, so a prefix is refused rather than ignored."""
        if v is not None:
            parse_address(v)
        return v

    @field_validator("wg_routes")
    @classmethod
    def validate_wg_routes(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Every route is a network, host bits and all.

        parse_network refuses them rather than masking them off, so 192.168.1.1/24 is an
        error here instead of a silent 192.168.1.0/24. Those are different subnets and the
        difference decides which traffic crosses the tunnel.
        """
        if v is not None:
            for route in v:
                parse_network(route)
        return v

    @field_validator("wg_endpoint")
    @classmethod
    def validate_wg_endpoint(cls, v: Optional[str]) -> Optional[str]:
        """An endpoint has to be something to dial, so an empty string is not one."""
        if v is not None and not v.strip():
            raise ValueError("Endpoint is empty")
        return v


class User(UserBase):
    """Full user model including timestamps."""

    created_at: datetime = Field(
        default_factory=utc_now, description="When the user was created"
    )
    last_used: Optional[datetime] = Field(default=None, description="Last authentication time")


class Credential(User):
    """
    User credential model including password hash.

    This extends User with sensitive authentication data.
    Should not be exposed via API responses.
    """

    password_hash: str = Field(..., description="Argon2id password hash")

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        data = self.model_dump()
        # Convert datetime to ISO string for JSON compatibility
        if data.get("created_at"):
            data["created_at"] = _stored_time(data["created_at"])
        if data.get("last_used"):
            data["last_used"] = _stored_time(data["last_used"])
        # Convert enums to values
        data["bridge_type"] = (
            data["bridge_type"].value
            if isinstance(data["bridge_type"], BridgeType)
            else data["bridge_type"]
        )
        data["security_level"] = (
            data["security_level"].value
            if isinstance(data["security_level"], SecurityLevel)
            else data["security_level"]
        )
        # The peer settings go to the store in the shapes it holds: an expiry as one of
        # this file's naive UTC strings, a role as its plain word. Left as a datetime and a
        # PeerRole they would reach json.dumps in the store and fail the write there,
        # which is a long way from here.
        if data.get("wg_expires_at"):
            data["wg_expires_at"] = _stored_time(data["wg_expires_at"])
        if isinstance(data.get("wg_role"), PeerRole):
            data["wg_role"] = data["wg_role"].value
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        """Create from dictionary (handles legacy date formats)."""
        # Handle ISO string dates
        if isinstance(data.get("created_at"), str):
            data["created_at"] = _loaded_time(data["created_at"])
        if isinstance(data.get("last_used"), str) and data["last_used"]:
            data["last_used"] = _loaded_time(data["last_used"])
        if isinstance(data.get("wg_expires_at"), str) and data["wg_expires_at"]:
            data["wg_expires_at"] = _loaded_time(data["wg_expires_at"])
        return cls(**data)
