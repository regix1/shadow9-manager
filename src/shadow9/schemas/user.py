"""
User API schemas for request/response validation.

These schemas control what data is accepted and exposed via the API.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models.user import BridgeType, PeerRole, SecurityLevel, UserBase


class UserCreate(BaseModel):
    """Schema for creating a new user (POST /users)."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique username",
        examples=["john_doe", "user-123"],
    )
    password: str = Field(
        ..., min_length=12, description="Strong password (min 12 chars, mixed case, digit, special)"
    )
    use_tor: bool = Field(default=True, description="Route traffic through Tor")
    bridge_type: BridgeType = Field(default=BridgeType.NONE, description="Tor bridge type")
    security_level: SecurityLevel = Field(
        default=SecurityLevel.BASIC, description="Security/evasion level"
    )
    allowed_ports: Optional[list[int]] = Field(
        default=None, description="Allowed destination ports (null = all)"
    )
    rate_limit: Optional[int] = Field(default=None, ge=1, description="Max requests per minute")
    bind_port: Optional[int] = Field(default=None, ge=1, le=65535, description="Custom bind port")
    logging_enabled: bool = Field(default=True, description="Enable activity logging")

    # WireGuard peer settings. Absent means the new user is not a peer, which is what a
    # plain proxy user is. The checks are UserBase's, called rather than restated, so a key
    # or a route the CLI would refuse is refused here too.
    wg_public_key: Optional[str] = Field(default=None, description="Base64 X25519 public key")
    wg_address: Optional[str] = Field(default=None, description="Tunnel address, no prefix")
    wg_routes: Optional[list[str]] = Field(
        default=None, description="Subnets reachable through this peer, in CIDR form"
    )
    wg_role: Optional[PeerRole] = Field(default=None, description="hub, node or device")
    wg_endpoint: Optional[str] = Field(default=None, description="host:port other peers dial")
    wg_keepalive: Optional[int] = Field(
        default=None, ge=1, le=65535, description="Seconds between keepalives"
    )
    wg_expires_at: Optional[datetime] = Field(
        default=None, description="When this peer stops being allowed in"
    )

    @field_validator("wg_public_key")
    @classmethod
    def validate_wg_public_key(cls, v: Optional[str]) -> Optional[str]:
        """Apply the key check the store and the renderer already apply."""
        return UserBase.validate_wg_public_key(v)

    @field_validator("wg_address")
    @classmethod
    def validate_wg_address(cls, v: Optional[str]) -> Optional[str]:
        """Apply the address check the store already applies."""
        return UserBase.validate_wg_address(v)

    @field_validator("wg_routes")
    @classmethod
    def validate_wg_routes(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Apply the route check the store already applies, host bits and all."""
        return UserBase.validate_wg_routes(v)

    @field_validator("wg_endpoint")
    @classmethod
    def validate_wg_endpoint(cls, v: Optional[str]) -> Optional[str]:
        """Apply the endpoint check the store already applies."""
        return UserBase.validate_wg_endpoint(v)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one special character")
        return v

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        """Validate all ports are in valid range."""
        if v is not None:
            for port in v:
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}. Must be 1-65535")
        return v


class UserUpdate(BaseModel):
    """Schema for updating a user (PATCH /users/{username})."""

    password: Optional[str] = Field(
        default=None, min_length=12, description="New password (optional)"
    )
    use_tor: Optional[bool] = Field(default=None, description="Route traffic through Tor")
    bridge_type: Optional[BridgeType] = Field(default=None, description="Tor bridge type")
    security_level: Optional[SecurityLevel] = Field(
        default=None, description="Security/evasion level"
    )
    allowed_ports: Optional[list[int]] = Field(
        default=None, description="Allowed destination ports"
    )
    rate_limit: Optional[int] = Field(default=None, ge=1, description="Max requests per minute")
    bind_port: Optional[int] = Field(default=None, ge=1, le=65535, description="Custom bind port")
    logging_enabled: Optional[bool] = Field(default=None, description="Enable activity logging")
    enabled: Optional[bool] = Field(default=None, description="Enable/disable user")

    # The same seven peer settings. A PATCH is the path a peer's address or routes change
    # by, and UserRepository.update setattrs whatever it is handed onto a dataclass that
    # does not check assignments, so a value that gets past here reaches the file unchecked.
    wg_public_key: Optional[str] = Field(default=None, description="Base64 X25519 public key")
    wg_address: Optional[str] = Field(default=None, description="Tunnel address, no prefix")
    wg_routes: Optional[list[str]] = Field(
        default=None, description="Subnets reachable through this peer, in CIDR form"
    )
    wg_role: Optional[PeerRole] = Field(default=None, description="hub, node or device")
    wg_endpoint: Optional[str] = Field(default=None, description="host:port other peers dial")
    wg_keepalive: Optional[int] = Field(
        default=None, ge=1, le=65535, description="Seconds between keepalives"
    )
    wg_expires_at: Optional[datetime] = Field(
        default=None, description="When this peer stops being allowed in"
    )

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        """Apply the range the create schema and the CLI already apply.

        Without this a PATCH stored ports the CLI refuses. `UserRepository.update`
        setattrs whatever it is given and `Credential` does not validate on assignment,
        so a 0 reached disk and then matched no real destination port for that user.
        """
        return UserCreate.validate_ports(v)

    @field_validator("wg_public_key")
    @classmethod
    def validate_wg_public_key(cls, v: Optional[str]) -> Optional[str]:
        """Apply the key check the store and the renderer already apply."""
        return UserBase.validate_wg_public_key(v)

    @field_validator("wg_address")
    @classmethod
    def validate_wg_address(cls, v: Optional[str]) -> Optional[str]:
        """Apply the address check the store already applies."""
        return UserBase.validate_wg_address(v)

    @field_validator("wg_routes")
    @classmethod
    def validate_wg_routes(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        """Apply the route check the store already applies, host bits and all."""
        return UserBase.validate_wg_routes(v)

    @field_validator("wg_endpoint")
    @classmethod
    def validate_wg_endpoint(cls, v: Optional[str]) -> Optional[str]:
        """Apply the endpoint check the store already applies."""
        return UserBase.validate_wg_endpoint(v)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: Optional[str]) -> Optional[str]:
        """Validate password if provided."""
        if v is None:
            return v
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserResponse(BaseModel):
    """Schema for user response (excludes sensitive data like password_hash)."""

    model_config = ConfigDict(from_attributes=True)

    username: str = Field(..., description="Username")
    use_tor: bool = Field(..., description="Routes through Tor")
    bridge_type: BridgeType = Field(..., description="Tor bridge type")
    security_level: SecurityLevel = Field(..., description="Security level")
    allowed_ports: Optional[list[int]] = Field(..., description="Allowed ports")
    rate_limit: Optional[int] = Field(..., description="Rate limit")
    bind_port: Optional[int] = Field(..., description="Custom bind port")
    logging_enabled: bool = Field(..., description="Logging enabled")
    enabled: bool = Field(..., description="Account enabled")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_used: Optional[datetime] = Field(..., description="Last authentication")

    # Optional here where the fields above are required, because a user who is not a
    # WireGuard peer is the ordinary case and a response for one carries none of these.
    wg_public_key: Optional[str] = Field(default=None, description="Base64 X25519 public key")
    wg_address: Optional[str] = Field(default=None, description="Tunnel address, no prefix")
    wg_routes: Optional[list[str]] = Field(
        default=None, description="Subnets reachable through this peer, in CIDR form"
    )
    wg_role: Optional[PeerRole] = Field(default=None, description="hub, node or device")
    wg_endpoint: Optional[str] = Field(default=None, description="host:port other peers dial")
    wg_keepalive: Optional[int] = Field(
        default=None, ge=1, le=65535, description="Seconds between keepalives"
    )
    wg_expires_at: Optional[datetime] = Field(
        default=None, description="When this peer stops being allowed in"
    )

    @field_validator("wg_public_key")
    @classmethod
    def validate_wg_public_key(cls, v: Optional[str]) -> Optional[str]:
        return UserBase.validate_wg_public_key(v)

    @field_validator("wg_address")
    @classmethod
    def validate_wg_address(cls, v: Optional[str]) -> Optional[str]:
        return UserBase.validate_wg_address(v)

    @field_validator("wg_routes")
    @classmethod
    def validate_wg_routes(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        return UserBase.validate_wg_routes(v)

    @field_validator("wg_endpoint")
    @classmethod
    def validate_wg_endpoint(cls, v: Optional[str]) -> Optional[str]:
        return UserBase.validate_wg_endpoint(v)


class UserListResponse(BaseModel):
    """Response for listing users."""

    users: list[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., ge=0, description="Total user count")
