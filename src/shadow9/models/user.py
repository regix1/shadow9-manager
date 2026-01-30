"""
User domain models with strong typing using Pydantic.

These models provide runtime validation and type safety for user-related data.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityLevel(str, Enum):
    """Security/evasion levels for traffic analysis protection."""
    NONE = "none"
    BASIC = "basic"
    MODERATE = "moderate"
    PARANOID = "paranoid"


class BridgeType(str, Enum):
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
        pattern=r'^[a-zA-Z0-9_-]+$',
        description="Unique username (alphanumeric, underscore, hyphen)"
    )
    use_tor: bool = Field(
        default=True,
        description="Whether to route traffic through Tor"
    )
    bridge_type: BridgeType = Field(
        default=BridgeType.NONE,
        description="Tor bridge type for censorship circumvention"
    )
    security_level: SecurityLevel = Field(
        default=SecurityLevel.BASIC,
        description="Security/evasion level for traffic analysis protection"
    )
    allowed_ports: Optional[list[int]] = Field(
        default=None,
        description="List of allowed destination ports (None = all ports)"
    )
    rate_limit: Optional[int] = Field(
        default=None,
        ge=1,
        description="Max requests per minute (None = server default)"
    )
    bind_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Custom bind port for this user (None = shared server port)"
    )
    logging_enabled: bool = Field(
        default=True,
        description="Whether to log activity for this user (privacy setting)"
    )
    enabled: bool = Field(
        default=True,
        description="Whether the user account is enabled"
    )

    @field_validator('allowed_ports')
    @classmethod
    def validate_ports(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        """Validate all ports are in valid range."""
        if v is not None:
            for port in v:
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}. Must be 1-65535")
        return v


class User(UserBase):
    """Full user model including timestamps."""
    
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the user was created"
    )
    last_used: Optional[datetime] = Field(
        default=None,
        description="Last authentication time"
    )


class Credential(User):
    """
    User credential model including password hash.
    
    This extends User with sensitive authentication data.
    Should not be exposed via API responses.
    """
    
    password_hash: str = Field(
        ...,
        description="Argon2id password hash"
    )
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        data = self.model_dump()
        # Convert datetime to ISO string for JSON compatibility
        if data.get('created_at'):
            data['created_at'] = data['created_at'].isoformat()
        if data.get('last_used'):
            data['last_used'] = data['last_used'].isoformat()
        # Convert enums to values
        data['bridge_type'] = data['bridge_type'].value if isinstance(data['bridge_type'], BridgeType) else data['bridge_type']
        data['security_level'] = data['security_level'].value if isinstance(data['security_level'], SecurityLevel) else data['security_level']
        return data
    
    @classmethod
    def from_dict(cls, data: dict) -> "Credential":
        """Create from dictionary (handles legacy date formats)."""
        # Handle ISO string dates
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('last_used'), str) and data['last_used']:
            data['last_used'] = datetime.fromisoformat(data['last_used'])
        return cls(**data)
