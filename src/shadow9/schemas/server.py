"""
Server API schemas for request/response validation.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ServerStatusResponse(BaseModel):
    """Response schema for server status."""
    
    model_config = ConfigDict(from_attributes=True)
    
    running: bool = Field(..., description="Server is running")
    host: str = Field(..., description="Bind address")
    port: int = Field(..., description="Bind port")
    active_connections: int = Field(default=0, description="Active connections")
    total_users: int = Field(default=0, description="Registered users")
    tor_enabled: bool = Field(default=False, description="Tor routing enabled")
    uptime_seconds: Optional[float] = Field(default=None, description="Uptime in seconds")


class ServerConfigUpdate(BaseModel):
    """Schema for updating server configuration."""
    
    host: Optional[str] = Field(
        default=None,
        description="Server bind address"
    )
    port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="Server bind port"
    )
    max_connections: Optional[int] = Field(
        default=None,
        ge=1,
        description="Maximum concurrent connections"
    )
    tor_enabled: Optional[bool] = Field(
        default=None,
        description="Enable Tor routing"
    )
    log_level: Optional[str] = Field(
        default=None,
        pattern=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$',
        description="Logging level"
    )
