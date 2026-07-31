"""
Server API schemas for request/response validation.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ServerStatusResponse(BaseModel):
    """Response schema for server status."""

    model_config = ConfigDict(from_attributes=True)

    running: bool = Field(
        ..., description="Something is accepting connections at the configured address"
    )
    host: str = Field(..., description="Bind address")
    port: int = Field(..., description="Bind port")
    active_connections: Optional[int] = Field(
        default=None, description="Active connections, null when not observable from this process"
    )
    total_users: int = Field(default=0, description="Registered users")
    tor_enabled: bool = Field(default=False, description="Tor routing enabled")
    uptime_seconds: Optional[float] = Field(
        default=None, description="Uptime in seconds, null when not observable from this process"
    )


class ServerSection(BaseModel):
    """Server values safe to return through the configuration endpoint."""

    host: str
    port: int
    max_connections: int
    connection_timeout: int


class TorSection(BaseModel):
    """Tor values safe to return through the configuration endpoint."""

    enabled: bool
    socks_port: int


class AuthSection(BaseModel):
    """Authentication values safe to return through the configuration endpoint."""

    require_auth: bool
    max_failed_attempts: int
    lockout_duration_minutes: int
    max_concurrent_auth: int | None
    max_concurrent_auth_api_process: int | None
    max_concurrent_auth_sized_from_memory: bool
    api_workers: int
    memory_budget_mib: int
    memory_budget_source: str
    memory_budget_detail: str
    memory_budget_measured: bool


class SecuritySection(BaseModel):
    """Network access values safe to return through the configuration endpoint."""

    allowed_ports: list[int]
    rate_limit_per_minute: int
    block_private_ranges: bool
    allow_localhost: bool
    blocked_hosts: list[str]


class LogSection(BaseModel):
    """Logging values safe to return through the configuration endpoint."""

    level: str
    format: str


class WireguardSection(BaseModel):
    """WireGuard values safe to return through the configuration endpoint."""

    enabled: bool
    listen_port: int
    enrollment_host: str
    enrollment_port: int
    tunnel_network: str
    hub_endpoint: str
    mtu: int
    dns: list[str]
    keepalive: int


class ServerConfigResponse(BaseModel):
    """Non-sensitive server configuration grouped by section."""

    server: ServerSection
    tor: TorSection
    auth: AuthSection
    security: SecuritySection
    log: LogSection
    wireguard: WireguardSection


class ServerConfigUpdate(BaseModel):
    """Schema for updating server configuration."""

    host: Optional[str] = Field(default=None, description="Server bind address")
    port: Optional[int] = Field(default=None, ge=1, le=65535, description="Server bind port")
    max_connections: Optional[int] = Field(
        default=None, ge=1, description="Maximum concurrent connections"
    )
    tor_enabled: Optional[bool] = Field(default=None, description="Enable Tor routing")
    log_level: Optional[str] = Field(
        default=None, pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$", description="Logging level"
    )
