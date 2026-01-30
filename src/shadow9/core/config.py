"""
Shadow9 Configuration using Pydantic Settings.

Provides strongly typed configuration with environment variable support,
validation, and sensible defaults.

Environment variables use SHADOW9_ prefix:
- SHADOW9_HOST, SHADOW9_PORT (server settings)
- SHADOW9_TOR_ENABLED, SHADOW9_TOR_SOCKS_PORT (tor settings)
- SHADOW9_LOG_LEVEL (log settings)
- SHADOW9_MASTER_KEY (auth settings)
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_project_root() -> Path:
    """Get the project root directory."""
    import os
    
    # Check for environment override
    if env_home := os.getenv("SHADOW9_HOME"):
        return Path(env_home)
    
    # Default to current working directory
    return Path.cwd()


class ServerSettings(BaseSettings):
    """Server configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_",
        extra="ignore",
    )
    
    host: str = Field(
        default="127.0.0.1",
        description="Server bind address"
    )
    port: int = Field(
        default=1080,
        ge=1,
        le=65535,
        description="Server bind port"
    )
    max_connections: int = Field(
        default=100,
        ge=1,
        description="Maximum concurrent connections"
    )
    connection_timeout: int = Field(
        default=300,
        ge=1,
        description="Connection timeout in seconds"
    )


class TorSettings(BaseSettings):
    """Tor routing configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_TOR_",
        extra="ignore",
    )
    
    enabled: bool = Field(
        default=True,
        description="Enable Tor routing"
    )
    socks_port: int = Field(
        default=9050,
        ge=1,
        le=65535,
        description="Tor SOCKS port"
    )
    control_port: int = Field(
        default=9051,
        ge=1,
        le=65535,
        description="Tor control port"
    )
    retry_attempts: int = Field(
        default=3,
        ge=1,
        description="Connection retry attempts"
    )
    retry_delay: float = Field(
        default=1.0,
        ge=0,
        description="Delay between retries in seconds"
    )


class AuthSettings(BaseSettings):
    """Authentication configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_AUTH_",
        extra="ignore",
    )
    
    require_auth: bool = Field(
        default=True,
        description="Require authentication"
    )
    credentials_file: Optional[str] = Field(
        default=None,
        description="Path to credentials file (relative to project root)"
    )
    max_failed_attempts: int = Field(
        default=5,
        ge=1,
        description="Max failed auth attempts before lockout"
    )
    lockout_duration: int = Field(
        default=300,
        ge=0,
        description="Lockout duration in seconds"
    )


class LogSettings(BaseSettings):
    """Logging configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_LOG_",
        extra="ignore",
    )
    
    level: str = Field(
        default="INFO",
        description="Log level"
    )
    format: str = Field(
        default="json",
        description="Log format (json, console)"
    )
    file: Optional[str] = Field(
        default=None,
        description="Log file path"
    )
    
    @field_validator('level')
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper


class SecuritySettings(BaseSettings):
    """Security configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_SECURITY_",
        extra="ignore",
    )
    
    allowed_ports: list[int] = Field(
        default_factory=lambda: [80, 443, 8080, 8443],
        description="Default allowed destination ports"
    )
    default_rate_limit: int = Field(
        default=100,
        ge=1,
        description="Default requests per minute"
    )
    block_private_ranges: bool = Field(
        default=True,
        description="Block connections to private IP ranges"
    )


class ApiSettings(BaseSettings):
    """API server configuration settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_API_",
        extra="ignore",
    )
    
    enabled: bool = Field(
        default=False,
        description="Enable API server"
    )
    host: str = Field(
        default="127.0.0.1",
        description="API host address"
    )
    port: int = Field(
        default=8080,
        ge=1,
        le=65535,
        description="API port"
    )
    api_key: Optional[str] = Field(
        default=None,
        description="API key for authentication (stored encrypted)"
    )


class Settings(BaseSettings):
    """
    Main application settings.
    
    Loads configuration from:
    1. Environment variables (SHADOW9_* prefix)
    2. YAML config file (config/config.yaml)
    3. Default values
    
    Environment variables take precedence.
    """
    
    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_",
        env_nested_delimiter="__",
        extra="ignore",
    )
    
    server: ServerSettings = Field(default_factory=ServerSettings)
    tor: TorSettings = Field(default_factory=TorSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    log: LogSettings = Field(default_factory=LogSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    
    # Global settings
    master_key: Optional[str] = Field(
        default=None,
        description="Master key for credential encryption"
    )
    
    @classmethod
    def load_from_yaml(cls, config_file: Path) -> "Settings":
        """Load settings from YAML file with environment overrides."""
        data = {}
        
        if config_file.exists():
            with open(config_file, 'r') as f:
                data = yaml.safe_load(f) or {}
        
        # Create nested settings from YAML data
        settings_dict = {}
        
        if 'server' in data:
            settings_dict['server'] = ServerSettings(**data['server'])
        if 'tor' in data:
            settings_dict['tor'] = TorSettings(**data['tor'])
        if 'auth' in data:
            settings_dict['auth'] = AuthSettings(**data['auth'])
        if 'log' in data:
            settings_dict['log'] = LogSettings(**data['log'])
        if 'security' in data:
            settings_dict['security'] = SecuritySettings(**data['security'])
        if 'api' in data:
            settings_dict['api'] = ApiSettings(**data['api'])
        
        return cls(**settings_dict)
    
    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path against the project root."""
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return get_project_root() / path
    
    def get_credentials_file(self) -> Path:
        """Get the absolute path to the credentials file."""
        if self.auth.credentials_file:
            return self.resolve_path(self.auth.credentials_file)
        return get_project_root() / "config" / "credentials.enc"
    
    def save_to_yaml(self, config_file: Path) -> None:
        """Save settings to YAML file."""
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'server': {
                'host': self.server.host,
                'port': self.server.port,
                'max_connections': self.server.max_connections,
                'connection_timeout': self.server.connection_timeout,
            },
            'tor': {
                'enabled': self.tor.enabled,
                'socks_port': self.tor.socks_port,
                'control_port': self.tor.control_port,
                'retry_attempts': self.tor.retry_attempts,
                'retry_delay': self.tor.retry_delay,
            },
            'auth': {
                'require_auth': self.auth.require_auth,
                'credentials_file': self.auth.credentials_file,
                'max_failed_attempts': self.auth.max_failed_attempts,
                'lockout_duration': self.auth.lockout_duration,
            },
            'log': {
                'level': self.log.level,
                'format': self.log.format,
                'file': self.log.file,
            },
            'security': {
                'allowed_ports': self.security.allowed_ports,
                'default_rate_limit': self.security.default_rate_limit,
                'block_private_ranges': self.security.block_private_ranges,
            },
            'api': {
                'enabled': self.api.enabled,
                'host': self.api.host,
                'port': self.api.port,
                # Note: api_key is not saved to YAML for security - use api_config module
            },
        }
        
        with open(config_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)
    
    def validate_all(self) -> list[str]:
        """
        Validate all settings.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Port range validation
        if self.server.port < 1 or self.server.port > 65535:
            errors.append(f"Invalid server port: {self.server.port}")
        
        if self.tor.enabled:
            if self.tor.socks_port < 1 or self.tor.socks_port > 65535:
                errors.append(f"Invalid Tor SOCKS port: {self.tor.socks_port}")
        
        # Security validation
        for port in self.security.allowed_ports:
            if port < 1 or port > 65535:
                errors.append(f"Invalid allowed port: {port}")
        
        return errors


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings (cached singleton).
    
    First attempts to load from config/config.yaml, then applies
    environment variable overrides.
    """
    config_file = get_project_root() / "config" / "config.yaml"
    
    if config_file.exists():
        return Settings.load_from_yaml(config_file)
    
    return Settings()
