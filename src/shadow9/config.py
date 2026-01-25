"""
Configuration management for Shadow9.

Provides secure configuration loading, validation, and storage.
"""

import os
import secrets
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, field, asdict

import yaml
import structlog

# Configure structlog early with consistent formatting
# This ensures all logs have the same format even before setup_logging() is called
def _configure_default_logging():
    """Configure structlog with default settings."""
    import logging
    
    def uppercase_log_level(logger, method_name, event_dict):
        if "level" in event_dict:
            event_dict["level"] = event_dict["level"].upper()
        return event_dict
    
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        uppercase_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(colors=True, pad_event=0, pad_level=False),
    ]
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,  # Allow reconfiguration
    )
    
    logging.basicConfig(format="%(message)s", level=logging.INFO)

_configure_default_logging()

logger = structlog.get_logger(__name__)


@dataclass
class ServerConfig:
    """SOCKS5 server configuration."""
    host: str = "0.0.0.0"
    port: int = 1080
    max_connections: int = 100
    connection_timeout: int = 30
    relay_timeout: int = 300
    buffer_size: int = 65536


@dataclass
class TorConfig:
    """Tor connection configuration."""
    enabled: bool = True
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_port: int = 9051
    control_password: Optional[str] = None
    auto_detect: bool = True


@dataclass
class AuthConfig:
    """Authentication configuration."""
    require_auth: bool = True
    credentials_file: str = "config/credentials.enc"
    master_key_env: str = "SHADOW9_MASTER_KEY"
    session_timeout_hours: int = 24
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15


@dataclass
class LogConfig:
    """Logging configuration."""
    level: str = "INFO"
    format: str = "json"  # json or console
    file: Optional[str] = None
    max_size_mb: int = 10
    backup_count: int = 3


@dataclass
class SecurityConfig:
    """Security settings."""
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8080, 8443])
    blocked_hosts: list[str] = field(default_factory=list)
    allow_localhost: bool = False
    rate_limit_per_minute: int = 100
    max_request_size: int = 1048576  # 1MB


def get_project_root() -> Path:
    """
    Get the project root directory.
    
    Searches for .env file or uses the package location as fallback.
    This ensures consistent path resolution regardless of current working directory.
    """
    # Search locations in priority order
    search_locations = [
        Path.cwd(),                                          # Current directory
        Path(__file__).parent.parent.parent,                 # Package location (src/shadow9/config.py -> project root)
        Path.home() / "shadow9-manager",                     # Common install location
        Path("/opt/shadow9-manager"),                        # System install location
        Path("/root/shadow9-manager"),                       # Root user location
    ]
    
    # Find the first location that has .env or config directory
    for loc in search_locations:
        if (loc / ".env").exists() or (loc / "config").exists():
            return loc.resolve()
    
    # Fallback to package location
    return Path(__file__).parent.parent.parent.resolve()


@dataclass
class Config:
    """Main configuration container."""
    server: ServerConfig = field(default_factory=ServerConfig)
    tor: TorConfig = field(default_factory=TorConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    log: LogConfig = field(default_factory=LogConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    def resolve_path(self, relative_path: str) -> Path:
        """Resolve a relative path against the project root."""
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return get_project_root() / path
    
    def get_credentials_file(self) -> Path:
        """Get the absolute path to the credentials file."""
        return self.resolve_path(self.auth.credentials_file)

    @classmethod
    def load(cls, config_file: Optional[Path] = None) -> 'Config':
        """
        Load configuration from file.

        Args:
            config_file: Path to YAML config file

        Returns:
            Config instance
        """
        config = cls()

        if config_file and config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    data = yaml.safe_load(f)

                if data:
                    config = cls._from_dict(data)

            except Exception as e:
                logger.error("Failed to load config", file=str(config_file), error=str(e))
                raise

        # Override with environment variables
        config._apply_env_overrides()

        return config

    @classmethod
    def _from_dict(cls, data: dict) -> 'Config':
        """Create Config from dictionary."""
        config = cls()

        if 'server' in data:
            config.server = ServerConfig(**data['server'])
        if 'tor' in data:
            config.tor = TorConfig(**data['tor'])
        if 'auth' in data:
            config.auth = AuthConfig(**data['auth'])
        if 'log' in data:
            config.log = LogConfig(**data['log'])
        if 'security' in data:
            config.security = SecurityConfig(**data['security'])

        return config

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # Server overrides
        if env_val := os.getenv('SHADOW9_HOST'):
            self.server.host = env_val
        if env_val := os.getenv('SHADOW9_PORT'):
            self.server.port = int(env_val)

        # Tor overrides
        if env_val := os.getenv('SHADOW9_TOR_ENABLED'):
            self.tor.enabled = env_val.lower() in ('true', '1', 'yes')
        if env_val := os.getenv('SHADOW9_TOR_PORT'):
            self.tor.socks_port = int(env_val)

        # Log overrides
        if env_val := os.getenv('SHADOW9_LOG_LEVEL'):
            self.log.level = env_val.upper()

    def save(self, config_file: Path) -> None:
        """Save configuration to file."""
        config_file.parent.mkdir(parents=True, exist_ok=True)

        data = {
            'server': asdict(self.server),
            'tor': asdict(self.tor),
            'auth': asdict(self.auth),
            'log': asdict(self.log),
            'security': asdict(self.security),
        }

        with open(config_file, 'w') as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info("Saved configuration", file=str(config_file))

    def validate(self) -> list[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate server config
        if self.server.port < 1 or self.server.port > 65535:
            errors.append(f"Invalid server port: {self.server.port}")

        if self.server.max_connections < 1:
            errors.append("max_connections must be positive")

        # Validate tor config
        if self.tor.enabled:
            if self.tor.socks_port < 1 or self.tor.socks_port > 65535:
                errors.append(f"Invalid Tor SOCKS port: {self.tor.socks_port}")

        # Validate auth config
        if self.auth.require_auth and self.auth.max_failed_attempts < 1:
            errors.append("max_failed_attempts must be positive")

        # Validate security config
        for port in self.security.allowed_ports:
            if port < 1 or port > 65535:
                errors.append(f"Invalid allowed port: {port}")

        return errors


def generate_default_config(output_path: Path) -> Config:
    """
    Generate a default configuration file.

    Args:
        output_path: Path to save the config file

    Returns:
        The generated Config instance
    """
    config = Config()
    config.save(output_path)
    return config


def setup_logging(config: LogConfig) -> None:
    """
    Configure structured logging.

    Args:
        config: Logging configuration
    """
    import logging

    def uppercase_log_level(logger, method_name, event_dict):
        """Uppercase the log level."""
        if "level" in event_dict:
            event_dict["level"] = event_dict["level"].upper()
        return event_dict

    # Configure structlog
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        uppercase_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if config.format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True, pad_event=0, pad_level=False))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Set log level
    log_level = getattr(logging, config.level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
    )

    # Add file handler if configured
    if config.file:
        from logging.handlers import RotatingFileHandler

        file_handler = RotatingFileHandler(
            config.file,
            maxBytes=config.max_size_mb * 1024 * 1024,
            backupCount=config.backup_count,
        )
        file_handler.setLevel(log_level)
        logging.getLogger().addHandler(file_handler)


def generate_master_key() -> str:
    """
    Generate a secure master key for credential encryption.

    Returns:
        URL-safe base64 encoded key
    """
    return secrets.token_urlsafe(32)
