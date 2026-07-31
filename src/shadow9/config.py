"""
Configuration management for Shadow9.

Provides secure configuration loading, validation, and storage.
"""

import os
import secrets
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, fields, asdict

import yaml
import structlog

from .paths import write_file_safely


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

    # binding every interface exposes the proxy to the internet, so opt in explicitly
    host: str = "127.0.0.1"
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
    retry_attempts: int = 3
    retry_delay: float = 5.0


def _permit_count_error(value: Optional[int]) -> Optional[str]:
    """What is wrong with an auth.max_concurrent_auth, or None when nothing is.

    Zero builds a permit pool nothing can ever take from, so the proxy binds its port,
    accepts connections, and leaves every password verification waiting for a slot that
    is never released. A negative number raises from inside the server constructor,
    naming a semaphore rather than the setting that produced it.
    """
    if value is None or value >= 1:
        return None
    return (
        f"auth.max_concurrent_auth must be at least 1, got {value}. "
        f"Leave it unset to size it from the memory this process may use."
    )


def _permits_from_env(name: str, raw: str) -> int:
    """Read a permit count out of the environment, refusing one that cannot work."""
    try:
        permits = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a whole number, got {raw!r}") from None
    error = _permit_count_error(permits)
    if error:
        raise ValueError(f"{name}: {error}")
    return permits


@dataclass
class AuthConfig:
    """Authentication configuration."""

    require_auth: bool = True
    credentials_file: Optional[str] = None  # None = use paths module default
    master_key_env: str = "SHADOW9_MASTER_KEY"
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    # A memory budget, not a throughput one: each verification reserves 64 MB, so this
    # times 64 MB is the peak password hashing can reach. None means work it out from
    # the memory this process is allowed to use, which is the only answer that is right
    # on both a 1 GB VPS and a 64 GB host. A number set here is used exactly as written.
    max_concurrent_auth: Optional[int] = None

    def __post_init__(self) -> None:
        # Refused at the boundary rather than reported by validate(), which returns a
        # list nothing on the serve path reads. The API's own settings class already
        # requires at least one, and a proxy that quietly accepts what the API rejects
        # is how the two halves end up running different limits.
        error = _permit_count_error(self.max_concurrent_auth)
        if error:
            raise ValueError(error)


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
    # Matched against the name the client asks for, and a parent entry covers everything
    # under it. What each name resolves to is refused as well, so a client that looks the
    # name up itself and sends the literal is stopped too.
    #
    # On the Tor route the name is all that is checked. A domain is handed to the upstream
    # unresolved there on purpose, because resolving it here would send every Tor user's
    # destination to this machine's resolver, so a second name pointing at a blocked
    # machine reaches it. Treat this as an operator convenience rather than a control that
    # cannot be walked around. block_private_ranges screens every literal address on both
    # routes, and what a name resolves to on the direct one.
    blocked_hosts: list[str] = field(default_factory=list)
    allow_localhost: bool = False
    block_private_ranges: bool = True
    rate_limit_per_minute: int = 100
    max_request_size: int = 1048576  # 1MB


def get_project_root() -> Path:
    """
    Get the project root directory.

    Uses the centralized paths module for consistent path resolution.
    """
    from .paths import get_root

    return get_root()


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
        if self.auth.credentials_file is None:
            # Use centralized paths module for consistent location
            from .paths import get_credentials_file

            return get_credentials_file()
        return self.resolve_path(self.auth.credentials_file)

    @classmethod
    def load(cls, config_file: Optional[Path] = None) -> "Config":
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
                with open(config_file, "r") as f:
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
    def _from_dict(cls, data: dict) -> "Config":
        """Create Config from dictionary."""
        config = cls()

        sections: list[tuple[str, type]] = [
            ("server", ServerConfig),
            ("tor", TorConfig),
            ("auth", AuthConfig),
            ("log", LogConfig),
            ("security", SecurityConfig),
        ]

        for name, section_type in sections:
            values = data.get(name)
            if not isinstance(values, dict):
                continue

            known = {f.name for f in fields(section_type)}
            unknown = sorted(set(values) - known)
            if unknown:
                # a stray key must not take the server down before it binds
                logger.warning("Ignoring unknown config keys", section=name, keys=unknown)

            setattr(config, name, section_type(**{k: v for k, v in values.items() if k in known}))

        return config

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        # Server overrides
        if env_val := os.getenv("SHADOW9_HOST"):
            self.server.host = env_val
        if env_val := os.getenv("SHADOW9_PORT"):
            self.server.port = int(env_val)

        # Tor overrides
        if env_val := os.getenv("SHADOW9_TOR_ENABLED"):
            self.tor.enabled = env_val.lower() in ("true", "1", "yes")
        if env_val := os.getenv("SHADOW9_TOR_PORT"):
            self.tor.socks_port = int(env_val)

        # Auth overrides. The API's settings class reads this same variable under the
        # same name, so leaving it out here let one process honour a number the other
        # never saw and size itself independently.
        if env_val := os.getenv("SHADOW9_AUTH_MAX_CONCURRENT_AUTH"):
            self.auth.max_concurrent_auth = _permits_from_env(
                "SHADOW9_AUTH_MAX_CONCURRENT_AUTH", env_val
            )

        # Log overrides
        if env_val := os.getenv("SHADOW9_LOG_LEVEL"):
            self.log.level = env_val.upper()

    def save(self, config_file: Path) -> None:
        """Save configuration to file.

        Written whole and renamed into place: this is the file the server reads at
        startup, so a crash or a full disk part-way through a plain write leaves the
        proxy unable to load its own config before it binds.

        0644 rather than the helper's 0600 default. There is nothing secret in here, the
        file used to be created under the umask, and the rename installs a new file owned
        by whoever ran the save. At 0600 a sudo run would leave the operator's own
        `shadow9 user list` failing with a PermissionError from Config.load.
        """
        data = {
            "server": asdict(self.server),
            "tor": asdict(self.tor),
            "auth": asdict(self.auth),
            "log": asdict(self.log),
            "security": asdict(self.security),
        }

        serialized = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
        write_file_safely(config_file, serialized.encode(), mode=0o644)

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

        # Construction already refuses this, so only a value assigned afterwards reaches
        # here, which is exactly what a config command is asked to check.
        permit_error = _permit_count_error(self.auth.max_concurrent_auth)
        if permit_error:
            errors.append(permit_error)

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
