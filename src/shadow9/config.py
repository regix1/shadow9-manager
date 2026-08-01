"""
Configuration management for Shadow9.

Provides secure configuration loading, validation, and storage.
"""

import ipaddress
import os
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, fields, asdict

import yaml
import structlog

from .paths import write_file_safely
from .wireguard import DEFAULT_INTERFACE, checked_interface


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


def _wireguard_listen_port_error(value: int) -> Optional[str]:
    """What is wrong with a wireguard.listen_port, or None when nothing is."""
    if 1 <= value <= 65535:
        return None
    return f"wireguard.listen_port must be between 1 and 65535, got {value}"


def _wireguard_enrollment_port_error(value: int) -> Optional[str]:
    """What is wrong with a wireguard.enrollment_port, or None when nothing is."""
    if 1 <= value <= 65535:
        return None
    return f"wireguard.enrollment_port must be between 1 and 65535, got {value}"


def listener_port_errors(
    api_port: Optional[int], enrollment_port: int, socks_port: int
) -> list[str]:
    """Name every pair of inbound listeners configured on the same port."""
    listeners = [
        ("wireguard.enrollment_port", enrollment_port),
        ("server.port", socks_port),
    ]
    if api_port is not None:
        listeners.insert(0, ("api.port", api_port))

    errors: list[str] = []
    for index, (left_name, left_port) in enumerate(listeners):
        for right_name, right_port in listeners[index + 1 :]:
            if left_port == right_port:
                errors.append(
                    f"{left_name} and {right_name} must use different ports; "
                    f"both are {left_port}"
                )
    return errors


def _is_private_tunnel_range(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Whether peer addresses may be handed out of this network.

    100.64.0.0/10 is the shared address space of RFC 6598. It is not globally routable, it
    is the range Tailscale hands out, and only Python 3.12.4 and later count it as
    private, so naming it here keeps the answer the same on every interpreter this runs on.
    """
    if network.is_private:
        return True
    shared = ipaddress.ip_network("100.64.0.0/10")
    return network.version == 4 and network.subnet_of(shared)


def _wireguard_tunnel_network_error(value: str) -> Optional[str]:
    """What is wrong with a wireguard.tunnel_network, or None when nothing is.

    A public range hands peers addresses that belong to someone else, and every packet
    bound for the real owner of that range is then sent into the tunnel instead of out to
    the internet, which looks like those sites being down rather than like a config error.
    """
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as e:
        return f"wireguard.tunnel_network is not a network: {value!r} ({e})"
    if _is_private_tunnel_range(network):
        return None
    return (
        f"wireguard.tunnel_network must be a private range, got {value}. "
        f"Use RFC 1918 space such as 10.9.0.0/24, the shared range 100.64.0.0/10, "
        f"or a random ULA under fd00::/8"
    )


def _wireguard_mtu_error(value: int) -> Optional[str]:
    """What is wrong with a wireguard.mtu, or None when nothing is.

    1280 is the smallest MTU an IPv6 link is allowed to carry, so below it the tunnel
    cannot carry IPv6 at all. 1440 is the largest that still fits a 1500 byte path once
    the 60 bytes of WireGuard framing and outer IPv4 and UDP headers are taken off, and
    anything above that is fragmented or dropped along the way rather than refused here.
    """
    if 1280 <= value <= 1440:
        return None
    return f"wireguard.mtu must be between 1280 and 1440, got {value}"


def _wireguard_keepalive_error(value: int) -> Optional[str]:
    """What is wrong with a wireguard.keepalive, or None when nothing is."""
    if 0 <= value <= 65535:
        return None
    return (
        f"wireguard.keepalive must be between 0 and 65535 seconds, got {value}. "
        f"0 turns keepalives off"
    )


def _wireguard_number_from_env(
    name: str, raw: str, error_of: Callable[[int], Optional[str]]
) -> int:
    """Read a WireGuard number out of the environment, refusing what a file would refuse.

    The variable is named in the message because an environment variable is invisible in
    a config file, so a message quoting only the value sends the operator to the wrong
    place to change it.
    """
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be a whole number, got {raw!r}") from None
    error = error_of(value)
    if error:
        raise ValueError(f"{name}: {error}")
    return value


def _wireguard_dns_from_env(raw: str) -> list[str]:
    """Split the comma separated resolver list SHADOW9_WIREGUARD_DNS carries.

    The API half reads this same variable through pydantic, which decodes a list from the
    environment as JSON unless told not to, so WireguardSettings.dns is marked NoDecode
    and splits on commas as well. One variable has to mean one thing on both halves.
    """
    return [part.strip() for part in raw.split(",") if part.strip()]


@dataclass
class WireguardConfig:
    """WireGuard hub settings, shared by every peer rather than set per user."""

    enabled: bool = False
    interface: str = DEFAULT_INTERFACE
    listen_port: int = 51820
    enrollment_host: str = "0.0.0.0"
    # Separate from the local admin API on 8080 and the SOCKS5 listener on 1080.
    enrollment_port: int = 8081
    tunnel_network: str = "10.9.0.0/24"
    # Empty until the operator knows the address peers dial. The hub is the one side that
    # has to be reachable from outside, and there is no sensible guess to make for it.
    hub_endpoint: str = ""
    # The MTU the kernel gives a fresh WireGuard device. Framing measures 32 bytes, a 16
    # byte header and a 16 byte Poly1305 tag, over an inner packet padded up to a multiple
    # of 16; with the outer IPv4 and UDP headers that is 60 bytes, so 1440 is what fits a
    # 1500 byte path. The 20 bytes below that are what an IPv6 underlay costs, whose outer
    # header is 40 bytes rather than 20. A wrong value here does not fail, it hangs: small
    # requests work and large transfers stall.
    mtu: int = 1420
    dns: list[str] = field(default_factory=list)
    # Common NAT and stateful firewall UDP mappings expire at around 30 seconds, so 25
    # refreshes the mapping just before it goes. It belongs on a peer behind NAT, not on
    # the hub, which is the side with the stable reachable address.
    keepalive: int = 25

    def __post_init__(self) -> None:
        # Refused at the boundary, as AuthConfig does, rather than reported by validate(),
        # which returns a list nothing on the serve path reads. Checked whether or not the
        # hub is enabled: a value that cannot work is a typo on the day it is written, not
        # on the day somebody turns the hub on.
        self.interface = checked_interface(self.interface)
        errors = _wireguard_setting_errors(self)
        if errors:
            raise ValueError("; ".join(errors))


def _wireguard_setting_errors(config: "WireguardConfig") -> list[str]:
    """Every problem with a WireguardConfig, empty when there is none.

    One list, read by construction and by Config.validate, so the two cannot come to
    disagree about which values are allowed.
    """
    try:
        checked_interface(config.interface)
        interface_error = None
    except ValueError as error:
        interface_error = str(error)

    found = (
        interface_error,
        _wireguard_listen_port_error(config.listen_port),
        _wireguard_enrollment_port_error(config.enrollment_port),
        _wireguard_tunnel_network_error(config.tunnel_network),
        _wireguard_mtu_error(config.mtu),
        _wireguard_keepalive_error(config.keepalive),
    )
    return [error for error in found if error]


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
    wireguard: WireguardConfig = field(default_factory=WireguardConfig)

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

        port_errors = listener_port_errors(
            None, config.wireguard.enrollment_port, config.server.port
        )
        if port_errors:
            raise ValueError("; ".join(port_errors))

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
            # A section missing from this list is never looked at and nothing warns about
            # it, so it loads as defaults forever while the file says otherwise.
            ("wireguard", WireguardConfig),
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

        # WireGuard overrides. These are the names WireguardSettings derives from its own
        # env prefix, so one variable configures the proxy half and the API half rather
        # than each of them reading a different one. Nothing here is automatic: a variable
        # left out of this block is read by the API and ignored by everything else.
        if env_val := os.getenv("SHADOW9_WIREGUARD_ENABLED"):
            self.wireguard.enabled = env_val.lower() in ("true", "1", "yes")
        if env_val := os.getenv("SHADOW9_WIREGUARD_INTERFACE"):
            self.wireguard.interface = checked_interface(env_val)
        if env_val := os.getenv("SHADOW9_WIREGUARD_LISTEN_PORT"):
            self.wireguard.listen_port = _wireguard_number_from_env(
                "SHADOW9_WIREGUARD_LISTEN_PORT", env_val, _wireguard_listen_port_error
            )
        if env_val := os.getenv("SHADOW9_WIREGUARD_ENROLLMENT_HOST"):
            self.wireguard.enrollment_host = env_val
        if env_val := os.getenv("SHADOW9_WIREGUARD_ENROLLMENT_PORT"):
            self.wireguard.enrollment_port = _wireguard_number_from_env(
                "SHADOW9_WIREGUARD_ENROLLMENT_PORT",
                env_val,
                _wireguard_enrollment_port_error,
            )
        if env_val := os.getenv("SHADOW9_WIREGUARD_TUNNEL_NETWORK"):
            network_error = _wireguard_tunnel_network_error(env_val)
            if network_error:
                raise ValueError(f"SHADOW9_WIREGUARD_TUNNEL_NETWORK: {network_error}")
            self.wireguard.tunnel_network = env_val
        if env_val := os.getenv("SHADOW9_WIREGUARD_HUB_ENDPOINT"):
            self.wireguard.hub_endpoint = env_val
        if env_val := os.getenv("SHADOW9_WIREGUARD_MTU"):
            self.wireguard.mtu = _wireguard_number_from_env(
                "SHADOW9_WIREGUARD_MTU", env_val, _wireguard_mtu_error
            )
        if env_val := os.getenv("SHADOW9_WIREGUARD_DNS"):
            self.wireguard.dns = _wireguard_dns_from_env(env_val)
        if env_val := os.getenv("SHADOW9_WIREGUARD_KEEPALIVE"):
            self.wireguard.keepalive = _wireguard_number_from_env(
                "SHADOW9_WIREGUARD_KEEPALIVE", env_val, _wireguard_keepalive_error
            )

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
            # A section left out of this dict is dropped from the file on the next save,
            # taking whatever the operator had set with it.
            "wireguard": asdict(self.wireguard),
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

        # Validate WireGuard config. Construction already refuses these, so only a value
        # assigned afterwards reaches here, which is what a config command is asked to
        # check. Reported whether or not the hub is enabled, so turning it on later cannot
        # be the moment a bad value first shows up.
        errors.extend(_wireguard_setting_errors(self.wireguard))
        errors.extend(
            listener_port_errors(None, self.wireguard.enrollment_port, self.server.port)
        )

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
