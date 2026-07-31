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

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import Field, PrivateAttr, field_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

from ..memory_budget import (
    MIB,
    HashPermits,
    MemoryCeilingTooLow,
    choose_hash_permits,
    read_memory_budget,
)
from ..paths import write_file_safely
from .logging import get_logger

logger = get_logger(__name__)


def get_project_root() -> Path:
    """Get the project root directory."""
    # Check for environment override
    if env_home := os.getenv("SHADOW9_HOME"):
        return Path(env_home)

    # Default to current working directory
    return Path.cwd()


class EnvFirstSettings(BaseSettings):
    """Settings whose environment variables outrank values handed in by the caller."""

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Order the sources so the environment wins.

        `load_from_yaml` hands the file's values in as init kwargs, and init kwargs
        outrank the environment by default, which silently ignores every SHADOW9_*
        variable for a section the file happens to define.
        """
        return env_settings, init_settings, dotenv_settings, file_secret_settings


class ServerSettings(EnvFirstSettings):
    """Server configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_",
        extra="ignore",
    )

    host: str = Field(default="127.0.0.1", description="Server bind address")
    port: int = Field(default=1080, ge=1, le=65535, description="Server bind port")
    max_connections: int = Field(default=100, ge=1, description="Maximum concurrent connections")
    connection_timeout: int = Field(default=30, ge=1, description="Connection timeout in seconds")


class TorSettings(EnvFirstSettings):
    """Tor routing configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_TOR_",
        extra="ignore",
    )

    enabled: bool = Field(default=True, description="Enable Tor routing")
    socks_port: int = Field(default=9050, ge=1, le=65535, description="Tor SOCKS port")
    control_port: int = Field(default=9051, ge=1, le=65535, description="Tor control port")
    retry_attempts: int = Field(default=3, ge=1, description="Connection retry attempts")
    retry_delay: float = Field(default=5.0, ge=0, description="Delay between retries in seconds")


class AuthSettings(EnvFirstSettings):
    """Authentication configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_AUTH_",
        extra="ignore",
    )

    require_auth: bool = Field(default=True, description="Require authentication")
    credentials_file: Optional[str] = Field(
        default=None, description="Path to credentials file (relative to project root)"
    )
    max_failed_attempts: int = Field(
        default=5, ge=1, description="Max failed auth attempts before lockout"
    )
    lockout_duration_minutes: int = Field(
        default=15, ge=0, description="Lockout duration in minutes"
    )
    max_concurrent_auth: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "Password verifications allowed to run at the same time, "
            "or unset to size it from the memory this process may use"
        ),
    )

    # get_settings() fills max_concurrent_auth in so callers read a real number without
    # each having to size it themselves. The file still has to say "unset", or the next
    # save would freeze today's figure as though a person had chosen it, and the value
    # would stop following the machine it runs on.
    _sized_from_memory: bool = PrivateAttr(default=False)

    @property
    def sized_from_memory(self) -> bool:
        """Whether the live max_concurrent_auth was worked out rather than configured."""
        return self._sized_from_memory

    def __setattr__(self, name: str, value: Any) -> None:
        """Assigning the value by hand makes it a setting, whatever it was before.

        Without this the provenance flag outlives the figure it described: an operator
        changing the number through the settings endpoint after startup had already
        filled one in would have their choice saved as null and lost on the next load,
        because the save writes "unset" for anything the sizing produced.
        """
        super().__setattr__(name, value)
        if name == "max_concurrent_auth":
            super().__setattr__("_sized_from_memory", False)

    def use_sized_concurrent_auth(self, permits: int) -> None:
        """Adopt a permit count that was worked out from the memory budget."""
        self.max_concurrent_auth = permits
        self._sized_from_memory = True


class LogSettings(EnvFirstSettings):
    """Logging configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_LOG_",
        extra="ignore",
    )

    level: str = Field(default="INFO", description="Log level")
    format: str = Field(default="json", description="Log format (json, console)")
    file: Optional[str] = Field(default=None, description="Log file path")

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v_upper


class SecuritySettings(EnvFirstSettings):
    """Security configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_SECURITY_",
        extra="ignore",
    )

    allowed_ports: list[int] = Field(
        default_factory=lambda: [80, 443, 8080, 8443],
        description="Default allowed destination ports",
    )
    blocked_hosts: list[str] = Field(
        default_factory=list,
        description=(
            "Blocked destination host names, parent entries covering everything under "
            "them. The name asked for is refused on both routes, and so is any address "
            "the name resolves to. On the Tor route the name is all that can be checked, "
            "because the destination is handed upstream unresolved, so another name for "
            "a blocked machine still reaches it"
        ),
    )
    allow_localhost: bool = Field(default=False, description="Allow connections to localhost")
    rate_limit_per_minute: int = Field(
        default=100, ge=1, description="Requests per minute per user"
    )
    block_private_ranges: bool = Field(
        default=True, description="Block connections to private IP ranges"
    )


class ApiSettings(EnvFirstSettings):
    """API server configuration settings."""

    model_config = SettingsConfigDict(
        env_prefix="SHADOW9_API_",
        extra="ignore",
    )

    enabled: bool = Field(default=False, description="Enable API server")
    host: str = Field(default="127.0.0.1", description="API host address")
    port: int = Field(default=8080, ge=1, le=65535, description="API port")
    api_key: Optional[str] = Field(
        default=None, description="API key for authentication (stored encrypted)"
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
        default=None, description="Master key for credential encryption"
    )

    @classmethod
    def load_from_yaml(cls, config_file: Path) -> "Settings":
        """Load settings from YAML file with environment overrides."""
        data = {}

        if config_file.exists():
            with open(config_file, "r") as f:
                data = yaml.safe_load(f) or {}

        # Create nested settings from YAML data
        settings_dict = {}

        if "server" in data:
            settings_dict["server"] = ServerSettings(**data["server"])
        if "tor" in data:
            settings_dict["tor"] = TorSettings(**data["tor"])
        if "auth" in data:
            settings_dict["auth"] = AuthSettings(**data["auth"])
        if "log" in data:
            settings_dict["log"] = LogSettings(**data["log"])
        if "security" in data:
            settings_dict["security"] = SecuritySettings(**data["security"])
        if "api" in data:
            settings_dict["api"] = ApiSettings(**data["api"])

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
        """Save settings to YAML file.

        Keys the file already carries are kept even when `Settings` does not model
        them. Writing only the modelled keys deleted fourteen of the user's settings
        on the first save, `server.relay_timeout` and `log.max_size_mb` among them.
        """
        data: dict = {}
        if config_file.exists():
            with open(config_file, "r") as f:
                data = yaml.safe_load(f) or {}

        modelled = {
            "server": {
                "host": self.server.host,
                "port": self.server.port,
                "max_connections": self.server.max_connections,
                "connection_timeout": self.server.connection_timeout,
            },
            "tor": {
                "enabled": self.tor.enabled,
                "socks_port": self.tor.socks_port,
                "control_port": self.tor.control_port,
                "retry_attempts": self.tor.retry_attempts,
                "retry_delay": self.tor.retry_delay,
            },
            "auth": {
                "require_auth": self.auth.require_auth,
                "credentials_file": self.auth.credentials_file,
                "max_failed_attempts": self.auth.max_failed_attempts,
                "lockout_duration_minutes": self.auth.lockout_duration_minutes,
                # A figure worked out from this machine's memory is written back as
                # unset. Saving it would turn one boot's answer into a fixed setting
                # that no longer follows the box it runs on.
                "max_concurrent_auth": (
                    None if self.auth.sized_from_memory else self.auth.max_concurrent_auth
                ),
            },
            "log": {
                "level": self.log.level,
                "format": self.log.format,
                "file": self.log.file,
            },
            "security": {
                "allowed_ports": self.security.allowed_ports,
                "blocked_hosts": self.security.blocked_hosts,
                "allow_localhost": self.security.allow_localhost,
                "rate_limit_per_minute": self.security.rate_limit_per_minute,
                "block_private_ranges": self.security.block_private_ranges,
            },
            "api": {
                "enabled": self.api.enabled,
                "host": self.api.host,
                "port": self.api.port,
                # Note: api_key is not saved to YAML for security - use api_config module
            },
        }

        for section, values in modelled.items():
            existing = data.get(section)
            if isinstance(existing, dict):
                existing.update(values)
            else:
                data[section] = values

        serialized = yaml.safe_dump(data, default_flow_style=False, sort_keys=False)
        # 0644 rather than the helper's 0600 default. There is nothing secret in here,
        # the file used to be created under the umask, and the rename installs a new file
        # owned by whoever ran the save, so 0600 after a sudo run locks the operator's own
        # CLI out of the config it reads at startup. api.yaml keeps 0600: it carries the
        # encrypted API key
        write_file_safely(config_file, serialized.encode("utf-8"), mode=0o644)

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


def api_worker_count() -> int:
    """How many API processes will be sharing one memory budget.

    uvicorn takes its worker count from WEB_CONCURRENCY when it is not given one, and
    this application never passes one, so a value in the environment quietly multiplies
    every figure worked out here. Each worker is a separate process with its own permit
    pool and its own interpreter, while MemoryMax is charged to the unit that holds them
    all, so the shared ceiling has to be divided rather than handed to each of them
    whole.
    """
    try:
        workers = int(os.getenv("WEB_CONCURRENCY", "1"))
    except ValueError:
        return 1
    return max(1, workers)


@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings (cached singleton).

    First attempts to load from config/config.yaml, then applies
    environment variable overrides.

    An unset `auth.max_concurrent_auth` is filled in here from the memory this process
    is allowed to use, so everything reading it gets a real number without each caller
    having to work one out. The decision is logged once, because a permit count nobody
    can trace is the failure that costs the most time to diagnose.
    """
    config_file = get_project_root() / "config" / "config.yaml"

    if config_file.exists():
        settings = Settings.load_from_yaml(config_file)
    else:
        settings = Settings()

    # This process serves the admin API and holds no relay buffers, so nothing is
    # reserved for them here. The budget is divided by the worker count first: this
    # function is cached per process and every worker runs its own copy, so without the
    # division each of them would size itself against the whole cgroup and the unit
    # would run the permit count several times over.
    #
    # Read once, unlike the proxy, which reads the ceiling again every 30 seconds. The
    # proxy has to: its permits gate a hash run for every client that authenticates, so a
    # ceiling lowered under it becomes an OOM kill within seconds of the next burst of
    # logins. The permits worked out here gate UserRepository._hash_slots, which is
    # entered only when an administrator writes a user. Nothing is waiting on that
    # semaphore between those calls, and get_user_repository is itself cached, so a
    # re-read would have to rebuild the semaphore as well as the number to change
    # anything. A ceiling changed under this process is applied by restarting it.
    #
    # The division here is between the workers of this one service, not between this
    # service and the proxy. They are not in the same cgroup: `shadow9 service install`
    # writes one unit, which runs the proxy alone, and the API is started separately. An
    # operator who does put both under one unit is giving each of them the unit's whole
    # MemoryMax to size against, and should give the API its own unit, or set MemoryMax
    # on each of them, rather than one figure covering both.
    workers = api_worker_count()
    budget = read_memory_budget().shared_between(workers)
    try:
        chosen = choose_hash_permits(
            settings.auth.max_concurrent_auth,
            relay_reserve_bytes=0,
            budget=budget,
        )
    except MemoryCeilingTooLow as e:
        # The proxy refuses to start on this, and is right to: its permits gate a hash
        # run for every client that logs in, so a share too small for one of them becomes
        # an OOM kill on the next burst. Here they gate an administrator writing a user,
        # one at a time, with nothing else in this process reserving memory. Serving the
        # management interface slowly beats having none of it, so this one says the whole
        # arithmetic out loud and carries on with the floor.
        chosen = HashPermits(
            permits=1,
            budget=budget,
            set_by_operator=False,
            exceeds_budget=True,
            reason=f"1 permit, the floor. {e}",
        )
    if not chosen.set_by_operator:
        settings.auth.use_sized_concurrent_auth(chosen.permits)
    # A number that does not fit is not a fact to file away with the others.
    say = logger.warning if chosen.exceeds_budget else logger.info
    say(
        "Password hashing limit",
        permits=chosen.permits,
        set_by_operator=chosen.set_by_operator,
        exceeds_budget=chosen.exceeds_budget,
        budget_mib=chosen.budget.usable_bytes // MIB,
        budget_source=chosen.budget.source,
        budget_detail=chosen.budget.detail,
        budget_measured=chosen.budget.measured,
        api_workers=workers,
        cores=os.cpu_count(),
        reason=chosen.reason,
    )

    return settings
