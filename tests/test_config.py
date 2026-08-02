"""Tests for configuration loading, saving and precedence."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from shadow9.config import (
    Config,
    LogConfig,
    ServerConfig,
    WireguardConfig,
    generate_default_config,
)
from shadow9.core.config import Settings, WireguardSettings

# The file a stock install reads at startup.
SHIPPED_CONFIG = Path(__file__).resolve().parents[1] / "config" / "config.yaml"

# One name per WireGuard setting, derived by WireguardSettings from its own env prefix and
# read by hand in Config._apply_env_overrides.
WIREGUARD_ENV_NAMES = [
    "SHADOW9_WIREGUARD_ENABLED",
    "SHADOW9_WIREGUARD_INTERFACE",
    "SHADOW9_WIREGUARD_LISTEN_PORT",
    "SHADOW9_WIREGUARD_ENROLLMENT_HOST",
    "SHADOW9_WIREGUARD_ENROLLMENT_PORT",
    "SHADOW9_WIREGUARD_TUNNEL_NETWORK",
    "SHADOW9_WIREGUARD_HUB_ENDPOINT",
    "SHADOW9_WIREGUARD_MTU",
    "SHADOW9_WIREGUARD_DNS",
    "SHADOW9_WIREGUARD_KEEPALIVE",
]


@pytest.fixture(autouse=True)
def clear_wireguard_environment(monkeypatch):
    """Keep a SHADOW9_WIREGUARD_* variable in the developer's shell out of the results."""
    for name in WIREGUARD_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


# Every key a real config/config.yaml carries. Settings models only a subset, and the
# ones it does not model are the ones save_to_yaml used to delete.
FULL_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 1080,
        "max_connections": 100,
        "connection_timeout": 30,
        "relay_timeout": 300,
        "buffer_size": 65536,
    },
    "tor": {
        "enabled": True,
        "socks_host": "127.0.0.1",
        "socks_port": 9050,
        "control_port": 9051,
        "control_password": "hunter2",
        "auto_detect": True,
    },
    "auth": {
        "require_auth": True,
        "credentials_file": "config/credentials.enc",
        "master_key_env": "SHADOW9_MASTER_KEY",
        "session_timeout_hours": 24,
        "max_failed_attempts": 5,
        "lockout_duration_minutes": 15,
        "max_concurrent_auth": 4,
    },
    "log": {
        "level": "INFO",
        "format": "console",
        "file": None,
        "max_size_mb": 10,
        "backup_count": 3,
    },
    "security": {
        "allowed_ports": [80, 443, 8080, 8443],
        "blocked_hosts": [],
        "allow_localhost": False,
        "rate_limit_per_minute": 100,
        "max_request_size": 1048576,
    },
    # Every value here differs from the default, so a save that quietly rewrites the
    # section with defaults fails rather than looking like a successful round trip.
    "wireguard": {
        "enabled": True,
        "interface": "shadow9",
        "listen_port": 51821,
        "enrollment_host": "198.51.100.9",
        "enrollment_port": 8191,
        "tunnel_network": "10.42.0.0/24",
        "hub_endpoint": "vpn.example.com:51821",
        "mtu": 1412,
        "dns": ["10.42.0.1"],
        "keepalive": 20,
    },
}

# The keys Settings does not model. Losing any of these is the bug under test.
UNMODELLED_KEYS = [
    ("server", "relay_timeout"),
    ("server", "buffer_size"),
    ("tor", "socks_host"),
    ("tor", "control_password"),
    ("tor", "auto_detect"),
    ("auth", "master_key_env"),
    ("auth", "session_timeout_hours"),
    ("log", "max_size_mb"),
    ("log", "backup_count"),
    ("security", "max_request_size"),
]


def write_config(path, data):
    """Write a config dict to a YAML file and return the path."""
    path.write_text(yaml.safe_dump(data, sort_keys=False))
    return path


class TestSettingsRoundTrip:
    """Saving settings must not drop keys the file already carries."""

    def test_save_keeps_every_key(self, tmp_path):
        """Load, save and reload keeps every key of a full config file."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        settings = Settings.load_from_yaml(config_file)
        settings.save_to_yaml(config_file)
        reloaded = yaml.safe_load(config_file.read_text())

        for section, keys in FULL_CONFIG.items():
            for key, value in keys.items():
                assert key in reloaded[section], f"{section}.{key} was deleted on save"
                assert reloaded[section][key] == value, f"{section}.{key} changed on save"

    def test_unmodelled_keys_survive(self, tmp_path):
        """The keys Settings does not model survive a save."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        Settings.load_from_yaml(config_file).save_to_yaml(config_file)
        reloaded = yaml.safe_load(config_file.read_text())

        for section, key in UNMODELLED_KEYS:
            assert key in reloaded[section], f"{section}.{key} was deleted on save"

    def test_saved_file_reloads_into_config(self, tmp_path):
        """A file written by Settings still loads through Config."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        Settings.load_from_yaml(config_file).save_to_yaml(config_file)
        config = Config.load(config_file)

        assert config.server.port == 1080
        assert config.auth.lockout_duration_minutes == 15
        assert config.security.rate_limit_per_minute == 100

    def test_save_creates_file_when_absent(self, tmp_path):
        """Saving to a path that does not exist still writes the modelled keys."""
        config_file = tmp_path / "nested" / "config.yaml"

        Settings().save_to_yaml(config_file)
        written = yaml.safe_load(config_file.read_text())

        assert written["server"]["host"] == "127.0.0.1"
        assert written["auth"]["lockout_duration_minutes"] == 15


class TestEnvironmentPrecedence:
    """Environment variables outrank the YAML file, as both docstrings claim."""

    def test_env_beats_yaml(self, tmp_path, monkeypatch):
        """SHADOW9_HOST wins even though the file has a server section."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)
        monkeypatch.setenv("SHADOW9_HOST", "10.0.0.5")

        settings = Settings.load_from_yaml(config_file)

        assert settings.server.host == "10.0.0.5"

    def test_yaml_used_when_env_absent(self, tmp_path, monkeypatch):
        """Without the variable the file's value is kept."""
        data = {**FULL_CONFIG, "server": {**FULL_CONFIG["server"], "host": "192.168.1.9"}}
        config_file = write_config(tmp_path / "config.yaml", data)
        monkeypatch.delenv("SHADOW9_HOST", raising=False)

        settings = Settings.load_from_yaml(config_file)

        assert settings.server.host == "192.168.1.9"

    def test_env_beats_yaml_for_nested_section(self, tmp_path, monkeypatch):
        """The same holds for a prefixed section."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)
        monkeypatch.setenv("SHADOW9_LOG_LEVEL", "DEBUG")

        settings = Settings.load_from_yaml(config_file)

        assert settings.log.level == "DEBUG"


class TestSharedEnvironmentVariables:
    """The proxy and API read the same environment names and values."""

    @pytest.mark.parametrize(
        ("name", "section", "field_name", "raw", "expected"),
        [
            pytest.param("SHADOW9_HOST", "server", "host", "192.0.2.10", "192.0.2.10", id="host"),
            pytest.param("SHADOW9_PORT", "server", "port", "1180", 1180, id="port"),
            pytest.param(
                "SHADOW9_MAX_CONNECTIONS",
                "server",
                "max_connections",
                "321",
                321,
                id="max_connections",
            ),
            pytest.param(
                "SHADOW9_CONNECTION_TIMEOUT",
                "server",
                "connection_timeout",
                "42",
                42,
                id="connection_timeout",
            ),
            pytest.param("SHADOW9_TOR_ENABLED", "tor", "enabled", "false", False, id="tor_enabled"),
            pytest.param(
                "SHADOW9_TOR_SOCKS_PORT",
                "tor",
                "socks_port",
                "9150",
                9150,
                id="tor_socks_port",
            ),
            pytest.param(
                "SHADOW9_TOR_CONTROL_PORT",
                "tor",
                "control_port",
                "9151",
                9151,
                id="tor_control_port",
            ),
            pytest.param(
                "SHADOW9_TOR_RETRY_ATTEMPTS",
                "tor",
                "retry_attempts",
                "7",
                7,
                id="tor_retry_attempts",
            ),
            pytest.param(
                "SHADOW9_TOR_RETRY_DELAY",
                "tor",
                "retry_delay",
                "1.25",
                1.25,
                id="tor_retry_delay",
            ),
            pytest.param(
                "SHADOW9_AUTH_REQUIRE_AUTH",
                "auth",
                "require_auth",
                "false",
                False,
                id="auth_required",
            ),
            pytest.param(
                "SHADOW9_AUTH_CREDENTIALS_FILE",
                "auth",
                "credentials_file",
                "private/users.enc",
                "private/users.enc",
                id="credentials_file",
            ),
            pytest.param(
                "SHADOW9_AUTH_MAX_FAILED_ATTEMPTS",
                "auth",
                "max_failed_attempts",
                "8",
                8,
                id="max_failed_attempts",
            ),
            pytest.param(
                "SHADOW9_AUTH_LOCKOUT_DURATION_MINUTES",
                "auth",
                "lockout_duration_minutes",
                "0",
                0,
                id="lockout_duration",
            ),
            pytest.param(
                "SHADOW9_AUTH_MAX_CONCURRENT_AUTH",
                "auth",
                "max_concurrent_auth",
                "2",
                2,
                id="max_concurrent_auth",
            ),
            pytest.param("SHADOW9_LOG_LEVEL", "log", "level", "debug", "DEBUG", id="log_level"),
            pytest.param(
                "SHADOW9_LOG_FORMAT",
                "log",
                "format",
                "console",
                "console",
                id="log_format",
            ),
            pytest.param(
                "SHADOW9_LOG_FILE",
                "log",
                "file",
                "logs/test.log",
                "logs/test.log",
                id="log_file",
            ),
            pytest.param(
                "SHADOW9_SECURITY_ALLOWED_PORTS",
                "security",
                "allowed_ports",
                "[53, 853]",
                [53, 853],
                id="allowed_ports",
            ),
            pytest.param(
                "SHADOW9_SECURITY_BLOCKED_HOSTS",
                "security",
                "blocked_hosts",
                '["example.com", "invalid.example"]',
                ["example.com", "invalid.example"],
                id="blocked_hosts",
            ),
            pytest.param(
                "SHADOW9_SECURITY_ALLOW_LOCALHOST",
                "security",
                "allow_localhost",
                "true",
                True,
                id="allow_localhost",
            ),
            pytest.param(
                "SHADOW9_SECURITY_RATE_LIMIT_PER_MINUTE",
                "security",
                "rate_limit_per_minute",
                "55",
                55,
                id="rate_limit",
            ),
            pytest.param(
                "SHADOW9_SECURITY_BLOCK_PRIVATE_RANGES",
                "security",
                "block_private_ranges",
                "false",
                False,
                id="block_private_ranges",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_ENABLED",
                "wireguard",
                "enabled",
                "true",
                True,
                id="wireguard_enabled",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_INTERFACE",
                "wireguard",
                "interface",
                "s9hub",
                "s9hub",
                id="wireguard_interface",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_LISTEN_PORT",
                "wireguard",
                "listen_port",
                "51999",
                51999,
                id="wireguard_listen_port",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_ENROLLMENT_HOST",
                "wireguard",
                "enrollment_host",
                "192.0.2.9",
                "192.0.2.9",
                id="wireguard_enrollment_host",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_ENROLLMENT_PORT",
                "wireguard",
                "enrollment_port",
                "8199",
                8199,
                id="wireguard_enrollment_port",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_TUNNEL_NETWORK",
                "wireguard",
                "tunnel_network",
                "10.77.0.0/24",
                "10.77.0.0/24",
                id="wireguard_tunnel_network",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_HUB_ENDPOINT",
                "wireguard",
                "hub_endpoint",
                "203.0.113.9:51999",
                "203.0.113.9:51999",
                id="wireguard_hub_endpoint",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_MTU",
                "wireguard",
                "mtu",
                "1380",
                1380,
                id="wireguard_mtu",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_DNS",
                "wireguard",
                "dns",
                "10.77.0.1, 10.77.0.2",
                ["10.77.0.1", "10.77.0.2"],
                id="wireguard_dns",
            ),
            pytest.param(
                "SHADOW9_WIREGUARD_KEEPALIVE",
                "wireguard",
                "keepalive",
                "15",
                15,
                id="wireguard_keepalive",
            ),
        ],
    )
    def test_both_config_systems_read_the_same_value(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        name: str,
        section: str,
        field_name: str,
        raw: str,
        expected: object,
    ) -> None:
        monkeypatch.setenv(name, raw)
        config_file = write_config(tmp_path / "config.yaml", {})

        proxy = Config.load(config_file)
        api = Settings.load_from_yaml(config_file)

        assert getattr(getattr(proxy, section), field_name) == expected
        assert getattr(getattr(api, section), field_name) == expected

    @pytest.mark.parametrize(
        ("name", "bad"),
        [
            pytest.param("SHADOW9_MAX_CONNECTIONS", "lots", id="integer"),
            pytest.param("SHADOW9_TOR_ENABLED", "sometimes", id="boolean"),
            pytest.param("SHADOW9_TOR_RETRY_DELAY", "soon", id="decimal"),
            pytest.param("SHADOW9_SECURITY_ALLOWED_PORTS", "not-json", id="list"),
        ],
    )
    def test_a_malformed_value_names_its_variable(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        name: str,
        bad: str,
    ) -> None:
        monkeypatch.setenv(name, bad)
        config_file = write_config(tmp_path / "config.yaml", {})

        with pytest.raises(ValueError, match=name):
            Config.load(config_file)


class TestConfigContract:
    """Both config modules agree on names, units and defaults."""

    def test_default_bind_is_loopback(self):
        """Listening on every interface has to be opted into."""
        from shadow9.core.config import ServerSettings

        assert ServerConfig().host == "127.0.0.1"
        assert ServerSettings().host == "127.0.0.1"

    def test_generated_config_binds_loopback(self, tmp_path):
        """A freshly generated file says 127.0.0.1."""
        config_file = tmp_path / "config.yaml"

        generate_default_config(config_file)
        written = yaml.safe_load(config_file.read_text())

        assert written["server"]["host"] == "127.0.0.1"

    def test_shared_fields_match(self):
        """The fields both modules define carry the same value and unit."""
        from shadow9.core.config import AuthSettings, ServerSettings, TorSettings

        config, settings = Config(), Settings()

        assert config.server.connection_timeout == ServerSettings().connection_timeout == 30
        assert config.server.max_connections == ServerSettings().max_connections == 100
        assert config.auth.max_failed_attempts == AuthSettings().max_failed_attempts == 5
        assert config.auth.lockout_duration_minutes == AuthSettings().lockout_duration_minutes == 15
        assert config.tor.retry_attempts == TorSettings().retry_attempts == 3
        assert config.tor.retry_delay == TorSettings().retry_delay == 5.0
        assert (
            settings.security.block_private_ranges is config.security.block_private_ranges is True
        )

    def test_lockout_duration_in_seconds_is_gone(self):
        """Only the minutes name survives, so the two modules cannot disagree."""
        from shadow9.core.config import AuthSettings

        assert not hasattr(AuthSettings(), "lockout_duration")
        assert not hasattr(Config().auth, "lockout_duration")

    def test_session_timeout_hours_is_gone(self):
        """Nothing honored it once the session service was deleted."""
        from shadow9.core.config import AuthSettings

        assert not hasattr(Config().auth, "session_timeout_hours")
        assert not hasattr(AuthSettings(), "session_timeout_hours")

    def test_hashing_cap_is_configurable(self):
        """Unset by default on both halves, meaning size it from the memory available."""
        from shadow9.core.config import AuthSettings

        assert Config().auth.max_concurrent_auth is None
        assert AuthSettings().max_concurrent_auth is None

    def test_hashing_cap_loads_from_file(self, tmp_path):
        """An operator can raise it, which is why MemoryMax documents the coupling."""
        data = {**FULL_CONFIG, "auth": {**FULL_CONFIG["auth"], "max_concurrent_auth": 8}}
        config_file = write_config(tmp_path / "config.yaml", data)

        assert Config.load(config_file).auth.max_concurrent_auth == 8


class TestAHashingCapBelowOneIsRefused:
    """Zero builds a permit pool nothing can ever take from.

    The proxy would bind its port, accept connections and leave every password
    verification waiting for a slot that is never released, which looks from outside
    like a network fault rather than a setting.
    """

    @pytest.mark.parametrize("permits", [0, -3])
    def test_the_file_is_refused_at_load_with_the_setting_named(self, tmp_path, permits):
        data = {**FULL_CONFIG, "auth": {**FULL_CONFIG["auth"], "max_concurrent_auth": permits}}
        config_file = write_config(tmp_path / "config.yaml", data)

        with pytest.raises(ValueError, match="max_concurrent_auth must be at least 1"):
            Config.load(config_file)

    def test_a_value_assigned_after_construction_is_reported_by_validate(self):
        """The one route that cannot raise at the boundary still has to be visible."""
        config = Config()
        config.auth.max_concurrent_auth = 0

        assert any("max_concurrent_auth must be at least 1" in e for e in config.validate())

    def test_the_api_settings_agree(self):
        """The two halves refusing different values is how they end up disagreeing."""
        from pydantic import ValidationError

        from shadow9.core.config import AuthSettings

        with pytest.raises(ValidationError):
            AuthSettings(max_concurrent_auth=0)


class TestTheHashingCapEnvironmentVariable:
    """One name, honoured by both halves, or the log does not describe what is running."""

    def test_the_proxy_honours_the_variable_the_api_reads(self, monkeypatch, tmp_path):
        """The proxy used to auto-size while the API used the number in the environment."""
        from shadow9.core.config import AuthSettings

        monkeypatch.setenv("SHADOW9_AUTH_MAX_CONCURRENT_AUTH", "3")
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        assert Config.load(config_file).auth.max_concurrent_auth == 3
        assert AuthSettings().max_concurrent_auth == 3

    @pytest.mark.parametrize("bad", ["nonsense", "0", "-2"])
    def test_a_value_that_cannot_work_is_refused_by_name(self, monkeypatch, tmp_path, bad):
        """Named in the message, because an environment variable is invisible in a file."""
        monkeypatch.setenv("SHADOW9_AUTH_MAX_CONCURRENT_AUTH", bad)
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        with pytest.raises(ValueError, match="SHADOW9_AUTH_MAX_CONCURRENT_AUTH"):
            Config.load(config_file)


class TestSecurityValuesReachTheServer:
    """The construction site must pass every policy value, or config is decorative."""

    def test_every_policy_value_is_passed(self):
        """Each security and auth setting the server accepts is wired from cfg."""
        import inspect

        from shadow9.commands.server import _serve

        source = inspect.getsource(_serve)
        expected = [
            "max_connections=cfg.server.max_connections",
            "max_concurrent_auth=cfg.auth.max_concurrent_auth",
            "block_private_ranges=cfg.security.block_private_ranges",
            "allow_localhost=cfg.security.allow_localhost",
            "blocked_hosts=cfg.security.blocked_hosts",
            "max_failed_attempts=cfg.auth.max_failed_attempts",
            "lockout_duration_minutes=cfg.auth.lockout_duration_minutes",
            "rate_limit_per_minute=cfg.security.rate_limit_per_minute",
        ]
        for line in expected:
            assert line in source, f"{line} is not passed to Socks5Server"

    def test_server_accepts_every_value_passed(self):
        """The names match the constructor, so none is silently dropped as a typo."""
        import inspect

        from shadow9.socks5_server import Socks5Server

        accepted = inspect.signature(Socks5Server.__init__).parameters
        for name in [
            "max_connections",
            "max_concurrent_auth",
            "block_private_ranges",
            "allow_localhost",
            "blocked_hosts",
            "max_failed_attempts",
            "lockout_duration_minutes",
            "rate_limit_per_minute",
        ]:
            assert name in accepted, f"Socks5Server does not accept {name}"

    def test_config_values_reach_the_server_instance(self):
        """A non-default config produces a server carrying those values, not the defaults."""
        from shadow9.socks5_server import Socks5Server

        config = Config()
        config.security.block_private_ranges = False
        config.security.allow_localhost = True
        config.security.blocked_hosts = ["example.invalid"]
        config.security.rate_limit_per_minute = 7
        config.auth.max_failed_attempts = 2
        config.auth.lockout_duration_minutes = 99
        config.auth.max_concurrent_auth = 3

        server = Socks5Server(
            host=config.server.host,
            port=config.server.port,
            max_connections=config.server.max_connections,
            max_concurrent_auth=config.auth.max_concurrent_auth,
            block_private_ranges=config.security.block_private_ranges,
            allow_localhost=config.security.allow_localhost,
            blocked_hosts=config.security.blocked_hosts,
            max_failed_attempts=config.auth.max_failed_attempts,
            lockout_duration_minutes=config.auth.lockout_duration_minutes,
            rate_limit_per_minute=config.security.rate_limit_per_minute,
        )

        assert server.block_private_ranges is False
        assert server.allow_localhost is True
        assert server.blocked_hosts == ["example.invalid"]
        assert server.rate_limit_per_minute == 7
        assert server.max_failed_attempts == 2
        assert server.max_concurrent_auth == 3
        # the server keeps the lockout window in seconds, so the units must convert
        assert server._lockout_seconds == 99 * 60


class TestUnknownKeysAreNotFatal:
    """An unrecognised key must not stop the server from binding."""

    def test_unknown_key_is_ignored(self, tmp_path):
        """Config.load survives a key no dataclass models."""
        data = {**FULL_CONFIG, "server": {**FULL_CONFIG["server"], "not_a_real_key": 1}}
        config_file = write_config(tmp_path / "config.yaml", data)

        config = Config.load(config_file)

        assert config.server.port == 1080

    def test_unknown_section_is_ignored(self, tmp_path):
        """A whole unknown section is skipped rather than raising."""
        data = {**FULL_CONFIG, "experimental": {"whatever": True}}
        config_file = write_config(tmp_path / "config.yaml", data)

        config = Config.load(config_file)

        assert config.server.host == "127.0.0.1"

    def test_missing_file_gives_defaults(self, tmp_path):
        """A path that does not exist falls back to defaults."""
        config = Config.load(tmp_path / "absent.yaml")

        assert config.server.host == "127.0.0.1"
        assert config.server.port == 1080


class TestTorRetryConfig:
    """The retry settings the Tor connector consumes are reachable from Config."""

    def test_config_carries_retry_fields(self):
        """Both retry knobs exist on the dataclass the serve path reads."""
        from shadow9.tor_connector import TorConfig as ConnectorTorConfig

        config = Config()

        assert config.tor.retry_attempts == 3
        assert config.tor.retry_delay == 5.0
        assert ConnectorTorConfig().retry_attempts == 3
        assert ConnectorTorConfig().retry_delay == 5.0

    def test_retry_values_load_from_file(self, tmp_path):
        """A file can override them."""
        data = {
            **FULL_CONFIG,
            "tor": {**FULL_CONFIG["tor"], "retry_attempts": 7, "retry_delay": 2.5},
        }
        config_file = write_config(tmp_path / "config.yaml", data)

        config = Config.load(config_file)

        assert config.tor.retry_attempts == 7
        assert config.tor.retry_delay == 2.5


class TestTheServePathReadsTheEnvironment:
    """The proxy has to honour SHADOW9_ variables on a host with no config file.

    Building a bare Config() when the file is absent skips _apply_env_overrides, which is
    the only place any of them is read, so an operator who capped password hashing with
    SHADOW9_AUTH_MAX_CONCURRENT_AUTH got a proxy that sized itself and said nothing.
    """

    def test_a_missing_config_file_still_applies_the_environment(self, tmp_path, monkeypatch):
        import asyncio
        from types import SimpleNamespace

        from shadow9.commands import server as server_commands

        monkeypatch.setenv("SHADOW9_AUTH_MAX_CONCURRENT_AUTH", "3")
        monkeypatch.setenv("SHADOW9_HOST", "10.9.9.9")

        loaded: list[Config] = []
        real_load = Config.load

        def recording_load(config_file=None) -> Config:
            config = real_load(config_file)
            loaded.append(config)
            return config

        def leave_logging_alone(log_config: LogConfig) -> None:
            return None

        def fixed_master_key() -> str:
            return "k" * 32

        # No users, so the serve path prints its message and returns before it binds
        # anything. Everything under test has already happened by then.
        def store_with_no_users(**kwargs: object) -> SimpleNamespace:
            def list_users() -> list[str]:
                return []

            return SimpleNamespace(list_users=list_users)

        monkeypatch.setattr(server_commands.Config, "load", staticmethod(recording_load))
        monkeypatch.setattr(server_commands, "setup_logging", leave_logging_alone)
        monkeypatch.setattr(server_commands, "load_master_key", fixed_master_key)
        monkeypatch.setattr(server_commands, "AuthManager", store_with_no_users)

        asyncio.run(server_commands._serve(str(tmp_path / "absent.yaml"), None, None))

        assert loaded, "the serve path never called Config.load"
        assert loaded[0].auth.max_concurrent_auth == 3
        assert loaded[0].server.host == "10.9.9.9"


class RecordingLogger:
    """A stand-in for the module logger that keeps what it was told."""

    def __init__(self) -> None:
        self.warnings: list[tuple[str, dict]] = []

    def warning(self, event: str, **kwargs: object) -> None:
        self.warnings.append((event, dict(kwargs)))

    def info(self, event: str, **kwargs: object) -> None:
        return None

    def error(self, event: str, **kwargs: object) -> None:
        return None


def settings_with_wireguard(**overrides: object) -> Settings:
    """A Settings whose WireGuard values were assigned after it was built.

    Pydantic checks a field when the model is constructed and not when one is assigned, so
    this is the route a bad value actually takes to reach validate_all.
    """
    settings = Settings()
    for name, value in overrides.items():
        setattr(settings.wireguard, name, value)
    return settings


class TestTheWireguardGroupExistsOnBothHalves:
    def test_the_shipped_comment_names_both_inbound_ports(self):
        text = SHIPPED_CONFIG.read_text(encoding="utf-8")

        assert "Open this UDP port for the WireGuard tunnel" in text
        assert "Open this TCP port; keep the admin API port closed" in text

    """The proxy reads one config module and the API reads the other.

    A field on one and not the other is read from the file, shown in the interface and
    then ignored by whichever half was missed, which is a defect this codebase has
    shipped before.
    """

    def test_both_halves_define_the_same_fields(self):
        from dataclasses import fields as dataclass_fields

        dataclass_names = {f.name for f in dataclass_fields(WireguardConfig)}

        assert dataclass_names == set(WireguardSettings.model_fields)

    def test_both_halves_default_the_same(self):
        """Same name, same unit, same value, or the two halves run different hubs."""
        config, settings = WireguardConfig(), WireguardSettings()

        for name in WireguardSettings.model_fields:
            assert getattr(config, name) == getattr(settings, name), name

    def test_the_hub_is_off_until_it_is_configured(self):
        """hub_endpoint has no sensible guess, so the feature cannot default to on."""
        assert WireguardConfig().enabled is False
        assert WireguardSettings().enabled is False
        assert WireguardConfig().hub_endpoint == ""

    def test_the_documented_defaults(self):
        """1420 is the MTU the kernel gives a fresh WireGuard device.

        Framing measures 32 bytes over an inner packet padded to a multiple of 16, so with
        the outer IPv4 and UDP headers 1440 fits a 1500 byte path and the 20 bytes below
        that cover an IPv6 underlay. 25 seconds sits under the 30 second UDP mapping
        timeout common to NAT and stateful firewalls.
        """
        config, settings = WireguardConfig(), WireguardSettings()

        assert config.mtu == settings.mtu == 1420
        assert config.keepalive == settings.keepalive == 25
        assert config.interface == settings.interface == "wg0"
        assert config.listen_port == settings.listen_port == 51820
        assert config.enrollment_host == settings.enrollment_host == "0.0.0.0"
        assert config.enrollment_port == settings.enrollment_port == 8081
        assert config.tunnel_network == settings.tunnel_network == "10.9.0.0/24"


class TestTheWireguardSectionIsRead:
    """The three steps that fail silently when they are skipped."""

    def test_the_file_beats_the_defaults(self, tmp_path):
        """Without the section in Config._from_dict the file is never looked at."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        config = Config.load(config_file)

        assert config.wireguard.enabled is True
        assert config.wireguard.interface == "shadow9"
        assert config.wireguard.listen_port == 51821
        assert config.wireguard.enrollment_host == "198.51.100.9"
        assert config.wireguard.enrollment_port == 8191
        assert config.wireguard.tunnel_network == "10.42.0.0/24"
        assert config.wireguard.hub_endpoint == "vpn.example.com:51821"
        assert config.wireguard.mtu == 1412
        assert config.wireguard.dns == ["10.42.0.1"]
        assert config.wireguard.keepalive == 20

    def test_config_save_writes_the_section(self, tmp_path):
        """Without it in Config.save the section vanishes on the next save."""
        config_file = tmp_path / "config.yaml"
        config = Config()
        config.wireguard.hub_endpoint = "10.0.0.9:51820"

        config.save(config_file)
        written = yaml.safe_load(config_file.read_text())

        assert written["wireguard"]["hub_endpoint"] == "10.0.0.9:51820"
        assert written["wireguard"]["interface"] == "wg0"
        assert written["wireguard"]["mtu"] == 1420

    def test_settings_load_from_yaml_reads_the_section(self, tmp_path):
        """Without it in the load_from_yaml chain the API reports the defaults."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        settings = Settings.load_from_yaml(config_file)

        assert settings.wireguard.interface == "shadow9"
        assert settings.wireguard.listen_port == 51821
        assert settings.wireguard.enrollment_host == "198.51.100.9"
        assert settings.wireguard.enrollment_port == 8191
        assert settings.wireguard.tunnel_network == "10.42.0.0/24"
        assert settings.wireguard.dns == ["10.42.0.1"]


class TestTheWireguardSectionSurvivesASave:
    """Load, save, reload, with every key still carrying its value."""

    def test_every_wireguard_key_round_trips(self, tmp_path):
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        Settings.load_from_yaml(config_file).save_to_yaml(config_file)
        reloaded = Settings.load_from_yaml(config_file)

        for key, value in FULL_CONFIG["wireguard"].items():
            assert getattr(reloaded.wireguard, key) == value, f"wireguard.{key} changed on save"

    def test_a_settings_save_still_loads_through_config(self, tmp_path):
        """The file the API writes is the file the proxy reads."""
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        Settings.load_from_yaml(config_file).save_to_yaml(config_file)
        config = Config.load(config_file)

        assert config.wireguard.tunnel_network == "10.42.0.0/24"
        assert config.wireguard.mtu == 1412
        assert config.wireguard.dns == ["10.42.0.1"]

    def test_no_hub_key_is_written(self, tmp_path):
        """config.yaml is written 0644, so a private key must not reach it."""
        config_file = tmp_path / "config.yaml"

        Settings().save_to_yaml(config_file)
        written = yaml.safe_load(config_file.read_text())

        assert "private_key" not in written["wireguard"]


class TestTheShippedConfigFile:
    """A stock install has to load the file the repository ships."""

    def test_it_loads_without_warnings(self, monkeypatch):
        """An unknown key inside a known section is warned about and then ignored."""
        from shadow9 import config as config_module

        recorder = RecordingLogger()
        monkeypatch.setattr(config_module, "logger", recorder)

        config = Config.load(SHIPPED_CONFIG)

        assert recorder.warnings == []
        assert config.wireguard == WireguardConfig()

    def test_the_api_half_reads_the_same_file(self):
        settings = Settings.load_from_yaml(SHIPPED_CONFIG)

        assert settings.wireguard.listen_port == 51820
        assert settings.wireguard.enrollment_host == "0.0.0.0"
        assert settings.wireguard.enrollment_port == 8081
        assert settings.wireguard.mtu == 1420
        assert settings.wireguard.dns == []

    def test_it_carries_every_wireguard_key(self):
        shipped = yaml.safe_load(SHIPPED_CONFIG.read_text())

        assert set(shipped["wireguard"]) == set(WireguardSettings.model_fields)


class TestTheWireguardEnvironmentVariables:
    """One name per setting, honoured by both halves, or the log describes one of them."""

    def test_both_halves_honour_every_variable(self, monkeypatch, tmp_path):
        """The file says something else, so this also shows the environment winning."""
        monkeypatch.setenv("SHADOW9_WIREGUARD_ENABLED", "true")
        monkeypatch.setenv("SHADOW9_WIREGUARD_INTERFACE", "s9hub")
        monkeypatch.setenv("SHADOW9_WIREGUARD_LISTEN_PORT", "51999")
        monkeypatch.setenv("SHADOW9_WIREGUARD_ENROLLMENT_HOST", "192.0.2.9")
        monkeypatch.setenv("SHADOW9_WIREGUARD_ENROLLMENT_PORT", "8199")
        monkeypatch.setenv("SHADOW9_WIREGUARD_TUNNEL_NETWORK", "10.77.0.0/24")
        monkeypatch.setenv("SHADOW9_WIREGUARD_HUB_ENDPOINT", "203.0.113.9:51999")
        monkeypatch.setenv("SHADOW9_WIREGUARD_MTU", "1380")
        monkeypatch.setenv("SHADOW9_WIREGUARD_DNS", "10.77.0.1, 10.77.0.2")
        monkeypatch.setenv("SHADOW9_WIREGUARD_KEEPALIVE", "15")
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        proxy = Config.load(config_file).wireguard
        api = Settings.load_from_yaml(config_file).wireguard

        for half in (proxy, api):
            assert half.enabled is True
            assert half.interface == "s9hub"
            assert half.listen_port == 51999
            assert half.enrollment_host == "192.0.2.9"
            assert half.enrollment_port == 8199
            assert half.tunnel_network == "10.77.0.0/24"
            assert half.hub_endpoint == "203.0.113.9:51999"
            assert half.mtu == 1380
            assert half.dns == ["10.77.0.1", "10.77.0.2"]
            assert half.keepalive == 15

    @pytest.mark.parametrize(
        ("name", "bad"),
        [
            ("SHADOW9_WIREGUARD_LISTEN_PORT", "0"),
            ("SHADOW9_WIREGUARD_LISTEN_PORT", "nonsense"),
            ("SHADOW9_WIREGUARD_ENROLLMENT_PORT", "0"),
            ("SHADOW9_WIREGUARD_ENROLLMENT_PORT", "nonsense"),
            ("SHADOW9_WIREGUARD_MTU", "9000"),
            ("SHADOW9_WIREGUARD_KEEPALIVE", "-1"),
            ("SHADOW9_WIREGUARD_TUNNEL_NETWORK", "8.8.8.0/24"),
        ],
    )
    def test_a_value_that_cannot_work_is_refused_by_variable_name(
        self, monkeypatch, tmp_path, name, bad
    ):
        """Named in the message, because an environment variable is invisible in a file."""
        monkeypatch.setenv(name, bad)
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        with pytest.raises(ValueError, match=name):
            Config.load(config_file)

    def test_a_hub_endpoint_without_a_host_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOW9_WIREGUARD_HUB_ENDPOINT", ":51820")
        config_file = write_config(tmp_path / "config.yaml", FULL_CONFIG)

        with pytest.raises(ValueError, match="port but no address"):
            Config.load(config_file)


class TestWireguardValuesThatCannotWork:
    """Each refusal names the offending value, on both halves."""

    @pytest.mark.parametrize("interface", ["", "name with spaces", "sixteencharslong", "túnel"])
    def test_an_interface_name_wireguard_cannot_use_is_refused(self, interface):
        with pytest.raises(ValueError, match=r"wireguard\.interface"):
            WireguardConfig(interface=interface)

        with pytest.raises(ValidationError, match=r"wireguard\.interface"):
            WireguardSettings(interface=interface)

    @pytest.mark.parametrize("network", ["8.8.8.0/24", "1.1.1.0/24", "0.0.0.0/0"])
    def test_a_public_tunnel_network_is_refused(self, network):
        """Peers would be handed addresses belonging to somebody else, and every packet
        for the real owner of that range would go into the tunnel."""
        with pytest.raises(ValueError, match=network):
            WireguardConfig(tunnel_network=network)

        with pytest.raises(ValidationError, match="private range"):
            WireguardSettings(tunnel_network=network)

        assert any(
            network in error
            for error in settings_with_wireguard(tunnel_network=network).validate_all()
        )

    @pytest.mark.parametrize(
        "network", ["10.9.0.0/24", "172.20.0.0/14", "100.64.0.0/10", "fd09:9::/64"]
    )
    def test_the_ranges_an_operator_would_reach_for_are_allowed(self, network):
        """The explicit private, shared, and local ranges work on every Python version."""
        assert WireguardConfig(tunnel_network=network).tunnel_network == network
        assert WireguardSettings(tunnel_network=network).tunnel_network == network

    @pytest.mark.parametrize("network", ["127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/64"])
    def test_ranges_reserved_for_the_host_or_link_are_refused(self, network):
        """A tunnel must use private address space, not a host-only or link-only range."""
        with pytest.raises(ValueError, match=network):
            WireguardConfig(tunnel_network=network)

        with pytest.raises(ValidationError, match="private range"):
            WireguardSettings(tunnel_network=network)

    @pytest.mark.parametrize("network", ["10.9.0.1/24", "not-a-network", ""])
    def test_a_tunnel_network_that_is_not_a_network_is_refused(self, network):
        """A host address with a prefix is the common way to write this one wrong."""
        with pytest.raises(ValueError, match="tunnel_network"):
            WireguardConfig(tunnel_network=network)

        with pytest.raises(ValidationError, match="tunnel_network"):
            WireguardSettings(tunnel_network=network)

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000])
    def test_a_listen_port_outside_the_range_is_refused(self, port):
        with pytest.raises(ValueError, match=str(port)):
            WireguardConfig(listen_port=port)

        with pytest.raises(ValidationError):
            WireguardSettings(listen_port=port)

        assert any(
            str(port) in error for error in settings_with_wireguard(listen_port=port).validate_all()
        )

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000])
    def test_an_enrollment_port_outside_the_range_is_refused(self, port: int) -> None:
        with pytest.raises(ValueError, match=str(port)):
            WireguardConfig(enrollment_port=port)

        with pytest.raises(ValidationError):
            WireguardSettings(enrollment_port=port)

        assert any(
            str(port) in error
            for error in settings_with_wireguard(enrollment_port=port).validate_all()
        )

    @pytest.mark.parametrize(
        ("left", "right", "port"),
        [
            ("api.port", "wireguard.enrollment_port", 8080),
            ("api.port", "server.port", 1080),
            ("wireguard.enrollment_port", "server.port", 1080),
        ],
    )
    def test_two_inbound_listeners_cannot_share_a_port(
        self, left: str, right: str, port: int
    ) -> None:
        settings = Settings()
        if left == "api.port":
            settings.api.port = port
        if left == "wireguard.enrollment_port":
            settings.wireguard.enrollment_port = port
        if right == "wireguard.enrollment_port":
            settings.wireguard.enrollment_port = port
        if right == "server.port":
            settings.server.port = port

        errors = settings.validate_all()

        assert any(left in error and right in error and str(port) in error for error in errors)

    @pytest.mark.parametrize("mtu", [0, 576, 1279, 1441, 9000])
    def test_an_mtu_outside_the_band_is_refused(self, mtu):
        """1280 is the smallest an IPv6 link may carry, 1440 the most a 1500 byte path
        leaves once WireGuard framing and the outer headers are taken off."""
        with pytest.raises(ValueError, match=str(mtu)):
            WireguardConfig(mtu=mtu)

        with pytest.raises(ValidationError):
            WireguardSettings(mtu=mtu)

        assert any(str(mtu) in error for error in settings_with_wireguard(mtu=mtu).validate_all())

    def test_a_negative_keepalive_is_refused(self):
        with pytest.raises(ValueError, match="-5"):
            WireguardConfig(keepalive=-5)

        with pytest.raises(ValidationError):
            WireguardSettings(keepalive=-5)

    def test_keepalive_zero_is_allowed(self):
        """0 is how wg-quick turns keepalives off, so it is a setting and not a mistake."""
        assert WireguardConfig(keepalive=0).keepalive == 0
        assert WireguardSettings(keepalive=0).keepalive == 0

    @pytest.mark.parametrize(
        ("key", "bad"),
        [("listen_port", 0), ("mtu", 70), ("tunnel_network", "8.8.8.0/24")],
    )
    def test_a_bad_value_in_a_file_is_refused_at_load(self, tmp_path, key, bad):
        """The file names the value, so the operator can find the line."""
        data = {**FULL_CONFIG, "wireguard": {**FULL_CONFIG["wireguard"], key: bad}}
        config_file = write_config(tmp_path / "config.yaml", data)

        with pytest.raises(ValueError, match=str(bad)):
            Config.load(config_file)

    def test_a_value_assigned_after_construction_is_reported_by_validate(self):
        """The one route that cannot raise at the boundary still has to be visible."""
        config = Config()
        config.wireguard.mtu = 500

        assert any("wireguard.mtu must be between 1280 and 1440" in e for e in config.validate())

    def test_both_halves_report_the_same_problem(self):
        """An operator seeing two different complaints has to guess which half is talking."""
        config = Config()
        config.wireguard.listen_port = 0
        config.wireguard.mtu = 70

        proxy_errors = [e for e in config.validate() if e.startswith("wireguard.")]
        api_errors = settings_with_wireguard(listen_port=0, mtu=70).validate_all()

        assert proxy_errors == [e for e in api_errors if e.startswith("wireguard.")]
        assert proxy_errors
