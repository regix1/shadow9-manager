"""Tests for configuration loading, saving and precedence."""

import pytest
import yaml

from shadow9.config import Config, LogConfig, ServerConfig, generate_default_config
from shadow9.core.config import Settings


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
        """Load, save and reload keeps all 30 keys of a full config file."""
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
