"""Tests for command replacements for the removed interactive menu."""

import re
from pathlib import Path
from types import SimpleNamespace
import pytest
from typer.testing import CliRunner

from shadow9.cli import app
from shadow9.config import Config
from shadow9.commands import api as api_commands
from shadow9.commands import probe
from shadow9.commands import user as user_commands
from shadow9.commands import utils
from shadow9.wizards import init_wizard


runner = CliRunner()


def plain(text: str) -> str:
    """
    Drop the terminal escapes so a sentence can be matched as one string.

    Rich styles values inside a line: an address and a port come back as
    "on \x1b[1;92m127.0.0.1\x1b[0m:\x1b[1;36m1080\x1b[0m", so the sentence the
    operator reads is never present in the raw output as plain text.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_no_arguments_show_help() -> None:
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert "Usage:" in result.stdout
    assert "show" in result.stdout
    assert "menu" not in result.stdout


def test_show_config_shows_wireguard_values(monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config()
    config.server.host = "127.0.0.21"
    config.server.port = 19080
    config.auth.max_failed_attempts = 7
    config.auth.lockout_duration_minutes = 13
    config.wireguard.enabled = True
    config.wireguard.listen_port = 52001
    config.wireguard.enrollment_host = "0.0.0.0"
    config.wireguard.enrollment_port = 8201
    config.wireguard.tunnel_network = "10.88.0.0/24"
    config.wireguard.hub_endpoint = "hub.example.test:52001"
    config.wireguard.mtu = 1360
    config.wireguard.dns = ["10.88.0.1", "9.9.9.9"]
    config.wireguard.keepalive = 17

    def paths() -> SimpleNamespace:
        return SimpleNamespace(config_file=Path("config-for-show.yaml"))

    def load_config(_cls: type[Config], _config_file: Path | None = None) -> Config:
        return config

    monkeypatch.setattr(utils, "get_paths", paths)
    monkeypatch.setattr(utils.Config, "load", classmethod(load_config))

    result = runner.invoke(app, ["show", "config"])

    assert result.exit_code == 0, result.stdout
    assert "127.0.0.21" in result.stdout
    assert "19080" in result.stdout
    assert "7" in result.stdout
    assert "13 min" in result.stdout
    assert "52001" in result.stdout
    assert "0.0.0.0" in result.stdout
    assert "8201" in result.stdout
    assert "10.88.0.0/24" in result.stdout
    assert "hub.example.test:52001" in result.stdout
    assert "1360" in result.stdout
    assert "10.88.0.1, 9.9.9.9" in result.stdout
    assert "17s" in result.stdout
    assert "private key" not in result.stdout.lower()


def test_show_paths_prints_every_configured_path(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = SimpleNamespace(
        root=Path("R:/shadow9-root"),
        config_file=Path("R:/shadow9-root/config/main.yaml"),
        credentials_file=Path("R:/shadow9-root/config/users.enc"),
        users_dir=Path("R:/shadow9-root/accounts"),
        logs_dir=Path("R:/shadow9-root/audit-logs"),
    )

    def get_test_paths() -> SimpleNamespace:
        return paths

    monkeypatch.setattr(utils, "get_paths", get_test_paths)

    result = runner.invoke(app, ["show", "paths"])

    assert result.exit_code == 0, result.stdout
    assert str(paths.root) in result.stdout
    assert str(paths.config_file) in result.stdout
    assert str(paths.credentials_file) in result.stdout
    assert str(paths.users_dir) in result.stdout
    assert str(paths.logs_dir) in result.stdout


def test_show_key_prints_the_stored_key_and_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    def load_key() -> str:
        return "stored-master-key-123"

    monkeypatch.setattr(init_wizard, "load_master_key", load_key)

    result = runner.invoke(app, ["show", "key"])

    assert result.exit_code == 0, result.stdout
    assert "stored-master-key-123" in result.stdout
    assert "Anyone with this key can decrypt credentials" in result.stdout


def test_show_key_explains_how_to_create_a_missing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def load_key() -> None:
        return None

    monkeypatch.setattr(init_wizard, "load_master_key", load_key)

    result = runner.invoke(app, ["show", "key"])

    assert result.exit_code == 0, result.stdout
    assert "Master key not found" in result.stdout
    assert "shadow9 init" in result.stdout


@pytest.mark.parametrize("listening", [True, False])
def test_status_reports_configured_proxy_and_api_ports(
    monkeypatch: pytest.MonkeyPatch, listening: bool
) -> None:
    config = Config()
    config.server.host = "127.0.0.31"
    config.server.port = 19180
    seen: list[tuple[str, int]] = []

    def paths() -> SimpleNamespace:
        return SimpleNamespace(
            config_file=Path("status-config.yaml"), config_dir=Path("status-config")
        )

    def load_config(_cls: type[Config], _config_file: Path | None = None) -> Config:
        return config

    def read_api_config(_config_file: str) -> dict[str, object]:
        return {"host": "127.0.0.32", "port": 19181}

    def check_setup() -> dict[str, dict[str, object]]:
        return {}

    def detect_tor_service() -> None:
        return None

    async def check_listener(host: str, port: int) -> bool:
        seen.append((host, port))
        return listening

    import shadow9.setup as setup_module

    monkeypatch.setattr(utils, "get_paths", paths)
    monkeypatch.setattr(utils.Config, "load", classmethod(load_config))
    monkeypatch.setattr(api_commands, "_read_api_config", read_api_config)
    monkeypatch.setattr(setup_module, "check_setup", check_setup)
    monkeypatch.setattr(
        utils.TorConnector, "detect_tor_service", staticmethod(detect_tor_service)
    )
    monkeypatch.setattr(probe, "_something_is_listening", check_listener)

    result = runner.invoke(app, ["status"])

    assert result.exit_code == 0, result.stdout
    state = "listening" if listening else "not listening"
    assert f"Proxy {state} on 127.0.0.31:19180" in plain(result.stdout)
    assert f"API {state} on 127.0.0.32:19181" in plain(result.stdout)
    assert seen == [("127.0.0.31", 19180), ("127.0.0.32", 19181)]


def test_user_generate_dry_run_prints_credentials_without_creating_a_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TestAuthManager:
        created = False

        def __init__(
            self,
            credentials_file: Path,
            master_key: str | None,
            tunnel_network: str,
        ) -> None:
            self.credentials_file = credentials_file
            self.master_key = master_key
            self.tunnel_network = tunnel_network

        def generate_credentials(self) -> tuple[str, str]:
            return "dry-user-481", "Dry-password-481!"

        def add_user(self, *_args: object, **_kwargs: object) -> None:
            TestAuthManager.created = True

    def load_key() -> str:
        return "test-master-key"

    monkeypatch.setattr(user_commands, "AuthManager", TestAuthManager)
    monkeypatch.setattr(user_commands, "load_master_key", load_key)

    result = runner.invoke(
        app,
        ["user", "generate", "--dry-run", "--config", "missing-dry-run-config.yaml"],
    )

    assert result.exit_code == 0, result.stdout
    assert "dry-user-481" in result.stdout
    assert "Dry-password-481!" in result.stdout
    assert "No user was created" in result.stdout
    assert TestAuthManager.created is False
    assert not Path("missing-dry-run-config.yaml").exists()
