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
from shadow9.commands import server as server_commands
from shadow9.commands import utils


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


def test_master_key_check_prints_the_stored_key_and_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--show is what 'show key' used to be, warning included."""

    def load_key() -> str:
        return "stored-master-key-123"

    monkeypatch.setattr(utils, "load_master_key", load_key)

    result = runner.invoke(app, ["master-key", "check", "--show"])

    assert result.exit_code == 0, result.stdout
    said = plain(result.stdout)
    assert "stored-master-key-123" in said
    assert "Anyone with this key can decrypt credentials" in said


def test_removing_a_user_takes_their_directory_with_them() -> None:
    """The interactive list used to remove the credential and leave the files behind.

    Both routes call this now, so a user removed from either one is gone from both places.
    """
    removed: list[str] = []
    deleted: list[str] = []

    class _Store:
        def remove_user(self, username: str) -> bool:
            removed.append(username)
            return True

    class _Paths:
        def delete_user_dir(self, username: str) -> bool:
            deleted.append(username)
            return True

    import shadow9.commands.user as user_module

    original = user_module.get_paths
    user_module.get_paths = lambda: _Paths()  # type: ignore[assignment]
    try:
        assert user_commands.remove_user(_Store(), "alice") is True
    finally:
        user_module.get_paths = original  # type: ignore[assignment]

    assert removed == ["alice"]
    assert deleted == ["alice"], "the user's directory was left on disk"


class TestStop:
    """Stopping the proxy must not stop somebody else's program."""

    def test_the_service_is_preferred_over_the_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When shadow9's own process is found, nothing looks at the port at all."""
        monkeypatch.setattr(utils, "stop_running_server", lambda: utils.RunningServer(True, True))

        def no_port_lookup(port: int) -> None:
            raise AssertionError("the port must not be consulted once the server was found")

        monkeypatch.setattr(server_commands, "_listener_on_port", no_port_lookup)

        result = runner.invoke(app, ["stop"])

        assert result.exit_code == 0, result.stdout
        assert "Server stopped" in plain(result.stdout)

    def test_an_unrecognised_process_is_named_and_not_killed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Declining the prompt has to leave the other program running."""
        monkeypatch.setattr(utils, "stop_running_server", lambda: utils.RunningServer(False, False))
        monkeypatch.setattr(
            server_commands,
            "_listener_on_port",
            lambda port: server_commands.PortHolder(4242, "postgres", False),
        )

        killed: list[int] = []
        monkeypatch.setattr(server_commands, "_terminate", lambda pid: killed.append(pid) or True)

        result = runner.invoke(app, ["stop"], input="n\n")

        assert result.exit_code == 1, result.stdout
        said = plain(result.stdout)
        assert "postgres" in said and "4242" in said
        assert killed == [], "it stopped a process the operator declined to stop"

    def test_yes_stops_the_unrecognised_process_without_asking(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(utils, "stop_running_server", lambda: utils.RunningServer(False, False))
        monkeypatch.setattr(
            server_commands,
            "_listener_on_port",
            lambda port: server_commands.PortHolder(4242, "postgres", False),
        )
        killed: list[int] = []
        monkeypatch.setattr(server_commands, "_terminate", lambda pid: killed.append(pid) or True)

        result = runner.invoke(app, ["stop", "--yes"])

        assert result.exit_code == 0, result.stdout
        assert killed == [4242]


class TestCheckTor:
    """The port on the command line is the port that gets tested."""

    def _connector(self, monkeypatch: pytest.MonkeyPatch, *, connects: bool) -> list[int]:
        """Record which SOCKS port a connector was built for, without touching Tor."""
        tested: list[int] = []

        class _Connector:
            def __init__(self, config: object) -> None:
                tested.append(config.socks_port)  # type: ignore[attr-defined]

            @staticmethod
            def detect_tor_service() -> object:
                raise AssertionError("a supplied port must not be second-guessed by autodetection")

            @staticmethod
            def get_tor_install_instructions() -> str:
                return "install tor"

            async def connect(self) -> bool:
                return connects

            async def disconnect(self) -> None:
                return None

            circuit_info = None

        monkeypatch.setattr(utils, "TorConnector", _Connector)
        return tested

    def test_the_supplied_port_is_the_one_tested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        tested = self._connector(monkeypatch, connects=True)

        result = runner.invoke(app, ["check-tor", "--tor-port", "9150"])

        assert result.exit_code == 0, result.stdout
        assert tested == [9150]

    def test_a_failed_check_exits_non_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A red line on the terminal is not enough for a script to notice."""
        self._connector(monkeypatch, connects=False)

        result = runner.invoke(app, ["check-tor", "--tor-port", "9150"])

        assert result.exit_code == 1, result.stdout


def test_master_key_check_explains_how_to_create_a_missing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A check that finds no key says how to make one, and fails so a script notices."""

    def load_key() -> None:
        return None

    monkeypatch.setattr(utils, "load_master_key", load_key)

    result = runner.invoke(app, ["master-key", "check"])

    assert result.exit_code == 1, result.stdout
    said = plain(result.stdout)
    assert "No master key configured" in said
    assert "master-key generate" in said


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
