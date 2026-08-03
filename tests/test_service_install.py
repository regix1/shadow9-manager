"""
Tests for `shadow9 socks5 service install`.

Nothing here touches the real /etc/systemd/system or /usr/local/bin. The unit file path is
pointed at tmp_path, systemctl is replaced with a recorder, and symlink creation is recorded
rather than performed, so the whole install runs on a machine that is not Linux.
"""

import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import Result
from typer import Typer
from typer.testing import CliRunner

from shadow9 import paths
from shadow9.commands import service

MASTER_KEY = "test-master-key-for-the-install-tests"
OLD_KEY = "the-key-a-previous-install-wrote-inline"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Path.symlink_to is replaced for the whole test file, so the calls have to land somewhere
# a fixture can reset between tests
_SYMLINKS: list[tuple[str, str]] = []


class _Systemctl:
    """Record the systemctl calls the install makes instead of running them."""

    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        self.commands.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


def _skip_check() -> None:
    """Stand in for the Linux and root checks, which cannot pass where the tests run."""


def _recent_systemd() -> int:
    """Report a systemd new enough for the decaying restart interval."""
    return 255


def _record_symlink(self: Path, target: Path, target_is_directory: bool = False) -> None:
    """Record the global command symlink instead of creating one on the test machine."""
    _SYMLINKS.append((str(self), str(target)))


def _flat(text: str) -> str:
    """Strip the styling and the wrapping rich adds, so a sentence reads as one string."""
    return re.sub(r"\s+", " ", _ANSI.sub("", text))


def _saved_master_key(env_file: Path) -> str:
    """Read the key back out of the environment file the way the service will."""
    for line in env_file.read_text().splitlines():
        if line.strip().startswith("SHADOW9_MASTER_KEY="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"no master key in {env_file}")


@pytest.fixture
def install_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Point the whole install at tmp_path and keep it off the real system."""
    monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
    # rich wraps to the terminal width, and a wrapped path cannot be searched for as one
    # string. A wide console keeps the assertions about what the operator sees
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(paths.Shadow9Paths, "_instance", None)
    monkeypatch.setattr(service, "SERVICE_FILE", str(tmp_path / "shadow9.service"))
    monkeypatch.setattr(service, "_check_linux", _skip_check)
    monkeypatch.setattr(service, "_check_root", _skip_check)
    monkeypatch.setattr(service, "_systemd_version", _recent_systemd)
    monkeypatch.setattr(service, "subprocess", _Systemctl())
    monkeypatch.setattr(Path, "symlink_to", _record_symlink)
    _SYMLINKS.clear()
    yield tmp_path
    paths.Shadow9Paths._instance = None


class TestReadingTheKeyBack:
    """The install writes the key, reads it back, and stops if they disagree.

    A hand-quoted value made those two disagree while looking identical, so the install
    refused with a message saying the file did not contain a key it was looking straight at.
    """

    @pytest.mark.parametrize(
        ("written", "expected"),
        [
            ("SHADOW9_MASTER_KEY=abc123", "abc123"),
            ('SHADOW9_MASTER_KEY="abc123"', "abc123"),
            ("SHADOW9_MASTER_KEY='abc123'", "abc123"),
        ],
    )
    def test_a_quoted_value_reads_back_as_the_value(
        self, tmp_path: Path, written: str, expected: str
    ) -> None:
        env_file = tmp_path / ".env"
        env_file.write_text(f"{written}\n", encoding="utf-8")

        assert service._read_master_key(env_file) == expected

    @pytest.mark.parametrize(
        ("written", "expected"),
        [
            ('SHADOW9_MASTER_KEY=ab"c123', 'ab"c123'),
            ('SHADOW9_MASTER_KEY="abc123', '"abc123'),
            ("SHADOW9_MASTER_KEY=abc123'", "abc123'"),
        ],
    )
    def test_only_a_matched_pair_comes_off(
        self, tmp_path: Path, written: str, expected: str
    ) -> None:
        """A quote that is part of the key, or an unbalanced one, is left where it is."""
        env_file = tmp_path / ".env"
        env_file.write_text(f"{written}\n", encoding="utf-8")

        assert service._read_master_key(env_file) == expected


def _run_install() -> Result:
    """Run `service install` against a throwaway app and hand back the runner result."""
    app = Typer()
    service.register_service_commands(app)
    return CliRunner().invoke(app, ["service", "install"])


def _install_unit() -> str:
    """Run a successful install and return the unit text it wrote."""
    result = _run_install()
    assert result.exit_code == 0, _flat(result.stdout)
    return Path(service.SERVICE_FILE).read_text()


def test_installed_unit_does_not_carry_the_master_key(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unit is world readable, so the key belongs in the 0600 file it points at."""
    monkeypatch.setenv("SHADOW9_MASTER_KEY", MASTER_KEY)

    unit = _install_unit()

    assert MASTER_KEY not in unit
    assert "SHADOW9_MASTER_KEY=" not in unit
    env_file = paths.get_paths().env_file
    assert f"EnvironmentFile={env_file}" in unit
    assert f"ExecStart={install_root}/shadow9 socks5 serve --host 127.0.0.1 --port 1080" in unit
    assert _saved_master_key(env_file) == MASTER_KEY


def test_reinstall_rewrites_a_unit_that_holds_an_inline_key(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An install that already leaked its key must not keep leaking it after an upgrade."""
    monkeypatch.setenv("SHADOW9_MASTER_KEY", MASTER_KEY)
    Path(service.SERVICE_FILE).write_text(
        f'[Service]\nEnvironment="SHADOW9_MASTER_KEY={OLD_KEY}"\nExecStart=/usr/bin/false\n'
    )

    unit = _install_unit()

    assert OLD_KEY not in unit
    assert MASTER_KEY not in unit
    assert "SHADOW9_MASTER_KEY=" not in unit


def test_install_generates_a_key_and_points_the_unit_at_it(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fresh install still gets a key, and that key still never reaches the unit."""
    monkeypatch.delenv("SHADOW9_MASTER_KEY", raising=False)

    unit = _install_unit()

    env_file = paths.get_paths().env_file
    generated = _saved_master_key(env_file)
    assert generated
    assert generated not in unit
    assert f"EnvironmentFile={env_file}" in unit


def test_install_keeps_the_other_environment_settings(install_root: Path) -> None:
    """Moving the key out must not take the rest of the environment with it."""
    unit = _install_unit()

    root = paths.get_paths().root
    assert 'Environment="PATH=' in unit
    assert f'Environment="PYTHONPATH={root}/src"' in unit
    assert f'Environment="SHADOW9_HOME={root}"' in unit
    assert f"WorkingDirectory={root}" in unit
    assert "ExecStart=" in unit


def test_install_stops_when_the_key_did_not_reach_the_env_file(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A unit pointing at an environment file that has no key starts a service with no key."""
    monkeypatch.setenv("SHADOW9_MASTER_KEY", MASTER_KEY)
    real_write = service.write_file_safely

    def drop_env_writes(path: Path, data: bytes, mode: int = 0o600) -> None:
        """Behave like a filesystem where the environment file never lands."""
        if path.name == ".env":
            return
        real_write(path, data, mode)

    monkeypatch.setattr(service, "write_file_safely", drop_env_writes)

    result = _run_install()

    assert result.exit_code == 1, _flat(result.stdout)
    assert not Path(service.SERVICE_FILE).exists()


def test_install_stops_when_the_stored_key_differs_from_the_environment(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored key is the only copy of what credentials.enc was encrypted with."""
    monkeypatch.setenv("SHADOW9_MASTER_KEY", MASTER_KEY)
    env_file = paths.get_paths().env_file
    env_file.write_text(f"# keep this secret\nSHADOW9_MASTER_KEY={OLD_KEY}\n")

    result = _run_install()

    assert result.exit_code == 1, _flat(result.stdout)
    assert _saved_master_key(env_file) == OLD_KEY
    assert not Path(service.SERVICE_FILE).exists()


@pytest.mark.skipif(sys.platform == "win32", reason="permission bits only mean something on Unix")
def test_install_leaves_the_env_file_readable_only_by_root(
    install_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """systemd reads this file as root, so nobody else needs to."""
    monkeypatch.setenv("SHADOW9_MASTER_KEY", MASTER_KEY)

    _install_unit()

    env_file = paths.get_paths().env_file
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600


def test_start_reports_a_service_that_stayed_running(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        parts = tuple(command)
        calls.append(parts)
        output = "active\n" if parts[:2] == ("systemctl", "is-active") else ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(service, "_check_linux", _skip_check)
    monkeypatch.setattr(service, "_check_root", _skip_check)
    monkeypatch.setattr(service, "_check_installed", _skip_check)
    monkeypatch.setattr(service.subprocess, "run", run)
    monkeypatch.setattr(service.time, "sleep", lambda _seconds: None)
    app = Typer()
    service.register_service_commands(app)

    result = CliRunner().invoke(app, ["service", "start"])

    assert result.exit_code == 0, result.output
    assert "Service started and is running" in _flat(result.output)
    assert ("systemctl", "is-active", service.SERVICE_NAME) in calls


@pytest.mark.parametrize("path", [["start"], ["restart"]])
def test_start_and_restart_are_also_on_the_menu_itself(
    path: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """stop sits beside serve, so the matching start and restart have to be there too."""
    calls: list[tuple[str, ...]] = []

    def run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        parts = tuple(command)
        calls.append(parts)
        output = "active\n" if parts[:2] == ("systemctl", "is-active") else ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(service, "_check_linux", _skip_check)
    monkeypatch.setattr(service, "_check_root", _skip_check)
    monkeypatch.setattr(service, "_check_installed", _skip_check)
    monkeypatch.setattr(service.subprocess, "run", run)
    monkeypatch.setattr(service.time, "sleep", lambda _seconds: None)
    app = Typer()
    service.register_service_commands(app)

    result = CliRunner().invoke(app, path)

    assert result.exit_code == 0, result.output
    assert ("systemctl", path[0], service.SERVICE_NAME) in calls


def test_start_rejects_a_service_that_entered_auto_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        parts = tuple(command)
        if parts[:2] == ("systemctl", "is-active"):
            return subprocess.CompletedProcess(command, 3, stdout="activating\n", stderr="")
        if parts[:2] == ("systemctl", "status"):
            return subprocess.CompletedProcess(
                command,
                3,
                stdout="Active: activating (auto-restart) (Result: exit-code)\n",
                stderr="",
            )
        if parts[0] == "journalctl":
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="Tor service not detected\n",
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(service, "_check_linux", _skip_check)
    monkeypatch.setattr(service, "_check_root", _skip_check)
    monkeypatch.setattr(service, "_check_installed", _skip_check)
    monkeypatch.setattr(service.subprocess, "run", run)
    monkeypatch.setattr(service.time, "sleep", lambda _seconds: None)
    app = Typer()
    service.register_service_commands(app)

    result = CliRunner().invoke(app, ["service", "start"])

    assert result.exit_code == 1
    output = _flat(result.output)
    assert "Service did not stay running (activating)" in output
    assert "Service started" not in output
    assert "Recent service logs" in output
    assert "Tor service not detected" in output
    assert "More logs: shadow9 socks5 service logs" in output


def test_uninstall_removes_wireguard_services_and_restores_the_saved_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from shadow9.commands import wireguard

    monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
    monkeypatch.setattr(paths.Shadow9Paths, "_instance", None)
    monkeypatch.setattr(service, "_check_linux", _skip_check)
    monkeypatch.setattr(service, "_check_root", _skip_check)

    systemd_dir = tmp_path / "etc" / "systemd" / "system"
    systemd_dir.mkdir(parents=True)
    service_file = systemd_dir / "shadow9.service"
    enrollment_file = systemd_dir / wireguard.ENROLLMENT_SERVICE_NAME
    service_file.write_text("main\n", encoding="utf-8")
    enrollment_file.write_text("enrollment\n", encoding="utf-8")
    monkeypatch.setattr(service, "SERVICE_FILE", str(service_file))
    monkeypatch.setattr(wireguard, "ENROLLMENT_SERVICE_FILE", enrollment_file)

    shadow9_paths = paths.get_paths()
    shadow9_paths.config_file.write_text(
        "wireguard:\n  enabled: true\n  interface: wg0\n",
        encoding="utf-8",
    )
    generated = shadow9_paths.config_dir / "wireguard" / "wg0.conf"
    generated.parent.mkdir(parents=True)
    generated.write_text("shadow9\n", encoding="utf-8")
    system_dir = tmp_path / "etc" / "wireguard"
    system_dir.mkdir(parents=True)
    target = system_dir / "wg0.conf"
    target.symlink_to(generated)
    saved = system_dir / "wg0.conf.before-shadow9"
    saved.write_text("operator\n", encoding="utf-8")
    monkeypatch.setattr(wireguard, "WIREGUARD_SYSTEM_DIR", system_dir)
    forwarding = tmp_path / "etc" / "sysctl.d" / "99-shadow9.conf"
    forwarding.parent.mkdir(parents=True)
    forwarding.write_text("net.ipv4.ip_forward=1\n", encoding="utf-8")
    monkeypatch.setattr(wireguard, "FORWARDING_CONFIG", forwarding)

    calls: list[tuple[str, ...]] = []

    def run(command: list[str], **_options: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(service.subprocess, "run", run)
    app = Typer()
    service.register_service_commands(app)

    result = CliRunner().invoke(app, ["service", "uninstall", "--yes"])

    assert result.exit_code == 0, result.output
    assert not service_file.exists()
    assert not enrollment_file.exists()
    assert not forwarding.exists()
    assert target.read_text(encoding="utf-8") == "operator\n"
    assert not target.is_symlink()
    assert not saved.exists()
    for unit in (
        service.SERVICE_NAME,
        wireguard.ENROLLMENT_SERVICE_NAME,
        "wg-quick@wg0",
    ):
        assert ("systemctl", "stop", unit) in calls
        assert ("systemctl", "disable", unit) in calls
