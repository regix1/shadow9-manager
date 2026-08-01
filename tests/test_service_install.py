"""
Tests for `shadow9 service install`.

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
