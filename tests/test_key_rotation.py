"""
Tests for master key rotation and for getting back to the key it replaced.

Rotating the master key deliberately makes every existing credential unreadable, so the
backup it takes is the only way back. The backup is only worth having if the whole set
comes back together: the credentials file cannot be decrypted without the salt that was
beside it, and the API key cannot be decrypted without the key file that encrypted it.
The round trip in `test_a_restored_backup_decrypts_a_user_stored_before_rotation` is what
proves the set is complete, so the rest of this file exists to hold that test up.

Nothing here touches the real install. `SHADOW9_HOME` points at `tmp_path` and the paths
singleton is reset so it picks that up, and `shutil.which` is answered so that no test
depends on whether the machine running it happens to have systemd.
"""

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import pytest
from typer.testing import CliRunner

from shadow9 import paths as paths_module
from shadow9.auth import AuthManager
from shadow9.cli import app
from shadow9.core import api_config

runner = CliRunner()

OLD_MASTER_KEY = "old-master-key-value-for-rotation"
PASSWORD = "SecurePass123!@#"


def plain(text: str) -> str:
    """
    Drop the terminal escapes so a sentence can be matched as one string.

    Rich styles values inside a line, so a path or a command name comes back wrapped in
    escape codes and the sentence the operator reads is never present in the raw output.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class Install(NamedTuple):
    """The one install every test in this file works against."""

    root: Path
    config_dir: Path
    env_file: Path
    credentials_file: Path
    salt_file: Path
    api_config_file: Path
    api_salt_file: Path

    @property
    def backups_dir(self) -> Path:
        return self.root / "key-backups"

    def latest_backup(self) -> Path:
        """The newest backup directory, which is the one rotation just wrote."""
        candidates = sorted(entry for entry in self.backups_dir.iterdir() if entry.is_dir())
        assert candidates, f"rotation left no backup under {self.backups_dir}"
        return candidates[-1]


def _write_env(env_file: Path, master_key: str) -> None:
    env_file.write_text(
        "# Shadow9 Master Key - Keep this secret!\n" f"SHADOW9_MASTER_KEY={master_key}\n",
        encoding="utf-8",
    )


def _empty_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Install:
    """An install rooted in tmp_path with no key placed yet, and no way out to the real one."""
    root = tmp_path / "install"
    config_dir = root / "config"
    config_dir.mkdir(parents=True)

    monkeypatch.setattr(paths_module.Shadow9Paths, "_instance", None)
    monkeypatch.setenv("SHADOW9_HOME", str(root))

    # Answering which() keeps the result the same on a machine with systemd and on one
    # without. The service gate gets its own answers in the test that exercises it.
    monkeypatch.setattr(shutil, "which", lambda name: None)

    # These tests rotate and delete key material, so a command that resolved its own root
    # instead of asking get_paths() would do that to the checkout this is running from.
    # That happened once. Fail here rather than there.
    assert paths_module.get_paths().root == root

    return Install(
        root=root,
        config_dir=config_dir,
        env_file=root / ".env",
        credentials_file=config_dir / "credentials.enc",
        salt_file=config_dir / ".salt",
        api_config_file=config_dir / "api.yaml",
        api_salt_file=config_dir / ".api_salt",
    )


def _forget_the_generated_key() -> None:
    """
    Drop the key the command exported into this process.

    monkeypatch.delenv records nothing when the variable was not set to begin with, so
    without this the key `key generate` writes into os.environ outlives the test. Any
    original value is restored after this by monkeypatch itself, which tears down later.
    """
    os.environ.pop("SHADOW9_MASTER_KEY", None)


@pytest.fixture
def install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Install]:
    """An install rooted in tmp_path, with an existing master key already in .env."""
    monkeypatch.delenv("SHADOW9_MASTER_KEY", raising=False)
    install = _empty_install(tmp_path, monkeypatch)
    _write_env(install.env_file, OLD_MASTER_KEY)

    yield install

    _forget_the_generated_key()


@pytest.fixture
def shell_key_install(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Install]:
    """
    An install whose master key is exported in the shell and written nowhere.

    The init wizard tells operators to do exactly this, at
    `src/shadow9/wizards/init_wizard.py:208`, so it is a normal install and not a corner
    case. There is no .env file at all here.
    """
    monkeypatch.setenv("SHADOW9_MASTER_KEY", OLD_MASTER_KEY)
    install = _empty_install(tmp_path, monkeypatch)
    assert not install.env_file.exists()

    yield install

    _forget_the_generated_key()


def _store_user(install: Install, username: str, master_key: str) -> None:
    """Write one user into the credentials file the way the CLI would."""
    auth = AuthManager(credentials_file=install.credentials_file, master_key=master_key)
    assert auth.add_user(username, PASSWORD) is True


def _master_key_on_disk(env_file: Path) -> str:
    for line in env_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("SHADOW9_MASTER_KEY="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"no master key in {env_file}")


class TestTheBackupSet:
    """Rotation has to save every file the old key needs, not just some of them."""

    def test_backup_holds_every_file_the_old_key_needs(self, install: Install) -> None:
        """
        The salt is the one everybody forgets. Without it the backed-up credentials file
        can never be decrypted again, so a backup missing it is not a backup.
        """
        _store_user(install, "alice", OLD_MASTER_KEY)
        api_config.set_api_key("api-key-before-rotation")

        result = runner.invoke(app, ["master-key","generate", "--force"])
        assert result.exit_code == 0, plain(result.stdout)

        backup = install.latest_backup()
        held = {entry.name for entry in backup.iterdir()}
        assert {".env", "credentials.enc", ".salt", "api.yaml", ".api_salt"} <= held

    def test_backup_records_what_it_captured(self, install: Install) -> None:
        """
        A manifest is what tells a restore whether the set is whole. Without it a backup
        cut short by a crash looks exactly like a complete one.
        """
        _store_user(install, "alice", OLD_MASTER_KEY)

        result = runner.invoke(app, ["master-key","generate", "--force"])
        assert result.exit_code == 0, plain(result.stdout)

        manifest = json.loads((install.latest_backup() / "manifest.json").read_text())
        recorded = {entry["name"] for entry in manifest["files"]}
        assert {".env", "credentials.enc", ".salt", "api.yaml", ".api_salt"} == recorded

        captured = {entry["name"] for entry in manifest["files"] if entry["present"]}
        assert {".env", "credentials.enc", ".salt"} <= captured

    def test_rotation_still_invalidates_the_live_credentials(self, install: Install) -> None:
        """Rotation is meant to make the live credentials unusable. That is not the bug."""
        _store_user(install, "alice", OLD_MASTER_KEY)

        result = runner.invoke(app, ["master-key","generate", "--force"])
        assert result.exit_code == 0, plain(result.stdout)

        assert not install.credentials_file.exists()
        assert _master_key_on_disk(install.env_file) != OLD_MASTER_KEY

    def test_a_restored_backup_decrypts_a_user_stored_before_rotation(
        self, install: Install
    ) -> None:
        """
        The whole point of the fix. Store a user, rotate the key, restore the backup, and
        read that same user back with the password that was set before the rotation.
        """
        _store_user(install, "alice", OLD_MASTER_KEY)

        rotated = runner.invoke(app, ["master-key","generate", "--force"])
        assert rotated.exit_code == 0, plain(rotated.stdout)
        assert not install.credentials_file.exists()

        restored = runner.invoke(app, ["master-key","restore", "--force"])
        assert restored.exit_code == 0, plain(restored.stdout)

        assert _master_key_on_disk(install.env_file) == OLD_MASTER_KEY
        assert install.salt_file.exists()
        assert paths_module.load_master_key() == OLD_MASTER_KEY

        auth = AuthManager(credentials_file=install.credentials_file, master_key=OLD_MASTER_KEY)
        assert auth.load_error is None
        assert auth.list_users() == ["alice"]
        assert auth.verify("alice", PASSWORD) is True

    def test_restore_refuses_a_backup_that_never_finished(self, install: Install) -> None:
        """
        A process killed part way through the copies leaves a directory holding some of
        the set. Restoring that half set would replace live key material with something
        that cannot be decrypted, so it has to be refused instead.
        """
        _store_user(install, "alice", OLD_MASTER_KEY)
        rotated = runner.invoke(app, ["master-key","generate", "--force"])
        assert rotated.exit_code == 0, plain(rotated.stdout)

        backup = install.latest_backup()
        (backup / "manifest.json").unlink()
        key_after_rotation = _master_key_on_disk(install.env_file)

        refused = runner.invoke(app, ["master-key","restore", str(backup), "--force"])

        assert refused.exit_code != 0
        assert _master_key_on_disk(install.env_file) == key_after_rotation
        assert not install.credentials_file.exists()

    def test_restore_refuses_when_a_backed_up_file_was_altered(self, install: Install) -> None:
        """A backup whose contents no longer match the manifest is not restorable either."""
        _store_user(install, "alice", OLD_MASTER_KEY)
        rotated = runner.invoke(app, ["master-key","generate", "--force"])
        assert rotated.exit_code == 0, plain(rotated.stdout)

        backup = install.latest_backup()
        (backup / "credentials.enc").write_bytes(b"not what was backed up")
        key_after_rotation = _master_key_on_disk(install.env_file)

        refused = runner.invoke(app, ["master-key","restore", str(backup), "--force"])

        assert refused.exit_code != 0
        assert _master_key_on_disk(install.env_file) == key_after_rotation


class TestAKeyThatLivesInTheShell:
    """
    An exported SHADOW9_MASTER_KEY is a real install, not a corner case.

    Deciding whether there is a key to lose by reading the text of .env misses it
    completely, so rotation would write a new key and leave the credentials and the salt
    of the old one sitting beside it with no backup taken and the service still running.
    """

    def test_a_key_only_in_the_environment_is_backed_up_and_restorable(
        self, shell_key_install: Install
    ) -> None:
        _store_user(shell_key_install, "alice", OLD_MASTER_KEY)

        rotated = runner.invoke(app, ["master-key","generate", "--force"])
        assert rotated.exit_code == 0, plain(rotated.stdout)

        assert shell_key_install.backups_dir.is_dir(), "rotation took no backup"
        assert not shell_key_install.credentials_file.exists()
        assert _master_key_on_disk(shell_key_install.env_file) != OLD_MASTER_KEY

        restored = runner.invoke(app, ["master-key","restore", "--force"])
        assert restored.exit_code == 0, plain(restored.stdout)

        auth = AuthManager(
            credentials_file=shell_key_install.credentials_file, master_key=OLD_MASTER_KEY
        )
        assert auth.load_error is None
        assert auth.list_users() == ["alice"]
        assert auth.verify("alice", PASSWORD) is True

    def test_the_backup_records_the_key_that_was_really_in_effect(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        The environment beats .env in load_master_key, so a stale line in the file is not
        the key the credentials were encrypted with. Copying .env as it stands would put
        the wrong key in the backup and the round trip would fail on restore.
        """
        monkeypatch.setenv("SHADOW9_MASTER_KEY", OLD_MASTER_KEY)
        install = _empty_install(tmp_path, monkeypatch)
        _write_env(install.env_file, "a-stale-line-no-longer-in-use")
        try:
            _store_user(install, "alice", OLD_MASTER_KEY)

            rotated = runner.invoke(app, ["master-key","generate", "--force"])
            assert rotated.exit_code == 0, plain(rotated.stdout)

            restored = runner.invoke(app, ["master-key","restore", "--force"])
            assert restored.exit_code == 0, plain(restored.stdout)

            assert _master_key_on_disk(install.env_file) == OLD_MASTER_KEY
            assert paths_module.load_master_key() == OLD_MASTER_KEY

            auth = AuthManager(credentials_file=install.credentials_file, master_key=OLD_MASTER_KEY)
            assert auth.load_error is None
            assert auth.verify("alice", PASSWORD) is True
        finally:
            _forget_the_generated_key()

    def test_the_service_is_stopped_even_when_the_key_is_only_in_the_shell(
        self, shell_key_install: Install, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The gate has to cover this install too, or the service writes with the old key."""
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/bin/systemctl" if name == "systemctl" else None
        )
        _store_user(shell_key_install, "alice", OLD_MASTER_KEY)
        credentials_before = shell_key_install.credentials_file.read_bytes()

        def fake_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
            argv = list(command)
            if "is-active" in argv:
                return subprocess.CompletedProcess(argv, 0, stdout="active\n", stderr="")
            if "stop" in argv:
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr="Failed to stop shadow9.service"
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = runner.invoke(app, ["master-key","generate", "--force"])

        assert result.exit_code != 0
        assert not shell_key_install.env_file.exists()
        assert shell_key_install.credentials_file.read_bytes() == credentials_before
        assert shell_key_install.salt_file.exists()


class TestTheServiceGate:
    """Key material must not move while the service is still able to write to it."""

    def _systemd_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/bin/systemctl" if name == "systemctl" else None
        )

    def test_rotation_aborts_when_the_service_will_not_stop(
        self, install: Install, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """
        A running service holds the old key and keeps writing with it. Ignoring a failed
        stop lets it write old-key ciphertext into a file rotation is in the middle of
        replacing, so a stop that fails has to end the command.
        """
        self._systemd_present(monkeypatch)
        _store_user(install, "alice", OLD_MASTER_KEY)
        credentials_before = install.credentials_file.read_bytes()

        def fake_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
            argv = list(command)
            if "is-active" in argv:
                return subprocess.CompletedProcess(argv, 0, stdout="active\n", stderr="")
            if "stop" in argv:
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr="Failed to stop shadow9.service"
                )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = runner.invoke(app, ["master-key","generate", "--force"])

        assert result.exit_code != 0
        assert _master_key_on_disk(install.env_file) == OLD_MASTER_KEY
        assert install.credentials_file.read_bytes() == credentials_before
        assert install.salt_file.exists()

    def test_rotation_stops_the_service_before_it_touches_key_material(
        self, install: Install, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stop has to come first, or the service writes into a half-rotated install."""
        self._systemd_present(monkeypatch)
        _store_user(install, "alice", OLD_MASTER_KEY)

        order: list[str] = []

        def fake_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
            argv = list(command)
            if "is-active" in argv:
                state = "active" if "stop" not in order else "inactive"
                return subprocess.CompletedProcess(argv, 0, stdout=f"{state}\n", stderr="")
            if "stop" in argv:
                order.append("stop")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)

        result = runner.invoke(app, ["master-key","generate", "--force"])

        assert result.exit_code == 0, plain(result.stdout)
        assert order == ["stop"]


class TestTheApiKey:
    """The API key is encrypted with the master key too, so rotation has to deal with it."""

    def test_api_authentication_keeps_working_after_rotation(self, install: Install) -> None:
        """
        Leaving the API key encrypted under the replaced master key stops API requests
        from authenticating, with nothing said about why.
        """
        api_config.set_api_key("api-key-before-rotation")
        assert api_config.get_api_key() == "api-key-before-rotation"

        result = runner.invoke(app, ["master-key","generate", "--force"])
        assert result.exit_code == 0, plain(result.stdout)

        assert api_config.get_api_key() == "api-key-before-rotation"

    def test_an_unreadable_api_key_is_cleared_and_the_operator_is_told(
        self, install: Install
    ) -> None:
        """
        When the stored key cannot be read there is nothing to re-encrypt, so it has to go
        rather than sit in the file failing every request quietly.
        """
        api_config.save_api_config(
            {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 8080,
                "api_key_encrypted": "bm90LWEtcmVhbC1jaXBoZXJ0ZXh0",
            }
        )

        result = runner.invoke(app, ["master-key","generate", "--force"])
        assert result.exit_code == 0, plain(result.stdout)

        remaining = api_config.load_api_config()
        assert "api_key_encrypted" not in remaining
        assert "key" not in remaining
        assert "api setup" in plain(result.stdout)

    def test_a_restored_backup_brings_the_old_api_key_back(self, install: Install) -> None:
        """The API key file and its salt belong to the same matched set as the credentials."""
        api_config.set_api_key("api-key-before-rotation")

        rotated = runner.invoke(app, ["master-key","generate", "--force"])
        assert rotated.exit_code == 0, plain(rotated.stdout)

        restored = runner.invoke(app, ["master-key","restore", "--force"])
        assert restored.exit_code == 0, plain(restored.stdout)

        assert api_config.get_api_key() == "api-key-before-rotation"


def test_generating_a_first_key_takes_no_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There is nothing to back up before the first key exists."""
    root = tmp_path / "fresh"
    (root / "config").mkdir(parents=True)
    monkeypatch.setattr(paths_module.Shadow9Paths, "_instance", None)
    monkeypatch.setenv("SHADOW9_HOME", str(root))
    monkeypatch.delenv("SHADOW9_MASTER_KEY", raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: None)

    result = runner.invoke(app, ["master-key","generate"])

    assert result.exit_code == 0, plain(result.stdout)
    assert (root / ".env").exists()
    assert not (root / "key-backups").exists()


def test_the_command_group_offers_a_restore(install: Install) -> None:
    """An operator who has just rotated needs to be able to find the way back."""
    result = runner.invoke(app, ["master-key","--help"])

    assert result.exit_code == 0
    assert "restore" in plain(result.stdout)
