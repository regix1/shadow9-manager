"""Tests for the update command, which pulls, reinstalls and restarts the proxy."""

import asyncio
import json
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import typer

from shadow9.commands import probe, utils
from shadow9.commands.service import SERVICE_NAME

OLD_COMMIT = "aaaaaaaaaaaa"
NEW_COMMIT = "bbbbbbbbbbbb"

# the real wait, kept before the fixtures replace it with an instant answer
wait_until_serving = utils._wait_until_serving


def plain(text: str) -> str:
    """Console output without the colour codes, so it can be read as text."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class StubProcess:
    """Replaces the subprocess module so commands are recorded instead of run."""

    DEVNULL = subprocess.DEVNULL

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.launched: list[list[str]] = []
        self.outcomes: dict[str, list[tuple[int, str, str]]] = {}

    def outcome(self, token: str, returncode: int, stdout: str = "", stderr: str = "") -> None:
        """Queue a result for the next command whose text contains token."""
        self.outcomes.setdefault(token, []).append((returncode, stdout, stderr))

    def set_outcome(self, token: str, returncode: int, stdout: str = "", stderr: str = "") -> None:
        """Replace whatever is queued for token with this one result."""
        self.outcomes[token] = [(returncode, stdout, stderr)]

    def run(self, command: list[str], **kwargs: object) -> "subprocess.CompletedProcess[str]":
        """Record a command and reply with the queued result, or success by default."""
        parts = [str(part) for part in command]
        self.calls.append(parts)
        joined = " ".join(parts)
        for token, queued in self.outcomes.items():
            if token in joined:
                returncode, stdout, stderr = queued[0] if len(queued) == 1 else queued.pop(0)
                return subprocess.CompletedProcess(parts, returncode, stdout, stderr)
        return subprocess.CompletedProcess(parts, 0, "", "")

    def Popen(self, command: list[str], **kwargs: object) -> object:
        """Record a background launch without starting anything."""
        self.launched.append([str(part) for part in command])
        return object()


def calls_with(stub: StubProcess, token: str) -> list[list[str]]:
    """Every recorded command whose text contains token."""
    return [call for call in stub.calls if token in " ".join(call)]


def position_of(stub: StubProcess, token: str) -> int:
    """Where a command containing token was recorded, or -1 if it never was."""
    for index, call in enumerate(stub.calls):
        if token in " ".join(call):
            return index
    return -1


@pytest.fixture
def update_command() -> Callable[..., None]:
    """The update callback, registered on a throwaway app."""
    app = typer.Typer()
    utils.register_util_commands(app, typer.Typer())
    for command in app.registered_commands:
        callback = command.callback
        if callback is not None and callback.__name__ == "update":
            return callback
    raise AssertionError("update is not registered as a command")


@pytest.fixture
def stub(monkeypatch: pytest.MonkeyPatch) -> StubProcess:
    """A recorded stand-in for every process the update command starts."""
    recorded = StubProcess()
    recorded.outcome("rev-parse HEAD", 0, f"{OLD_COMMIT}\n")
    recorded.outcome("rev-parse origin/main", 0, f"{NEW_COMMIT}\n")
    recorded.outcome("log", 0, "bbbbbbb latest thing\n")
    monkeypatch.setattr(utils, "subprocess", recorded)
    return recorded


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch) -> set[str]:
    """The set of programs the command can find, starting with git alone."""
    available = {"git"}

    def which(name: str, mode: int = 1, path: str | None = None) -> str | None:
        return f"/usr/bin/{name}" if name in available else None

    monkeypatch.setattr(utils.shutil, "which", which)
    return available


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A checkout the command will accept as the project root."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "shadow9"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    venv_python = utils._venv_python(tmp_path)
    venv_python.parent.mkdir(parents=True)
    venv_python.touch()
    monkeypatch.setattr(utils, "SERVICE_FILE", str(tmp_path / "shadow9.service"))

    def find_repo_root() -> Path:
        return tmp_path

    monkeypatch.setattr(utils, "_find_repo_root", find_repo_root)
    return tmp_path


@pytest.fixture(autouse=True)
def quiet_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the real waits, prompts and probes."""

    def sleep(seconds: float) -> None:
        return None

    def kill(pid: int, signal_number: int) -> None:
        raise ProcessLookupError(pid)

    def confirm(text: str, default: bool = False) -> bool:
        raise AssertionError(f"unexpected prompt: {text}")

    def wait_until_serving(host: str, port: int, timeout_seconds: float = 20.0) -> bool:
        return True

    monkeypatch.setattr(utils.time, "sleep", sleep)
    monkeypatch.setattr(utils.os, "kill", kill)
    monkeypatch.setattr(utils.typer, "confirm", confirm)
    monkeypatch.setattr(utils, "_wait_until_serving", wait_until_serving)


def answer_prompt(monkeypatch: pytest.MonkeyPatch, answer: bool) -> None:
    """Make the next confirmation prompt return answer."""

    def confirm(text: str, default: bool = False) -> bool:
        return answer

    monkeypatch.setattr(utils.typer, "confirm", confirm)


def running_service(stub: StubProcess, tools: set[str]) -> None:
    """Present a systemd service that is active and stops when asked."""
    tools.add("systemctl")
    stub.outcome("is-active", 0, "active\n")
    stub.outcome("is-active", 3, "inactive\n")


def serving_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the restart check report that nothing is listening."""

    def wait_until_serving(host: str, port: int, timeout_seconds: float = 20.0) -> bool:
        return False

    monkeypatch.setattr(utils, "_wait_until_serving", wait_until_serving)


class TestUncommittedWork:
    """Local changes are never thrown away as a side effect of updating."""

    def test_dirty_tree_stops_the_default_update(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Without --force the update refuses rather than asking to destroy work."""
        stub.outcome("status --porcelain", 0, " M src/shadow9/cli.py\n?? notes.txt\n")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, "merge") == []
        assert calls_with(stub, "reset --hard") == []
        assert calls_with(stub, "systemctl stop") == []

    def test_dirty_tree_is_not_discarded_without_an_answer(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Declining the --force prompt leaves the checkout and the server alone."""
        stub.outcome("status --porcelain", 0, " M src/shadow9/cli.py\n")
        answer_prompt(monkeypatch, False)

        with pytest.raises(typer.Exit):
            update_command(force=True)

        assert calls_with(stub, "reset --hard") == []
        assert calls_with(stub, "systemctl stop") == []

    def test_dirty_tree_is_discarded_once_it_is_answered(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Accepting the --force prompt runs the reset that deletes the changes."""
        stub.outcome("status --porcelain", 0, " M src/shadow9/cli.py\n")
        answer_prompt(monkeypatch, True)

        update_command(force=True)

        assert calls_with(stub, "reset --hard origin/main")

    def test_clean_tree_is_not_prompted(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """With nothing uncommitted the update runs without asking anything."""
        update_command()

        assert calls_with(stub, "merge --ff-only origin/main")


class TestWhatIsComing:
    """The operator sees what the update holds before it rewrites the install."""

    def test_check_reports_and_changes_nothing(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """--check fetches, lists the waiting commits and touches nothing."""
        running_service(stub, tools)

        update_command(check=True)

        assert calls_with(stub, "fetch --all")
        assert "latest thing" in plain(capsys.readouterr().out)
        assert calls_with(stub, "systemctl stop") == []
        assert calls_with(stub, "merge") == []
        assert calls_with(stub, "pip install") == []

    def test_commits_are_listed_before_the_server_stops(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Reading the log first means the outage starts after the operator is told."""
        running_service(stub, tools)

        update_command()

        assert position_of(stub, "log") < position_of(stub, "systemctl stop")
        assert "latest thing" in plain(capsys.readouterr().out)

    def test_already_up_to_date_stops_there(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Nothing to pull costs no outage, no reinstall and no restart."""
        running_service(stub, tools)
        stub.set_outcome("rev-parse origin/main", 0, f"{OLD_COMMIT}\n")

        update_command()

        assert "Already up to date" in plain(capsys.readouterr().out)
        assert calls_with(stub, "systemctl stop") == []
        assert calls_with(stub, "merge") == []
        assert calls_with(stub, "pip install") == []

    def test_dependency_changes_are_called_out(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A pyproject.toml in the incoming files is why the reinstall matters."""
        stub.outcome("diff --name-only", 0, "pyproject.toml\nsrc/shadow9/cli.py\n")

        update_command()

        assert "Dependencies changed" in plain(capsys.readouterr().out)

    def test_both_versions_are_reported(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The version and commit from before and after make support calls shorter."""
        update_command()

        out = plain(capsys.readouterr().out)
        assert "1.2.3" in out
        assert OLD_COMMIT[:8] in out
        assert NEW_COMMIT[:8] in out


class TestFastForward:
    """The destructive form is asked for, not the default."""

    def test_default_update_does_not_force(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A fast forward cannot lose a commit, so it is what runs by default."""
        update_command()

        assert calls_with(stub, "merge --ff-only origin/main")
        assert calls_with(stub, "reset --hard") == []

    def test_force_resets_to_the_remote_branch(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """--force is the only way to get the reset that discards local commits."""
        update_command(force=True)

        assert calls_with(stub, "reset --hard origin/main")
        assert calls_with(stub, "merge") == []

    def test_the_tracked_branch_is_used_when_there_is_one(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A checkout tracking another branch updates from that branch."""
        stub.outcome("symbolic-full-name", 0, "origin/testing\n")
        stub.outcome("rev-parse origin/testing", 0, f"{NEW_COMMIT}\n")

        update_command()

        assert calls_with(stub, "merge --ff-only origin/testing")

    def test_a_fast_forward_that_fails_explains_force(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Diverged history stops the update and names the flag that would fix it."""
        stub.outcome("merge --ff-only", 1, "", "not possible to fast-forward")

        with pytest.raises(typer.Exit):
            update_command()

        assert "--force" in plain(capsys.readouterr().out)
        assert calls_with(stub, "pip install") == []


class TestFailedUpdate:
    """A failure stops the update rather than carrying on to the restart."""

    def test_failed_fetch_never_reaches_the_server(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A network failure costs no downtime because nothing is stopped first."""
        running_service(stub, tools)
        stub.outcome("fetch --all", 128, "", "could not resolve host github.com")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, "systemctl stop") == []
        assert calls_with(stub, "merge") == []

    def test_failed_pull_does_not_reinstall(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A merge that fails leaves the old code, so nothing is installed over it."""
        stub.outcome("merge --ff-only", 1, "", "not possible to fast-forward")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, "pip install") == []

    def test_failed_pull_starts_the_service_it_stopped(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """The proxy is put back rather than left down by a failed update."""
        running_service(stub, tools)
        stub.outcome("merge --ff-only", 1, "", "not possible to fast-forward")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, f"systemctl start {SERVICE_NAME}")

    def test_service_that_will_not_stop_leaves_the_checkout_alone(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Nothing is pulled while the old server still holds the port."""
        tools.add("systemctl")
        stub.outcome("is-active", 0, "active\n")
        stub.outcome("systemctl stop", 1, "", "interactive authentication required")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, "merge") == []
        assert calls_with(stub, "reset --hard") == []


class TestRollback:
    """A bad update is recoverable without the operator knowing any git."""

    def test_the_commit_is_recorded_where_it_survives(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """The commit is written to disk, so a later run can still find it."""
        update_command()

        record = json.loads(utils._update_record_path(repo).read_text(encoding="utf-8"))
        assert record["commit"] == OLD_COMMIT
        assert record["version"] == "1.2.3"

    def test_a_recorded_commit_reads_back(self, repo: Path) -> None:
        """What was written is what a later process reads."""
        utils._write_update_record(repo, OLD_COMMIT, "1.2.3")

        record = utils._read_update_record(repo)
        assert record is not None
        assert record.commit == OLD_COMMIT
        assert record.version == "1.2.3"

    def test_failed_install_rolls_back_to_the_recorded_commit(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """New code that will not install is undone instead of left in place."""
        running_service(stub, tools)
        stub.outcome("pip install", 1, "", "no matching distribution found for h11>=0.16.0")

        with pytest.raises(typer.Exit):
            update_command()

        assert position_of(stub, "merge --ff-only") < position_of(
            stub, f"reset --hard {OLD_COMMIT}"
        )
        assert calls_with(stub, f"systemctl start {SERVICE_NAME}")

    def test_a_server_that_does_not_come_back_is_rolled_back(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Updated but not serving is treated as a failed update, not a success."""
        running_service(stub, tools)
        serving_fails(monkeypatch)

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, f"reset --hard {OLD_COMMIT}")

    def test_rollback_flag_returns_to_the_recorded_commit(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """--rollback stops the server, goes back, reinstalls and starts it again."""
        running_service(stub, tools)
        utils._write_update_record(repo, OLD_COMMIT, "1.2.3")

        update_command(rollback=True)

        assert calls_with(stub, "fetch") == []
        assert position_of(stub, f"systemctl stop {SERVICE_NAME}") < position_of(
            stub, f"reset --hard {OLD_COMMIT}"
        )
        assert position_of(stub, "pip install") < position_of(
            stub, f"systemctl start {SERVICE_NAME}"
        )

    def test_rollback_without_a_record_changes_nothing(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """An install that has never updated has nothing to go back to."""
        with pytest.raises(typer.Exit):
            update_command(rollback=True)

        assert stub.calls == []

    def test_rollback_is_not_combined_with_the_other_modes(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Asking to go back and to update at once is refused rather than guessed."""
        with pytest.raises(typer.Exit):
            update_command(check=True, rollback=True)

        assert stub.calls == []


class TestRestartMode:
    """Whatever was stopped is what has to come back."""

    def test_service_is_stopped_then_started_again(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A systemd server is stopped before the pull and started after the install."""
        running_service(stub, tools)

        update_command()

        assert position_of(stub, f"systemctl stop {SERVICE_NAME}") < position_of(stub, "merge")
        assert position_of(stub, "pip install") < position_of(
            stub, f"systemctl start {SERVICE_NAME}"
        )

    def test_standalone_server_is_not_restarted_as_a_service(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """A server started by hand comes back the same way it went down."""
        tools.add("pgrep")
        stub.outcome("pgrep", 0, "4242\n")

        update_command()

        assert calls_with(stub, "kill 4242")
        assert calls_with(stub, "systemctl") == []
        assert len(stub.launched) == 1
        assert stub.launched[0][-2:] == ["socks5", "serve"]

    def test_standalone_restart_uses_the_checkout_script(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """The launcher in the checkout is preferred over the installed entry point."""
        script = repo / ("shadow9.bat" if sys.platform == "win32" else "shadow9")
        script.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        tools.add("pgrep")
        stub.outcome("pgrep", 0, "4242\n")

        update_command()

        assert stub.launched == [[str(script), "socks5", "serve"]]

    def test_nothing_running_means_nothing_to_restart(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Without systemctl or pgrep the update still runs and starts no server."""
        update_command()

        assert calls_with(stub, "merge --ff-only origin/main")
        assert calls_with(stub, "systemctl") == []
        assert stub.launched == []

    def test_a_running_wireguard_listener_restarts_after_reinstall(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        tools.add("systemctl")
        stub.outcome("shadow9-wireguard.service", 0, "active\n")

        update_command()

        restart = calls_with(stub, "systemctl restart shadow9-wireguard.service")
        assert restart
        assert position_of(stub, "pip install") < position_of(
            stub, "systemctl restart shadow9-wireguard.service"
        )

    def test_a_failed_wireguard_restart_rolls_back_and_restarts_the_listener(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        tools.add("systemctl")
        stub.outcome("shadow9-wireguard.service", 0, "active\n")
        stub.outcome("shadow9-wireguard.service", 1, stderr="restart failed")
        stub.outcome("shadow9-wireguard.service", 0)

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, f"reset --hard {OLD_COMMIT}")
        assert len(calls_with(stub, "systemctl restart shadow9-wireguard.service")) == 2


class TestServingCheck:
    """A service that was asked to start is not the same as a proxy that serves."""

    def test_a_listening_port_is_seen(self) -> None:
        """An accepted connection is the signal that something is there."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

            assert asyncio.run(probe._something_is_listening("127.0.0.1", port)) is True

    def test_a_closed_port_is_not_seen(self) -> None:
        """A refused connection proves the proxy is not serving."""
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]

        assert asyncio.run(probe._something_is_listening("127.0.0.1", port)) is False

    def test_waiting_stops_at_the_first_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A proxy that is already up is not waited on."""

        async def listening(host: str, port: int) -> bool:
            return True

        monkeypatch.setattr(probe, "_something_is_listening", listening)

        assert wait_until_serving("127.0.0.1", 1080) is True

    def test_waiting_gives_up_when_nothing_answers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The wait is bounded, so a dead proxy is reported rather than hung on."""

        async def listening(host: str, port: int) -> bool:
            return False

        monkeypatch.setattr(probe, "_something_is_listening", listening)

        assert wait_until_serving("127.0.0.1", 1080, timeout_seconds=0.0) is False

    def test_the_serving_address_is_reported(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The operator is told where the proxy came back, not just that it started."""
        running_service(stub, tools)
        host, port = utils._configured_address(repo)

        update_command()

        assert f"{host}:{port}" in plain(capsys.readouterr().out)


class TestDependencies:
    """A pull installs no packages, so the update has to install them itself."""

    def test_install_uses_the_running_interpreter(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Packages land in the checkout environment that will run the server."""
        update_command()

        assert [
            str(utils._venv_python(repo)),
            "-m",
            "pip",
            "install",
            "-e",
            ".",
            "-q",
        ] in stub.calls

    def test_an_unsupported_python_stops_before_local_work_is_discarded(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """The incoming floor is checked while the checkout and server are untouched."""
        stub.outcome(
            "show origin/main:pyproject.toml",
            0,
            '[project]\nrequires-python = ">=99.0"\n',
        )
        stub.outcome("status --porcelain", 0, " M setup\n")

        with pytest.raises(typer.Exit):
            update_command(force=True)

        assert calls_with(stub, "status --porcelain") == []
        assert calls_with(stub, "reset --hard") == []
        assert calls_with(stub, "systemctl stop") == []

    def test_install_retries_for_a_distro_managed_interpreter(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Debian's split-out venv support is installed before creation is retried."""
        utils._venv_python(repo).unlink()
        tools.add("apt-get")
        stub.outcome("-m venv", 1, "", "ensurepip is not available")
        stub.outcome("-m venv", 0)

        update_command()

        assert calls_with(stub, "apt-get install -y python3-venv")
        assert len(calls_with(stub, "-m venv")) == 2
        assert calls_with(stub, "--break-system-packages") == []

    def test_a_failed_venv_install_does_not_write_to_the_system_interpreter(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """PEP 668 remains intact even when dependency installation fails."""
        stub.outcome("pip install", 1, "", "externally-managed-environment")

        with pytest.raises(typer.Exit):
            update_command()

        assert calls_with(stub, "--break-system-packages") == []

    def test_an_existing_service_is_moved_to_the_checkout_wrapper(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """The service enters through the wrapper so it uses the same venv as the command."""
        service_file = Path(utils.SERVICE_FILE)
        service_file.write_text(
            f"WorkingDirectory={repo}\n"
            "ExecStart=/usr/bin/python3 -m shadow9.cli serve --host 127.0.0.1 --port 1080\n",
            encoding="utf-8",
        )

        update_command()

        unit = service_file.read_text(encoding="utf-8")
        assert f"ExecStart={repo / 'shadow9'} socks5 serve --host 127.0.0.1 --port 1080" in unit
        assert calls_with(stub, "systemctl daemon-reload")

    def test_install_happens_after_the_pull(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """New dependencies come from the pulled pyproject.toml, so order matters."""
        update_command()

        assert position_of(stub, "merge --ff-only") < position_of(stub, "pip install")


class TestWithoutACheckout:
    """A wheel install has no repository to pull from."""

    def test_missing_checkout_changes_nothing(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The operator is told where to clone from and no command is run."""

        def find_repo_root() -> Path | None:
            return None

        monkeypatch.setattr(utils, "_find_repo_root", find_repo_root)

        with pytest.raises(typer.Exit):
            update_command()

        assert stub.calls == []
        assert "shadow9-manager" in plain(capsys.readouterr().out)

    def test_missing_git_changes_nothing(
        self,
        update_command: Callable[..., None],
        stub: StubProcess,
        tools: set[str],
        repo: Path,
    ) -> None:
        """Without the git program the command stops before touching anything."""
        tools.discard("git")

        with pytest.raises(typer.Exit):
            update_command()

        assert stub.calls == []


class TestPrivilege:
    """systemctl needs root, and a password prompt nobody can see would hang."""

    def test_root_runs_systemctl_directly(
        self, tools: set[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Already being root means sudo is not involved at all."""
        tools.add("sudo")

        def geteuid() -> int:
            return 0

        monkeypatch.setattr(utils.os, "geteuid", geteuid, raising=False)

        assert utils.privileged(["systemctl", "stop", SERVICE_NAME]) == [
            "systemctl",
            "stop",
            SERVICE_NAME,
        ]

    def test_other_users_get_a_sudo_that_cannot_block(
        self, tools: set[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sudo -n fails straight away instead of waiting on an invisible prompt."""
        tools.add("sudo")

        def geteuid() -> int:
            return 1000

        monkeypatch.setattr(utils.os, "geteuid", geteuid, raising=False)

        assert utils.privileged(["systemctl", "stop", SERVICE_NAME])[:2] == ["sudo", "-n"]

    def test_a_box_without_sudo_runs_the_command_as_it_is(
        self, tools: set[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No sudo binary means the command is tried directly rather than crashing."""

        def geteuid() -> int:
            return 1000

        monkeypatch.setattr(utils.os, "geteuid", geteuid, raising=False)

        assert utils.privileged(["systemctl", "start", SERVICE_NAME]) == [
            "systemctl",
            "start",
            SERVICE_NAME,
        ]
