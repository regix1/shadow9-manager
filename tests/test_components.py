"""Managing Tor and the bridge transports, and telling the truth about which is which."""

import re
import subprocess

import pytest
from typer.testing import CliRunner

from shadow9.cli import app
from shadow9.commands import components as components_commands


runner = CliRunner()


def plain(text: str) -> str:
    """Drop the terminal escapes so a sentence can be matched as one string."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


class _Ran:
    """Records the systemctl calls a test caused, instead of making them."""

    def __init__(self, returncode: int = 0, stdout: str = "") -> None:
        self.calls: list[list[str]] = []
        self._returncode = returncode
        self._stdout = stdout

    def __call__(self, command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        self.calls.append(command)
        return subprocess.CompletedProcess(command, self._returncode, self._stdout, "")


@pytest.fixture(autouse=True)
def _pretend_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """These commands refuse off systemd, and the point here is the behaviour on it."""
    monkeypatch.setattr(components_commands.sys, "platform", "linux")


class TestTheTransportsAreNotServices:
    """obfs4proxy and snowflake have no lifecycle, and saying so beats pretending."""

    @pytest.mark.parametrize("name", ["obfs4proxy", "snowflake-client"])
    @pytest.mark.parametrize("action", ["start", "stop", "restart"])
    def test_it_refuses_and_explains(self, name: str, action: str) -> None:
        result = runner.invoke(app, ["components", action, name])

        assert result.exit_code == 1
        said = plain(result.stdout)
        assert "not a service" in said
        assert "Tor starts it" in said

    def test_it_never_calls_systemctl_for_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        runner.invoke(app, ["components", "stop", "obfs4proxy"])

        assert ran.calls == [], "it tried to manage a binary that has no unit"


class TestStoppingTor:
    def test_it_names_what_else_depends_on_tor_and_stops_when_declined(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tor is system wide, so taking it down without warning can break the host."""
        monkeypatch.setattr(
            components_commands,
            "units_pulling_in",
            lambda unit: ["shadow9.service", "privoxy.service"],
        )
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["components", "stop", "tor"], input="n\n")

        assert result.exit_code == 1
        said = plain(result.stdout)
        assert "privoxy.service" in said
        assert ran.calls == [], "it stopped Tor after the operator declined"

    def test_yes_skips_the_question(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            components_commands, "units_pulling_in", lambda unit: ["privoxy.service"]
        )
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["components", "stop", "tor", "--yes"])

        assert result.exit_code == 0, result.stdout
        assert ["systemctl", "stop", "tor"] in ran.calls

    def test_it_warns_that_shadow9_will_pull_tor_back_up(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The unit has Wants=tor.service, so a stop looks like it failed without this."""
        monkeypatch.setattr(
            components_commands, "units_pulling_in", lambda unit: ["shadow9.service"]
        )
        monkeypatch.setattr(subprocess, "run", _Ran())

        result = runner.invoke(app, ["components", "stop", "tor"])

        assert result.exit_code == 0, result.stdout
        said = plain(result.stdout)
        assert "Wants=tor.service" in said

    def test_only_shadow9_depending_on_it_asks_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """shadow9's own dependency is not a reason to interrogate the operator."""
        monkeypatch.setattr(
            components_commands, "units_pulling_in", lambda unit: ["shadow9.service"]
        )
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["components", "stop", "tor"])

        assert result.exit_code == 0
        assert ["systemctl", "stop", "tor"] in ran.calls

    def test_a_failed_systemctl_exits_non_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(components_commands, "units_pulling_in", lambda unit: [])
        monkeypatch.setattr(subprocess, "run", _Ran(returncode=1))

        result = runner.invoke(app, ["components", "stop", "tor"])

        assert result.exit_code == 1


class TestStartAndRestart:
    @pytest.mark.parametrize("action", ["start", "restart"])
    def test_it_asks_systemd_for_tor(self, action: str, monkeypatch: pytest.MonkeyPatch) -> None:
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["components", action, "tor"])

        assert result.exit_code == 0, result.stdout
        assert ["systemctl", action, "tor"] in ran.calls


class TestNaming:
    def test_an_unknown_component_lists_the_real_ones(self) -> None:
        result = runner.invoke(app, ["components", "start", "kettle"])

        assert result.exit_code == 1
        said = plain(result.stdout)
        assert "tor" in said and "obfs4proxy" in said and "snowflake-client" in said

    def test_reverse_dependencies_drop_the_unit_itself(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """systemctl lists the unit it was asked about, which is not a dependent."""
        listing = "tor.service\nshadow9.service\nprivoxy.service\n"
        monkeypatch.setattr(subprocess, "run", _Ran(stdout=listing))

        found = components_commands.units_pulling_in("tor.service")

        assert "tor.service" not in found
        assert found == ["shadow9.service", "privoxy.service"]
