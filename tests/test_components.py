"""Managing Tor and the bridge transports, and telling the truth about which is which."""

import os
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


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    The assertions below name the bare systemctl call, which is what root runs.

    Anywhere else `privileged` puts sudo in front, so the same command arrives as
    ['sudo', '-n', 'systemctl', ...] and every one of those assertions misses it. Saying
    which of the two this is keeps the tests meaning the same thing on a developer's
    machine, on a build that runs as root, and on one that does not.
    """

    def root() -> int:
        return 0

    monkeypatch.setattr(os, "geteuid", root, raising=False)


class TestTheTransportsAreNotServices:
    """obfs4proxy and snowflake have no lifecycle, and saying so beats pretending."""

    @pytest.mark.parametrize("name", ["obfs4proxy", "snowflake-client"])
    @pytest.mark.parametrize("action", ["start", "stop", "restart"])
    def test_it_refuses_and_explains(self, name: str, action: str) -> None:
        result = runner.invoke(app, ["socks5", "components", action, name])

        assert result.exit_code == 1
        said = plain(result.stdout)
        assert "not a service" in said
        assert "Tor starts it" in said

    def test_it_never_calls_systemctl_for_them(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        runner.invoke(app, ["socks5", "components", "stop", "obfs4proxy"])

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

        result = runner.invoke(app, ["socks5", "components", "stop", "tor"], input="n\n")

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

        result = runner.invoke(app, ["socks5", "components", "stop", "tor", "--yes"])

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

        result = runner.invoke(app, ["socks5", "components", "stop", "tor"])

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

        result = runner.invoke(app, ["socks5", "components", "stop", "tor"])

        assert result.exit_code == 0
        assert ["systemctl", "stop", "tor"] in ran.calls

    def test_a_failed_systemctl_exits_non_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(components_commands, "units_pulling_in", lambda unit: [])
        monkeypatch.setattr(subprocess, "run", _Ran(returncode=1))

        result = runner.invoke(app, ["socks5", "components", "stop", "tor"])

        assert result.exit_code == 1


class TestBootPersistence:
    """Stopping Tor is not the same as keeping it stopped across a reboot."""

    @pytest.mark.parametrize("action", ["enable", "disable"])
    def test_it_asks_systemd(self, action: str, monkeypatch: pytest.MonkeyPatch) -> None:
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["socks5", "components", action, "tor"])

        assert result.exit_code == 0, result.stdout
        assert ["systemctl", action, "tor"] in ran.calls

    def test_disable_says_it_did_not_stop_anything(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Otherwise an operator assumes disable stopped it and walks away."""
        monkeypatch.setattr(subprocess, "run", _Ran())

        result = runner.invoke(app, ["socks5", "components", "disable", "tor"])

        assert "still running" in plain(result.stdout)

    @pytest.mark.parametrize("action", ["enable", "disable"])
    def test_the_transports_still_refuse(self, action: str) -> None:
        result = runner.invoke(app, ["socks5", "components", action, "obfs4proxy"])

        assert result.exit_code == 1
        assert "not a service" in plain(result.stdout)


class TestStartAndRestart:
    @pytest.mark.parametrize("action", ["start", "restart"])
    def test_it_asks_systemd_for_tor(self, action: str, monkeypatch: pytest.MonkeyPatch) -> None:
        ran = _Ran()
        monkeypatch.setattr(subprocess, "run", ran)

        result = runner.invoke(app, ["socks5", "components", action, "tor"])

        assert result.exit_code == 0, result.stdout
        assert ["systemctl", action, "tor"] in ran.calls


class TestTabCompletion:
    """Without a completer the shell lists files, because the script ends -o default."""

    def test_it_offers_every_component(self) -> None:
        assert components_commands.complete_component("") == [
            "tor",
            "obfs4proxy",
            "snowflake-client",
        ]

    def test_it_narrows_on_what_was_typed(self) -> None:
        assert components_commands.complete_component("t") == ["tor"]
        assert components_commands.complete_component("s") == ["snowflake-client"]

    def test_no_match_gives_nothing_rather_than_everything(self) -> None:
        assert components_commands.complete_component("zzz") == []

    @pytest.mark.parametrize("action", ["start", "stop", "restart"])
    def test_every_action_has_the_completer_attached(self, action: str) -> None:
        """A completer that exists but is not wired up is the same as none at all."""
        socks5 = next(item for item in app.registered_groups if item.name == "socks5")
        assert socks5.typer_instance is not None
        group = next(
            item for item in socks5.typer_instance.registered_groups if item.name == "components"
        )
        assert group.typer_instance is not None
        found = next(
            item for item in group.typer_instance.registered_commands if item.name == action
        )
        assert found.callback is not None
        argument = found.callback.__annotations__["name"]

        assert any(
            getattr(piece, "autocompletion", None) is components_commands.complete_component
            for piece in getattr(argument, "__metadata__", ())
        ), f"'{action}' takes a component name with no completer"


class TestNaming:
    def test_an_unknown_component_lists_the_real_ones(self) -> None:
        result = runner.invoke(app, ["socks5", "components", "start", "kettle"])

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
