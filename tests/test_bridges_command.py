"""Seeing which bridges exist and whether their transports will run."""

import re

import pytest
from typer.testing import CliRunner

from shadow9.bridge_list import BridgeType
from shadow9.cli import app
from shadow9.commands import bridges as bridge_commands


runner = CliRunner()


def plain(text: str) -> str:
    """Drop the terminal escapes so a sentence can be matched as one string."""
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


@pytest.fixture(autouse=True)
def _no_transports(monkeypatch: pytest.MonkeyPatch) -> None:
    """Detection shells out, and these tests are about the commands, not the host."""
    monkeypatch.setattr(bridge_commands, "_transport_paths", lambda: {})


class TestNaming:
    def test_only_types_that_have_bridges_are_offered(self) -> None:
        """NONE is a direct connection, so it has no bridges and nothing to check."""
        assert bridge_commands.complete_bridge_type("") == ["obfs4", "snowflake"]
        assert BridgeType.NONE not in bridge_commands.CATALOG

    def test_completion_narrows_on_what_was_typed(self) -> None:
        assert bridge_commands.complete_bridge_type("s") == ["snowflake"]
        assert bridge_commands.complete_bridge_type("zzz") == []

    def test_an_unknown_type_lists_the_real_ones(self) -> None:
        result = runner.invoke(app, ["bridges", "show", "kettle"])

        assert result.exit_code == 1
        said = plain(result.stdout)
        assert "obfs4" in said and "snowflake" in said

    def test_none_is_rejected_rather_than_shown_empty(self) -> None:
        """'none' is a real BridgeType but has no bridges, so it must not silently work."""
        result = runner.invoke(app, ["bridges", "show", "none"])

        assert result.exit_code == 1


class TestList:
    def test_it_counts_the_bridges_of_each_type(self) -> None:
        result = runner.invoke(app, ["bridges", "list"])

        assert result.exit_code == 0, result.stdout
        said = plain(result.stdout)
        assert "obfs4" in said and "snowflake" in said

    def test_a_missing_transport_is_called_out(self) -> None:
        result = runner.invoke(app, ["bridges", "list"])

        assert "not installed" in plain(result.stdout)

    def test_an_installed_transport_shows_its_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            bridge_commands,
            "_transport_paths",
            lambda: {BridgeType.OBFS4: "/usr/bin/obfs4proxy"},
        )

        result = runner.invoke(app, ["bridges", "list"])

        assert "/usr/bin/obfs4proxy" in plain(result.stdout)

    def test_one_type_can_be_asked_for_on_its_own(self) -> None:
        result = runner.invoke(app, ["bridges", "list", "--type", "snowflake"])

        assert result.exit_code == 0, result.stdout
        said = plain(result.stdout)
        assert "snowflake" in said
        assert "obfs4" not in said


class TestShow:
    def test_it_prints_a_line_per_bridge(self) -> None:
        result = runner.invoke(app, ["bridges", "show", "obfs4"])

        assert result.exit_code == 0, result.stdout
        lines = [line for line in plain(result.stdout).splitlines() if line.strip()]
        assert len(lines) == len(bridge_commands.CATALOG[BridgeType.OBFS4])

    def test_the_lines_are_torrc_bridge_lines(self) -> None:
        result = runner.invoke(app, ["bridges", "show", "snowflake"])

        assert plain(result.stdout).lstrip().startswith("Bridge ")


class TestCheck:
    def test_a_working_transport_exits_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            bridge_commands, "_transport_paths", lambda: {BridgeType.OBFS4: "/usr/bin/obfs4proxy"}
        )

        async def available(self: object, bridge_type: BridgeType) -> bool:
            return True

        from shadow9 import bridges as bridges_module

        monkeypatch.setattr(
            bridges_module.PluggableTransportManager, "check_transport_available", available
        )

        result = runner.invoke(app, ["bridges", "check", "obfs4"])

        assert result.exit_code == 0, result.stdout
        assert "works" in plain(result.stdout)

    def test_a_missing_transport_exits_non_zero_with_instructions(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A red line is not enough for a script to notice."""

        async def unavailable(self: object, bridge_type: BridgeType) -> bool:
            return False

        from shadow9 import bridges as bridges_module

        monkeypatch.setattr(
            bridges_module.PluggableTransportManager, "check_transport_available", unavailable
        )

        result = runner.invoke(app, ["bridges", "check", "snowflake"])

        assert result.exit_code == 1
        assert "not usable" in plain(result.stdout)
