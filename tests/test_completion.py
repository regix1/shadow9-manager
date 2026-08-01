"""Removing shell completion takes out this program's files and nothing else."""

import re
from pathlib import Path

from typer.testing import CliRunner

from shadow9.cli import app
from shadow9.completion import remove_completion


runner = CliRunner()


def plain(text: str) -> str:
    """
    Drop the terminal escapes so a flag can be matched as one string.

    Rich colours its output whenever the run looks like a terminal, which a CI job does,
    and it puts the escapes inside the flag name rather than around it.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _installed_bash(home: Path) -> Path:
    """Write what typer's bash installer writes, so removal has something real to undo."""
    script = home / ".bash_completions" / "shadow9.sh"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("_shadow9_completion() { :; }\n", encoding="utf-8")
    (home / ".bashrc").write_text(
        f"export PATH=$PATH:/usr/local/bin\nsource '{script}'\nalias ll='ls -l'\n",
        encoding="utf-8",
    )
    return script


class TestRemoval:
    def test_the_bash_script_and_its_source_line_both_go(self, tmp_path: Path) -> None:
        script = _installed_bash(tmp_path)

        result = remove_completion("shadow9", home=tmp_path)

        assert script.exists() is False
        assert f"source '{script}'" not in (tmp_path / ".bashrc").read_text()
        assert result.found_anything is True

    def test_the_rest_of_bashrc_is_untouched(self, tmp_path: Path) -> None:
        """Only the one line typer added comes out, not the operator's own setup."""
        _installed_bash(tmp_path)

        remove_completion("shadow9", home=tmp_path)

        kept = (tmp_path / ".bashrc").read_text()
        assert "export PATH=$PATH:/usr/local/bin" in kept
        assert "alias ll='ls -l'" in kept

    def test_zsh_and_fish_files_go_too(self, tmp_path: Path) -> None:
        zfunc = tmp_path / ".zfunc" / "_shadow9"
        zfunc.parent.mkdir(parents=True)
        zfunc.write_text("#compdef shadow9\n", encoding="utf-8")
        fish = tmp_path / ".config" / "fish" / "completions" / "shadow9.fish"
        fish.parent.mkdir(parents=True)
        fish.write_text("complete --command shadow9\n", encoding="utf-8")

        remove_completion("shadow9", home=tmp_path)

        assert zfunc.exists() is False
        assert fish.exists() is False

    def test_another_programs_completion_is_left_alone(self, tmp_path: Path) -> None:
        """The files are named after the program, so removal cannot reach past its own."""
        other = tmp_path / ".zfunc" / "_kubectl"
        other.parent.mkdir(parents=True)
        other.write_text("#compdef kubectl\n", encoding="utf-8")

        remove_completion("shadow9", home=tmp_path)

        assert other.exists() is True

    def test_the_shared_zshrc_lines_stay(self, tmp_path: Path) -> None:
        """Every typer program shares these, so taking them out breaks other tools."""
        shared = "fpath+=~/.zfunc; autoload -Uz compinit; compinit\n"
        (tmp_path / ".zshrc").write_text(shared, encoding="utf-8")
        zfunc = tmp_path / ".zfunc" / "_shadow9"
        zfunc.parent.mkdir(parents=True)
        zfunc.write_text("#compdef shadow9\n", encoding="utf-8")

        result = remove_completion("shadow9", home=tmp_path)

        assert (tmp_path / ".zshrc").read_text() == shared
        assert any("compinit" in note for note in result.notes)

    def test_removing_when_nothing_is_installed_says_so(self, tmp_path: Path) -> None:
        result = remove_completion("shadow9", home=tmp_path)

        assert result.found_anything is False
        assert result.removed == []

    def test_a_bashrc_without_the_line_is_not_rewritten(self, tmp_path: Path) -> None:
        """Nothing to remove means the file is left exactly as it was, byte for byte."""
        original = "export PATH=$PATH:/usr/local/bin\n"
        (tmp_path / ".bashrc").write_text(original, encoding="utf-8")

        remove_completion("shadow9", home=tmp_path)

        assert (tmp_path / ".bashrc").read_text() == original


def test_it_undoes_what_typer_itself_installs(tmp_path: Path, monkeypatch) -> None:
    """Drive typer's own installer, then remove it.

    The other tests write what typer is believed to write. This one lets typer write it,
    so if a future version moves the script or changes the line it adds to .bashrc, this
    fails instead of the removal quietly missing.
    """
    from typer._completion_shared import install_bash

    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    installed = install_bash(
        prog_name="shadow9", complete_var="_SHADOW9_COMPLETE", shell="bash"
    )
    assert installed.is_file(), "typer did not install where this test expected"
    assert str(installed) in (tmp_path / ".bashrc").read_text()

    result = remove_completion("shadow9", home=tmp_path)

    assert installed.exists() is False
    assert str(installed) not in (tmp_path / ".bashrc").read_text()
    assert len(result.removed) == 2


class TestTheOption:
    def test_the_flag_is_offered(self) -> None:
        result = runner.invoke(app, ["--help"])

        assert result.exit_code == 0
        assert "--remove-completion" in plain(result.stdout)

    def test_it_reports_when_there_was_nothing_to_remove(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["--remove-completion"])

        assert result.exit_code == 0, result.stdout
        assert "No shell completion is installed" in result.stdout

    def test_it_reports_what_it_removed(self, tmp_path: Path, monkeypatch) -> None:
        _installed_bash(tmp_path)
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["--remove-completion"])

        assert result.exit_code == 0, result.stdout
        assert "Removed" in result.stdout
        assert (tmp_path / ".bash_completions" / "shadow9.sh").exists() is False
