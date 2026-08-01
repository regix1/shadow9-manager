"""Undo what --install-completion wrote.

Typer installs shell completion but offers no way to take it back out, so an operator who
tried it is left editing dotfiles by hand. This removes the parts that belong to one
program and deliberately leaves the parts that do not.
"""

from pathlib import Path


class CompletionRemoval:
    """What removing the completion did, and what it deliberately left alone."""

    def __init__(self) -> None:
        self.removed: list[str] = []
        self.notes: list[str] = []

    @property
    def found_anything(self) -> bool:
        """Whether there was any completion to remove."""
        return bool(self.removed)


def completion_files(prog_name: str, home: Path) -> list[Path]:
    """
    The per-program files that --install-completion writes, one per shell.

    Each is named after the program, so removing one cannot affect another tool. The
    paths mirror typer's own installers.

    Args:
        prog_name: The command name, as typer knows it
        home: The home directory to look in

    Returns:
        Every path that might hold this program's completion
    """
    return [
        home / ".bash_completions" / f"{prog_name}.sh",
        home / ".zfunc" / f"_{prog_name}",
        home / ".config" / "fish" / "completions" / f"{prog_name}.fish",
    ]


def remove_completion(prog_name: str, home: Path | None = None) -> CompletionRemoval:
    """
    Remove this program's shell completion from the shells that have it.

    Every shell is checked rather than only the current one, because completion may have
    been installed from a shell the operator is no longer using, and the files are named
    after the program so there is nothing to guess at.

    Two things are left alone on purpose. The `fpath+=~/.zfunc` and `compinit` lines that
    zsh installation adds to .zshrc are shared by every typer program, so removing them
    would take tab completion away from other tools. PowerShell installation appends the
    script to the user profile with no marker around it, so there is no way to find the
    end of it reliably, and a wrong guess edits a file the operator wrote themselves.

    Args:
        prog_name: The command name, as typer knows it
        home: The home directory to work in, or None for the real one

    Returns:
        What was removed and what was left
    """
    home = home if home is not None else Path.home()
    result = CompletionRemoval()

    for path in completion_files(prog_name, home):
        if path.is_file():
            path.unlink()
            result.removed.append(str(path))

    bash_script = home / ".bash_completions" / f"{prog_name}.sh"
    bashrc = home / ".bashrc"
    if bashrc.is_file():
        source_line = f"source '{bash_script}'"
        lines = bashrc.read_text(encoding="utf-8").splitlines()
        kept = [line for line in lines if line.strip() != source_line]
        if len(kept) != len(lines):
            bashrc.write_text("\n".join(kept) + "\n", encoding="utf-8")
            result.removed.append(f"{bashrc} (the line sourcing {bash_script.name})")

    if (home / ".zshrc").is_file():
        result.notes.append(
            "Left the fpath and compinit lines in .zshrc alone, because every program "
            "installed this way shares them."
        )

    profile = home / "Documents" / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1"
    if profile.is_file():
        result.notes.append(
            f"If completion was installed for PowerShell, its script was appended to "
            f"{profile} and has to come out by hand. It is the block mentioning "
            f"{prog_name}."
        )

    return result
