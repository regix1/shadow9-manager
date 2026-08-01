"""
Finding out what is listening on a port, and stopping it when asked.

Shared by the CLI and the API status reports, and by the stop commands. It lives in one
place because there were four ways to ask whether something was listening, and because a
stop that kills whoever holds a port has taken down unrelated programs.
"""

import asyncio
import subprocess
import sys
from typing import NamedTuple

from ..core.logging import get_logger


logger = get_logger(__name__)

# A status probe must answer quickly even when the configured host drops packets.
PROBE_TIMEOUT = 1.0


class PortHolder(NamedTuple):
    """The process listening on a port, and whether it looks like one of ours."""

    pid: int
    name: str
    looks_like_shadow9: bool


async def _something_is_listening(host: str, port: int) -> bool:
    """Return whether a TCP connection is accepted at the configured address."""
    probe_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host

    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(probe_host, port), timeout=PROBE_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as error:
        logger.debug(
            "Configured service did not accept a probe connection",
            host=probe_host,
            port=port,
            error=str(error),
        )
        return False

    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        pass
    return True


def listener_on_port(port: int) -> PortHolder | None:
    """
    Find the process listening on exactly this port.

    The port is compared as a number rather than as text. Matching the string ":1080"
    against a netstat line also matches ":10801", which is a different service, and that
    is how a stop command reached the wrong process.

    Args:
        port: The TCP port to look for

    Returns:
        The listening process, or None when nothing holds the port
    """
    pid = _listening_pid(port)
    if pid is None:
        return None
    name = process_name(pid)
    return PortHolder(pid, name, "shadow9" in name.lower() or "python" in name.lower())


def _listening_pid(port: int) -> int | None:
    """Ask the platform which process is listening on a port."""
    if sys.platform == "win32":
        try:
            result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError):
            return None
        for line in result.stdout.splitlines():
            parts = line.split()
            # proto, local address, foreign address, state, pid
            if len(parts) < 5 or parts[3] != "LISTENING":
                continue
            _, _, local_port = parts[1].rpartition(":")
            if local_port.isdigit() and int(local_port) == port and parts[4].isdigit():
                return int(parts[4])
        return None

    try:
        result = subprocess.run(["lsof", "-t", f"-i:{port}"], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return None
    found = [entry for entry in result.stdout.split() if entry.isdigit()]
    return int(found[0]) if found else None


def process_name(pid: int) -> str:
    """Best effort name for a pid, so the operator is told what they are about to stop."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
            )
            first = result.stdout.strip().splitlines()[:1]
            return first[0].split(",")[0].strip('"') if first else "unknown"
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unknown"


def terminate(pid: int) -> bool:
    """Ask a process to stop, and say whether the request was accepted."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(pid)], capture_output=True, text=True
            )
        else:
            result = subprocess.run(["kill", str(pid)], capture_output=True, text=True)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def pids_matching(pattern: str) -> list[int]:
    """
    Find processes by what they are running rather than by what port they hold.

    Identity is the safe way to find something to stop. A port tells you who is there,
    not whether it is yours.

    Args:
        pattern: A pgrep -f pattern, matched against the whole command line

    Returns:
        The matching pids, empty on Windows or when pgrep is absent
    """
    if sys.platform == "win32":
        return []
    try:
        result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return []
    return [int(entry) for entry in result.stdout.split() if entry.isdigit()]
