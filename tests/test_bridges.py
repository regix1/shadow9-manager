import asyncio
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from shadow9 import bridges as bridge_module
from shadow9.bridge_list import Bridge, BridgeType
from shadow9.bridges import BridgeConfig, TorBridgeConnector


class _SlowProcess:
    def __init__(self) -> None:
        self.stdout = None
        self.stderr = None
        self.terminated = False
        self.killed = False
        self.reaped = False
        self.wait_calls = 0

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def poll(self) -> int | None:
        return -9 if self.reaped else None

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if not self.killed:
            time.sleep(0.12)
            raise subprocess.TimeoutExpired(
                "tor", timeout if timeout is not None else 0.0
            )
        self.reaped = True
        return -9

    def communicate(self, timeout: float | None = None) -> tuple[bytes, None]:
        return b"", None


@pytest.mark.asyncio
@pytest.mark.parametrize("method_name", ["_cleanup_tor", "stop"])
async def test_stopping_tor_keeps_the_loop_running_and_reaps_after_kill(
    method_name: str,
) -> None:
    connector = TorBridgeConnector(BridgeConfig())
    process = _SlowProcess()
    connector._tor_process = cast(subprocess.Popen, process)
    ticks = 0
    stop_heartbeat = asyncio.Event()

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop_heartbeat.is_set():
            await asyncio.sleep(0.01)
            ticks += 1

    beat = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)
    try:
        await getattr(connector, method_name)()
    finally:
        stop_heartbeat.set()
        await beat

    assert ticks >= 5
    assert process.terminated
    assert process.killed
    assert process.reaped
    assert process.wait_calls == 2


@pytest.mark.asyncio
async def test_quick_test_cleanup_keeps_the_loop_running_and_reaps_after_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = TorBridgeConnector(BridgeConfig(bridge_type=BridgeType.SNOWFLAKE))
    process = _SlowProcess()
    files: dict[str, str] = {}

    class _MemoryPath:
        def __init__(self, value: str) -> None:
            self.value = value

        def __truediv__(self, name: str) -> "_MemoryPath":
            return _MemoryPath(f"{self.value}/{name}")

        def __str__(self) -> str:
            return self.value

        def write_text(self, content: str) -> int:
            files[self.value] = content
            return len(content)

        def read_text(self) -> str:
            return files[self.value]

        def exists(self) -> bool:
            return self.value in files

    def generate_torrc(
        data_dir: Path,
        socks_port: int,
        specific_bridge: Bridge | None = None,
    ) -> str:
        del data_dir, socks_port, specific_bridge
        return ""

    def find_tor(name: str) -> str:
        assert name == "tor"
        return "tor"

    def start_tor(
        command: list[str], *, stdout: int, stderr: int
    ) -> _SlowProcess:
        del stdout, stderr
        root = command[2].rsplit("/", 1)[0]
        files[f"{root}/tor.log"] = "Bootstrapped 15%\n"
        return process

    class _TestDirectory:
        def __init__(self, prefix: str) -> None:
            del prefix
            self.name = "test-root"

        def cleanup(self) -> None:
            files.clear()

    monkeypatch.setattr(connector.pt_manager, "generate_torrc", generate_torrc)
    monkeypatch.setattr(bridge_module.shutil, "which", find_tor)
    monkeypatch.setattr(bridge_module, "Path", _MemoryPath)
    monkeypatch.setattr(
        bridge_module,
        "subprocess",
        SimpleNamespace(
            Popen=start_tor,
            PIPE=subprocess.PIPE,
            STDOUT=subprocess.STDOUT,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(
        bridge_module,
        "tempfile",
        SimpleNamespace(TemporaryDirectory=_TestDirectory),
    )

    ticks = 0
    stop_heartbeat = asyncio.Event()

    async def heartbeat() -> None:
        nonlocal ticks
        while not stop_heartbeat.is_set():
            await asyncio.sleep(0.01)
            ticks += 1

    bridge = Bridge(
        type=BridgeType.SNOWFLAKE,
        address="192.0.2.1:1",
        fingerprint="",
        params={"front": "bridge.example"},
    )
    beat = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)
    try:
        speed, error = await connector._quick_bridge_test(bridge, 1, 15)
    finally:
        stop_heartbeat.set()
        await beat

    assert speed is not None, error
    assert error is None
    assert ticks >= 5
    assert process.terminated
    assert process.killed
    assert process.reaped
    assert process.wait_calls == 2


@pytest.mark.asyncio
async def test_bridge_selection_has_a_deadline_and_releases_the_shared_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bridge_module, "BRIDGE_SELECTION_TIMEOUT_SECONDS", 0.05, raising=False
    )
    slow_connector = TorBridgeConnector(
        BridgeConfig(bridge_type=BridgeType.SNOWFLAKE)
    )
    fast_connector = TorBridgeConnector(BridgeConfig(bridge_type=BridgeType.OBFS4))
    slow_bridges = [
        Bridge(
            type=BridgeType.SNOWFLAKE,
            address=f"192.0.2.{index + 1}:1",
            fingerprint="",
            params={"front": f"bridge-{index}.example"},
        )
        for index in range(14)
    ]
    fast_bridge = Bridge(
        type=BridgeType.OBFS4,
        address="198.51.100.1:1",
        fingerprint="",
    )
    never_finishes = asyncio.Event()
    first_test_started = asyncio.Event()
    running = 0
    max_running = 0
    started = 0
    cancelled = 0

    async def hanging_test(
        bridge: Bridge,
        timeout: float,
        target_progress: int,
        show_config: bool = False,
    ) -> tuple[float | None, str | None]:
        del bridge, timeout, target_progress, show_config
        nonlocal running, max_running, started, cancelled
        running += 1
        started += 1
        max_running = max(max_running, running)
        first_test_started.set()
        try:
            await never_finishes.wait()
            return None, None
        except asyncio.CancelledError:
            cancelled += 1
            raise
        finally:
            running -= 1

    async def working_test(
        bridge: Bridge,
        timeout: float,
        target_progress: int,
        show_config: bool = False,
    ) -> tuple[float | None, str | None]:
        del bridge, timeout, target_progress, show_config
        return 0.01, None

    monkeypatch.setattr(slow_connector, "_quick_bridge_test", hanging_test)
    monkeypatch.setattr(fast_connector, "_quick_bridge_test", working_test)

    selection_lock = asyncio.Lock()

    async def select(
        connector: TorBridgeConnector, bridges: list[Bridge]
    ) -> list[tuple[Bridge, float | None]]:
        async with selection_lock:
            return await connector._test_bridge_speeds(bridges)

    started_at = asyncio.get_running_loop().time()
    slow_selection = asyncio.create_task(select(slow_connector, slow_bridges))
    await asyncio.wait_for(first_test_started.wait(), timeout=0.2)
    fast_selection = asyncio.create_task(select(fast_connector, [fast_bridge]))
    slow_results, fast_results = await asyncio.wait_for(
        asyncio.gather(slow_selection, fast_selection), timeout=0.5
    )
    elapsed = asyncio.get_running_loop().time() - started_at

    assert elapsed < 0.3
    assert len(slow_results) == 14
    assert all(speed is None for _, speed in slow_results)
    assert fast_results == [(fast_bridge, 0.01)]
    assert started == cancelled
    assert 1 < max_running <= 2


@pytest.mark.asyncio
async def test_bridge_selection_stops_after_enough_working_choices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = TorBridgeConnector(BridgeConfig(bridge_type=BridgeType.SNOWFLAKE))
    bridges = [
        Bridge(
            type=BridgeType.SNOWFLAKE,
            address=f"203.0.113.{index + 1}:1",
            fingerprint="",
            params={"front": f"working-{index}.example"},
        )
        for index in range(14)
    ]
    calls = 0
    running = 0
    max_running = 0

    async def working_test(
        bridge: Bridge,
        timeout: float,
        target_progress: int,
        show_config: bool = False,
    ) -> tuple[float | None, str | None]:
        del bridge, timeout, target_progress, show_config
        nonlocal calls, running, max_running
        calls += 1
        running += 1
        max_running = max(max_running, running)
        await asyncio.sleep(0)
        running -= 1
        return 0.01, None

    monkeypatch.setattr(connector, "_quick_bridge_test", working_test)

    results = await connector._test_bridge_speeds(bridges)
    working = sum(speed is not None for _, speed in results)

    assert 3 <= working <= 4
    assert calls < len(bridges)
    assert max_running == 2
