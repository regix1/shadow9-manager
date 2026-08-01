"""Tests for reading the memory this process may use, and sizing hashing under it.

The cgroup files are written by hand under tmp_path rather than read from a real
machine, so the walk up the tree is exercised on every platform including the one this
is developed on, which mounts no cgroups at all.
"""

import shutil
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from shadow9 import memory_budget
from shadow9.memory_budget import (
    MIB,
    HEADROOM_FRACTION,
    INTERPRETER_RESERVE,
    MAX_PERMITS,
    HashPermits,
    MemoryBudget,
    argon2_bytes_per_hash,
    choose_hash_permits,
    compute_hash_permits,
    read_memory_budget,
)

GIB = 1024 * MIB

# The mount line a real cgroup2 host prints, with its optional fields left in. They vary
# in number from line to line, which is why the reader finds the "-" instead of counting.
CGROUP2_MOUNT = "122 112 0:25 / {mount} rw,nosuid,nodev,noexec,relatime shared:23 - cgroup2 cgroup2 rw,nsdelegate"  # noqa: E501
CGROUP1_MOUNT = "35 24 0:30 / {mount} rw,nosuid,nodev,noexec,relatime - cgroup cgroup rw,memory"


@dataclass(frozen=True)
class FakeProc:
    """A hand-written /proc and cgroup tree for one test."""

    proc_dir: Path
    mount: Path


def build_fake_proc(
    tmp_path: Path,
    mount_lines: list[str],
    cgroup_line: str,
    limit_files: dict[str, dict[str, str]],
    mem_total_kb: int,
    mem_available_kb: int,
    meminfo: str | None = None,
) -> FakeProc:
    """Write a /proc and a cgroup hierarchy the reader can walk for real.

    Args:
        tmp_path: The test's own directory
        mount_lines: mountinfo lines, with {mount} filled in with the cgroup mount point
        cgroup_line: The single line /proc/self/cgroup should hold
        limit_files: cgroup sub-path -> file name -> contents, "" being the mount root
        mem_total_kb: MemTotal, in the kB the kernel prints
        mem_available_kb: MemAvailable, in kB
        meminfo: The whole of /proc/meminfo, for the tests about fields being absent
    """
    proc_dir = tmp_path / "proc"
    (proc_dir / "self").mkdir(parents=True)
    mount = tmp_path / "cgroup"
    mount.mkdir()

    filled = "\n".join(line.format(mount=mount.as_posix()) for line in mount_lines)
    (proc_dir / "self" / "mountinfo").write_text(filled + "\n", encoding="utf-8")
    (proc_dir / "self" / "cgroup").write_text(cgroup_line + "\n", encoding="utf-8")
    (proc_dir / "meminfo").write_text(
        meminfo
        if meminfo is not None
        else (
            f"MemTotal:       {mem_total_kb} kB\n"
            f"MemFree:        {mem_available_kb // 2} kB\n"
            f"MemAvailable:   {mem_available_kb} kB\n"
        ),
        encoding="utf-8",
    )

    for sub_path, files in limit_files.items():
        directory = mount / sub_path if sub_path else mount
        directory.mkdir(parents=True, exist_ok=True)
        for name, contents in files.items():
            (directory / name).write_text(contents + "\n", encoding="utf-8")

    return FakeProc(proc_dir=proc_dir, mount=mount)


class TestCgroupV2:
    """The reader must find the ceiling that actually binds this process."""

    def test_a_limit_on_an_ancestor_is_found_when_this_cgroup_has_no_file(
        self, tmp_path, monkeypatch
    ):
        """The case that would otherwise ship broken.

        A process moved into a nested cgroup has no memory.max of its own, and the real
        384 MiB ceiling sits on the parent scope. Reading only its own directory reports
        no limit and sizes for the whole machine, which is the failure this exists for.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.scope/leaf",
            limit_files={
                "system.slice/shadow9.scope": {"memory.max": "402653184"},
                # The leaf directory exists and holds no memory files at all.
                "system.slice/shadow9.scope/leaf": {},
            },
            mem_total_kb=8 * 1024 * 1024,
            mem_available_kb=7 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 384 * MIB
        assert budget.source == "cgroup v2"
        assert "shadow9.scope" in budget.detail
        assert budget.detail.endswith("memory.max = 402653184")

    def test_memory_high_wins_when_it_is_lower_than_memory_max(self, tmp_path, monkeypatch):
        """Being throttled into permanent reclaim is an outage even though nothing dies."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.scope",
            limit_files={
                "system.slice/shadow9.scope": {
                    "memory.max": str(2 * GIB),
                    "memory.high": str(512 * MIB),
                }
            },
            mem_total_kb=8 * 1024 * 1024,
            mem_available_kb=7 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 512 * MIB
        assert budget.detail.endswith(f"memory.high = {512 * MIB}")

    def test_the_word_max_means_no_ceiling(self, tmp_path, monkeypatch):
        """cgroup v2 spells unlimited as a word, so there is no number to misread."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/user.slice",
            limit_files={"user.slice": {"memory.max": "max", "memory.high": "max"}},
            mem_total_kb=8 * 1024 * 1024,
            mem_available_kb=7 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 8 * GIB
        assert budget.source == "/proc/meminfo (cgroup v2)"
        assert budget.detail == "cgroup v2, no ceiling set"

    def test_a_root_cgroup_with_no_memory_files_is_not_an_error(self, tmp_path, monkeypatch):
        """memory.max exists only on non-root cgroups, so its absence means no ceiling."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/",
            limit_files={"": {"memory.stat": "anon 0"}},
            mem_total_kb=2 * 1024 * 1024,
            mem_available_kb=1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 2 * GIB
        assert budget.available_bytes == GIB
        assert budget.usable_bytes == GIB

    def test_the_mount_point_is_read_rather_than_assumed(self, tmp_path, monkeypatch):
        """A mount somewhere other than /sys/fs/cgroup still has to be found.

        The lines before it carry a different number of optional fields, which is what
        stops the reader from counting columns from the left.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[
                "21 27 0:20 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
                "24 27 0:22 / /sys rw,nosuid,nodev,noexec shared:7 master:2 - sysfs sysfs rw",
                CGROUP2_MOUNT,
            ],
            cgroup_line="0::/shadow9",
            limit_files={"shadow9": {"memory.max": str(256 * MIB)}},
            mem_total_kb=4 * 1024 * 1024,
            mem_available_kb=3 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert str(fake.mount.as_posix()) in budget.detail.replace("\\", "/")


class TestCgroupV1:
    """v1 spells unlimited as a number, and the number moves with the page size."""

    def test_the_unlimited_sentinel_is_recognised_without_hardcoding_it(
        self, tmp_path, monkeypatch
    ):
        """PAGE_COUNTER_MAX in bytes is not a ceiling, whatever the page size makes it."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="7:memory:/",
            limit_files={"": {"memory.limit_in_bytes": "9223372036854771712"}},
            mem_total_kb=1024 * 1024,
            mem_available_kb=900 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == GIB
        assert budget.source == "/proc/meminfo (cgroup v1)"
        assert "at or above MemTotal" in budget.detail

    def test_a_sentinel_for_a_larger_page_size_is_recognised_too(self, tmp_path, monkeypatch):
        """A 64 KiB-page machine reports a different number for the same "no limit"."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="7:memory:/",
            limit_files={"": {"memory.limit_in_bytes": "9223372036854710272"}},
            mem_total_kb=1024 * 1024,
            mem_available_kb=900 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        assert memory_budget._linux_budget().limit_bytes == GIB

    def test_a_real_v1_ceiling_is_used(self, tmp_path, monkeypatch):
        """A number below physical RAM is a ceiling and must be respected."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="7:memory:/",
            limit_files={"": {"memory.limit_in_bytes": str(256 * MIB)}},
            mem_total_kb=1024 * 1024,
            mem_available_kb=900 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.source == "cgroup v1"


class TestNothingFoundIsNotTheSameAsNothingSet:
    """Every reader here can fail, and a failure must never size for the whole machine.

    These all describe the same mistake: an error on the way to the ceiling being read
    as proof that no ceiling exists, which turns straight into the largest permit count
    the arithmetic allows. On a 64 GiB host that is sixteen concurrent hashes chosen by
    a process that could not read its own limit.
    """

    def test_an_unreadable_mountinfo_is_not_a_machine_without_cgroups(
        self, tmp_path, monkeypatch
    ):
        """EACCES on mountinfo used to report "no cgroups" and size from host RAM."""
        proc_dir = tmp_path / "proc"
        (proc_dir / "self").mkdir(parents=True)
        # A directory where the file belongs. open() refuses it on every platform, which
        # is the portable stand-in for the permission error a container gives.
        (proc_dir / "self" / "mountinfo").mkdir()
        (proc_dir / "self" / "cgroup").write_text("0::/shadow9\n", encoding="utf-8")
        (proc_dir / "meminfo").write_text(
            "MemTotal:       67108864 kB\nMemAvailable:   62914560 kB\n", encoding="utf-8"
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.source == "fallback"
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET
        assert "mountinfo could not be read" in budget.detail
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    def test_an_unreadable_limit_file_is_not_an_absent_ceiling(self, tmp_path, monkeypatch):
        """A missing memory.max means no ceiling; one that will not open means nothing."""
        proc_dir = tmp_path / "proc"
        (proc_dir / "self").mkdir(parents=True)
        mount = tmp_path / "cgroup"
        (mount / "shadow9").mkdir(parents=True)
        (mount / "shadow9" / "memory.max").mkdir()
        (proc_dir / "self" / "mountinfo").write_text(
            CGROUP2_MOUNT.format(mount=mount.as_posix()) + "\n", encoding="utf-8"
        )
        (proc_dir / "self" / "cgroup").write_text("0::/shadow9\n", encoding="utf-8")
        (proc_dir / "meminfo").write_text(
            "MemTotal:       67108864 kB\nMemAvailable:   62914560 kB\n", encoding="utf-8"
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    def test_a_namespace_that_hides_the_binding_ancestor_is_unknown(self, tmp_path, monkeypatch):
        """A cgroup namespace roots the process at a cgroup that calls itself "/".

        Measured on a real kernel: with /tenant capped at 512 MiB and a namespace rooted
        at /tenant/app, the process reads 0::/ and sees a memory.max of "max", while the
        512 MiB above it is not reachable by any path. The true root of the hierarchy
        has no memory.max file at all, and that is the difference between the two.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/",
            limit_files={"": {"memory.max": "max", "memory.high": "max"}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert "hidden from this process" in budget.detail
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    def test_a_hidden_ancestor_makes_a_loose_visible_ceiling_unknown_too(
        self, tmp_path, monkeypatch
    ):
        """The corner the first version of this missed.

        A namespace showing memory.max = 1 GiB while a parent it cannot see binds it to
        256 MiB reads exactly like a genuine 1 GiB unit. Sixteen hashes then plan a
        gigabyte inside a quarter of one. What is visible is a reading, but there is
        nothing here that makes it the reading that binds.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/",
            limit_files={"": {"memory.max": str(GIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert "hidden from this process" in budget.detail
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET
        # The way back to the old number, named in the message rather than left to be
        # guessed at, because this is the case that costs a container its permits.
        assert "auth.max_concurrent_auth" in budget.detail

    def test_a_hidden_ancestor_does_not_throw_away_a_tighter_visible_ceiling(
        self, tmp_path, monkeypatch
    ):
        """128 MiB is below the figure the fallback would assume, so it still binds.

        No ancestor, hidden or not, could make it safe to plan for more than what is
        already visible here, and replacing 128 MiB with an assumed 256 MiB would be a
        step in the one direction this module exists to avoid.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/",
            limit_files={"": {"memory.max": str(128 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is True
        assert budget.limit_bytes == 128 * MIB

    def test_a_cgroup_directory_that_is_not_there_is_not_an_absent_ceiling(
        self, tmp_path, monkeypatch
    ):
        """The mount goes away between mountinfo being read and the walk starting.

        Every open then raises FileNotFoundError, which on its own reads as "no limit
        file here", and the top of a tree that is not there reads as the real root of
        the hierarchy. Together they turn a vanished mount into the whole 64 GiB host.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={"system.slice/shadow9.service": {"memory.max": str(256 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        shutil.rmtree(fake.mount)

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET

    def test_the_real_hierarchy_root_is_still_read_as_unlimited(self, tmp_path, monkeypatch):
        """The half of that distinction which would be easy to break while fixing it.

        An ordinary unconfined host has no memory.max at the root, and it must go on
        sizing from its own memory rather than being called unknown.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/",
            limit_files={"": {"memory.stat": "anon 0"}},
            mem_total_kb=8 * 1024 * 1024,
            mem_available_kb=7 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is True
        assert budget.limit_bytes == 8 * GIB
        assert budget.detail == "cgroup v2, no ceiling set"

    def test_a_missing_mem_available_does_not_become_the_whole_machine(
        self, tmp_path, monkeypatch
    ):
        """MemTotal is the size of the box and says nothing about what is free on it."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[],
            cgroup_line="",
            limit_files={},
            mem_total_kb=0,
            mem_available_kb=0,
            meminfo="MemTotal:       67108864 kB\nMemFree:        204800 kB\n",
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.available_bytes == 200 * MIB
        assert budget.usable_bytes == 200 * MIB
        assert "MemAvailable absent" in budget.detail
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    def test_a_meminfo_with_no_memory_figures_at_all_is_unknown(self, tmp_path, monkeypatch):
        """Nothing to read is not the same as nothing to spare, nor as plenty."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[],
            cgroup_line="",
            limit_files={},
            mem_total_kb=0,
            mem_available_kb=0,
            meminfo="Hugepagesize:       2048 kB\n",
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET


class TestTheMountHasToBeMappedNotJoined:
    """mountinfo field 4 is the filesystem root and field 5 is the mount point."""

    def test_a_mount_publishing_a_subtree_is_resolved_through_its_root(
        self, tmp_path, monkeypatch
    ):
        """The shape a container gets: only part of the hierarchy is mounted.

        With a mount root of /system.slice, the cgroup /system.slice/shadow9.service
        appears as shadow9.service under the mount point. Joining the membership path
        straight onto the mount point looks a level too deep, finds nothing, and reports
        a service capped at 256 MiB as having the whole 64 GiB host.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[
                "122 112 0:25 /system.slice {mount} rw,relatime shared:23 - cgroup2 cgroup2 rw"
            ],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={"shadow9.service": {"memory.max": str(256 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.source == "cgroup v2"

    def test_an_escaped_mount_point_is_decoded_before_it_is_opened(self, tmp_path, monkeypatch):
        """mountinfo writes a space as \\040, and four literal characters open nothing."""
        proc_dir = tmp_path / "proc"
        (proc_dir / "self").mkdir(parents=True)
        mount = tmp_path / "cgroup dir"
        (mount / "shadow9").mkdir(parents=True)
        (mount / "shadow9" / "memory.max").write_text(str(256 * MIB), encoding="utf-8")
        escaped = mount.as_posix().replace(" ", "\\040")
        (proc_dir / "self" / "mountinfo").write_text(
            f"122 112 0:25 / {escaped} rw,relatime shared:23 - cgroup2 cgroup2 rw\n",
            encoding="utf-8",
        )
        (proc_dir / "self" / "cgroup").write_text("0::/shadow9\n", encoding="utf-8")
        (proc_dir / "meminfo").write_text(
            "MemTotal:       67108864 kB\nMemAvailable:   62914560 kB\n", encoding="utf-8"
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB

    def test_a_mount_that_cannot_show_this_cgroup_is_passed_over_for_one_that_can(
        self, tmp_path, monkeypatch
    ):
        """Both are mounted, and only the second can resolve the membership path."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[
                "100 99 0:25 /other/branch {mount} rw,relatime - cgroup2 cgroup2 rw",
                "122 112 0:25 / {mount} rw,relatime - cgroup2 cgroup2 rw",
            ],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={"system.slice/shadow9.service": {"memory.max": str(256 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        assert memory_budget._linux_budget().limit_bytes == 256 * MIB


class TestCgroupV1FindsThisProcessNotTheRoot:
    def test_the_limit_on_this_process_own_cgroup_is_found(self, tmp_path, monkeypatch):
        """The container shape: the root is unlimited and /docker/app is 256 MiB.

        Reading only the mount root reported no ceiling and sized from the 64 GiB host,
        which is the failure this module exists to prevent, rebuilt in the v1 reader.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="7:memory:/docker/app",
            limit_files={
                "": {"memory.limit_in_bytes": "9223372036854771712"},
                "docker/app": {"memory.limit_in_bytes": str(256 * MIB)},
            },
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.source == "cgroup v1"

    def test_the_memory_controller_is_found_when_it_shares_a_hierarchy(
        self, tmp_path, monkeypatch
    ):
        """v1 mounts several controllers together, so the field is a list not a name."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="4:cpu,cpuacct,memory:/docker/app",
            limit_files={"docker/app": {"memory.limit_in_bytes": str(128 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        assert memory_budget._linux_budget().limit_bytes == 128 * MIB

    def test_a_hybrid_host_falls_through_to_v1_when_the_unified_line_is_absent(
        self, tmp_path, monkeypatch
    ):
        """Both hierarchies mounted, and the ceiling is only in the v1 one.

        A hybrid host mounts cgroup2 and the v1 memory controller together, and a process
        placed in the v1 controller can have no line in the unified hierarchy at all.
        Stopping at the v2 lookup because cgroup2 is mounted reports no ceiling on a
        process that has one.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT, CGROUP1_MOUNT],
            cgroup_line="7:memory:/docker/app",
            limit_files={"docker/app": {"memory.limit_in_bytes": str(256 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.source == "cgroup v1"

    def test_a_hybrid_host_checks_v1_when_the_unified_line_has_no_memory_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A unified membership does not mean the memory controller belongs to v2."""
        unified_mount = tmp_path / "cgroup2"
        legacy_mount = tmp_path / "cgroup1"
        (unified_mount / "unified").mkdir(parents=True)
        (legacy_mount / "docker" / "app").mkdir(parents=True)
        (legacy_mount / "docker" / "app" / "memory.limit_in_bytes").write_text(
            str(256 * MIB), encoding="utf-8"
        )
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[
                CGROUP2_MOUNT.format(mount=unified_mount.as_posix()),
                CGROUP1_MOUNT.format(mount=legacy_mount.as_posix()),
            ],
            cgroup_line="0::/unified\n7:memory:/docker/app",
            limit_files={},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.source == "cgroup v1"

    def test_v1_usage_already_held_is_read_from_usage_in_bytes(self, tmp_path, monkeypatch):
        """v1 names the file differently, and the figure is used the same way.

        Whatever is already resident in the cgroup is not memory hashing may plan to
        spend, and reading only the ceiling on v1 would offer it twice.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="7:memory:/docker/app",
            limit_files={
                "docker/app": {
                    "memory.limit_in_bytes": str(768 * MIB),
                    "memory.usage_in_bytes": str(400 * MIB),
                }
            },
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 768 * MIB
        assert budget.current_bytes == 400 * MIB

    def test_a_v1_mount_this_process_is_not_in_is_not_an_absent_ceiling(
        self, tmp_path, monkeypatch
    ):
        """The memory controller is mounted and this process has no line in it.

        Nothing here says the process is uncapped, only that the reader cannot tell, and
        the difference has to survive as an unmeasured budget rather than the whole host.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP1_MOUNT],
            cgroup_line="3:cpu,cpuacct:/docker/app",
            limit_files={"docker/app": {"memory.limit_in_bytes": str(256 * MIB)}},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET
        assert "not in /proc/self/cgroup" in budget.detail


class TestTheCgroupIsSharedWithTor:
    """memory.max applies to every process in the unit, not to this one."""

    def test_memory_already_held_in_the_cgroup_is_not_offered_to_hashing(
        self, tmp_path, monkeypatch
    ):
        """The systemd unit starts Tor bridges into the same cgroup as the proxy.

        400 MiB of Tor inside a 768 MiB ceiling is 400 MiB the proxy may not plan to
        spend, and the fixed interpreter estimate does not know about it.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={
                "system.slice/shadow9.service": {
                    "memory.max": str(768 * MIB),
                    "memory.current": str(400 * MIB),
                }
            },
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))

        budget = memory_budget._linux_budget()
        assert budget.current_bytes == 400 * MIB

        crowded = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=32)
        empty = compute_hash_permits(
            MemoryBudget(
                limit_bytes=768 * MIB, available_bytes=60 * GIB, source="cgroup v2", detail=""
            ),
            relay_reserve_bytes=0,
            cpu_count=32,
        )

        assert crowded.permits < empty.permits

    def test_a_cgroup_holding_less_than_the_interpreter_estimate_does_not_lower_it(self):
        """The reading includes this interpreter, so it is a floor and not an addition."""
        budget = MemoryBudget(
            limit_bytes=768 * MIB,
            available_bytes=768 * MIB,
            source="cgroup v2",
            detail="",
            current_bytes=20 * MIB,
        )

        assert memory_budget._baseline_bytes(budget) == INTERPRETER_RESERVE


class TestAPlanThatDoesNotFitSaysSo:
    """A memory-safety calculation must not quietly break its own ceiling."""

    def test_a_read_ceiling_with_no_room_for_one_hash_refuses_to_start(self):
        """200 MiB of ceiling cannot hold a 160 MiB interpreter and a 64 MiB hash.

        Handing back one permit anyway plans 224 MiB against 200 MiB and waits for the
        first login to be killed for it, which takes every established connection with
        it and reads as a crash. The refusal costs the same service and says which
        number to change while somebody is still watching.
        """
        budget = MemoryBudget(
            limit_bytes=200 * MIB, available_bytes=200 * MIB, source="cgroup v2", detail=""
        )

        with pytest.raises(memory_budget.MemoryCeilingTooLow) as raised:
            compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=8)

        message = str(raised.value)
        assert "224 MiB is needed" in message
        assert "The limit is 200 MiB" in message
        assert "auth.max_concurrent_auth" in message

    def test_a_ceiling_that_was_assumed_rather_than_read_still_starts(self):
        """The 256 MiB figure is invented for a platform with no reader.

        Refusing to serve on the strength of a number this module made up would take a
        macOS box with 64 GiB free off the air, so the assumed budget keeps the floor of
        one permit and the warning that goes with it.
        """
        budget = memory_budget._unmeasured_budget("no reader for this platform")

        chosen = compute_hash_permits(budget, relay_reserve_bytes=200 * MIB, cpu_count=8)

        assert chosen.permits == 1
        assert chosen.exceeds_budget is True
        assert "does not fit" in chosen.reason

    def test_a_busy_machine_is_not_refused_for_being_busy(self):
        """MemFree understates what an allocation can have, on purpose.

        A host with 64 GiB installed and 200 MiB free right now is sized down to one
        permit, because that is what is free. It is not refused, because the number that
        condemned it will be different in a second and a refusal would repeat every time
        the page cache filled.
        """
        budget = MemoryBudget(
            limit_bytes=64 * GIB,
            available_bytes=200 * MIB,
            source="/proc/meminfo (no cgroups)",
            detail="MemAvailable absent, available read from MemFree",
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64)

        assert chosen.permits == 1
        assert chosen.exceeds_budget is True

    def test_an_operator_who_chose_the_number_is_never_refused(self):
        """They can see the machine and this code cannot."""
        budget = MemoryBudget(
            limit_bytes=200 * MIB, available_bytes=200 * MIB, source="cgroup v2", detail=""
        )

        chosen = choose_hash_permits(2, relay_reserve_bytes=0, budget=budget, cpu_count=8)

        assert chosen.permits == 2
        assert chosen.exceeds_budget is True

    def test_a_budget_that_fits_is_not_flagged(self):
        """The flag has to stay quiet in the ordinary case to mean anything."""
        budget = MemoryBudget(
            limit_bytes=768 * MIB, available_bytes=768 * MIB, source="cgroup v2", detail=""
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=32)

        assert chosen.exceeds_budget is False
        assert "does not fit" not in chosen.reason

    def test_an_operator_number_too_large_for_the_box_is_flagged_but_still_used(self):
        """The setting is still obeyed. It is no longer obeyed silently."""
        budget = MemoryBudget(
            limit_bytes=256 * MIB, available_bytes=256 * MIB, source="cgroup v2", detail=""
        )

        chosen = choose_hash_permits(12, relay_reserve_bytes=0, budget=budget, cpu_count=1)

        assert chosen.permits == 12
        assert chosen.exceeds_budget is True
        assert "does not fit" in chosen.reason

    def test_a_permit_count_below_one_is_refused(self):
        """Zero builds a pool nothing can take from, so every login waits for good."""
        budget = MemoryBudget(
            limit_bytes=GIB, available_bytes=GIB, source="cgroup v2", detail=""
        )

        with pytest.raises(ValueError, match="at least 1"):
            choose_hash_permits(0, relay_reserve_bytes=0, budget=budget)
        with pytest.raises(ValueError, match="at least 1"):
            choose_hash_permits(-3, relay_reserve_bytes=0, budget=budget)


class TestOneBudgetSharedBySeveralWorkers:
    def test_the_budget_divides_between_processes_that_share_a_ceiling(self):
        """Four uvicorn workers in one cgroup are four shares of it, not four copies."""
        budget = MemoryBudget(
            limit_bytes=4 * GIB,
            available_bytes=8 * GIB,
            source="cgroup v2",
            detail="memory.max = 4294967296",
            current_bytes=80 * MIB,
        )

        share = budget.shared_between(4)

        assert share.limit_bytes == GIB
        assert share.current_bytes == 20 * MIB
        assert "one share of 4" in share.detail
        assert compute_hash_permits(share, 0, 32).permits < compute_hash_permits(
            budget, 0, 32
        ).permits

    def test_a_share_too_small_for_one_hash_is_refused_like_any_other_ceiling(self):
        """A 768 MiB unit cannot run four workers each holding an argon2 hash.

        The division is what makes it visible: each worker planning 224 MiB inside its
        192 MiB share is 896 MiB of a 768 MiB unit, and every one of them would size
        itself against the whole thing without it.
        """
        budget = MemoryBudget(
            limit_bytes=768 * MIB,
            available_bytes=8 * GIB,
            source="cgroup v2",
            detail="memory.max = 805306368",
        )

        with pytest.raises(memory_budget.MemoryCeilingTooLow):
            compute_hash_permits(budget.shared_between(4), relay_reserve_bytes=0, cpu_count=32)

    def test_a_single_worker_is_left_alone(self):
        """The ordinary deployment must not pay for a case it is not in."""
        budget = MemoryBudget(
            limit_bytes=768 * MIB, available_bytes=8 * GIB, source="cgroup v2", detail=""
        )

        assert budget.shared_between(1) is budget


class TestAProcessLimitTheCgroupsDoNotKnowAbout:
    """`ulimit -v` caps the process, and nothing in /proc or the cgroup tree says so."""

    def test_an_address_space_limit_is_taken_over_the_size_of_the_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """64 GiB of host, no cgroup, and RLIMIT_AS at 256 MiB.

        Without this the reader calls tens of gigabytes a measured budget and allows
        sixteen concurrent hashes, and the kernel refuses the allocation at the fourth.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[],
            cgroup_line="",
            limit_files={},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        (fake.proc_dir / "self" / "status").write_text(
            "VmSize:\t131072 kB\n", encoding="utf-8"
        )

        def capped_at_256_mib() -> int:
            return 256 * MIB

        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        monkeypatch.setattr(memory_budget, "_address_space_limit", capped_at_256_mib)

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 256 * MIB
        assert budget.usable_bytes == 256 * MIB
        assert "ulimit -v" in budget.detail
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    @pytest.mark.parametrize(
        "status_text",
        [
            "MemFree:\t0 kB\n",
            "VmSize:\tnot a number kB\n",
            "VmSize:\t131072\n",
            "VmSize:\t0 kB\n",
        ],
        ids=["absent", "not-a-number", "no-unit", "zero"],
    )
    def test_a_virtual_size_it_cannot_read_falls_back_rather_than_assuming_none(
        self, status_text: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """RLIMIT_AS is set and /proc/self/status will not say how much is already spent.

        Sizing permits under RLIMIT_AS needs that reading, so a value it cannot read has
        to land on the fallback. Reading it as "nothing is charged yet" would let 64 GiB
        of host decide the permit count, which is the out-of-memory crash this module
        exists to prevent.
        """
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[],
            cgroup_line="",
            limit_files={},
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        (fake.proc_dir / "self" / "status").write_text(status_text, encoding="utf-8")

        def capped_at_256_mib() -> int:
            return 256 * MIB

        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        monkeypatch.setattr(memory_budget, "_address_space_limit", capped_at_256_mib)

        budget = memory_budget._linux_budget()

        assert budget.measured is False
        assert budget.limit_bytes == memory_budget.FALLBACK_BUDGET
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET
        assert compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64).permits == 1

    def test_the_looser_of_the_two_is_left_where_it_is(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An 8 GiB RLIMIT_AS over a 384 MiB cgroup changes nothing and says nothing."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={
                "": {"memory.stat": "anon 0"},
                "system.slice/shadow9.service": {"memory.max": str(384 * MIB)},
            },
            mem_total_kb=8 * 1024 * 1024,
            mem_available_kb=7 * 1024 * 1024,
        )
        (fake.proc_dir / "self" / "status").write_text(
            "VmSize:\t131072 kB\n", encoding="utf-8"
        )

        def capped_at_8_gib() -> int:
            return 8 * GIB

        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        monkeypatch.setattr(memory_budget, "_address_space_limit", capped_at_8_gib)

        budget = memory_budget._linux_budget()

        assert budget.limit_bytes == 384 * MIB
        assert "ulimit -v" not in budget.detail

    def test_each_limit_is_compared_with_the_usage_it_covers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Other processes in a cgroup do not consume this process's address space."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={
                "system.slice/shadow9.service": {
                    "memory.max": str(GIB),
                    "memory.current": str(600 * MIB),
                }
            },
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        (fake.proc_dir / "self" / "status").write_text(
            "VmSize:\t327680 kB\n", encoding="utf-8"
        )

        def capped_at_512_mib() -> int:
            return 512 * MIB

        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        monkeypatch.setattr(memory_budget, "_address_space_limit", capped_at_512_mib)

        budget = memory_budget._linux_budget()
        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=32)
        share = budget.shared_between(2)
        shared = compute_hash_permits(share, relay_reserve_bytes=0, cpu_count=32)

        assert budget.limit_bytes == 512 * MIB
        assert budget.current_bytes == 320 * MIB
        assert chosen.permits == 1
        assert share.limit_bytes == 512 * MIB
        assert share.current_bytes == 320 * MIB
        assert shared.permits == 1

    def test_the_cgroup_limit_still_binds_when_its_usage_leaves_less_room(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tighter per-process number does not replace the shared cgroup constraint."""
        fake = build_fake_proc(
            tmp_path,
            mount_lines=[CGROUP2_MOUNT],
            cgroup_line="0::/system.slice/shadow9.service",
            limit_files={
                "system.slice/shadow9.service": {
                    "memory.max": str(GIB),
                    "memory.current": str(760 * MIB),
                }
            },
            mem_total_kb=64 * 1024 * 1024,
            mem_available_kb=60 * 1024 * 1024,
        )
        (fake.proc_dir / "self" / "status").write_text(
            "VmSize:\t163840 kB\n", encoding="utf-8"
        )

        def capped_at_512_mib() -> int:
            return 512 * MIB

        monkeypatch.setattr(memory_budget, "PROC_DIR", str(fake.proc_dir))
        monkeypatch.setattr(memory_budget, "_address_space_limit", capped_at_512_mib)

        budget = memory_budget._linux_budget()
        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=32)

        assert budget.source == "cgroup v2"
        assert budget.current_bytes == 760 * MIB
        assert chosen.permits == 1

    def test_no_such_limit_leaves_the_budget_alone(self):
        """The ordinary host has RLIM_INFINITY here and must keep its own figures."""
        budget = MemoryBudget(
            limit_bytes=4 * GIB, available_bytes=2 * GIB, source="cgroup v2", detail="d"
        )

        assert memory_budget._narrowed_to_address_space(budget) is budget

    @pytest.mark.skipif(sys.platform == "win32", reason="getrlimit is POSIX only")
    def test_the_real_call_answers_without_raising(self):
        """It is read from the running process, so it has to work on a real one."""
        limit = memory_budget._address_space_limit()

        assert limit is None or limit > 0


class TestWindows:
    """No cgroups, so the figures come from the kernel32 call."""

    @pytest.mark.skipif(sys.platform != "win32", reason="needs the Windows API")
    def test_the_real_call_returns_usable_figures(self):
        """dwLength and the declared restype are what stop this returning zeros."""
        budget = memory_budget._windows_budget()

        assert budget.source == "GlobalMemoryStatusEx"
        assert budget.limit_bytes > 0
        assert 0 < budget.available_bytes <= budget.limit_bytes
        assert budget.detail.startswith("total=")

    def test_windows_is_routed_away_from_the_cgroup_reader(self, monkeypatch):
        """The dispatch, checked where the Windows API is not available to call."""
        called: list[str] = []

        def fake_windows_budget() -> MemoryBudget:
            called.append("windows")
            return MemoryBudget(
                limit_bytes=8 * GIB,
                available_bytes=4 * GIB,
                source="GlobalMemoryStatusEx",
                detail="total=8589934592 avail=4294967296 load=50%",
            )

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(memory_budget, "_windows_budget", fake_windows_budget)

        budget = read_memory_budget()

        assert called == ["windows"]
        assert budget.source == "GlobalMemoryStatusEx"
        assert budget.usable_bytes == 4 * GIB

    def test_a_failed_call_falls_back_rather_than_raising(self, monkeypatch):
        """A reader that raises would stop the proxy from starting at all."""

        def failing_windows_budget() -> MemoryBudget:
            raise OSError("GlobalMemoryStatusEx said no")

        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(memory_budget, "_windows_budget", failing_windows_budget)

        budget = read_memory_budget()

        assert budget.source == "fallback"
        assert budget.usable_bytes == memory_budget.FALLBACK_BUDGET


class TestTheBudgetItself:
    def test_the_smaller_of_the_ceiling_and_what_is_free_is_what_can_be_spent(self):
        """A 4 GiB ceiling does not conjure 4 GiB on a host with 200 MiB left."""
        tight_host = MemoryBudget(
            limit_bytes=4 * GIB, available_bytes=200 * MIB, source="cgroup v2", detail=""
        )
        tight_cgroup = MemoryBudget(
            limit_bytes=200 * MIB, available_bytes=4 * GIB, source="cgroup v2", detail=""
        )

        assert tight_host.usable_bytes == 200 * MIB
        assert tight_cgroup.usable_bytes == 200 * MIB


class TestThePermitCount:
    def test_the_cost_per_hash_follows_the_hasher_setting(self, monkeypatch):
        """Retuning argon2 must move the permit count with it, not leave it stale."""
        from shadow9.auth import AuthManager

        assert argon2_bytes_per_hash() == AuthManager.ARGON2_MEMORY_COST * 1024

        monkeypatch.setattr(AuthManager, "ARGON2_MEMORY_COST", 32768)
        assert argon2_bytes_per_hash() == 32 * MIB

    def test_a_small_box_gets_the_floor_of_one_rather_than_zero(self):
        """Zero permits means nobody can ever log in, which fails silently.

        A 256 MiB ceiling is the 1 GB VPS this work is aimed at, and it has nothing
        left for hashing once the interpreter and the relay buffers are counted.
        """
        budget = MemoryBudget(
            limit_bytes=256 * MIB,
            available_bytes=256 * MIB,
            source="cgroup v2",
            detail="memory.max = 268435456",
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=100 * 2 * 65536, cpu_count=8)

        assert chosen.permits == 1
        assert "the floor" in chosen.reason
        assert chosen.set_by_operator is False

    def test_a_768_mib_ceiling_gives_more_than_one_and_says_memory_bound_it(self):
        """The figure the unit used to hardcode, now derived rather than assumed."""
        budget = MemoryBudget(
            limit_bytes=768 * MIB,
            available_bytes=8 * GIB,
            source="cgroup v2",
            detail="memory.max = 805306368",
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=100 * 2 * 65536, cpu_count=32)

        spendable = int(768 * MIB * HEADROOM_FRACTION)
        expected = (
            spendable - INTERPRETER_RESERVE - 100 * 2 * 65536
        ) // argon2_bytes_per_hash()
        assert chosen.permits == expected
        assert chosen.permits > 1
        assert "bound by memory" in chosen.reason

    def test_a_large_host_is_capped_by_the_ceiling_not_by_its_memory(self):
        """An unbounded permit count is what turns a login flood into 16 GiB reserved."""
        budget = MemoryBudget(
            limit_bytes=64 * GIB,
            available_bytes=64 * GIB,
            source="/proc/meminfo (no cgroups)",
            detail="",
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=64)

        assert chosen.permits == MAX_PERMITS
        assert f"bound by ceiling ({MAX_PERMITS})" in chosen.reason

    def test_a_small_core_count_bounds_it_before_memory_does(self):
        """argon2 is CPU-bound too, so permits past the core count only queue."""
        budget = MemoryBudget(
            limit_bytes=64 * GIB, available_bytes=64 * GIB, source="cgroup v2", detail=""
        )

        chosen = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=2)

        assert chosen.permits == 2
        assert "bound by cpu count (2)" in chosen.reason

    def test_relay_buffers_are_taken_out_before_hashing_gets_a_share(self):
        """The relay holds two buffers per connection and hashing cannot spend them."""
        budget = MemoryBudget(
            limit_bytes=GIB, available_bytes=GIB, source="cgroup v2", detail=""
        )

        without_relay = compute_hash_permits(budget, relay_reserve_bytes=0, cpu_count=32)
        with_relay = compute_hash_permits(
            budget, relay_reserve_bytes=2000 * 2 * 65536, cpu_count=32
        )

        assert with_relay.permits < without_relay.permits


class TestTheOperatorSettingWins:
    """D5: a number a person chose is used exactly as written."""

    def test_an_explicit_setting_is_used_verbatim(self):
        """Even on a box the arithmetic would have sized differently."""
        budget = MemoryBudget(
            limit_bytes=256 * MIB, available_bytes=256 * MIB, source="cgroup v2", detail=""
        )

        chosen = choose_hash_permits(12, relay_reserve_bytes=0, budget=budget, cpu_count=1)

        assert chosen.permits == 12
        assert chosen.set_by_operator is True
        assert "set explicitly as auth.max_concurrent_auth" in chosen.reason

    def test_an_unset_value_is_worked_out(self):
        """None is the only value that means "size this for me"."""
        budget = MemoryBudget(
            limit_bytes=64 * GIB, available_bytes=64 * GIB, source="cgroup v2", detail=""
        )

        chosen = choose_hash_permits(None, relay_reserve_bytes=0, budget=budget, cpu_count=64)

        assert chosen.permits == MAX_PERMITS
        assert chosen.set_by_operator is False


class TestTheServerSizesItsOwnPermits:
    def test_an_unset_setting_produces_a_sized_semaphore(self):
        """The permit pool has to be the size the budget allowed, not a fixed 4."""
        from shadow9.socks5_server import Socks5Server

        server = Socks5Server(max_concurrent_auth=None)

        assert server.max_concurrent_auth == server.hash_permits.permits
        assert server.max_concurrent_auth >= 1
        assert server._auth_slots._initial_value == server.max_concurrent_auth
        assert server.hash_permits.set_by_operator is False

    def test_an_explicit_setting_reaches_the_semaphore_unchanged(self):
        """A person who asked for 3 gets 3, whatever this machine has."""
        from shadow9.socks5_server import Socks5Server

        server = Socks5Server(max_concurrent_auth=3)

        assert server.max_concurrent_auth == 3
        assert server._auth_slots._initial_value == 3
        assert server.hash_permits.set_by_operator is True


class TestThePermitPoolFollowsAChangingCeiling:
    """A limit can be lowered under a running process, and nothing announces it.

    `systemctl set-property shadow9.service MemoryMax=256M` applies at once. Reading the
    budget only at startup leaves the process planning for memory it no longer has,
    which is the dangerous direction to be wrong in.
    """

    def _server_with_permits(self, monkeypatch, permits: int):
        from shadow9.socks5_server import Socks5Server

        server = Socks5Server(max_concurrent_auth=None)
        # Sizing it by hand rather than by writing a fake cgroup, because the point here
        # is what the pool does with a new answer, not where the answer came from.
        monkeypatch.setattr(server, "_auth_slots_initial", permits)
        monkeypatch.setattr(server, "_parked_auth_slots", 0)
        monkeypatch.setattr(server, "_auth_slots", threading.BoundedSemaphore(permits))
        monkeypatch.setattr(server, "max_concurrent_auth", permits)
        return server

    def _answer(self, monkeypatch, permits: int) -> None:
        from shadow9 import socks5_server

        def sized(
            configured, relay_reserve_bytes: int, budget=None, cpu_count=None
        ) -> HashPermits:
            return HashPermits(
                permits=permits,
                budget=MemoryBudget(
                    limit_bytes=256 * MIB, available_bytes=256 * MIB, source="cgroup v2",
                    detail="",
                ),
                reason="test",
                set_by_operator=False,
            )

        monkeypatch.setattr(socks5_server, "choose_hash_permits", sized)

    def test_a_lowered_ceiling_takes_permits_out_of_the_pool(self, monkeypatch):
        server = self._server_with_permits(monkeypatch, 4)
        self._answer(monkeypatch, 1)

        server.resize_auth_slots()

        assert server.max_concurrent_auth == 1
        assert server._auth_slots.acquire(timeout=0.1) is True
        assert server._auth_slots.acquire(timeout=0.1) is False

    def test_a_raised_ceiling_puts_them_back_but_no_further(self, monkeypatch):
        """Growing past the size it started at is refused, and that refusal is the point.

        The pool is a BoundedSemaphore, so it cannot be released above its initial
        value. Keeping that means the worst this can do is make logins slower.
        """
        server = self._server_with_permits(monkeypatch, 4)
        self._answer(monkeypatch, 1)
        server.resize_auth_slots()

        self._answer(monkeypatch, 16)
        server.resize_auth_slots()

        assert server.max_concurrent_auth == 4
        assert server._parked_auth_slots == 0
        for _ in range(4):
            assert server._auth_slots.acquire(timeout=0.1) is True
        assert server._auth_slots.acquire(timeout=0.1) is False

    def test_a_number_an_operator_chose_is_left_alone(self, monkeypatch):
        from shadow9.socks5_server import Socks5Server

        server = Socks5Server(max_concurrent_auth=3)
        self._answer(monkeypatch, 1)

        server.resize_auth_slots()

        assert server.max_concurrent_auth == 3

    def test_an_unchanged_ceiling_moves_nothing(self, monkeypatch):
        server = self._server_with_permits(monkeypatch, 4)
        self._answer(monkeypatch, 4)

        server.resize_auth_slots()

        assert server.max_concurrent_auth == 4
        assert server._parked_auth_slots == 0

    def test_a_ceiling_that_no_longer_holds_one_hash_goes_to_the_floor(self, monkeypatch):
        """The proxy refuses to start under a ceiling this small. It does not stop for it.

        There are connections open on it by now, so refusing to serve is no longer one of
        the choices. Keeping the count it had is the one answer that is certainly wrong,
        and the arithmetic that condemned it belongs in the log either way.
        """
        from shadow9 import socks5_server

        server = self._server_with_permits(monkeypatch, 4)

        def refuse(
            configured, relay_reserve_bytes: int, budget=None, cpu_count=None
        ) -> HashPermits:
            raise memory_budget.MemoryCeilingTooLow(
                "224 MiB is needed. The limit is 192 MiB, read from cgroup v2"
            )

        def lowered_ceiling() -> MemoryBudget:
            return MemoryBudget(
                limit_bytes=192 * MIB,
                available_bytes=192 * MIB,
                source="cgroup v2",
                detail="memory.max = 201326592",
            )

        monkeypatch.setattr(socks5_server, "choose_hash_permits", refuse)
        monkeypatch.setattr(socks5_server, "read_memory_budget", lowered_ceiling)

        server.resize_auth_slots()

        assert server.max_concurrent_auth == 1
        assert server.hash_permits.exceeds_budget is True
        assert "The limit is 192 MiB" in server.hash_permits.reason

    def test_a_shrink_stops_as_soon_as_the_server_does(self, monkeypatch):
        """Shutdown must not wait behind every permit still held by a hash.

        Each permit is taken by acquiring it, so with all of them in use the resize is a
        run of waits. Without a look at the stop event between them, stop() sits behind
        the lot of them: three permits at a five second interval here, and fifteen at
        thirty seconds on a real machine, which is several minutes.
        """
        server = self._server_with_permits(monkeypatch, 4)
        self._answer(monkeypatch, 1)
        monkeypatch.setattr(server, "BUDGET_RECHECK_SECONDS", 5.0)
        for _ in range(4):
            assert server._auth_slots.acquire(timeout=0.5) is True
        server._budget_watch_stop.set()

        started = time.monotonic()
        server.resize_auth_slots()
        elapsed = time.monotonic() - started

        assert elapsed < 1.0
        assert server._parked_auth_slots == 0

    def test_the_whole_shrink_shares_one_deadline(self, monkeypatch):
        """Not one deadline per permit.

        A permit given an interval of its own is only a bound when nothing frees it. A
        busy proxy frees one every so often, each wait lands inside its own interval, and
        seven of them in a row is seven intervals spent acting on a reading that was
        already a round out of date when the first one started.
        """
        server = self._server_with_permits(monkeypatch, 8)
        self._answer(monkeypatch, 1)
        monkeypatch.setattr(server, "BUDGET_RECHECK_SECONDS", 1.0)
        for _ in range(8):
            assert server._auth_slots.acquire(timeout=0.5) is True

        # One hash finishing every 0.9 seconds, which is inside the interval every time.
        stop_releasing = threading.Event()

        def hashes_finishing() -> None:
            for _ in range(7):
                if stop_releasing.wait(0.9):
                    return
                server._auth_slots.release()

        releaser = threading.Thread(target=hashes_finishing, daemon=True)
        releaser.start()
        try:
            started = time.monotonic()
            server.resize_auth_slots()
            elapsed = time.monotonic() - started
        finally:
            stop_releasing.set()
            releaser.join(timeout=5)

        assert elapsed < 2.0
        # It did take the permit it waited for, rather than passing the test by giving up.
        assert server._parked_auth_slots >= 1


class TestTheSettingSurvivesASave:
    """A worked-out number must not be written back as though a person chose it."""

    def test_unset_stays_unset_across_a_save_and_reload(self, tmp_path):
        """Otherwise one boot's answer freezes and stops following the machine."""
        from shadow9.core.config import Settings

        config_file = tmp_path / "config.yaml"
        Settings().save_to_yaml(config_file)

        reloaded = Settings.load_from_yaml(config_file)

        assert reloaded.auth.max_concurrent_auth is None
        assert reloaded.auth.sized_from_memory is False

    def test_a_worked_out_number_is_not_saved_as_a_setting(self, tmp_path):
        """The live object carries the number; the file keeps saying "unset"."""
        from shadow9.core.config import Settings

        settings = Settings()
        settings.auth.use_sized_concurrent_auth(9)
        assert settings.auth.max_concurrent_auth == 9
        assert settings.auth.sized_from_memory is True

        config_file = tmp_path / "config.yaml"
        settings.save_to_yaml(config_file)

        assert Settings.load_from_yaml(config_file).auth.max_concurrent_auth is None

    def test_an_explicit_setting_survives_the_round_trip(self, tmp_path):
        """The half of the distinction that would be easy to break while fixing the other."""
        from shadow9.core.config import Settings

        config_file = tmp_path / "config.yaml"
        settings = Settings()
        settings.auth.max_concurrent_auth = 6
        settings.save_to_yaml(config_file)

        reloaded = Settings.load_from_yaml(config_file)

        assert reloaded.auth.max_concurrent_auth == 6
        assert reloaded.auth.sized_from_memory is False

    def test_the_dataclass_config_keeps_unset_through_a_save(self, tmp_path):
        """The proxy half reads Config, and it has the same distinction to keep."""
        from shadow9.config import Config

        config_file = tmp_path / "config.yaml"
        Config().save(config_file)

        assert Config.load(config_file).auth.max_concurrent_auth is None

    def test_a_number_assigned_after_sizing_is_saved_and_not_lost(self, tmp_path):
        """An operator changing it through the settings endpoint had their choice erased.

        Startup fills the value in and marks it as worked out. A later assignment made
        it a setting, but the mark stayed, so the save wrote null over the number the
        operator had just chosen and the next load came back without it.
        """
        from shadow9.core.config import Settings

        settings = Settings()
        settings.auth.use_sized_concurrent_auth(9)
        assert settings.auth.sized_from_memory is True

        settings.auth.max_concurrent_auth = 6
        assert settings.auth.sized_from_memory is False

        config_file = tmp_path / "config.yaml"
        settings.save_to_yaml(config_file)

        assert Settings.load_from_yaml(config_file).auth.max_concurrent_auth == 6
