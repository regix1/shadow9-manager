"""Work out how much memory this process is actually allowed to use, and how many
password hashes fit inside it.

Sizing from the machine's total RAM is wrong under a systemd ``MemoryMax=`` or inside a
container: the process sizes itself to the box, then gets killed inside its own cgroup
while the host still has memory to spare. Every reader here answers the narrower
question of what *this* process may hold, and every result carries the reason it chose
the number so a startup log can say why.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

MIB = 1024 * 1024

# Nothing on any platform reports a real limit this large, so it stands in for "no
# ceiling found here" without a sentinel that could be mistaken for a measurement.
_NO_LIMIT = sys.maxsize

# Where the kernel's own files are read from. A name rather than a literal in three
# places, so the walk up the cgroup tree can be exercised against a directory written by
# hand instead of only on a machine that happens to be under a real limit.
PROC_DIR = "/proc"

# What to assume when the ceiling cannot be worked out at all: an unreadable cgroup
# file, a procfs with no memory figures in it, a platform with no reader here. Small on
# purpose. It is the smallest budget one password hash still fits inside, and every
# larger guess is a guess in the direction that gets the process killed. An operator
# whose machine can afford more says so with auth.max_concurrent_auth.
FALLBACK_BUDGET = 256 * MIB


@dataclass(frozen=True)
class MemoryBudget:
    """How much memory is available, and where that figure came from."""

    limit_bytes: int
    available_bytes: int
    source: str
    detail: str
    # What the cgroup holding the ceiling already uses. memory.max applies to every
    # process in the unit, so a Tor bridge sharing it has already spent part of the
    # budget. Zero where nothing reports it.
    current_bytes: int = 0
    # False when the figures are an assumption rather than a reading. "No ceiling is
    # set" and "the ceiling could not be read" look the same from outside and mean
    # opposite things, and reading the second as the first is how a process inside a
    # 256 MiB cgroup decides it may run sixteen password hashes.
    measured: bool = True

    @property
    def usable_bytes(self) -> int:
        """The smaller of the two.

        A cgroup ceiling does not conjure free RAM, and free RAM does not let a process
        exceed its ceiling, so only the minimum is safe in both directions.
        """
        return min(self.limit_bytes, self.available_bytes)

    def shared_between(self, processes: int) -> "MemoryBudget":
        """This budget divided among processes that all draw on it.

        A cgroup ceiling is charged to the unit rather than to a process, so workers
        under one MemoryMax hold shares of it and not copies. Each sizing itself against
        the whole thing is how four of them come to plan sixteen concurrent hashes
        inside a budget that allowed for four.
        """
        if processes <= 1:
            return self
        return MemoryBudget(
            limit_bytes=self.limit_bytes // processes,
            available_bytes=self.available_bytes // processes,
            source=self.source,
            detail=f"{self.detail}, one share of {processes}",
            current_bytes=self.current_bytes // processes,
            measured=self.measured,
        )


@dataclass(frozen=True)
class CgroupMount:
    """One mount of a cgroup filesystem: which part of the tree it shows, and where."""

    # mountinfo field 4. The part of the hierarchy this mount publishes, which is not
    # always the whole of it.
    root: str
    # mountinfo field 5. Where that part appears in this process's own filesystem.
    point: str


@dataclass(frozen=True)
class CgroupLimit:
    """The tightest ceiling found in this process's cgroup tree."""

    limit_bytes: int
    current_bytes: int
    where: str
    # True when a ceiling could sit on a cgroup this process cannot see, so "nothing
    # found" must not be read as "nothing set".
    ancestors_hidden: bool


def _unmeasured_budget(reason: str) -> MemoryBudget:
    """The answer when the ceiling could not be determined.

    Every failure below lands here rather than on host memory, because the whole point
    of this module is that sizing from the machine is what gets the process killed.
    """
    return MemoryBudget(
        limit_bytes=FALLBACK_BUDGET,
        available_bytes=FALLBACK_BUDGET,
        source="fallback",
        detail=f"{reason}, assuming {FALLBACK_BUDGET // MIB} MiB",
        measured=False,
    )


def _unescape_mountinfo(field: str) -> str:
    """Decode the octal escapes mountinfo writes into its path fields.

    A mount point holding a space is written ``\\040``. Used literally that is four
    ordinary characters, every open() below it misses, and the process concludes it has
    no ceiling. Space, tab, newline and backslash are the four the kernel escapes.
    """
    if "\\" not in field:
        return field
    decoded: list[str] = []
    index = 0
    while index < len(field):
        digits = field[index + 1 : index + 4]
        if field[index] == "\\" and len(digits) == 3 and all(d in "01234567" for d in digits):
            decoded.append(chr(int(digits, 8)))
            index += 4
        else:
            decoded.append(field[index])
            index += 1
    return "".join(decoded)


def _cgroup_mounts(
    filesystem_type: str, required_option: Optional[str] = None
) -> Optional[list[CgroupMount]]:
    """Every mount of one cgroup filesystem, from /proc/self/mountinfo.

    Do not assume /sys/fs/cgroup. Each line carries a variable number of optional fields
    before a ``-`` separator, so the type and options can only be found by locating that
    separator rather than by counting from the left.

    Every match is returned rather than the first. A container commonly has both its own
    subtree and the whole hierarchy mounted, and only one of them can resolve this
    process's cgroup by name.

    None means mountinfo itself could not be read, which is a different answer from an
    empty list: the first is a failed measurement, the second is a machine with no
    cgroups on it.
    """
    try:
        with open(os.path.join(PROC_DIR, "self", "mountinfo"), encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return None

    found: list[CgroupMount] = []
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        # The root and mount point sit at 3 and 4, so a separator before 5 means the
        # line is too short to be a mount line at all.
        if separator < 5:
            continue
        if len(fields) <= separator + 1 or fields[separator + 1] != filesystem_type:
            continue
        if required_option is not None:
            options = fields[separator + 3] if len(fields) > separator + 3 else ""
            if required_option not in options.split(","):
                continue
        found.append(
            CgroupMount(
                root=_unescape_mountinfo(fields[3]),
                point=_unescape_mountinfo(fields[4]),
            )
        )
    return found


def _read_limit_file(path: str) -> Optional[int]:
    """Read one cgroup limit file. None means there is no ceiling at this level.

    A missing file is not an error. memory.max and memory.high exist only on non-root
    cgroups, so the v2 root genuinely has neither, and the memory controller has to be
    delegated before a child gets them at all.

    Every other failure is left to raise. Treating an unreadable or unparseable file as
    "no ceiling" is how one permission error becomes the largest possible permit count.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read().strip()
    except (FileNotFoundError, NotADirectoryError):
        return None
    if raw == "max":
        return _NO_LIMIT
    return int(raw)


def _cgroup_lines() -> list[str]:
    """The lines of /proc/self/cgroup.

    Left to raise. This is only read once a cgroup filesystem has been found mounted, so
    a process that cannot read its own membership has a measurement problem rather than
    an absent limit.
    """
    with open(os.path.join(PROC_DIR, "self", "cgroup"), encoding="utf-8") as handle:
        return handle.read().splitlines()


def _own_cgroup2_path() -> Optional[str]:
    """This process's cgroup, relative to the cgroup2 mount point."""
    for line in _cgroup_lines():
        parts = line.split(":", 2)
        # The unified hierarchy is the line with hierarchy id 0 and no controller name.
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            return parts[2]
    return None


def _own_cgroup1_path() -> Optional[str]:
    """This process's cgroup in the v1 memory hierarchy.

    The controller field lists every controller mounted together on that hierarchy, so
    the memory one is usually sharing a line and cannot be found by matching the field
    whole.
    """
    for line in _cgroup_lines():
        parts = line.split(":", 2)
        if len(parts) == 3 and "memory" in parts[1].split(","):
            return parts[2]
    return None


def _path_within_mount(membership: str, mount_root: str) -> Optional[str]:
    """Where a cgroup sits inside one mount, or None when that mount cannot show it.

    mountinfo field 4 says which part of the hierarchy a mount publishes. A mount rooted
    at /system.slice publishes /system.slice/shadow9.service as shadow9.service, so
    joining the membership path onto the mount point directly looks one level too deep,
    finds nothing, and reports no ceiling on a service that is firmly capped.
    """
    inside = "/" + membership.strip("/")
    root = "/" + mount_root.strip("/")
    # The kernel writes an unreachable root as a path of "..", which is what a mount
    # showing part of the tree outside this process's cgroup namespace looks like.
    # Nothing under it can be reached by name.
    if ".." in root.split("/"):
        return None
    if root == "/":
        return inside
    if inside == root:
        return "/"
    if inside.startswith(root + "/"):
        return inside[len(root) :]
    return None


def _tightest_limit(
    mounts: list[CgroupMount],
    membership: str,
    limit_names: tuple[str, ...],
    usage_name: str,
    limit_file_on_root: bool,
) -> CgroupLimit:
    """Walk from this process's cgroup to the top of every mount that can show it.

    Two things make the walk necessary. A ceiling set on an ancestor slice binds this
    process even though its own directory says unlimited, and a process moved into a
    nested cgroup may have no limit file of its own at all while the real ceiling sits
    on the parent. Reading only the process's own directory reports "unlimited" for a
    service that is firmly capped.

    Args:
        mounts: Every mount of this hierarchy, from _cgroup_mounts()
        membership: This process's cgroup path, from /proc/self/cgroup
        limit_names: Limit files to read at each level, the tightest winning
        usage_name: The file holding what a cgroup already uses
        limit_file_on_root: Whether the hierarchy root carries a limit file. cgroup v2
            does not, which is what makes the absence of one at the top of a mount the
            proof that the walk reached the real root rather than a namespace root that
            merely looks like it

    Raises:
        FileNotFoundError: No mount publishes a directory for this process's cgroup. The
            caller reads that as an unknown ceiling rather than an absent one
    """
    tightest = _NO_LIMIT
    usage = 0
    where = ""
    reached_true_root = False
    walked_any = False

    for mount in mounts:
        node = _path_within_mount(membership, mount.root)
        if node is None:
            continue
        # A missing limit file inside a cgroup directory is ordinary, and _read_limit_file
        # answers it with "no ceiling here". A missing directory is not ordinary: it means
        # the mount was unmounted, or this process left the cgroup, between mountinfo
        # being read and the walk starting. Every open below it would then raise
        # FileNotFoundError, the whole walk would read as "nothing is capping me", and the
        # top of an absent tree would look like the real root. Checked once per mount,
        # because every directory above an existing one exists by construction.
        if not os.path.isdir(os.path.join(mount.point, node.lstrip("/"))):
            continue
        walked_any = True
        while True:
            directory = os.path.join(mount.point, node.lstrip("/"))
            saw_limit_file = False
            for name in limit_names:
                value = _read_limit_file(os.path.join(directory, name))
                if value is None:
                    continue
                saw_limit_file = True
                if value < tightest:
                    tightest = value
                    where = os.path.join(directory, name)
                    usage = _read_limit_file(os.path.join(directory, usage_name)) or 0
            if node in ("/", ""):
                # The top of what this mount can show. It is the real root of the
                # hierarchy only when the mount publishes the whole tree, and on v2 only
                # when there is no limit file here: a cgroup namespace roots a process
                # at a cgroup that reports itself as "/" while still being a child with
                # a memory.max of its own and ancestors it is not allowed to see.
                at_root = "/" + mount.root.strip("/") == "/"
                if at_root and (limit_file_on_root or not saw_limit_file):
                    reached_true_root = True
                break
            node = os.path.dirname(node) or "/"

    if not walked_any:
        # This is only reached with a hierarchy mounted and this process listed in it, so
        # no mount being able to show it is a contradiction rather than an absence.
        raise FileNotFoundError(
            f"no mount of this hierarchy holds a directory for {membership}"
        )

    return CgroupLimit(
        limit_bytes=tightest,
        current_bytes=usage,
        where=where,
        ancestors_hidden=not reached_true_root,
    )


def _cgroup2_limit(mounts: list[CgroupMount]) -> Optional[CgroupLimit]:
    """The ceiling binding this process in the unified hierarchy.

    memory.high counts as well as memory.max. Passing memory.high does not kill the
    process, it puts it under permanent reclaim, and a proxy whose every relay stalls is
    an outage too.
    """
    membership = _own_cgroup2_path()
    if membership is None:
        return None
    return _tightest_limit(
        mounts,
        membership,
        limit_names=("memory.max", "memory.high"),
        usage_name="memory.current",
        limit_file_on_root=False,
    )


def _cgroup1_limit(mounts: list[CgroupMount]) -> Optional[CgroupLimit]:
    """The ceiling binding this process in the v1 memory hierarchy."""
    membership = _own_cgroup1_path()
    if membership is None:
        return None
    return _tightest_limit(
        mounts,
        membership,
        limit_names=("memory.limit_in_bytes",),
        usage_name="memory.usage_in_bytes",
        limit_file_on_root=True,
    )


def _meminfo() -> dict[str, int]:
    """Parse /proc/meminfo into bytes. The kernel prints these fields in kB.

    Left to raise on a read failure. Returning an empty result would make the machine
    look as though it has no memory, and no caller could tell that apart from a
    genuinely tiny box.
    """
    result: dict[str, int] = {}
    with open(os.path.join(PROC_DIR, "meminfo"), encoding="utf-8") as handle:
        for line in handle:
            key, _, rest = line.partition(":")
            parts = rest.split()
            if not parts:
                continue
            try:
                number = int(parts[0])
            except ValueError:
                continue
            unit = parts[1].lower() if len(parts) > 1 else "kb"
            result[key.strip()] = number * 1024 if unit == "kb" else number
    return result


def _address_space_limit() -> Optional[int]:
    """The soft RLIMIT_AS ceiling, or None where there is not one.

    ``ulimit -v`` caps the process itself rather than a cgroup, so nothing in /proc and
    nothing in the cgroup tree mentions it. A daemon started under ``ulimit -v 262144``
    on a 64 GiB host with no cgroup reads tens of gigabytes as a measured budget, allows
    itself sixteen concurrent hashes, and then has its allocations refused by the kernel
    at the fourth one.

    The figure is address space rather than resident memory, so it is larger than what
    the process will actually hold. That is the safe direction: it can only make this
    module hand out fewer permits than the limit would truly allow.
    """
    try:
        import resource
    except ImportError:
        # Not POSIX. Windows has its own reader and no getrlimit.
        return None
    soft, _ = resource.getrlimit(resource.RLIMIT_AS)
    if soft == resource.RLIM_INFINITY:
        return None
    return soft


def _narrowed_to_address_space(budget: MemoryBudget) -> MemoryBudget:
    """The same budget cut to RLIMIT_AS, where that is the tighter of the two.

    Left alone when there is no such limit or it is the looser one, so the ordinary host
    keeps the figure and the reason it already had.
    """
    address_space = _address_space_limit()
    if address_space is None or address_space >= budget.limit_bytes:
        return budget
    return MemoryBudget(
        limit_bytes=address_space,
        available_bytes=min(budget.available_bytes, address_space),
        source=f"RLIMIT_AS under {budget.source}",
        detail=(
            f"ulimit -v caps this process at {address_space // MIB} MiB, below "
            f"{budget.limit_bytes // MIB} MiB from {budget.detail}"
        ),
        current_bytes=budget.current_bytes,
        measured=budget.measured,
    )


def _linux_budget() -> MemoryBudget:
    """What this process may hold on Linux.

    Every measurement below can fail, and every failure produces the conservative figure
    rather than a host-sized one. An unreadable mountinfo, an unreadable memory.max and
    a procfs with no MemAvailable in it are all "I could not tell", and the largest
    possible answer is the one thing none of them mean.
    """
    try:
        info = _meminfo()
        total = info.get("MemTotal", 0)
        if "MemAvailable" in info:
            available = info["MemAvailable"]
            availability = ""
        elif "MemFree" in info:
            # Old and restricted procfs files omit MemAvailable. MemFree ignores
            # reclaimable page cache and so understates what a new allocation can have,
            # which is the safe direction to be wrong in. MemTotal is the unsafe one: it
            # is the size of the machine and says nothing about what is free on it.
            available = info["MemFree"]
            availability = "MemAvailable absent, available read from MemFree"
        else:
            return _unmeasured_budget("/proc/meminfo has neither MemAvailable nor MemFree")

        unified = _cgroup_mounts("cgroup2")
        legacy = _cgroup_mounts("cgroup", required_option="memory")
        if unified is None or legacy is None:
            return _unmeasured_budget("/proc/self/mountinfo could not be read")

        # Which hierarchy is mounted decides the label, not which lookup happened to
        # return a number: a v2 host with no ceiling set is still a v2 host.
        found: Optional[CgroupLimit] = None
        flavour = "no cgroups"
        if unified:
            flavour = "cgroup v2"
            found = _cgroup2_limit(unified)
        if found is None and legacy:
            # A hybrid host mounts both, and a process can be placed in the v1 memory
            # controller with no line in the unified hierarchy at all.
            flavour = "cgroup v1"
            found = _cgroup1_limit(legacy)
        if found is None and (unified or legacy):
            return _unmeasured_budget(
                f"{flavour} is mounted and this process's own cgroup is not in "
                f"/proc/self/cgroup"
            )

        limit = _NO_LIMIT
        usage = 0
        detail = f"{flavour}, no ceiling set"
        if found is not None:
            candidate = found.limit_bytes
            # A ceiling on a cgroup this process cannot see binds it exactly as hard as
            # one it can read, and nothing here can tell whether a hidden parent is
            # tighter than what is visible. A visible ceiling at or below the
            # conservative figure is still worth taking, because no hidden ancestor could
            # make it safe to plan for more than that; anything looser is a number that
            # may not be the one that binds, and sizing sixteen hashes against it is how
            # the process is killed inside a parent it never saw.
            #
            # The cost of this lands on a container started with a generous memory limit,
            # which drops to the conservative figure because its own cgroup is all it can
            # see. That is recoverable in one line, and the message says so.
            if found.ancestors_hidden and candidate > FALLBACK_BUDGET:
                visible = (
                    "no ceiling"
                    if candidate == _NO_LIMIT
                    else f"a {candidate // MIB} MiB ceiling at {found.where}"
                )
                return _unmeasured_budget(
                    f"{flavour} shows {visible} here, and a cgroup above this one is "
                    f"hidden from this process, so a tighter one may still be set. Set "
                    f"auth.max_concurrent_auth to size password hashing by hand"
                )
            if candidate == _NO_LIMIT:
                detail = f"{flavour}, no ceiling set"
            # cgroup v1 spells "unlimited" as a huge number rather than a word, and the
            # exact value moves with the page size, so hardcoding it breaks on a 64
            # KiB-page machine. Anything at or above physical RAM is not a ceiling worth
            # respecting, whatever its exact value, which also catches a limit set
            # larger than the box.
            elif total and candidate >= total:
                detail = f"{found.where} reads {candidate}, at or above MemTotal, so not a real ceiling"  # noqa: E501
            else:
                limit = candidate
                usage = found.current_bytes
                detail = f"{found.where} = {candidate}"

        if availability:
            detail = f"{detail}, {availability}"

        if limit == _NO_LIMIT:
            return _narrowed_to_address_space(
                MemoryBudget(
                    limit_bytes=total or available,
                    available_bytes=available,
                    source=f"/proc/meminfo ({flavour})",
                    detail=detail,
                )
            )
        return _narrowed_to_address_space(
            MemoryBudget(
                limit_bytes=limit,
                available_bytes=available,
                source=flavour,
                detail=detail,
                current_bytes=usage,
            )
        )
    except (OSError, ValueError) as e:
        # Reached only from a file that exists and would not be read or parsed. A
        # missing file is answered above, in the place that knows whether its absence is
        # ordinary.
        return _unmeasured_budget(f"a memory limit file could not be read ({e!r})")


def _windows_budget() -> MemoryBudget:
    """What this process may hold on Windows, from the machine's own figures.

    A Job Object memory limit is the Windows counterpart of a cgroup ceiling and is not
    read here. It is set by container runtimes and sandboxes rather than by hand, and
    this platform is where the CLI and the wizards run while the daemon runs under
    systemd, so the case does not arise on the deployment this sizing is for. Reading it
    would mean QueryInformationJobObject and two more ctypes structures for a ceiling
    nothing in this project sets. An operator who does set one caps password hashing with
    auth.max_concurrent_auth, which is honoured exactly as written.
    """
    import ctypes
    import ctypes.wintypes as wintypes

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # Declared rather than left to guesswork: ctypes defaults a return value to c_int,
    # which truncates a 64-bit result and hands back a plausible-looking zero instead of
    # failing, so an undeclared call reports a machine with no memory.
    kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL
    kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]

    status = MEMORYSTATUSEX()
    # The API versions its struct by size, and refuses the call without this.
    status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError(ctypes.get_last_error())

    return MemoryBudget(
        limit_bytes=status.ullTotalPhys,
        # ullAvailPhys is the closest thing Windows has to MemAvailable. The virtual
        # figures describe the 128 TiB address space and mean nothing as a budget.
        available_bytes=status.ullAvailPhys,
        source="GlobalMemoryStatusEx",
        detail=(
            f"total={status.ullTotalPhys} avail={status.ullAvailPhys} "
            f"load={status.dwMemoryLoad}%"
        ),
    )


def read_memory_budget() -> MemoryBudget:
    """How much memory this process may use, and where that number came from."""
    if sys.platform == "win32":
        try:
            return _windows_budget()
        except OSError as e:
            # A failed call says nothing about the size of the machine, so it cannot be
            # answered with a comfortable number and a shrug.
            return _unmeasured_budget(f"GlobalMemoryStatusEx failed ({e})")
    if sys.platform.startswith("linux"):
        return _linux_budget()
    # macOS and the BSDs have no cheap portable reader without a dependency. A fixed
    # conservative figure is better than a confident wrong one, and the operator setting
    # covers anyone who needs more.
    return _unmeasured_budget(f"no reader for {sys.platform}")


# Measured at 63 MiB of imports for the full application surface on Windows and 62.7 MiB
# of VmRSS for the same imports on Linux, so the two platforms agree and the reserve does
# not need to cover a difference between them. What the remaining margin covers is the
# event loop, the connection tables and the per-request objects a running daemon holds on
# top of its imports, none of which appear in a reading taken at startup. Kept at 160
# rather than cut to the measurement: this number is subtracted before permits are
# handed out, so setting it too low hands the difference to argon2 and moves the process
# towards the OOM kill it exists to prevent.
INTERPRETER_RESERVE = 160 * MIB

# Never plan to fill a cgroup to its edge. The per-hash figure is argon2's own
# allocation, and the kernel charges page cache and socket buffers to the same ceiling.
HEADROOM_FRACTION = 0.80

# Zero permits would mean nobody can ever log in, which fails silently and looks like a
# network fault. Serialised logins at roughly 90 ms each are still a working service.
MIN_PERMITS = 1

# argon2 is CPU-bound as well as memory-bound, so permits beyond the core count buy
# queueing and nothing else. The ceiling also caps what unauthenticated login attempts
# can make the process reserve.
MAX_PERMITS = 16


def argon2_bytes_per_hash() -> int:
    """Memory one concurrent argon2 verification reserves.

    Read from the hasher's own setting rather than restated here, so retuning argon2
    moves the permit count with it. Imported inside the function because the auth module
    pulls in argon2 and cryptography, which the config path should not have to load just
    to size itself.
    """
    from .auth import AuthManager

    return AuthManager.ARGON2_MEMORY_COST * 1024


def _baseline_bytes(budget: MemoryBudget) -> int:
    """Memory that is spoken for before any hashing, and cannot be planned twice.

    A cgroup ceiling covers every process in the unit, not this interpreter alone. The
    systemd unit starts Tor bridge processes into the same cgroup, and several hundred
    megabytes of Tor is several hundred megabytes this process may not have. What the
    cgroup already holds includes this interpreter, so it replaces the fixed estimate
    rather than adding to it.

    It is a reading taken once, at startup. A bridge started later is not in it, which
    is why the count is re-read rather than trusted for the life of the process.
    """
    return max(INTERPRETER_RESERVE, budget.current_bytes)


def _planned_bytes(budget: MemoryBudget, relay_reserve_bytes: int, permits: int) -> int:
    """Everything this process plans to hold at peak, hashing included."""
    return _baseline_bytes(budget) + relay_reserve_bytes + permits * argon2_bytes_per_hash()


def _over_ceiling(budget: MemoryBudget, relay_reserve_bytes: int, permits: int) -> bool:
    """Whether that plan does not fit in what this process may hold right now.

    Measured against the whole of it rather than against the headroom, so it stays a
    real safety signal instead of firing every time the arithmetic spends into the
    margin it deliberately keeps.

    Free memory is part of this, which makes it a reason to warn and not a reason to
    refuse: a machine whose page cache is full this second reports very little free and
    will report plenty a moment later. _over_limit is the question worth refusing over.
    """
    return _planned_bytes(budget, relay_reserve_bytes, permits) > budget.usable_bytes


def _over_limit(budget: MemoryBudget, relay_reserve_bytes: int, permits: int) -> bool:
    """Whether that plan does not fit under the limit itself.

    The limit is the part of the budget that will not move on its own: a cgroup ceiling,
    an RLIMIT_AS, or the size of the machine. A plan that does not fit under it will not
    come to fit by waiting, which is what separates the two questions. How much is free
    at this instant is deliberately not in it, because MemFree understates what an
    allocation can have and a process refused on that number would be refused every time
    the machine happened to be busy.
    """
    return _planned_bytes(budget, relay_reserve_bytes, permits) > budget.limit_bytes


def _shortfall(budget: MemoryBudget, relay_reserve_bytes: int, permits: int) -> str:
    """The sentence a permit count that does not fit has to carry with it.

    Reached by the two counts that are still used after failing this test: a number an
    operator set by hand, which is theirs to be wrong about, and the floor of one permit
    under a budget that was assumed rather than read. The auto-sized count under a real
    reading does not get here, because compute_hash_permits refuses to start instead.
    """
    if not _over_ceiling(budget, relay_reserve_bytes, permits):
        return ""
    planned = _planned_bytes(budget, relay_reserve_bytes, permits)
    return (
        f" This does not fit: {planned // MIB} MiB planned against a "
        f"{budget.usable_bytes // MIB} MiB ceiling, so the process may be killed under "
        f"load. Raise the memory limit, or lower argon2's memory cost."
    )


@dataclass(frozen=True)
class HashPermits:
    """How many password hashes may run at once, and why that number."""

    permits: int
    budget: MemoryBudget
    reason: str
    set_by_operator: bool
    # True when the interpreter, the relay buffers and these hashes together plan for
    # more than the ceiling allows. An operator setting a number by hand can do this, and
    # so can the floor of one permit under a budget that was assumed rather than read.
    # Neither is refused, and neither is hidden: this is what turns the log line from
    # information into a warning.
    exceeds_budget: bool = False


class MemoryCeilingTooLow(Exception):
    """The ceiling this process was given cannot hold even one password verification.

    Raised only where all three are true: the ceiling was read rather than assumed, the
    operator did not choose the permit count, and the interpreter, the relay buffers and
    a single argon2 hash do not fit under the limit together. The limit and not what is
    free this second, so a machine that is merely busy is never refused.

    Refusing to start is the lesser of the two outages on offer. Starting anyway means
    the first login allocates past the ceiling and the kernel kills the process, which
    takes every established connection with it and reads as a crash; and the process is
    then restarted into the same arithmetic. Refusing costs the same service and says
    exactly which number to change, at the moment somebody is watching.

    The two conditions on it are what keep it from firing on a working machine. An
    assumed budget is 256 MiB invented for a platform with no reader, and no process
    should be refused on the strength of a number this module made up; an operator who
    set the count has seen the machine and this code has not.
    """


def compute_hash_permits(
    budget: MemoryBudget,
    relay_reserve_bytes: int,
    cpu_count: Optional[int] = None,
) -> HashPermits:
    """Fit as many concurrent hashes as the budget allows, between the floor and ceiling.

    Args:
        budget: What this process may use, from read_memory_budget()
        relay_reserve_bytes: Memory the connection relay holds at full load, which the
            hashing must not eat into. Zero for a process that relays nothing.
        cpu_count: Cores to size the ceiling against, or None to ask the machine

    Raises:
        MemoryCeilingTooLow: A ceiling that was read rather than assumed has no room in
            it for one hash, so there is no permit count this process could start with
    """
    per_hash = argon2_bytes_per_hash()
    spendable = int(budget.usable_bytes * HEADROOM_FRACTION)
    baseline = _baseline_bytes(budget)
    for_hashing = spendable - baseline - relay_reserve_bytes

    if for_hashing < per_hash:
        if budget.measured and _over_limit(budget, relay_reserve_bytes, MIN_PERMITS):
            planned = _planned_bytes(budget, relay_reserve_bytes, MIN_PERMITS)
            raise MemoryCeilingTooLow(
                f"There is not enough memory here to verify one password. "
                f"{planned // MIB} MiB is needed: {baseline // MIB} MiB for the "
                f"interpreter and the running daemon, {relay_reserve_bytes // MIB} MiB "
                f"of relay buffers, and {per_hash // MIB} MiB for a single argon2 hash. "
                f"The limit is {budget.limit_bytes // MIB} MiB, read from "
                f"{budget.source} ({budget.detail}). Raise that limit above "
                f"{planned // MIB} MiB, or lower server.max_connections, or lower "
                f"argon2's memory cost, or set auth.max_concurrent_auth to start with a "
                f"number you have chosen and accept the risk."
            )
        return HashPermits(
            permits=MIN_PERMITS,
            budget=budget,
            set_by_operator=False,
            exceeds_budget=_over_ceiling(budget, relay_reserve_bytes, MIN_PERMITS),
            reason=(
                f"{MIN_PERMITS} permit, the floor: only {for_hashing // MIB} MiB is left of "
                f"{budget.usable_bytes // MIB} MiB after {baseline // MIB} MiB "
                f"interpreter and {relay_reserve_bytes // MIB} MiB relay buffers, which is "
                f"less than the {per_hash // MIB} MiB one hash needs. "
                f"Budget from {budget.source}."
                + _shortfall(budget, relay_reserve_bytes, MIN_PERMITS)
            ),
        )

    by_memory = for_hashing // per_hash
    cores = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    permits = max(MIN_PERMITS, min(by_memory, cores, MAX_PERMITS))

    if permits == by_memory:
        bound_by = f"memory ({for_hashing // MIB} MiB / {per_hash // MIB} MiB)"
    elif permits == cores:
        bound_by = f"cpu count ({cores})"
    else:
        bound_by = f"ceiling ({MAX_PERMITS})"

    return HashPermits(
        permits=permits,
        budget=budget,
        set_by_operator=False,
        exceeds_budget=_over_ceiling(budget, relay_reserve_bytes, permits),
        reason=(
            f"{permits} permits = {permits * per_hash // MIB} MiB of password hashing, "
            f"bound by {bound_by}. Budget {budget.usable_bytes // MIB} MiB from "
            f"{budget.source}."
            + _shortfall(budget, relay_reserve_bytes, permits)
        ),
    )


def choose_hash_permits(
    configured: Optional[int],
    relay_reserve_bytes: int,
    budget: Optional[MemoryBudget] = None,
    cpu_count: Optional[int] = None,
) -> HashPermits:
    """Decide the permit count, honouring an operator who set one.

    An explicit setting is used exactly as written, including one this arithmetic would
    call too large: the operator can see their machine and this code cannot, and a
    number quietly overridden is worse than a number that is wrong on purpose.

    Args:
        configured: auth.max_concurrent_auth, or None when the operator left it unset
        relay_reserve_bytes: Memory the connection relay holds at full load
        budget: A budget already read, or None to read one now
        cpu_count: Cores to size the ceiling against, or None to ask the machine

    Raises:
        ValueError: configured is below one. Zero builds a permit pool nobody can ever
            take from, so every login waits for a slot that is never released and the
            proxy accepts connections while authenticating none of them.
    """
    if configured is not None and configured < 1:
        raise ValueError(
            f"auth.max_concurrent_auth must be at least 1, got {configured}. "
            f"Zero or fewer permits stops every password verification for good. "
            f"Leave it unset to size it from the memory this process may use."
        )

    if budget is None:
        budget = read_memory_budget()

    if configured is not None:
        per_hash = argon2_bytes_per_hash()
        return HashPermits(
            permits=configured,
            budget=budget,
            set_by_operator=True,
            exceeds_budget=_over_ceiling(budget, relay_reserve_bytes, configured),
            reason=(
                f"{configured} permits = {configured * per_hash // MIB} MiB of password "
                f"hashing, set explicitly as auth.max_concurrent_auth. "
                f"Budget {budget.usable_bytes // MIB} MiB from {budget.source}."
                + _shortfall(budget, relay_reserve_bytes, configured)
            ),
        )

    return compute_hash_permits(
        budget,
        relay_reserve_bytes=relay_reserve_bytes,
        cpu_count=cpu_count,
    )
