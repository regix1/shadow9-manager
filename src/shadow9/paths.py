"""
Centralized path management for Shadow9.

This module provides a single source of truth for all file paths used by Shadow9.
It ensures consistent path resolution regardless of where commands are run from.

The install directory priority is:
1. SHADOW9_HOME environment variable (if set)
2. /opt/shadow9-manager (Linux system install)
3. ~/shadow9-manager (User install)
4. Package location (development/local install)
"""

import os
import secrets
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import structlog

try:
    import fcntl
except ImportError:  # not on Windows
    fcntl = None

try:
    import msvcrt
except ImportError:  # not on POSIX
    msvcrt = None

logger = structlog.get_logger(__name__)


class Shadow9Paths:
    """
    Centralized path manager for Shadow9.

    All paths are relative to a single root directory that is determined
    once and used consistently throughout the application.
    """

    _instance: Optional["Shadow9Paths"] = None

    # Set by _initialize, which __new__ runs before any caller can reach an instance, so
    # every property below really does return a Path. Declaring it Optional here made all
    # of them return Path | None against a signature promising Path, and pushed a check
    # nothing can ever fail onto every call site.
    _root: Path

    # Standard directory names
    CONFIG_DIR = "config"
    USERS_DIR = "users"
    LOGS_DIR = "logs"

    # Standard file names
    ENV_FILE = ".env"
    CREDENTIALS_FILE = "credentials.enc"
    SALT_FILE = ".salt"
    CONFIG_FILE = "config.yaml"

    def __new__(cls):
        """Singleton pattern to ensure consistent paths across the application."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize the path manager by finding the root directory."""
        self._root = self._find_root()

        # Ensure critical directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.users_dir.mkdir(parents=True, exist_ok=True)

    def _find_root(self) -> Path:
        """
        Find the Shadow9 root directory.

        Priority order:
        1. SHADOW9_HOME environment variable
        2. /opt/shadow9-manager (if .env or config exists there)
        3. Current package location (if .env or config exists there)
        4. ~/shadow9-manager (user install location)
        5. Create at /opt/shadow9-manager (Linux) or ~/shadow9-manager (other)
        """
        # Check environment variable first
        if env_home := os.getenv("SHADOW9_HOME"):
            path = Path(env_home)
            if path.exists():
                return path.resolve()

        # Standard install locations to check
        check_locations = [
            Path("/opt/shadow9-manager"),  # Linux system install
            Path("/root/shadow9-manager"),  # Root user install
            self._get_package_location(),  # Package/dev location
            Path.home() / "shadow9-manager",  # User home install
        ]

        # Find first location that has .env or config directory
        for loc in check_locations:
            if loc and loc.exists():
                if (loc / self.ENV_FILE).exists() or (loc / self.CONFIG_DIR).exists():
                    return loc.resolve()

        # If nothing found, use the first writable location
        # Prefer /opt on Linux for system-wide install
        if sys.platform == "linux":
            default = Path("/opt/shadow9-manager")
        else:
            default = Path.home() / "shadow9-manager"

        # If package location exists and has files, prefer it
        pkg_loc = self._get_package_location()
        if pkg_loc and pkg_loc.exists():
            return pkg_loc.resolve()

        return default.resolve()

    def _get_package_location(self) -> Optional[Path]:
        """Get the package installation location (parent of src directory)."""
        # Go from src/shadow9/paths.py -> project root
        current = Path(__file__).resolve()
        # paths.py -> shadow9 -> src -> project_root
        project_root = current.parent.parent.parent

        # Verify it looks like a valid project root
        if (project_root / "src" / "shadow9").is_dir():
            return project_root

        return None

    @property
    def root(self) -> Path:
        """Get the Shadow9 root directory."""
        return self._root

    @property
    def config_dir(self) -> Path:
        """Get the config directory path."""
        return self._root / self.CONFIG_DIR

    @property
    def users_dir(self) -> Path:
        """Get the users directory path."""
        return self._root / self.USERS_DIR

    @property
    def logs_dir(self) -> Path:
        """Get the logs directory path."""
        return self._root / self.LOGS_DIR

    @property
    def env_file(self) -> Path:
        """Get the .env file path."""
        return self._root / self.ENV_FILE

    @property
    def credentials_file(self) -> Path:
        """Get the encrypted credentials file path."""
        return self.config_dir / self.CREDENTIALS_FILE

    @property
    def salt_file(self) -> Path:
        """Get the encryption salt file path."""
        return self.config_dir / self.SALT_FILE

    @property
    def config_file(self) -> Path:
        """Get the main config.yaml file path."""
        return self.config_dir / self.CONFIG_FILE

    # Bridge cache file name
    BRIDGE_CACHE_FILE = "bridge_cache.json"

    @property
    def bridge_cache_file(self) -> Path:
        """Get the bridge cache file path (in config directory)."""
        return self.config_dir / self.BRIDGE_CACHE_FILE

    def get_user_dir(self, username: str) -> Path:
        """
        Get the directory for a specific user.

        Args:
            username: The username

        Returns:
            Path to the user's directory

        Raises:
            ValueError: If the username is not a plain name, or if joining it onto the
                users directory would land outside that directory
        """
        # a pathlib join is absolute-overriding, so "/etc" would yield "/etc" and the
        # result feeds shutil.rmtree in delete_user_dir
        if not username or username in (".", "..") or "/" in username or "\\" in username:
            raise ValueError(f"Invalid username for a user directory: {username!r}")

        user_dir = self.users_dir / username
        users_root = self.users_dir.resolve()
        if users_root not in user_dir.resolve().parents:
            raise ValueError(f"Username escapes the users directory: {username!r}")

        return user_dir

    def get_user_credentials_file(self, username: str) -> Path:
        """
        Get the plaintext credentials file for a user (optional save).

        Args:
            username: The username

        Returns:
            Path to the user's plaintext credentials file
        """
        return self.get_user_dir(username) / "credentials.txt"

    def get_user_config_file(self, username: str) -> Path:
        """
        Get the user-specific config file path.

        Args:
            username: The username

        Returns:
            Path to the user's config file
        """
        return self.get_user_dir(username) / "config.yaml"

    def ensure_user_dir(self, username: str) -> Path:
        """
        Ensure the user directory exists and return its path.

        Args:
            username: The username

        Returns:
            Path to the user's directory
        """
        user_dir = self.get_user_dir(username)
        user_dir.mkdir(parents=True, exist_ok=True)

        # Set restrictive permissions on Unix
        if os.name != "nt":
            try:
                os.chmod(user_dir, 0o700)
            except Exception:
                pass

        return user_dir

    def save_user_credentials(
        self,
        username: str,
        password: str,
        routing: str,
        security: str,
        bind_port: Optional[int] = None,
        allowed_ports: Optional[list[int]] = None,
        rate_limit: Optional[int] = None,
    ) -> Path:
        """
        Save user credentials to their user folder.

        Args:
            username: The username
            password: The plaintext password
            routing: The routing description (e.g., "Tor + obfs4")
            security: The security level
            bind_port: Optional custom bind port
            allowed_ports: Optional list of allowed ports
            rate_limit: Optional rate limit

        Returns:
            Path to the saved credentials file
        """
        from datetime import datetime

        self.ensure_user_dir(username)
        cred_file = self.get_user_credentials_file(username)

        content = f"""Shadow9 User Credentials
========================
Username: {username}
Password: {password}

Settings:
- Routing: {routing}
- Security: {security}
"""
        if bind_port:
            content += f"- Bind Port: {bind_port}\n"
        if allowed_ports:
            content += f"- Allowed Ports: {', '.join(map(str, allowed_ports))}\n"
        if rate_limit:
            content += f"- Rate Limit: {rate_limit} req/min\n"

        content += f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

        write_file_safely(cred_file, content.encode())

        return cred_file

    def delete_user_dir(self, username: str) -> bool:
        """
        Delete a user's directory and all its contents.

        Args:
            username: The username

        Returns:
            True if deleted, False if didn't exist
        """
        import shutil

        user_dir = self.get_user_dir(username)

        if user_dir.exists():
            shutil.rmtree(user_dir)
            return True
        return False

    def resolve_path(self, relative_path: str) -> Path:
        """
        Resolve a relative path against the root directory.

        Args:
            relative_path: Path relative to root, or absolute path

        Returns:
            Resolved absolute path
        """
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return self._root / path

    def load_master_key(self) -> Optional[str]:
        """
        Load the master key from environment or .env file.

        Returns:
            The master key if found, None otherwise
        """
        # Check environment first
        if master_key := os.getenv("SHADOW9_MASTER_KEY"):
            return master_key

        # Check .env file
        if self.env_file.exists():
            try:
                for line in self.env_file.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("SHADOW9_MASTER_KEY="):
                        return line.split("=", 1)[1].strip()
            except Exception as e:
                # returning None here means the credentials file cannot be decrypted later,
                # so the reason has to reach the log rather than being swallowed
                logger.error(
                    "Failed to read master key from .env", path=str(self.env_file), error=str(e)
                )

        return None

    def __repr__(self) -> str:
        return f"Shadow9Paths(root={self._root})"


def write_file_safely(path: Path, data: bytes, mode: int = 0o600) -> None:
    """
    Write to a temp file in the same directory, flush it to disk, then rename over the target.

    os.replace is atomic on the same filesystem, so a reader sees either the whole old file or
    the whole new one. A process killed mid-write leaves the temp file behind and the target
    untouched, instead of a truncated target that cannot be read back.

    Args:
        path: The file to write
        data: The bytes to write
        mode: Permission bits for the new file. On Unix these are applied before any content
            exists. On Windows they only ever toggled the read-only attribute, so they are
            close to decorative there and are not what keeps the file private
    """
    created = _make_directory(path.parent)

    fd, temp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    temp_path = Path(temp_name)
    # Nothing else closes this descriptor until os.fdopen takes it over, so a failure
    # before that point has to close it here or the process leaks one per attempt
    descriptor_is_ours = True
    try:
        # ask for the call rather than the platform: os.fchmod is absent on Windows before
        # 3.13, and this picks the real one up by itself once it is there. mkstemp already
        # created the file 0600, so the fallback path is not an open window either
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)

        with os.fdopen(fd, "wb") as handle:
            descriptor_is_ours = False
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        if not hasattr(os, "fchmod"):
            # no descriptor form available, so this has to wait until the handle is closed
            os.chmod(temp_path, mode)

        os.replace(temp_path, path)
    except BaseException:
        # Windows refuses to replace a file another process holds open without
        # FILE_SHARE_DELETE, and scanners take transient handles on new files. The target
        # keeps its old contents whatever happens here, so the caller has to hear about it.
        if descriptor_is_ours:
            # closing first, because Windows will not unlink a file that is still open
            os.close(fd)
        logger.error("Failed to write file", path=str(path))
        temp_path.unlink(missing_ok=True)
        raise

    _sync_directory(path.parent)
    # a directory this call created is itself only a name in its own parent, and that
    # name is as easy to lose to a power cut as the file's is
    for directory in created:
        _sync_directory(directory.parent)


def _make_directory(directory: Path) -> list[Path]:
    """
    Create `directory` and any missing parent, and report which ones did not exist.

    The caller flushes the parent of each one. Their names have to reach the disk too, or
    a power cut can leave a durable file inside a directory that is not there any more.

    Args:
        directory: The directory to create

    Returns:
        The directories that were created, deepest first
    """
    created: list[Path] = []
    probe = directory
    while not probe.exists():
        created.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent

    directory.mkdir(parents=True, exist_ok=True)
    return created


def _sync_directory(directory: Path) -> None:
    """
    Flush the directory entry so a rename that already happened survives power loss.

    fsync on the file covers its contents, not the name pointing at it. This runs after the
    rename is committed and visible, and not every filesystem accepts fsync on a directory,
    so a failure here costs durability and must not turn a finished write into a failed one.
    """
    if not hasattr(os, "O_DIRECTORY"):
        # Windows cannot open a directory as a file
        return

    try:
        fd = os.open(str(directory), os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as e:
        logger.warning("Could not flush the directory entry", path=str(directory), error=str(e))


# How long a caller waits for a file another process is changing. Long enough to sit
# through a slow disk, short enough that a holder which is never going to let go turns
# into an error somebody can read instead of a process that hangs for ever.
LOCK_TIMEOUT_SECONDS = 10.0

# Neither flock nor msvcrt.locking accepts a deadline, so waiting is a retry loop.
_LOCK_RETRY_SECONDS = 0.02

_locks: dict[Path, "_FileLock"] = {}
_locks_guard = threading.Lock()
_lock_support_warned = False

# Held while a lock file is opened and its descriptor recorded on the _FileLock, and held
# by the fork handlers for the length of a fork. A fork landing between those two steps
# hands the child a descriptor no lock object names, and the child's handler can only
# close what it can find. What flock belongs to is the open file description the two of
# them share, so a parent that then died without unlocking would leave that invisible
# copy holding the file for good and every later change in the child waiting out its
# timeout. Waiting for another process to let go stays outside this, so a fork never
# queues behind a lock somebody else is holding.
_fork_guard = threading.Lock()


class _FileLock:
    """One process's hold on one lock file.

    The operating system's lock belongs to the open descriptor, not to the process, so
    two threads here opening the file twice would each get a lock of their own and
    neither would exclude the other. Threads queue on the re-entrant guard first and only
    the outermost holder opens the file, which also makes a locked section that nests
    inside another one free instead of a deadlock against itself.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._guard = threading.RLock()
        self._depth = 0
        self._descriptor: Optional[int] = None
        self._abandoned = False

    def acquire(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        if not self._guard.acquire(timeout=timeout):
            raise TimeoutError(
                f"Waited {timeout}s for {self.path} and another thread still holds it"
            )
        try:
            if self._depth == 0:
                self._open_and_lock(deadline)
            self._depth += 1
        except BaseException:
            self._guard.release()
            raise

    def release(self) -> None:
        if self._abandoned:
            # A fork took this one away mid-`with`, so the descriptor is already closed
            # and the guard being unwound belongs to a thread in the other process.
            # Whoever is still inside the `with` here has nothing left to give back.
            return

        try:
            self._depth -= 1
            if self._depth == 0 and self._descriptor is not None:
                descriptor, self._descriptor = self._descriptor, None
                _release_descriptor(descriptor)
        finally:
            self._guard.release()

    def abandon_after_fork(self) -> None:
        """Drop the child's copy of an inherited lock without releasing it.

        fork() hands the child the parent's descriptors, and on POSIX the two of them are
        one open file description, so the lock belongs to both. An explicit unlock on the
        child's copy would free the file for a third process while the parent is still
        inside its critical section, which is worse than the bug being fixed. Closing is
        not an unlock while the parent's own descriptor is still open, so the child closes
        and forgets: it holds nothing, and its next caller either takes the lock properly
        or waits out the timeout for the parent to finish.
        """
        descriptor, self._descriptor = self._descriptor, None
        self._depth = 0
        self._abandoned = True

        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                # No log line: this runs in a just-forked child, where writing anywhere
                # can wait on a lock a thread that no longer exists was holding. The only
                # way this fails is a descriptor that is already gone, which is the state
                # being asked for anyway.
                pass

    def _open_and_lock(self, deadline: float) -> None:
        """Take the interprocess lock and record the descriptor that now holds it.

        Recording happens under _fork_guard together with the open that produced it,
        rather than after the wait finishes, because a descriptor no lock object names is
        one the child of a fork can never close.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)

        while True:
            with _fork_guard:
                descriptor = os.open(str(self.path), os.O_RDWR | os.O_CREAT, 0o600)
                self._descriptor = descriptor

            try:
                self._wait_for_the_lock(descriptor, deadline)
            except BaseException:
                with _fork_guard:
                    self._descriptor = None
                    os.close(descriptor)
                raise

            if _is_the_file_at(descriptor, self.path):
                return

            # The sidecar was replaced or unlinked between the open and the lock, so what
            # is held is an inode no later process will reach and it excludes nobody.
            # Whoever created the replacement is inside its own section already. Start
            # again on whatever is at the name now, which is the file that will exclude.
            logger.warning(
                "The lock file was replaced while it was being taken, so it is being taken again",
                path=str(self.path),
            )
            with _fork_guard:
                self._descriptor = None
                _release_descriptor(descriptor)

            if time.monotonic() >= deadline:
                raise TimeoutError(f"Waited for {self.path} and it kept being replaced")
            time.sleep(_LOCK_RETRY_SECONDS)

    def _wait_for_the_lock(self, descriptor: int, deadline: float) -> None:
        """Block until `descriptor` holds the lock, or raise once `deadline` has passed."""
        # Windows locks a range of bytes rather than the file itself, but it allows a
        # range past the end of the file, so an empty lock file locks fine. Putting a
        # byte in it first only added a write nobody holds the lock for: two processes
        # that both find the file empty race, and the one that writes second is
        # refused outright instead of waiting its turn in the loop below.
        while True:
            try:
                _lock_descriptor(descriptor)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Waited for {self.path} and another process still holds it"
                    ) from None
                time.sleep(_LOCK_RETRY_SECONDS)


def _is_the_file_at(descriptor: int, path: Path) -> bool:
    """True when the locked descriptor is still the file that `path` names.

    What both platforms lock is the open file, not the name. A sidecar unlinked or
    replaced between the open and the lock leaves this descriptor holding an inode
    nothing else will ever open, so two processes end up inside at once with nothing to
    say so. Asking after the lock is taken catches that ordering.

    It cannot catch a sidecar removed while it is already held: the holder is inside its
    section by then and has nothing left to check. Nothing on POSIX can, which is why
    lock_file says these files have to stay put.
    """
    try:
        held = os.fstat(descriptor)
        named = os.stat(str(path))
    except OSError:
        # the name leads nowhere now, so it certainly does not lead here
        return False

    return (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)


def _lock_descriptor(descriptor: int) -> None:
    """Take the exclusive lock, or raise OSError when somebody else holds it."""
    global _lock_support_warned

    if fcntl is not None:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    elif msvcrt is not None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
    elif not _lock_support_warned:
        _lock_support_warned = True
        logger.warning(
            "This build has neither fcntl nor msvcrt, so files shared with another "
            "process are only protected against other threads here"
        )


def _release_descriptor(descriptor: int) -> None:
    """Drop the lock and close the descriptor.

    Both platforms also drop it when the descriptor closes and when the process dies, so
    a crash cannot leave a lock behind that keeps every later start out.
    """
    try:
        if fcntl is not None:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif msvcrt is not None:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    except OSError as e:
        # the close below releases it anyway, so this costs nothing but a log line
        logger.warning("Could not release the file lock", path=str(descriptor), error=str(e))
    finally:
        os.close(descriptor)


def _forget_locks_after_fork() -> None:
    """Start the child of a fork holding nothing, with a guard nobody is inside.

    A child inherits the whole table and the mutex that protects it. Two things go wrong
    without this. The guard first: if another thread held it at the moment of the fork it
    stays held for ever in the child, because that thread does not exist there, and a
    caller queueing behind it waits outside the timeout lock_file promises rather than
    getting the TimeoutError the timeout is for. The descriptors are worse: they are the
    parent's locks rather than copies of them, so the child would find a table saying it
    already holds every file the parent holds, skip the operating system entirely and walk
    into a critical section the parent is still inside. Two writers in one section is the
    lost update this lock exists to prevent.

    It matters because uvicorn starts its extra workers by forking on Linux, so with
    WEB_CONCURRENCY above one every worker but the first is a child of a process that had
    already built this table.
    """
    global _locks_guard

    inherited = list(_locks.values())
    _locks.clear()
    # A just-forked child has one thread, so nothing here is competing for the new mutex
    # and nothing is left waiting on the old one.
    _locks_guard = threading.Lock()

    for lock in inherited:
        lock.abandon_after_fork()


def _hold_locks_across_a_fork() -> None:
    """Keep a fork out of the window where a descriptor is open but not yet recorded."""
    _fork_guard.acquire()


def _resume_locks_after_a_fork() -> None:
    """Let the parent's other threads open lock files again."""
    _fork_guard.release()


def _reset_locks_in_the_child() -> None:
    """Give the guard back in the child's copy of it, then start the child holding nothing."""
    _fork_guard.release()
    _forget_locks_after_fork()


if hasattr(os, "register_at_fork"):
    # POSIX only; on Windows there is no fork for these to run around
    os.register_at_fork(
        before=_hold_locks_across_a_fork,
        after_in_parent=_resume_locks_after_a_fork,
        after_in_child=_reset_locks_in_the_child,
    )


@contextmanager
def lock_file(path: Path, timeout: float = LOCK_TIMEOUT_SECONDS) -> Iterator[None]:
    """
    Hold every other process out of `path` for the body of the `with`.

    The lock is taken on a sidecar file beside the target rather than on the target
    itself, because an atomic write replaces the target with a different file and any
    lock held on the old one would go with it.

    A change to a shared file has to hold this from before it re-reads the file until
    after it has replaced it. Locking only the write is no protection at all: two writers
    a second apart never overlap, and the later one still replaces the file with a table
    it read before the earlier one wrote.

    The lock file itself has to stay put for as long as anything is running. What both
    platforms lock is the open file, not the name, so on POSIX a tidy-up job that
    unlinks or replaces the sidecar leaves the holder locking a file nobody can reach:
    the next process creates a new one, locks that instead, and the two of them are
    inside at the same time with nothing to say so. It is empty and tiny, and it belongs
    to the directory it protects. Windows will not normally let it be replaced while a
    handle is open, so this is a POSIX hazard.

    Half of that is now caught. A caller checks after taking the lock that what it holds
    is still the file the name leads to, and starts again when it is not, which covers
    the removal that lands while somebody is waiting. The other half is not reachable
    from here: a sidecar removed while a process is already inside its section leaves
    that process with nothing left to check, and it finds out only by having its work
    overwritten. Removing these files while Shadow9 is running is the operator's one
    hard rule; deleting them with the service stopped is fine and costs nothing.

    Args:
        path: The file being protected. The lock file sits next to it.
        timeout: Seconds to wait before giving up

    Raises:
        TimeoutError: when the lock is still held after `timeout` seconds
    """
    lock_path = Path(os.path.abspath(str(path)))
    lock_path = lock_path.with_name(lock_path.name + ".lock")

    with _locks_guard:
        lock = _locks.get(lock_path)
        if lock is None:
            lock = _FileLock(lock_path)
            _locks[lock_path] = lock

    lock.acquire(timeout)
    try:
        yield
    finally:
        lock.release()


# How much key-derivation salt a fresh install generates.
SALT_BYTES = 32


def read_or_create_salt(path: Path) -> bytes:
    """
    Read the key-derivation salt at `path`, generating it once if it is not there yet.

    Every process that derives a key from this salt has to end up with the same bytes.
    Looking for the file and then writing it is not enough: two processes starting
    together both find it missing, both generate a salt and both write it. The second
    one wins on disk, and whatever the first wrote with its own key can never be
    decrypted again. Generating happens under the file's lock instead, so whoever gets
    there second reads what the winner wrote rather than making a salt of its own.

    An empty file counts as no salt, so a process killed between creating the file and
    filling it does not leave every later start deriving its key from nothing.

    Args:
        path: Where the salt lives

    Returns:
        The salt bytes every process derives its key from
    """
    salt = _read_salt(path)
    if salt:
        return salt

    with lock_file(path):
        salt = _read_salt(path)
        if salt:
            return salt

        salt = secrets.token_bytes(SALT_BYTES)
        # a half-written salt makes everything stored under it permanently undecryptable
        write_file_safely(path, salt)
        logger.info("Generated a key-derivation salt", path=str(path))

    return salt


def _read_salt(path: Path) -> bytes:
    """The salt on disk, or empty bytes when there is not one to read yet.

    Only a missing file counts as absent. A salt that is there but unreadable has to
    raise, because generating a replacement would silently orphan everything the real
    one encrypted.
    """
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return b""


def resolve_salt_file(credentials_file: Path) -> Path:
    """
    Where the salt for one credentials file lives.

    The proxy and the API derive their key from the same master key and have to agree on
    this path or each rejects what the other wrote. They did not agree: one always took
    the install's own salt and the other always took the credentials file's directory,
    which are the same place only while the credentials file sits where the install put it.

    An existing salt is never moved. A store that cannot find its salt can never read
    what it wrote, so a salt already next to the credentials file wins: it is the best
    evidence there is about which key wrote that particular file. For a credentials file
    still sitting where the install put it the two are the same path anyway, so an
    ordinary install is not affected either way.

    Args:
        credentials_file: The credentials file whose salt is wanted

    Returns:
        The salt path both entry points will agree on
    """
    beside_credentials = credentials_file.parent / Shadow9Paths.SALT_FILE
    if beside_credentials.exists():
        return beside_credentials

    return get_paths().salt_file


# Module-level convenience functions
def get_paths() -> Shadow9Paths:
    """Get the singleton Shadow9Paths instance."""
    return Shadow9Paths()


def get_root() -> Path:
    """Get the Shadow9 root directory."""
    return get_paths().root


def get_credentials_file() -> Path:
    """Get the credentials file path."""
    return get_paths().credentials_file


def get_config_dir() -> Path:
    """Get the config directory path."""
    return get_paths().config_dir


def get_bridge_cache_file() -> Path:
    """Get the bridge cache file path."""
    return get_paths().bridge_cache_file


def get_users_dir() -> Path:
    """Get the users directory path."""
    return get_paths().users_dir


def load_master_key() -> Optional[str]:
    """Load the master key."""
    return get_paths().load_master_key()
