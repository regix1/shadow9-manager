"""Tests for authentication module."""

import asyncio
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import AbstractContextManager
from datetime import datetime
from pathlib import Path

import pytest
from argon2 import PasswordHasher

import shadow9.auth as auth_module
import shadow9.paths as paths_module
from shadow9.auth import AuthManager, Credential as StoredCredential
from shadow9.models.user import Credential
from shadow9.paths import get_paths, lock_file, read_or_create_salt, write_file_safely
from shadow9.repositories.user_repository import UserRepository
from shadow9.wireguard.addresses import parse_address, parse_network
from shadow9.wireguard.keys import generate_keypair
from shadow9.wireguard.render import Peer, PeerRole, Topology


# cheap enough that a test can afford one per credential, and still the encoded shape the
# store checks a record against when it reads the file back
_CHEAP_HASHER = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def _credential(username: str) -> Credential:
    """Build a credential without paying for a full-cost Argon2 hash."""
    return Credential(username=username, password_hash=_CHEAP_HASHER.hash(username))


def _truncate(path: Path) -> None:
    """Cut a file in half, the way a process killed mid-write leaves it."""
    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) // 2])


def _bump_mtime(path: Path, seconds: float = 10.0) -> None:
    """Push a file's mtime forward so a reload cannot miss the change."""
    stamp = time.time() + seconds
    os.utime(path, (stamp, stamp))


def _reap(child: int, seconds: float) -> int | None:
    """Wait for `child` to exit and answer its status, or kill it and answer None.

    A child that inherited a held guard waits for a thread that does not exist in it, so
    the failure being tested for looks like a wait that never ends. Bounding it here is
    what turns that into a test result instead of a run that has to be killed by hand.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        done, status = os.waitpid(child, os.WNOHANG)
        if done:
            return status
        time.sleep(0.05)

    os.kill(child, signal.SIGKILL)
    os.waitpid(child, 0)
    return None


class TestAuthManager:
    """Tests for AuthManager."""

    def test_add_user(self, tmp_path):
        """Test adding a new user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        result = auth.add_user("testuser", "SecurePass123!@#")
        assert result is True
        assert "testuser" in auth.list_users()

    def test_add_duplicate_user(self, tmp_path):
        """Test adding a duplicate user fails."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.add_user("testuser", "AnotherPass123!@#")
        assert result is False

    def test_verify_correct_password(self, tmp_path):
        """Test verification with correct password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.verify("testuser", "SecurePass123!@#")
        assert result is True

    def test_verify_wrong_password(self, tmp_path):
        """Test verification with wrong password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.verify("testuser", "WrongPassword123!@#")
        assert result is False

    def test_verify_nonexistent_user(self, tmp_path):
        """Test verification for non-existent user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        result = auth.verify("nonexistent", "AnyPassword123!@#")
        assert result is False

    def test_remove_user(self, tmp_path):
        """Test removing a user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.remove_user("testuser")
        assert result is True
        assert "testuser" not in auth.list_users()

    def test_generate_credentials(self, tmp_path):
        """Test generating random credentials."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        username, password = auth.generate_credentials()
        assert len(username) > 0
        assert len(password) >= 12  # Minimum secure password length
        # Verify password meets requirements
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)

    def test_invalid_username(self, tmp_path):
        """Test adding user with invalid username."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        with pytest.raises(ValueError):
            auth.add_user("ab", "SecurePass123!@#")  # Too short

    def test_weak_password(self, tmp_path):
        """Test adding user with weak password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        with pytest.raises(ValueError):
            auth.add_user("testuser", "weak")

    def test_persistence(self, tmp_path):
        """Test that credentials persist across instances."""
        creds_file = tmp_path / "credentials.enc"

        # Create user with first instance
        auth1 = AuthManager(credentials_file=creds_file)
        auth1.add_user("testuser", "SecurePass123!@#")

        # Verify with second instance
        auth2 = AuthManager(credentials_file=creds_file)
        result = auth2.verify("testuser", "SecurePass123!@#")
        assert result is True

    def test_encrypted_persistence(self, tmp_path):
        """Test encrypted credential storage."""
        creds_file = tmp_path / "credentials.enc"
        master_key = "test_master_key_12345"

        # Create user with encryption
        auth1 = AuthManager(credentials_file=creds_file, master_key=master_key)
        auth1.add_user("testuser", "SecurePass123!@#")

        # Verify with same key
        auth2 = AuthManager(credentials_file=creds_file, master_key=master_key)
        result = auth2.verify("testuser", "SecurePass123!@#")
        assert result is True


class TestWriteFileSafely:
    """Tests for the atomic credential write."""

    def test_replaces_the_target_in_one_step(self, tmp_path, monkeypatch):
        """The new content arrives via os.replace, never by writing over the target."""
        target = tmp_path / "credentials.enc"
        target.write_bytes(b"old")

        replaced: list[str] = []
        real_replace = os.replace

        def recording_replace(src: str, dst: str) -> None:
            replaced.append(str(dst))
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", recording_replace)
        write_file_safely(target, b"new")

        assert target.read_bytes() == b"new"
        # count this target rather than the whole list: a background credentials writer left
        # running by an earlier test can land inside the patched window and add its own entry
        assert replaced.count(str(target)) == 1

    def test_a_failed_write_keeps_the_old_content(self, tmp_path, monkeypatch):
        """A write that dies partway leaves the previous file readable and no temp file."""
        target = tmp_path / "credentials.enc"
        target.write_bytes(b"old")

        def failing_replace(src: str, dst: str) -> None:
            raise OSError("no space left on device")

        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(OSError):
            write_file_safely(target, b"new")

        assert target.read_bytes() == b"old"
        assert list(tmp_path.iterdir()) == [target]

    def test_creates_missing_parent_directories(self, tmp_path):
        """The credentials directory may not exist on a first run."""
        target = tmp_path / "config" / "credentials.enc"
        write_file_safely(target, b"secret")
        assert target.read_bytes() == b"secret"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
    def test_the_file_is_never_readable_by_others(self, tmp_path):
        """The mode is applied before any content exists, so there is no open window."""
        target = tmp_path / "credentials.enc"
        write_file_safely(target, b"secret")
        assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_a_directory_flush_failure_does_not_fail_the_write(self, tmp_path, monkeypatch):
        """The rename is already committed by then, so losing the flush costs durability only."""
        # Windows has no O_DIRECTORY and cannot open a directory as a file, so pretending the
        # flag exists is what drives the failure branch on this platform
        monkeypatch.setattr(os, "O_DIRECTORY", getattr(os, "O_DIRECTORY", 0), raising=False)

        target = tmp_path / "credentials.enc"
        write_file_safely(target, b"secret")
        assert target.read_bytes() == b"secret"


class TestCredentialFileDurability:
    """A kill mid-write must not take the next start down with it."""

    def test_truncated_file_does_not_kill_startup(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"

        auth1 = AuthManager(credentials_file=creds_file)
        auth1.add_user("testuser", "SecurePass123!@#")
        _truncate(creds_file)

        auth2 = AuthManager(credentials_file=creds_file)
        assert auth2.list_users() == []

    def test_a_store_that_will_not_read_says_so(self, tmp_path):
        """An unreadable file must be distinguishable from a store that is simply empty."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")
        assert auth.load_error is None

        _truncate(creds_file)
        damaged = AuthManager(credentials_file=creds_file)

        assert damaged.list_users() == []
        assert damaged.load_error

    def test_a_fresh_install_is_not_reported_as_unreadable(self, tmp_path):
        """No file at all is a legitimate empty store, not a failure."""
        auth = AuthManager(credentials_file=tmp_path / "credentials.enc")

        assert auth.list_users() == []
        assert auth.load_error is None

    def test_a_file_that_will_not_read_is_not_replaced_by_the_next_save(self, tmp_path):
        """The operator sees "no users", generates one, and must not lose the real table.

        A lost salt or a regenerated master key makes the ciphertext undecryptable, which
        looks exactly like a fresh install from the CLI. Writing the empty table over it
        is atomic and leaves nothing to restore from, so the save has to refuse instead.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        auth.add_user("bob", "SecurePass123!@#")
        original = creds_file.read_bytes()

        _truncate(creds_file)
        creds_file.write_bytes(original + b"damaged")

        damaged = AuthManager(credentials_file=creds_file)
        assert damaged.list_users() == []

        with pytest.raises(RuntimeError):
            damaged.add_user("carol", "SecurePass123!@#")

        assert creds_file.read_bytes() == original + b"damaged"

    def test_saving_goes_through_the_atomic_write(self, tmp_path, monkeypatch):
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        replaced: list[str] = []
        real_replace = os.replace

        def recording_replace(src: str, dst: str) -> None:
            replaced.append(str(dst))
            real_replace(src, dst)

        monkeypatch.setattr(os, "replace", recording_replace)
        auth.add_user("testuser", "SecurePass123!@#")

        assert str(creds_file) in replaced

    def test_failed_reload_keeps_the_users_already_loaded(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")

        _truncate(creds_file)
        _bump_mtime(creds_file)

        assert auth.reload_credentials() is False
        assert len(auth._credentials) == 1
        assert auth.verify("testuser", "SecurePass123!@#") is True

    def test_a_save_is_not_seen_as_an_outside_change(self, tmp_path):
        """Without this the server reloads its own output and races its own writer."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")

        assert auth._last_version == auth_module._file_version(creds_file)
        assert auth.reload_credentials() is False

    def test_verify_still_works_after_the_background_save(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")

        assert auth.verify("testuser", "SecurePass123!@#") is True
        auth.flush_credentials()
        assert auth.verify("testuser", "SecurePass123!@#") is True

    def test_a_save_requested_during_a_save_still_reaches_disk(self, tmp_path, monkeypatch):
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("first", "SecurePass123!@#")
        auth.add_user("second", "SecurePass123!@#")

        real_write = auth_module.write_file_safely
        first_write_started = threading.Event()
        release_first_write = threading.Event()
        writes: list[int] = []

        def stalling_write(path: Path, data: bytes, mode: int = 0o600) -> None:
            writes.append(len(data))
            if len(writes) == 1:
                first_write_started.set()
                release_first_write.wait(timeout=10)
            real_write(path, data, mode)

        monkeypatch.setattr(auth_module, "write_file_safely", stalling_write)

        auth._stamp_last_used("first")
        auth._save_credentials_async()
        assert first_write_started.wait(timeout=10)

        # requested while the first write is still in flight
        second_stamp = auth._stamp_last_used("second")
        auth._save_credentials_async()

        release_first_write.set()
        auth.flush_credentials()

        on_disk = json.loads(creds_file.read_text())
        assert on_disk["second"]["last_used"] == second_stamp

    def test_a_disabled_account_costs_the_same_as_an_unknown_one(self, tmp_path, monkeypatch):
        """A fast rejection tells an attacker the account exists."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")
        auth.set_user_enabled("testuser", False)

        hashed: list[str] = []
        real_hash = PasswordHasher.hash

        def counting_hash(hasher: PasswordHasher, password: str, *args, **kwargs) -> str:
            hashed.append(password)
            return real_hash(hasher, password, *args, **kwargs)

        monkeypatch.setattr(PasswordHasher, "hash", counting_hash)

        assert auth.verify("nobody_at_all", "SecurePass123!@#") is False
        unknown_user_hashes = len(hashed)
        assert unknown_user_hashes == 1

        hashed.clear()
        assert auth.verify("testuser", "SecurePass123!@#") is False
        assert len(hashed) == unknown_user_hashes


class TestCredentialFileLock:
    """The lock has to end, has to let its own holder back in, and has to die with it."""

    def test_it_gives_up_instead_of_waiting_for_ever(self, tmp_path):
        """A lock that can hang is a new way for the proxy to stop answering."""
        target = tmp_path / "credentials.enc"
        holding = threading.Event()
        release = threading.Event()

        def hold_the_lock() -> None:
            with lock_file(target):
                holding.set()
                release.wait(timeout=30)

        holder = threading.Thread(target=hold_the_lock)
        holder.start()
        try:
            assert holding.wait(timeout=10)

            started = time.monotonic()
            with pytest.raises(TimeoutError):
                with lock_file(target, timeout=0.2):
                    pass
            assert time.monotonic() - started < 5
        finally:
            release.set()
            holder.join(timeout=10)

        # and the file is usable again once the holder is done with it
        with lock_file(target, timeout=10):
            pass

    def test_the_lock_file_is_never_written_to(self, tmp_path):
        """Windows locks a range rather than a file, but it allows one past the end.

        Putting a byte in the file first added a write that nobody held the lock for.
        Two processes that both found the file empty raced there, and whichever wrote
        second was refused outright instead of waiting its turn for the lock.
        """
        target = tmp_path / "credentials.enc"

        with lock_file(target, timeout=10):
            pass

        lock_path = target.with_name(target.name + ".lock")
        assert lock_path.exists()
        assert lock_path.stat().st_size == 0

    def test_taking_it_twice_in_one_thread_does_not_wait_for_itself(self, tmp_path):
        target = tmp_path / "credentials.enc"

        with lock_file(target, timeout=5):
            with lock_file(target, timeout=5):
                pass

    def test_a_change_that_writes_from_inside_the_lock_does_not_wait_for_itself(self, tmp_path):
        """Every change holds the file across its write, and the write takes the lock too."""
        auth = AuthManager(credentials_file=tmp_path / "credentials.enc")

        assert auth.add_user("testuser", "SecurePass123!@#") is True
        assert auth.set_user_enabled("testuser", False) is True

    def test_a_holder_that_is_killed_does_not_block_the_next_process(self, tmp_path):
        """The kernel drops the lock when the process dies, so no start has to clear one."""
        target = tmp_path / "credentials.enc"
        holding = tmp_path / "holding"
        source_root = Path(auth_module.__file__).resolve().parents[1]
        script = (
            "import sys, time\n"
            "from pathlib import Path\n"
            "from shadow9.paths import lock_file\n"
            "with lock_file(Path(sys.argv[1]), timeout=30):\n"
            "    Path(sys.argv[2]).write_text('held')\n"
            "    time.sleep(120)\n"
        )
        holder = subprocess.Popen(
            [sys.executable, "-c", script, str(target), str(holding)],
            env={**os.environ, "PYTHONPATH": str(source_root)},
        )
        try:
            deadline = time.monotonic() + 60
            while not holding.exists() and time.monotonic() < deadline:
                assert holder.poll() is None, "the holder exited before taking the lock"
                time.sleep(0.05)
            assert holding.exists()

            with pytest.raises(TimeoutError):
                with lock_file(target, timeout=0.5):
                    pass
        finally:
            holder.kill()
            holder.wait(timeout=60)

        with lock_file(target, timeout=10):
            pass

    def test_a_login_still_succeeds_when_the_time_cannot_be_written(self, tmp_path, monkeypatch):
        """The password was checked against a hash out of the file; the stamp is extra."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("testuser", "SecurePass123!@#")
        auth.flush_credentials()

        def always_needs_a_rehash(self: AuthManager, password_hash: str) -> bool:
            return True

        def refuse_the_lock(
            path: Path, timeout: float = 10.0
        ) -> AbstractContextManager[None]:  # pragma: no cover - raises before it yields
            raise TimeoutError(f"another process is holding {path}")

        monkeypatch.setattr(AuthManager, "check_needs_rehash", always_needs_a_rehash)
        monkeypatch.setattr(auth_module, "lock_file", refuse_the_lock)

        assert auth.verify("testuser", "SecurePass123!@#") is True


class TestLocksAcrossAFork:
    """uvicorn starts its extra workers by forking, so a worker inherits this whole table."""

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="fork is POSIX only")
    def test_a_child_does_not_inherit_the_parents_hold(self, tmp_path):
        """Parent and child both believing they hold one lock is two writers in one section.

        The descriptors a child inherits are the parent's locks rather than copies, so a
        child that trusted the table it woke up with would skip the operating system
        entirely and walk into a section the parent is still inside.
        """
        target = tmp_path / "credentials.enc"

        with lock_file(target, timeout=10):
            child = os.fork()
            if child == 0:
                # 0 says the child found the file locked against it, which is the truth:
                # the parent is holding it and the child holds nothing
                code = 3
                try:
                    with lock_file(target, timeout=1):
                        code = 1
                except TimeoutError:
                    code = 0
                except BaseException:
                    code = 2
                os._exit(code)

            status = _reap(child, seconds=60)

        assert status is not None, "the child never came back, which is the inherited guard"
        assert os.WIFEXITED(status)
        assert os.WEXITSTATUS(status) == 0, "the child let itself into the parent's section"

    def test_the_child_starts_with_nothing_held(self, tmp_path):
        """A guard held at fork time is never released in the child, and cannot be waited out.

        The wait for the table's own mutex happens before the timeout lock_file promises
        applies to anything, so a child that inherited a held one stops for good rather
        than raising. This builds the state a child wakes up with and runs the handler
        over it, which is the part that has to work on every platform the table exists on.
        """
        target = tmp_path / "credentials.enc"
        lock_path = target.with_name(target.name + ".lock")
        original_guard = paths_module._locks_guard

        try:
            held = paths_module._FileLock(lock_path)
            held.acquire(timeout=10)
            paths_module._locks[lock_path] = held
            # what the fork leaves behind when another thread was inside the guard
            original_guard.acquire()

            paths_module._forget_locks_after_fork()

            assert paths_module._locks == {}
            assert paths_module._locks_guard is not original_guard
            assert paths_module._locks_guard.acquire(blocking=False) is True
            paths_module._locks_guard.release()
            assert held._descriptor is None

            # the inherited hold is gone rather than still standing in the child's way
            with lock_file(target, timeout=5):
                pass
        finally:
            paths_module._locks.pop(lock_path, None)
            paths_module._locks_guard = threading.Lock()

    def test_the_descriptor_is_recorded_before_the_wait_for_it_begins(self, tmp_path, monkeypatch):
        """A descriptor no lock object names is one the child of a fork cannot close.

        Recording it only once the wait had finished left a window: a fork landing inside
        it handed the child an open descriptor the child's handler could not find, and
        flock belongs to the open file description the two of them share. A parent that
        then died without unlocking left that invisible copy holding the file, and every
        later credential change in the child waited out its timeout for good.
        """
        target = tmp_path / "credentials.enc"
        lock_path = Path(os.path.abspath(str(target)))
        lock_path = lock_path.with_name(lock_path.name + ".lock")
        recorded: list[object] = []
        real_lock = paths_module._lock_descriptor

        def note_what_the_fork_handler_would_find(descriptor: int) -> None:
            recorded.append(paths_module._locks[lock_path]._descriptor)
            real_lock(descriptor)

        monkeypatch.setattr(paths_module, "_lock_descriptor", note_what_the_fork_handler_would_find)
        try:
            with lock_file(target, timeout=10):
                pass
        finally:
            paths_module._locks.pop(lock_path, None)

        assert recorded == [recorded[0]]
        assert recorded[0] is not None

    def test_forking_is_held_off_while_a_lock_file_is_being_opened(self):
        """The guard the fork handlers take is the one the open holds, or it excludes nothing."""
        assert paths_module._fork_guard.acquire(blocking=False) is True
        paths_module._fork_guard.release()

        paths_module._hold_locks_across_a_fork()
        try:
            assert paths_module._fork_guard.acquire(blocking=False) is False
        finally:
            paths_module._resume_locks_after_a_fork()

        assert paths_module._fork_guard.acquire(blocking=False) is True
        paths_module._fork_guard.release()


class TestALockFileThatWasReplaced:
    """What both platforms lock is the open file, not the name it was opened by."""

    def test_the_check_tells_two_lock_files_apart(self, tmp_path):
        one = tmp_path / "one.lock"
        one.write_bytes(b"")
        two = tmp_path / "two.lock"
        two.write_bytes(b"")

        descriptor = os.open(str(one), os.O_RDWR)
        try:
            assert paths_module._is_the_file_at(descriptor, one) is True
            assert paths_module._is_the_file_at(descriptor, two) is False
            assert paths_module._is_the_file_at(descriptor, tmp_path / "gone.lock") is False
        finally:
            os.close(descriptor)

    def test_a_lock_taken_on_a_replaced_file_is_taken_again(self, tmp_path, monkeypatch):
        """Holding an inode the name no longer leads to keeps nobody out.

        A tidy-up job that unlinks the sidecar while somebody is waiting for it leaves
        that waiter locking a file no later process will ever open, so it and whoever
        created the replacement are both inside at once with nothing to say so.
        """
        target = tmp_path / "credentials.enc"
        lock_path = Path(os.path.abspath(str(target)))
        lock_path = lock_path.with_name(lock_path.name + ".lock")
        answers = [False, True]
        real_check = paths_module._is_the_file_at

        def replaced_once(descriptor: int, path: Path) -> bool:
            return answers.pop(0) if answers else real_check(descriptor, path)

        monkeypatch.setattr(paths_module, "_is_the_file_at", replaced_once)
        try:
            with lock_file(target, timeout=10):
                held = os.fstat(paths_module._locks[lock_path]._descriptor)
                named = os.stat(str(lock_path))
                assert (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
        finally:
            paths_module._locks.pop(lock_path, None)

        assert answers == [], "the lock was not taken again after the file was replaced"


class TestOneFileTwoStores:
    """The proxy and the API write the same file, so one must not erase the other's users."""

    def test_a_user_added_while_a_login_is_in_flight_is_not_erased(self, tmp_path, monkeypatch):
        """The window is the argon2 verify: the proxy reads before it, the API writes during it.

        Disk holds alice. The proxy reloads, then spends hundreds of milliseconds hashing;
        the API creates bob inside that window and disk becomes alice and bob. The proxy
        then writes the table it read before bob existed, and bob is gone with no error
        anywhere. os.replace makes that write atomic, which is exactly why nothing is left
        to recover from.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        auth.flush_credentials()

        repo = UserRepository(credentials_file=creds_file)
        real_verify = PasswordHasher.verify
        created_bob = threading.Event()

        def verify_while_the_api_creates_bob(
            hasher: PasswordHasher, password_hash: str, password: str
        ) -> bool:
            result = real_verify(hasher, password_hash, password)
            if not created_bob.is_set():
                created_bob.set()
                asyncio.run(repo.create(_credential("bob")))
            return result

        monkeypatch.setattr(PasswordHasher, "verify", verify_while_the_api_creates_bob)

        assert auth.verify("alice", "SecurePass123!@#") is True
        assert created_bob.is_set()
        auth.flush_credentials()

        on_disk = AuthManager(credentials_file=creds_file)
        assert sorted(on_disk.list_users()) == ["alice", "bob"]

    def test_mutations_from_both_stores_all_land(self, tmp_path):
        """Two stores over one file, writing at the same time, must not drop each other."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        repo = UserRepository(credentials_file=creds_file)
        failures: list[str] = []

        def add_through_the_proxy_store() -> None:
            for index in range(4):
                try:
                    auth.add_user(f"proxy{index}", "SecurePass123!@#")
                except Exception as e:  # noqa: BLE001 - reported, not swallowed
                    failures.append(str(e))

        def add_through_the_api_store() -> None:
            for index in range(4):
                try:
                    asyncio.run(repo.create(_credential(f"api{index}")))
                except Exception as e:  # noqa: BLE001 - reported, not swallowed
                    failures.append(str(e))

        proxy_side = threading.Thread(target=add_through_the_proxy_store)
        api_side = threading.Thread(target=add_through_the_api_store)
        proxy_side.start()
        api_side.start()
        proxy_side.join(timeout=60)
        api_side.join(timeout=60)

        assert failures == []
        auth.flush_credentials()
        on_disk = AuthManager(credentials_file=creds_file)
        expected = sorted([f"proxy{i}" for i in range(4)] + [f"api{i}" for i in range(4)])
        assert sorted(on_disk.list_users()) == expected


class TestDecisionsMadeBeforeTheLock:
    """A decision taken from the table as it was before the lock is a decision about the past.

    Every one of these reads something, waits, and then writes on the strength of what it
    read. In between, the other process changed the very thing that was read.
    """

    def test_a_rehash_does_not_put_back_a_password_that_was_changed(self, tmp_path):
        """Otherwise a login silently reverts the password and locks the user out.

        The proxy verifies the old password, notices its hash is due a rehash, and hashes
        the password it was given. While that runs, the API changes the password. The
        proxy then takes the lock, rereads the new hash, and overwrites it with a hash of
        the password that is no longer the user's.
        """
        creds_file = tmp_path / "credentials.enc"
        # a hash made with weaker parameters than the store uses, so a login rehashes it
        outdated = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("OldPass123!@#")

        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            auth_module.Credential(
                username="alice", password_hash=outdated, created_at="2026-01-01T00:00:00"
            )
        )
        assert auth.check_needs_rehash(outdated) is True

        other_process = AuthManager(credentials_file=creds_file)
        assert other_process.change_password("alice", "OldPass123!@#", "NewPass456!@#") is True

        # the state verify() is in once it has read the old hash and let go of the file
        auth._record_login("alice", outdated, "OldPass123!@#")

        on_disk = AuthManager(credentials_file=creds_file)
        assert on_disk.verify("alice", "NewPass456!@#") is True
        assert on_disk.verify("alice", "OldPass123!@#") is False

    def test_a_password_change_loses_to_one_that_landed_first(self, tmp_path):
        """The old password stops authorizing anything the moment somebody else replaces it."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "OldPass123!@#")

        # this instance still remembers the old hash, the way it would mid-change
        stale_hash = auth.get_credential("alice").password_hash

        other_process = AuthManager(credentials_file=creds_file)
        assert other_process.change_password("alice", "OldPass123!@#", "FirstChange456!@#") is True

        auth._credentials["alice"].password_hash = stale_hash
        assert auth.change_password("alice", "OldPass123!@#", "SecondChange789!@#") is False

        on_disk = AuthManager(credentials_file=creds_file)
        assert on_disk.verify("alice", "FirstChange456!@#") is True
        assert on_disk.verify("alice", "SecondChange789!@#") is False

    def test_a_removed_file_does_not_bring_back_its_users(self, tmp_path):
        """A deleted credential that comes back still authenticates, which is the whole problem."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")

        creds_file.unlink()
        auth.add_user("bob", "SecurePass123!@#")

        on_disk = AuthManager(credentials_file=creds_file)
        assert on_disk.list_users() == ["bob"]
        assert on_disk.verify("alice", "SecurePass123!@#") is False

    def test_a_removed_file_stops_its_users_authenticating(self, tmp_path):
        """The path that serves logins has to see the deletion, not only the one that writes.

        Emptying the table for a change but not for a login left every user an operator
        had deleted authenticating for as long as the process stayed up.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        assert auth.verify("alice", "SecurePass123!@#") is True
        # the login schedules a save, and letting it finish first is what stops it
        # writing the file back out from under the deletion below
        auth.flush_credentials()

        creds_file.unlink()

        assert auth.verify("alice", "SecurePass123!@#") is False
        assert auth.list_users() == []
        # a file that is gone is not a file that would not read
        assert auth.load_error is None

    def test_a_user_another_process_removed_can_be_created_again(self, tmp_path):
        """Refusing the name because this instance still remembers her rejects a valid create."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")

        other_process = AuthManager(credentials_file=creds_file)
        assert other_process.remove_user("alice") is True

        assert auth.add_user("alice", "Recreated456!@#") is True

        on_disk = AuthManager(credentials_file=creds_file)
        assert on_disk.verify("alice", "Recreated456!@#") is True


class TestSaltAgreement:
    """Two processes deriving different keys from one master key is unrecoverable."""

    def test_stores_starting_together_all_get_the_same_salt(self, tmp_path):
        """Checking for the salt and then writing it lets every starter write its own.

        The loser's salt is replaced on disk while it goes on encrypting with the key it
        derived, and after a restart nothing can read what it wrote.
        """
        salt_file = tmp_path / ".salt"
        collected: list[bytes] = []
        collected_guard = threading.Lock()
        all_started = threading.Barrier(4)

        def start_a_store() -> None:
            all_started.wait(timeout=10)
            salt = read_or_create_salt(salt_file)
            with collected_guard:
                collected.append(salt)

        starters = [threading.Thread(target=start_a_store) for _ in range(4)]
        for starter in starters:
            starter.start()
        for starter in starters:
            starter.join(timeout=30)

        assert len(collected) == 4
        assert len(set(collected)) == 1
        assert collected[0] == salt_file.read_bytes()

    def test_an_empty_salt_file_is_not_used_as_a_salt(self, tmp_path):
        """A process killed between creating the file and filling it must not set the key."""
        salt_file = tmp_path / ".salt"
        salt_file.write_bytes(b"")

        salt = read_or_create_salt(salt_file)

        assert salt != b""
        assert salt == salt_file.read_bytes()

    def test_both_entry_points_read_each_other_at_a_custom_path(self, tmp_path, monkeypatch):
        """The proxy and the API have to derive one key from one master key.

        One took the install's salt and the other took the credentials file's own
        directory. Those are the same place only while the credentials file has not been
        moved, so a custom path left each rejecting what the other wrote.
        """
        install_root = tmp_path / "install"
        install_root.mkdir()
        monkeypatch.setattr(paths_module.Shadow9Paths, "_instance", None)
        monkeypatch.setenv("SHADOW9_HOME", str(install_root))

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        creds_file = elsewhere / "credentials.enc"

        api_side = UserRepository(credentials_file=creds_file, master_key="one-master-key")
        asyncio.run(api_side.create(_credential("alice")))

        proxy_side = AuthManager(credentials_file=creds_file, master_key="one-master-key")
        assert proxy_side.load_error is None
        assert proxy_side.list_users() == ["alice"]


class TestReloadSeesEveryChange:
    """A change the reload cannot see is a change that never reaches the proxy."""

    def test_a_replacement_on_the_same_timestamp_is_still_seen(self, tmp_path):
        """A whole-second filesystem reports no change for a write in the same second.

        Time passing never alters that timestamp afterwards either, so the users the
        write added stay invisible until somebody restarts the process.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        auth.flush_credentials()

        frozen = creds_file.stat()
        writer = AuthManager(credentials_file=creds_file)
        writer.add_user("bob", "SecurePass123!@#")
        writer.flush_credentials()
        # pin the clock back to what the first read saw, which is all a coarse
        # filesystem would ever have reported
        os.utime(creds_file, (frozen.st_mtime, frozen.st_mtime))

        assert auth.reload_credentials() is True
        assert sorted(auth.list_users()) == ["alice", "bob"]


class TestStoredRecordsAreChecked:
    """A record that parses is not the same as a record the rest of the system can use."""

    def test_a_record_no_model_would_accept_is_refused_at_load(self, tmp_path):
        """Otherwise it loads clean, raises far away at the API, and can still be rewritten."""
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": "x",
                        "created_at": "2026-01-01T00:00:00",
                        "bridge_type": "bogus",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_a_store_that_could_not_read_the_file_refuses_to_rewrite_it(self, tmp_path):
        """The invalid records are still somebody's users, and a write would replace them."""
        creds_file = tmp_path / "credentials.enc"
        original = json.dumps(
            {
                "alice": {
                    "username": "alice",
                    "password_hash": "x",
                    "created_at": "2026-01-01T00:00:00",
                    "rate_limit": 0,
                }
            }
        ).encode()
        creds_file.write_bytes(original)

        auth = AuthManager(credentials_file=creds_file)
        with pytest.raises(RuntimeError):
            auth.add_user("bob", "SecurePass123!@#")

        assert creds_file.read_bytes() == original

    def test_an_out_of_range_port_update_keeps_the_store_readable(
        self, tmp_path: Path
    ) -> None:
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            StoredCredential(
                username="alice",
                password_hash=_CHEAP_HASHER.hash("alice"),
                created_at="2026-01-01T00:00:00",
            )
        )

        rejected = False
        try:
            auth.update_credential("alice", {"allowed_ports": [70000]})
        except ValueError:
            rejected = True

        reloaded = AuthManager(credentials_file=creds_file)
        assert reloaded.list_users() == ["alice"]
        assert reloaded.load_error is None
        assert rejected is True

    def test_a_negative_rate_limit_update_keeps_the_store_readable(
        self, tmp_path: Path
    ) -> None:
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            StoredCredential(
                username="alice",
                password_hash=_CHEAP_HASHER.hash("alice"),
                created_at="2026-01-01T00:00:00",
            )
        )

        rejected = False
        try:
            auth.update_credential("alice", {"rate_limit": -1})
        except ValueError:
            rejected = True

        reloaded = AuthManager(credentials_file=creds_file)
        assert reloaded.list_users() == ["alice"]
        assert reloaded.load_error is None
        assert rejected is True

    def test_an_invalid_added_credential_keeps_the_store_readable(
        self, tmp_path: Path
    ) -> None:
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            StoredCredential(
                username="alice",
                password_hash=_CHEAP_HASHER.hash("alice"),
                created_at="2026-01-01T00:00:00",
            )
        )

        rejected = False
        try:
            auth.add_credential(
                StoredCredential(
                    username="bob",
                    password_hash=_CHEAP_HASHER.hash("bob"),
                    created_at="2026-01-01T00:00:00",
                    allowed_ports=[70000],
                )
            )
        except ValueError:
            rejected = True

        reloaded = AuthManager(credentials_file=creds_file)
        assert reloaded.list_users() == ["alice"]
        assert reloaded.load_error is None
        assert rejected is True

    def test_a_hash_nothing_can_verify_is_refused_at_load(self, tmp_path):
        """Every other field was checked, so this one loaded clean and failed at login.

        A record holding "x" reached the table with load_error unset, and the operator
        found out when that user could not get in, which is a long way from the file that
        caused it. The store also went on believing it had read the file, so the next
        change would have rewritten it.
        """
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": "x",
                        "created_at": "2026-01-01T00:00:00",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_a_hash_made_with_older_parameters_still_loads(self, tmp_path):
        """The check is what the verifier can read, not what this store would write now.

        A hash from weaker parameters is one the store deliberately accepts and rehashes
        on the next successful login, so rejecting it would lock out every install that
        has not logged in since the parameters changed.
        """
        creds_file = tmp_path / "credentials.enc"
        outdated = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("OldPass123!@#")
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": outdated,
                        "created_at": "2026-01-01T00:00:00",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is None
        assert auth.list_users() == ["alice"]
        assert auth.check_needs_rehash(outdated) is True

    def test_a_valid_record_still_loads(self, tmp_path):
        """The check must not reject what the store itself writes."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#", rate_limit=10, allowed_ports=[80, 443])
        auth.update_last_used("alice")
        auth.flush_credentials()

        on_disk = AuthManager(credentials_file=creds_file)
        assert on_disk.load_error is None
        assert on_disk.list_users() == ["alice"]


class TestStoredTimes:
    """These strings go into credentials.enc and come back out, so their shape is a format."""

    def test_a_stored_time_carries_no_offset(self, tmp_path):
        """An install already holding naive strings must not start getting offset ones.

        _apply_pending_last_used decides which of two logins is the later one by comparing
        the text, and an offset sorts after every digit, so one record in the new shape
        would look newer than every record in the old one whatever the clock said.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        assert auth.update_last_used("alice") is True

        on_disk = AuthManager(credentials_file=creds_file)
        record = on_disk.get_credential("alice")
        assert record is not None

        for stamp in (record.created_at, record.last_used):
            assert stamp is not None
            assert "+" not in stamp
            assert not stamp.endswith("Z")
            assert datetime.fromisoformat(stamp).tzinfo is None

    def test_a_stamp_that_arrives_with_an_offset_is_converted_at_load(self, tmp_path):
        """An offset sorts after every digit, so 11:00 UTC beat a login an hour later.

        Nothing here writes that shape, but a file repaired by hand or left behind by a
        version that used the timezone-aware clock holds it, and it compared wrong for as
        long as it stayed. Sol's case exactly: stored 13:00:00+02:00 is 11:00 UTC, pending
        12:00:00 is an hour after it, and as text the stored one is the larger.
        """
        stored = "2026-07-31T13:00:00+02:00"
        later_login = "2026-07-31T12:00:00"
        assert stored > later_login, "the comparison that made this go wrong"

        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": _CHEAP_HASHER.hash("alice"),
                        "created_at": "2026-01-01T00:00:00+05:00",
                        "last_used": stored,
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        record = auth.get_credential("alice")
        assert record is not None
        assert record.last_used == "2026-07-31T11:00:00"
        assert record.created_at == "2025-12-31T19:00:00"

        auth._pending_last_used["alice"] = later_login
        auth._apply_pending_last_used()
        assert record.last_used == later_login

    def test_a_stamp_this_store_wrote_comes_back_byte_for_byte(self, tmp_path):
        """Converting on the way in must not change what an existing file looks like."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        assert auth.update_last_used("alice") is True

        written = json.loads(creds_file.read_text())["alice"]

        on_disk = AuthManager(credentials_file=creds_file)
        record = on_disk.get_credential("alice")
        assert record is not None
        assert record.created_at == written["created_at"]
        assert record.last_used == written["last_used"]

    def test_a_stamp_written_with_a_space_gets_the_separator_back(self, tmp_path):
        """A space sorts before the T, so a hand repair looked older than every other stamp."""
        assert "2026-07-31 12:00:00" < "2026-07-31T00:00:00"

        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": _CHEAP_HASHER.hash("alice"),
                        "created_at": "2026-01-01 08:30:00",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        record = auth.get_credential("alice")
        assert record is not None
        assert record.created_at == "2026-01-01T08:30:00"

    def test_the_text_order_of_these_stamps_is_their_time_order(self):
        """_stamp_last_used keeps the largest string, so that has to be the latest time.

        It holds because these carry no offset and because a stamp with no microseconds
        is a prefix of one in the same second that has them. Both of those are properties
        of the format rather than of the comparison, so they are pinned here: an offset
        sorts after every digit, and would make one record look newer than every record
        written before it whatever the clock said.
        """
        moments = [
            datetime(2026, 7, 31, 11, 59, 59, 999999),
            datetime(2026, 7, 31, 12, 0, 0),
            datetime(2026, 7, 31, 12, 0, 0, 1),
            datetime(2026, 7, 31, 13, 0, 0),
            datetime(2026, 12, 31, 23, 59, 59, 999999),
            datetime(2027, 1, 1, 0, 0, 0),
        ]
        written = [moment.isoformat() for moment in moments]

        assert written == sorted(written)
        assert max(written) == moments[-1].isoformat()

        now = auth_module._utc_now_text()
        assert datetime.fromisoformat(now).isoformat() == now


class TestTwoLoginsAtOnce:
    """Both read the clock before either writes, so the order they arrive in is not time order."""

    def test_the_later_of_two_logins_is_the_one_kept(self, tmp_path):
        """The first to read the clock can be the last to write, and it was overwriting.

        A user's last-seen time went backwards, and the next save carried that to disk.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            auth_module.Credential(
                username="alice",
                password_hash=_CHEAP_HASHER.hash("alice"),
                created_at="2026-01-01T00:00:00",
            )
        )

        real_now = auth_module._utc_now_text
        handed_out: list[str] = []
        stored_the_later_one = threading.Event()

        def hand_the_first_caller_an_early_time() -> str:
            stamp = real_now()
            handed_out.append(stamp)
            if len(handed_out) == 1:
                # the first caller holds its time while the second stores a later one
                stored_the_later_one.wait(timeout=10)
            return stamp

        auth_module._utc_now_text = hand_the_first_caller_an_early_time
        try:
            first = threading.Thread(target=auth._stamp_last_used, args=("alice",))
            first.start()
            while not handed_out:
                time.sleep(0.005)
            time.sleep(0.05)

            auth._stamp_last_used("alice")
            stored_the_later_one.set()
            first.join(timeout=10)
        finally:
            auth_module._utc_now_text = real_now

        early, late = handed_out
        assert early < late
        assert auth._credentials["alice"].last_used == late
        assert auth._pending_last_used["alice"] == late

    def test_a_clock_that_steps_backwards_does_not_move_a_record_back(self, tmp_path):
        """A time already on the record came from a login that really happened."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_credential(
            auth_module.Credential(
                username="alice",
                password_hash=_CHEAP_HASHER.hash("alice"),
                created_at="2026-01-01T00:00:00",
            )
        )

        assert auth._stamp_last_used("alice") is not None
        recorded = auth._credentials["alice"].last_used
        assert recorded is not None

        real_now = auth_module._utc_now_text
        auth_module._utc_now_text = lambda: "2020-01-01T00:00:00"
        try:
            assert auth._stamp_last_used("alice") == recorded
        finally:
            auth_module._utc_now_text = real_now

        assert auth._credentials["alice"].last_used == recorded
        assert auth._pending_last_used["alice"] == recorded


class TestUserRepositoryDurability:
    """The API-side copy of the store has the same failure modes and needs the same fixes."""

    def test_a_login_stamp_that_cannot_be_written_does_not_reach_the_caller(
        self, tmp_path, monkeypatch
    ):
        """The password has already passed by then, so a busy file must not fail the login."""
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("alice")))

        def refuse_the_write(self: AuthManager, username: str) -> bool:
            raise TimeoutError(f"another process is holding {creds_file}")

        monkeypatch.setattr(AuthManager, "update_last_used", refuse_the_write)

        asyncio.run(repo.update_last_used("alice"))

    def test_truncated_file_does_not_kill_startup(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"

        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("testuser")))
        _truncate(creds_file)

        second = UserRepository(credentials_file=creds_file)
        assert asyncio.run(second.count()) == 0

    def test_failed_reload_keeps_the_users_already_loaded(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("testuser")))

        _truncate(creds_file)
        _bump_mtime(creds_file)

        assert repo.reload_if_changed() is False
        assert asyncio.run(repo.count()) == 1

    def test_a_store_that_will_not_read_says_so(self, tmp_path):
        """An unreadable file must be distinguishable from a store that is simply empty.

        Nothing raises on a failed load, and the count that comes back on a cold start is
        zero either way, so a caller deciding whether this instance can serve has no other
        way to tell the two apart.
        """
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("testuser")))
        assert repo.load_error is None

        _truncate(creds_file)
        damaged = UserRepository(credentials_file=creds_file)

        assert asyncio.run(damaged.count()) == 0
        assert damaged.load_error

    def test_a_file_that_will_not_read_is_not_replaced_by_the_next_save(self, tmp_path):
        """Both processes write this one file, so the API side needs the same refusal."""
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("alice")))
        original = creds_file.read_bytes()

        creds_file.write_bytes(original + b"damaged")
        damaged = UserRepository(credentials_file=creds_file)
        assert damaged.load_error

        with pytest.raises(RuntimeError):
            asyncio.run(damaged.create(_credential("carol")))

        assert creds_file.read_bytes() == original + b"damaged"

    def test_a_fresh_install_is_not_reported_as_unreadable(self, tmp_path):
        """No file at all is a legitimate empty store, not a failure."""
        repo = UserRepository(credentials_file=tmp_path / "credentials.enc")

        assert asyncio.run(repo.count()) == 0
        assert repo.load_error is None

    def test_a_backup_restored_with_its_own_timestamp_is_picked_up(self, tmp_path):
        """Restoring with a tool that keeps timestamps puts an older mtime back.

        A damaged file leaves its own, later, mtime recorded, so a check for a newer file
        would never look at the restored one and the users would stay missing until the
        process was restarted.
        """
        creds_file = tmp_path / "credentials.enc"
        backup = tmp_path / "credentials.backup"

        repo = UserRepository(credentials_file=creds_file)
        asyncio.run(repo.create(_credential("testuser")))
        shutil.copy2(creds_file, backup)
        good_mtime = creds_file.stat().st_mtime

        _truncate(creds_file)
        os.utime(creds_file, (good_mtime + 60, good_mtime + 60))
        assert repo.reload_if_changed() is False

        shutil.copy2(backup, creds_file)
        assert creds_file.stat().st_mtime < good_mtime + 60

        assert repo.reload_if_changed() is True
        assert asyncio.run(repo.exists("testuser")) is True

    @pytest.mark.asyncio
    async def test_update_can_clear_a_field(self, tmp_path):
        """PATCH with an explicit null has to actually clear the value."""
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)

        cred = _credential("testuser")
        cred.allowed_ports = [443]
        cred.rate_limit = 10
        cred.bind_port = 1080
        await repo.create(cred)

        updated = await repo.update(
            "testuser",
            {
                "allowed_ports": None,
                "rate_limit": None,
                "bind_port": None,
            },
        )

        assert updated is not None
        assert updated.allowed_ports is None
        assert updated.rate_limit is None
        assert updated.bind_port is None

        on_disk = json.loads(creds_file.read_text())
        assert on_disk["testuser"]["allowed_ports"] is None
        assert on_disk["testuser"]["rate_limit"] is None
        assert on_disk["testuser"]["bind_port"] is None

    @pytest.mark.asyncio
    async def test_update_leaves_unmentioned_fields_alone(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)

        cred = _credential("testuser")
        cred.rate_limit = 10
        await repo.create(cred)

        updated = await repo.update("testuser", {"enabled": False})

        assert updated is not None
        assert updated.enabled is False
        assert updated.rate_limit == 10

    @pytest.mark.asyncio
    async def test_saving_does_not_hold_the_event_loop(self, tmp_path, monkeypatch):
        """The write runs on a worker thread, so other requests keep being served."""
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        await repo.create(_credential("testuser"))

        real_write = auth_module.write_file_safely

        def slow_write(path: Path, data: bytes, mode: int = 0o600) -> None:
            time.sleep(0.2)
            real_write(path, data, mode)

        monkeypatch.setattr(auth_module, "write_file_safely", slow_write)

        ticks = 0

        async def heartbeat() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        await repo.update_last_used("testuser")
        beat.cancel()

        assert ticks >= 5

    @pytest.mark.asyncio
    async def test_update_last_used_does_not_start_a_thread_per_call(self, tmp_path, monkeypatch):
        """One writer. A thread per authentication piles up without bound.

        Counting live threads around the call measured the interpreter's scheduling
        rather than this code, and failed on that: asyncio.to_thread hands the write to a
        shared pool whose workers are created lazily, and whether one is idle at the
        moment of the next call is a race the code under test does not control.

        What does not depend on scheduling is the ceiling. The shared pool holds at most
        min(32, cpu_count + 4) workers however many jobs it is given, so the writes here
        land on a bounded number of threads no matter how many calls are made. A thread
        started per call would use one per call and blow straight through it.
        """
        creds_file = tmp_path / "credentials.enc"
        repo = UserRepository(credentials_file=creds_file)
        await repo.create(_credential("testuser"))

        real_write = auth_module.write_file_safely
        wrote_on: list[int] = []

        def recording_write(path: Path, data: bytes, mode: int = 0o600) -> None:
            wrote_on.append(threading.get_ident())
            real_write(path, data, mode)

        monkeypatch.setattr(auth_module, "write_file_safely", recording_write)

        calls = 100
        for _ in range(calls):
            await repo.update_last_used("testuser")

        pool_ceiling = min(32, (os.cpu_count() or 1) + 4)
        assert len(wrote_on) == calls
        assert len(set(wrote_on)) <= pool_ceiling
        assert len(set(wrote_on)) < calls


class TestUserDirectoryValidation:
    """get_user_dir feeds shutil.rmtree, so the check belongs there."""

    @pytest.mark.parametrize("username", ["../../etc", "/etc", "..", ".", "", "a/b", "a\\b"])
    def test_a_username_cannot_escape_the_users_directory(self, username):
        with pytest.raises(ValueError):
            get_paths().get_user_dir(username)

    def test_a_plain_username_still_works(self):
        paths = get_paths()
        assert paths.get_user_dir("testuser") == paths.users_dir / "testuser"


def _peer_record(username: str, public_key: str, address: str) -> dict:
    """A stored record for a user who is also a WireGuard peer."""
    return {
        "username": username,
        "password_hash": _CHEAP_HASHER.hash(username),
        "created_at": "2026-01-01T00:00:00",
        "wg_public_key": public_key,
        "wg_address": address,
        "wg_routes": ["192.168.1.0/24"],
        "wg_role": "node",
        "wg_endpoint": "203.0.113.10:51820",
        "wg_keepalive": 25,
        "wg_expires_at": "2027-01-01T00:00:00",
    }


class TestPeerSettingsOnAStoredRecord:
    """A peer lives on the user record, so it is checked where every other field is."""

    def test_a_user_who_is_not_a_peer_is_written_the_way_it_always_was(self, tmp_path):
        """Almost nobody is a peer, and a record with no wg_ keys is one any version reads."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")

        written = json.loads(creds_file.read_text())["alice"]
        assert [name for name in written if name.startswith("wg_")] == []

    def test_a_peer_record_survives_a_read_and_a_write(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        keypair = generate_keypair()
        creds_file.write_bytes(
            json.dumps({"alice": _peer_record("alice", keypair.public_key, "10.9.0.2")}).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        assert auth.load_error is None

        record = auth.get_credential("alice")
        assert record is not None
        assert record.wg_public_key == keypair.public_key
        assert record.wg_address == "10.9.0.2"
        assert record.wg_routes == ["192.168.1.0/24"]
        assert record.wg_role == "node"
        assert record.wg_keepalive == 25

        auth.add_user("bob", "SecurePass123!@#")
        written = json.loads(creds_file.read_text())
        assert written["alice"]["wg_public_key"] == keypair.public_key
        assert [name for name in written["bob"] if name.startswith("wg_")] == []

    def test_a_public_key_the_tunnel_would_reject_is_refused_at_load(self, tmp_path):
        """is_valid_key is the renderer's own check, so one key cannot mean two things."""
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", "not-a-key", "10.9.0.2")
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert "wg_public_key" in auth.load_error
        assert auth.list_users() == []

    def test_an_address_written_as_a_range_is_refused(self, tmp_path):
        """wg_address names one host. A prefix means somebody meant a different thing."""
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2/24")
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_a_peer_address_outside_the_configured_tunnel_is_refused(self):
        credential = StoredCredential(
            username="alice",
            password_hash=_CHEAP_HASHER.hash("alice"),
            created_at="2026-01-01T00:00:00",
            wg_public_key=generate_keypair().public_key,
            wg_address="10.9.0.2",
            wg_role="node",
        )

        with pytest.raises(ValueError, match=r"10\.20\.0\.0/24"):
            auth_module._check_peer_fields(
                credential, parse_network("10.20.0.0/24")
            )

    def test_a_route_carrying_host_bits_is_refused_rather_than_masked_off(self, tmp_path):
        """192.168.1.1/24 and 192.168.1.0/24 differ, and the difference is what routes."""
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
        record["wg_routes"] = ["192.168.1.1/24"]
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_a_role_that_is_not_one_of_the_three_is_refused(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
        record["wg_role"] = "gateway"
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_every_role_the_renderer_knows_is_accepted(self, tmp_path):
        for role in (PeerRole.HUB, PeerRole.NODE, PeerRole.DEVICE):
            creds_file = tmp_path / f"credentials-{role.value}.enc"
            record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
            record["wg_role"] = role.value
            creds_file.write_bytes(json.dumps({"alice": record}).encode())

            auth = AuthManager(credentials_file=creds_file)

            assert auth.load_error is None
            stored = auth.get_credential("alice")
            assert stored is not None
            assert stored.wg_role == role.value

    def test_a_keepalive_of_zero_is_refused(self, tmp_path):
        """Zero is not "send none", which is the field being absent. It is not an interval."""
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
        record["wg_keepalive"] = 0
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_an_expiry_carrying_an_offset_is_stored_the_way_the_other_times_are(self, tmp_path):
        """Text order is time order in this file only while nothing carries an offset."""
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
        record["wg_expires_at"] = "2027-01-01T13:00:00+02:00"
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        stored = auth.get_credential("alice")
        assert stored is not None
        assert stored.wg_expires_at == "2027-01-01T11:00:00"

    def test_an_expiry_that_is_not_a_time_is_refused(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        record = _peer_record("alice", generate_keypair().public_key, "10.9.0.2")
        record["wg_expires_at"] = "soon"
        creds_file.write_bytes(json.dumps({"alice": record}).encode())

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is not None
        assert auth.list_users() == []

    def test_a_peer_key_a_caller_makes_up_never_reaches_the_file(self, tmp_path):
        """update_credential setattrs what it is handed, and the load refuses what it wrote.

        Written, that record would fail the next load, and a failed load sets load_error,
        which stops every write after it. The store would come up holding no users, with
        the real ones still on disk and no way to save over them.
        """
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")
        before = creds_file.read_bytes()

        with pytest.raises(ValueError):
            auth.update_credential("alice", {"wg_public_key": "nonsense"})

        assert creds_file.read_bytes() == before
        stored = auth.get_credential("alice")
        assert stored is not None
        assert stored.wg_public_key is None

        reopened = AuthManager(credentials_file=creds_file)
        assert reopened.load_error is None
        assert reopened.list_users() == ["alice"]

    def test_removing_a_user_takes_its_peer_with_it(self, tmp_path):
        """A peer record in a file of its own would outlive the user it belongs to."""
        creds_file = tmp_path / "credentials.enc"
        keypair = generate_keypair()
        creds_file.write_bytes(
            json.dumps({"alice": _peer_record("alice", keypair.public_key, "10.9.0.2")}).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        assert auth.remove_user("alice") is True

        assert keypair.public_key not in creds_file.read_text()
        assert json.loads(creds_file.read_text()) == {}

    def test_disabling_a_peer_keeps_its_keys_and_enabling_puts_it_back(self, tmp_path):
        """A disabled peer is left out of every config, not stripped of its identity."""
        creds_file = tmp_path / "credentials.enc"
        keypair = generate_keypair()
        creds_file.write_bytes(
            json.dumps({"alice": _peer_record("alice", keypair.public_key, "10.9.0.2")}).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        assert auth.set_user_enabled("alice", False) is True

        disabled = auth.get_credential("alice")
        assert disabled is not None
        assert disabled.enabled is False
        assert disabled.wg_public_key == keypair.public_key
        assert disabled.wg_address == "10.9.0.2"
        assert disabled.wg_routes == ["192.168.1.0/24"]

        assert auth.set_user_enabled("alice", True) is True
        restored = auth.get_credential("alice")
        assert restored is not None
        assert restored.enabled is True
        assert restored.wg_public_key == keypair.public_key

    def test_a_disabled_peer_is_left_out_of_the_configs_and_its_routes_go_with_it(self, tmp_path):
        """The stored flag has to be the one the renderer reads, or disabling does nothing."""
        creds_file = tmp_path / "credentials.enc"
        keypair = generate_keypair()
        creds_file.write_bytes(
            json.dumps({"alice": _peer_record("alice", keypair.public_key, "10.9.0.2")}).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        auth.set_user_enabled("alice", False)
        stored = auth.get_credential("alice")
        assert stored is not None
        assert stored.wg_public_key is not None
        assert stored.wg_address is not None
        assert stored.wg_role is not None
        assert stored.wg_routes is not None

        gateway = Peer(
            name=stored.username,
            public_key=stored.wg_public_key,
            address=parse_address(stored.wg_address),
            role=PeerRole(stored.wg_role),
            routes=tuple(parse_network(route) for route in stored.wg_routes),
            enabled=stored.enabled,
        )
        hub = Peer(
            name="hub",
            public_key=generate_keypair().public_key,
            address=parse_address("10.9.0.1"),
            role=PeerRole.HUB,
            endpoint="203.0.113.10:51820",
        )
        phone = Peer(
            name="phone",
            public_key=generate_keypair().public_key,
            address=parse_address("10.9.0.3"),
            role=PeerRole.DEVICE,
        )
        topology = Topology(
            tunnel_network=parse_network("10.9.0.0/24"), hub=hub, spokes=(gateway, phone)
        )

        assert [peer.name for peer in topology.active_spokes()] == ["phone"]
        assert topology.routes_reachable_from(phone) == ()


class TestAFileWrittenByALaterVersion:
    """A key this version has no field for used to fail the whole load, which stopped writes."""

    def test_a_field_from_a_later_version_loads_instead_of_failing_the_file(self, tmp_path):
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": _CHEAP_HASHER.hash("alice"),
                        "created_at": "2026-01-01T00:00:00",
                        "wg_preshared_key": "a setting this version has never heard of",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)

        assert auth.load_error is None
        assert auth.list_users() == ["alice"]

    def test_a_field_from_a_later_version_is_still_there_after_a_write(self, tmp_path):
        """Dropping it would mean one login on an older build deletes the newer settings."""
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    "alice": {
                        "username": "alice",
                        "password_hash": _CHEAP_HASHER.hash("alice"),
                        "created_at": "2026-01-01T00:00:00",
                        "wg_preshared_key": "kept",
                        "wg_table": "off",
                    }
                }
            ).encode()
        )

        auth = AuthManager(credentials_file=creds_file)
        assert auth.add_user("bob", "SecurePass123!@#") is True

        written = json.loads(creds_file.read_text())
        assert written["alice"]["wg_preshared_key"] == "kept"
        assert written["alice"]["wg_table"] == "off"
        assert "unknown_fields" not in written["alice"]
        assert "unknown_fields" not in written["bob"]

    def test_an_unknown_field_is_named_once_per_load_rather_than_per_record(
        self, tmp_path, monkeypatch
    ):
        """An operator seeing this is running an older build than the one that wrote the file."""
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(
            json.dumps(
                {
                    name: {
                        "username": name,
                        "password_hash": _CHEAP_HASHER.hash(name),
                        "created_at": "2026-01-01T00:00:00",
                        "wg_preshared_key": "x",
                    }
                    for name in ("alice", "bob")
                }
            ).encode()
        )

        named: list[list[str]] = []

        def record_warning(event: str, **kwargs: object) -> None:
            if "fields" in kwargs:
                named.append(kwargs["fields"])

        monkeypatch.setattr(auth_module.logger, "warning", record_warning)
        AuthManager(credentials_file=creds_file)

        assert named == [["wg_preshared_key"]]

    def test_a_caller_cannot_write_arbitrary_keys_through_the_update_path(self, tmp_path):
        """The box unknown keys are kept in is not a field a caller may set."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)
        auth.add_user("alice", "SecurePass123!@#")

        auth.update_credential("alice", {"unknown_fields": {"injected": "value"}})

        written = json.loads(creds_file.read_text())["alice"]
        assert "injected" not in written
        assert "unknown_fields" not in written


def _look_like_an_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take away what lets the store keep plain JSON, so it behaves as an install does.

    conftest.py sets SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS for the whole session, because
    most of the stores in this suite are built without a master key. A test that wants to
    see what an installed copy sees has to take it away again, along with any real key the
    developer running the suite happens to have in their environment.

    The assertion is the reason this is a helper rather than two lines copied around. The
    opt-in now arrives from conftest.py rather than from the test, so a test that failed to
    clear it would still pass and would prove nothing at all. This refuses to hand back a
    process that can still write plaintext.
    """
    monkeypatch.delenv(auth_module.ALLOW_PLAINTEXT_ENV, raising=False)
    monkeypatch.delenv("SHADOW9_MASTER_KEY", raising=False)
    assert auth_module.plaintext_credentials_allowed() is False


def _one_line(text: str) -> str:
    """Flatten styled, wrapped terminal output so a sentence can be matched in it.

    Rich colours values inside a line and wraps the line to the width of the terminal, so
    a message the operator reads as one sentence is never present in the raw output as
    plain text.
    """
    return " ".join(re.sub(r"\x1b\[[0-9;]*m", "", text).split())


def test_the_suite_does_not_run_against_the_working_tree():
    """conftest.py moves the install root off the checkout, and this fails if that goes.

    Shadow9Paths takes the first standard location holding a .env or a config directory,
    and on a developer's machine that is the working tree. A suite that finds it reads the
    operator's own master key, so tests pass or fail depending on whose checkout they run
    on, and a command under test can write into a real install. No test fails today if the
    line goes, because the files that need a root of their own already set one per test.
    This is what says why the line is there.
    """
    assert get_paths().root != Path(__file__).resolve().parent.parent


class TestAStoreWithNoMasterKey:
    """A store with no key to encrypt with must refuse rather than keep plain JSON.

    Without a master key the store used to write ordinary JSON into a file called
    credentials.enc, so password hashes and WireGuard private keys sat in the clear under
    a name that said otherwise. It also compounded: adding a key later made that same file
    fail to decrypt, and the service came up with no users at all.
    """

    def test_a_store_with_no_master_key_refuses_to_open(self, tmp_path, monkeypatch):
        _look_like_an_install(monkeypatch)
        creds_file = tmp_path / "credentials.enc"

        with pytest.raises(auth_module.MissingMasterKey) as refused:
            AuthManager(credentials_file=creds_file)

        assert "SHADOW9_MASTER_KEY" in str(refused.value)
        assert not creds_file.exists()

    def test_creating_the_first_user_without_a_key_writes_no_credentials_file(
        self, tmp_path, monkeypatch
    ):
        """The CLI has to say the key is missing, and leave nothing behind when it does."""
        from typer.testing import CliRunner

        from shadow9.cli import app

        # a fresh install: the key is in neither the environment nor the .env file.
        # Shadow9Paths keeps one instance per process and reads SHADOW9_HOME only while
        # building it, so a test that has to move the root has to drop that instance as
        # well. Without this the command finds the developer's own .env, succeeds, and
        # writes a user into the real install.
        monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
        monkeypatch.setattr(paths_module.Shadow9Paths, "_instance", None)
        _look_like_an_install(monkeypatch)
        assert get_paths().root == tmp_path.resolve()
        assert not (tmp_path / ".env").exists()

        result = CliRunner().invoke(
            app,
            [
                "user",
                "generate",
                "--username",
                "alice",
                "--password",
                "SecurePass123!@#",
                "--no-tor",
                "--bridge",
                "none",
                "--security",
                "none",
                "--no-logging",
                "--config",
                str(tmp_path / "config" / "config.yaml"),
            ],
        )

        assert result.exit_code != 0
        assert "SHADOW9_MASTER_KEY" in _one_line(result.output)
        assert list(tmp_path.rglob("credentials.enc")) == []

    def test_the_proxy_refuses_to_start_without_a_key(self, tmp_path, monkeypatch):
        """Starting the proxy is the path where this matters most.

        A proxy that came up against a store it cannot read would answer every login from
        an empty table, so it has to refuse and say why rather than exit on a traceback
        that systemd will bury.
        """
        from typer.testing import CliRunner

        from shadow9.cli import app

        monkeypatch.setenv("SHADOW9_HOME", str(tmp_path))
        monkeypatch.setattr(paths_module.Shadow9Paths, "_instance", None)
        _look_like_an_install(monkeypatch)
        assert get_paths().root == tmp_path.resolve()

        result = CliRunner().invoke(
            app,
            [
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                "19998",
                "--config",
                str(tmp_path / "config" / "config.yaml"),
            ],
        )

        assert result.exit_code != 0
        said = _one_line(result.output)
        assert "SHADOW9_MASTER_KEY" in said
        assert "will not start" in said

        # a traceback here would be the failure this replaces
        assert "Traceback" not in result.output
        assert list(tmp_path.rglob("credentials.enc")) == []

    def test_the_api_answers_that_the_key_is_missing_rather_than_failing_deeper_in(
        self, tmp_path, monkeypatch
    ):
        from fastapi import HTTPException

        from shadow9.api import deps
        from shadow9.core.config import Settings

        _look_like_an_install(monkeypatch)

        settings = Settings()
        settings.auth.credentials_file = str(tmp_path / "credentials.enc")
        monkeypatch.setattr(deps, "get_settings", lambda: settings)

        deps.get_user_repository.cache_clear()
        try:
            assert deps.get_master_key() is None

            with pytest.raises(HTTPException) as refused:
                deps.get_user_repository()

            assert refused.value.status_code == 503
            assert "SHADOW9_MASTER_KEY" in refused.value.detail
            assert not (tmp_path / "credentials.enc").exists()
        finally:
            deps.get_user_repository.cache_clear()

    def test_a_store_that_is_already_there_is_not_told_to_generate_a_key(
        self, tmp_path, monkeypatch
    ):
        """Generating a key over an existing file is what loses every user in it.

        The encryption key comes from the master key and the salt in .salt together, so a
        new key, or a new salt, locks the file just as thoroughly as a lost key. An
        operator who reaches this message with a file already on disk needs the original
        key, and telling them to generate one would walk them into exactly the cold
        start _save_credentials refuses to write over.
        """
        _look_like_an_install(monkeypatch)
        creds_file = tmp_path / "credentials.enc"
        creds_file.write_bytes(b"{}")

        with pytest.raises(auth_module.MissingMasterKey) as refused:
            AuthManager(credentials_file=creds_file)

        said = str(refused.value)
        assert "SHADOW9_MASTER_KEY" in said
        assert ".salt" in said
        assert "master-key generate" not in said

        # the file it refused to open is still exactly as it was
        assert creds_file.read_bytes() == b"{}"

    def test_a_fresh_install_is_told_how_to_get_a_key(self, tmp_path, monkeypatch):
        _look_like_an_install(monkeypatch)
        creds_file = tmp_path / "credentials.enc"

        with pytest.raises(auth_module.MissingMasterKey) as refused:
            AuthManager(credentials_file=creds_file)

        assert "master-key generate" in str(refused.value)

    def test_a_master_key_is_all_a_store_needs_to_open(self, tmp_path, monkeypatch):
        """The refusal is about the missing key, not about being outside a test run."""
        _look_like_an_install(monkeypatch)
        creds_file = tmp_path / "credentials.enc"

        auth = AuthManager(credentials_file=creds_file, master_key="a-master-key")
        auth.add_user("alice", "SecurePass123!@#")

        assert AuthManager(
            credentials_file=creds_file, master_key="a-master-key"
        ).verify("alice", "SecurePass123!@#")


class TestThePlaintextOptIn:
    """SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS is how a developer works without a key.

    It is the whole mechanism, and the only one. There is no constructor argument for it,
    because the store is reached through UserRepository as well and a second way in is a
    second thing to get wrong. The suite takes it in conftest.py, once and in the open,
    rather than each test being let through by something it never asked for. An installed
    copy never sets it.
    """

    def test_the_opt_in_lets_a_store_open_with_no_master_key(self, tmp_path, monkeypatch):
        _look_like_an_install(monkeypatch)
        monkeypatch.setenv("SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS", "1")
        creds_file = tmp_path / "credentials.enc"

        auth = AuthManager(credentials_file=creds_file)
        assert auth.add_user("alice", "SecurePass123!@#") is True

        # what it writes really is plain JSON, which is the point of the opt-in
        assert json.loads(creds_file.read_text())["alice"]["password_hash"]
        assert AuthManager(credentials_file=creds_file).verify("alice", "SecurePass123!@#")

    def test_the_constant_names_the_variable_the_tests_set(self):
        """A caller reading auth.py finds the same spelling these tests use."""
        assert auth_module.ALLOW_PLAINTEXT_ENV == "SHADOW9_ALLOW_PLAINTEXT_CREDENTIALS"

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on", " on "])
    def test_the_values_that_take_the_opt_in(self, value, monkeypatch):
        _look_like_an_install(monkeypatch)
        monkeypatch.setenv(auth_module.ALLOW_PLAINTEXT_ENV, value)

        assert auth_module.plaintext_credentials_allowed() is True

    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
    def test_the_values_that_do_not(self, value, monkeypatch):
        _look_like_an_install(monkeypatch)
        monkeypatch.setenv(auth_module.ALLOW_PLAINTEXT_ENV, value)

        assert auth_module.plaintext_credentials_allowed() is False

    def test_the_suite_takes_the_opt_in_for_every_test(self):
        """conftest.py is what lets the suite's 90-odd keyless stores build.

        Nothing else does it now, so if this ever fails the refusal is about to fire in
        roughly 250 tests that have nothing to do with master keys.
        """
        assert os.environ[auth_module.ALLOW_PLAINTEXT_ENV] == "1"
        assert auth_module.plaintext_credentials_allowed() is True

    def test_pytest_alone_does_not_open_the_door(self, monkeypatch):
        """A test run is not itself permission, which is why conftest.py has to ask.

        The guard used to treat pytest's own environment variables as the opt-in. That put
        test-framework detection inside shipped credential code, where a reader of auth.py
        could not tell what actually enables plaintext.
        """
        _look_like_an_install(monkeypatch)
        monkeypatch.setenv("PYTEST_VERSION", "9.0.3")
        monkeypatch.setenv("PYTEST_CURRENT_TEST", "tests/test_auth.py::somewhere (call)")

        assert auth_module.plaintext_credentials_allowed() is False
