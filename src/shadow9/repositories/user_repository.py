"""
User repository for credential persistence.

Reads and writes user credentials through the AuthManager store, which is the same
store the proxy uses.
"""

import asyncio
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from ..auth import AuthManager
from ..auth import Credential as StoredCredential
from ..core.logging import get_logger
from ..models.user import Credential
from .base import Repository


logger = get_logger(__name__)


def _stored(credential: Credential) -> StoredCredential:
    """Convert an API credential into the record the store keeps.

    to_dict already writes the timestamps as ISO strings and the enums as their values,
    which is the shape the store holds and the shape that reaches the file.
    """
    return StoredCredential(**credential.to_dict())


def _from_stored(record: StoredCredential) -> Credential:
    """Convert a stored record back into the API's credential model."""
    return Credential.from_dict(asdict(record))


class UserRepository(Repository[Credential, str]):
    """
    Repository for user credential storage.

    The store itself is AuthManager, so key derivation, loading, saving, reloading and
    the credential table have one implementation shared with the proxy. Two of them
    writing this one file is what let each replace users the other had just added.

    What this class adds is the API's side of it: the pydantic credential model, the
    worker threads that keep blocking work off the event loop, and a cap on how many
    password hashes may run at once.
    """

    # Used when the caller does not pass a value, and it matches the default of
    # auth.max_concurrent_auth so the two halves agree out of the box.
    MAX_CONCURRENT_HASHES = 4

    def __init__(
        self,
        credentials_file: Path,
        master_key: Optional[str] = None,
        salt_file: Optional[Path] = None,
        max_concurrent_hashes: Optional[int] = None,
        tunnel_network: Optional[str] = None,
    ):
        """
        Initialize the user repository.

        Args:
            credentials_file: Path to encrypted credentials file
            master_key: Master key for encryption
            salt_file: Path to salt file for key derivation, or None to let the store
                resolve it the same way the proxy does. Forcing the credentials file's
                own directory here was how this half and the proxy came to derive
                different keys from the same master key whenever the credentials file
                was moved off the install's default path.
            max_concurrent_hashes: Password hashes that may run at once, or None for
                MAX_CONCURRENT_HASHES
        """
        self.credentials_file = credentials_file
        self._auth = AuthManager(
            credentials_file=credentials_file,
            master_key=master_key,
            salt_file=salt_file,
            tunnel_network=tunnel_network,
        )

        # Every REST create and password change starts one of these hashes on asyncio's
        # default executor, sized min(32, cpu_count + 4), so peak memory followed the
        # host's core count instead of anything set here. Sized from
        # auth.max_concurrent_auth where the caller has it, so the systemd unit's
        # MemoryMax means the same thing for this process as it does for the proxy;
        # get_user_repository builds one repository per API process, so a per-instance
        # permit is a per-process one. Taken inside the worker thread, so a thread waiting
        # for one holds no argon2 memory and a caller that goes away cannot hand its
        # permit back while its hash is still running.
        self._hash_slots = threading.BoundedSemaphore(
            max_concurrent_hashes or self.MAX_CONCURRENT_HASHES
        )

    @property
    def auth_manager(self) -> AuthManager:
        """The store itself, for callers that work in records rather than API models.

        WireGuard enrollment writes peer fields onto a stored record and needs the same
        store this repository already holds. Building a second one in the same process
        would give each its own copy of the credential table, and this file has already
        cost the project once for exactly that.
        """
        return self._auth

    @property
    def load_error(self) -> Optional[str]:
        """Why the last read of the credentials file failed, or None when it read."""
        return self._auth.load_error

    def reload_if_changed(self) -> bool:
        """Reload credentials if file has been modified."""
        return self._auth.reload_credentials()

    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2id.

        Blocking on purpose, and both callers run it through asyncio.to_thread. The
        permit is what bounds how many of these hold their 64 MB at once, and it is
        taken here rather than by the caller so it tracks the thread that does the work.
        """
        with self._hash_slots:
            return self._auth.hash_password(password)

    # CRUD Operations

    async def create(self, entity: Credential) -> Credential:
        """Create a new user credential."""
        added = await asyncio.to_thread(self._auth.add_credential, _stored(entity))
        if not added:
            raise ValueError(f"User already exists: {entity.username}")

        logger.info("Created user", username=entity.username)
        return entity

    async def get(self, id: str) -> Optional[Credential]:
        """Get a user by username."""
        await asyncio.to_thread(self.reload_if_changed)
        record = self._auth.get_credential(id)
        return None if record is None else _from_stored(record)

    async def list(self, skip: int = 0, limit: Optional[int] = 100) -> list[Credential]:
        """List users with pagination.

        A limit of None returns everything from skip, so a caller that wants the whole
        table gets it from this one read instead of asking for a count first and then a
        page of that size, which reads the file at two different moments.
        """
        await asyncio.to_thread(self.reload_if_changed)
        records = self._auth.list_credentials()
        page = records[skip:] if limit is None else records[skip : skip + limit]
        return [_from_stored(record) for record in page]

    async def update(self, id: str, data: dict) -> Optional[Credential]:
        """
        Update a user's fields.

        A key that is present with a value of None clears that field. Callers build this
        dict with exclude_unset, so a field the caller never mentioned is absent from the
        dict rather than present as None, and clearing a field is possible.

        Args:
            id: The username to update
            data: Field names mapped to their new values

        Returns:
            The updated credential, or None if the user does not exist
        """
        record = await asyncio.to_thread(self._auth.update_credential, id, data)
        if record is None:
            return None

        logger.info("Updated user", username=id)
        return _from_stored(record)

    async def delete(self, id: str) -> bool:
        """Delete a user."""
        removed = await asyncio.to_thread(self._auth.remove_user, id)
        if removed:
            logger.info("Deleted user", username=id)
        return removed

    async def count(self) -> int:
        """Count total users."""
        await asyncio.to_thread(self.reload_if_changed)
        return len(self._auth.list_users())

    async def exists(self, id: str) -> bool:
        """Check if a user exists."""
        await asyncio.to_thread(self.reload_if_changed)
        return self._auth.get_credential(id) is not None

    # Additional user-specific methods

    async def update_last_used(self, username: str) -> None:
        """Record the time of the last successful authentication, if it can be recorded.

        The password has already been checked by the time this runs, so a credentials
        file that is busy or unwritable must not turn a login that succeeded into one
        that failed. A write that cannot be done is logged and dropped, which is the same
        thing the proxy does with its own login stamp.
        """
        # one writer at a time on a pooled thread. A fresh daemon thread per
        # authentication piles up without bound and dies part-way through its
        # write when the process is killed
        try:
            await asyncio.to_thread(self._auth.update_last_used, username)
        except Exception as e:
            logger.warning(
                "Could not record the last authentication time",
                username=username,
                error=str(e),
            )
