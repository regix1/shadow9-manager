"""
User service implementing business logic for user management.

This service layer sits between the API/CLI and the repository,
providing validation, business rules, and transformation logic.
"""

import asyncio
import secrets
import string
from typing import Optional

from ..core.logging import get_logger
from ..models.user import Credential
from ..repositories.user_repository import UserRepository
from ..schemas.user import UserCreate, UserResponse, UserUpdate


logger = get_logger(__name__)


class UserService:
    """
    Service for user management operations.

    Implements CRUD operations with business logic:
    - Create: Validate and hash password, create user
    - Read: Get user(s) with optional filtering
    - Update: Partial update with validation
    - Delete: Remove user and cleanup
    """

    # Fields where None is a real setting ("no port restriction", "no rate limit",
    # "no dedicated bind port") rather than a missing value. Every other field has a
    # required type, so a null on it would leave the credential unusable.
    CLEARABLE_FIELDS: frozenset[str] = frozenset({"allowed_ports", "rate_limit", "bind_port"})

    def __init__(self, repository: UserRepository):
        """
        Initialize the user service.

        Args:
            repository: User repository for data access
        """
        self._repo = repository

    # CREATE

    async def create(self, data: UserCreate) -> UserResponse:
        """
        Create a new user.

        Args:
            data: User creation data (validated by schema)

        Returns:
            Created user response

        Raises:
            ValueError: If username already exists
        """
        # Check if user exists
        if await self._repo.exists(data.username):
            raise ValueError(f"User already exists: {data.username}")

        # argon2 allocates 64 MB and runs for hundreds of milliseconds, so hashing on
        # the loop would stall every other request in this process
        password_hash = await asyncio.to_thread(self._repo.hash_password, data.password)

        # Create credential model
        credential = Credential(
            username=data.username,
            password_hash=password_hash,
            use_tor=data.use_tor,
            bridge_type=data.bridge_type,
            security_level=data.security_level,
            allowed_ports=data.allowed_ports,
            rate_limit=data.rate_limit,
            bind_port=data.bind_port,
            logging_enabled=data.logging_enabled,
            enabled=True,
        )

        # Persist
        created = await self._repo.create(credential)

        logger.info("Created user", username=data.username)
        return self._to_response(created)

    # READ

    async def get(self, username: str) -> Optional[UserResponse]:
        """
        Get a user by username.

        Args:
            username: The username to look up

        Returns:
            User response if found, None otherwise
        """
        credential = await self._repo.get(username)
        if credential is None:
            return None
        return self._to_response(credential)

    async def list(
        self, skip: int = 0, limit: int = 100, enabled_only: bool = False
    ) -> list[UserResponse]:
        """
        List users with optional filtering.

        Args:
            skip: Number of users to skip
            limit: Maximum users to return
            enabled_only: Only return enabled users

        Returns:
            List of user responses
        """
        if enabled_only:
            # the repository slices before this filter runs, so filtering the page it
            # returns drops enabled users off the end of every page
            credentials = await self._all_enabled()
            credentials = credentials[skip : skip + limit]
        else:
            credentials = await self._repo.list(skip=skip, limit=limit)

        return [self._to_response(c) for c in credentials]

    async def count(self, enabled_only: bool = False) -> int:
        """
        Get the number of users.

        Args:
            enabled_only: Count only enabled users

        Returns:
            Number of users matching the filter
        """
        if enabled_only:
            return len(await self._all_enabled())
        return await self._repo.count()

    # the annotation stays a string because this class binds its own name `list` above
    async def _all_enabled(self) -> "list[Credential]":
        """Get every enabled credential, unpaged, from a single read of the store.

        Asking for a count and then a page of that size read the file twice. A user
        created between the two calls made the second read longer than the size the first
        one reported, so the newest user was sliced off the end and never appeared.
        """
        credentials = await self._repo.list(skip=0, limit=None)
        return [c for c in credentials if c.enabled]

    # UPDATE

    async def update(self, username: str, data: UserUpdate) -> Optional[UserResponse]:
        """
        Update a user's properties.

        Args:
            username: The username to update
            data: Partial update data

        Returns:
            Updated user response if found, None otherwise
        """
        if not await self._repo.exists(username):
            return None

        # Only fields the caller actually sent, so an explicit null still clears a value
        update_data = data.model_dump(exclude_unset=True)

        # A null is only meaningful for the three fields whose absence is itself a
        # setting. On any other field it would store None over a required value:
        # a null use_tor reads as false at connection time and routes the user
        # directly, exposing the address Tor was hiding.
        nulled = sorted(
            field
            for field, value in update_data.items()
            if value is None and field not in self.CLEARABLE_FIELDS
        )
        if nulled:
            raise ValueError(
                f"Field(s) cannot be set to null: {', '.join(nulled)}. "
                f"Only {', '.join(sorted(self.CLEARABLE_FIELDS))} may be cleared."
            )

        # Handle password change
        if "password" in update_data:
            update_data["password_hash"] = await asyncio.to_thread(
                self._repo.hash_password, update_data.pop("password")
            )

        # Perform update
        updated = await self._repo.update(username, update_data)

        if updated:
            logger.info("Updated user", username=username, fields=list(update_data.keys()))
            return self._to_response(updated)

        return None

    async def enable(self, username: str) -> bool:
        """Enable a user account."""
        result = await self._repo.update(username, {"enabled": True})
        if result:
            logger.info("Enabled user", username=username)
        return result is not None

    async def disable(self, username: str) -> bool:
        """Disable a user account."""
        result = await self._repo.update(username, {"enabled": False})
        if result:
            logger.info("Disabled user", username=username)
        return result is not None

    # DELETE

    async def delete(self, username: str) -> bool:
        """
        Delete a user.

        Args:
            username: The username to delete

        Returns:
            True if deleted, False if not found
        """
        deleted = await self._repo.delete(username)
        if deleted:
            logger.info("Deleted user", username=username)
        return deleted

    # SPECIAL OPERATIONS

    async def generate_credentials(self) -> tuple[str, str]:
        """
        Generate secure random credentials.

        Returns:
            Tuple of (username, password)
        """
        username = f"user_{secrets.token_hex(8)}"
        password = self._generate_secure_password()
        return username, password

    # HELPERS

    def _to_response(self, credential: Credential) -> UserResponse:
        """Convert credential to response schema (excludes sensitive data)."""
        return UserResponse(
            username=credential.username,
            use_tor=credential.use_tor,
            bridge_type=credential.bridge_type,
            security_level=credential.security_level,
            allowed_ports=credential.allowed_ports,
            rate_limit=credential.rate_limit,
            bind_port=credential.bind_port,
            logging_enabled=credential.logging_enabled,
            enabled=credential.enabled,
            created_at=credential.created_at,
            last_used=credential.last_used,
        )

    def _generate_secure_password(self, length: int = 24) -> str:
        """Generate a password meeting security requirements."""
        words = [
            "tiger",
            "ocean",
            "maple",
            "river",
            "storm",
            "eagle",
            "frost",
            "blaze",
            "coral",
            "drift",
            "ember",
            "grove",
            "haven",
            "lunar",
            "nexus",
            "oasis",
            "prism",
            "quartz",
            "ridge",
            "solar",
            "thorn",
        ]

        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()-_=+"

        word = secrets.choice(words)
        if secrets.randbelow(2):
            word = word.capitalize()

        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        remaining = length - len(word) - 4
        all_chars = uppercase + lowercase + digits + special
        for _ in range(remaining):
            password_chars.append(secrets.choice(all_chars))

        secrets.SystemRandom().shuffle(password_chars)
        insert_pos = secrets.randbelow(len(password_chars) + 1)
        password_chars.insert(insert_pos, word)

        return "".join(password_chars)
