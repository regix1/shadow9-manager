"""
User service implementing business logic for user management.

This service layer sits between the API/CLI and the repository,
providing validation, business rules, and transformation logic.
"""

import secrets
import string
from datetime import datetime
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
        
        # Hash password
        password_hash = self._repo.hash_password(data.password)
        
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
            created_at=datetime.utcnow(),
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
        self,
        skip: int = 0,
        limit: int = 100,
        enabled_only: bool = False
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
        credentials = await self._repo.list(skip=skip, limit=limit)
        
        if enabled_only:
            credentials = [c for c in credentials if c.enabled]
        
        return [self._to_response(c) for c in credentials]
    
    async def count(self) -> int:
        """Get total number of users."""
        return await self._repo.count()
    
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
        
        # Prepare update dict (excluding None values)
        update_data = data.model_dump(exclude_unset=True)
        
        # Handle password change
        if 'password' in update_data:
            update_data['password_hash'] = self._repo.hash_password(update_data.pop('password'))
        
        # Convert enums to values for storage
        if 'bridge_type' in update_data and update_data['bridge_type']:
            update_data['bridge_type'] = update_data['bridge_type']
        if 'security_level' in update_data and update_data['security_level']:
            update_data['security_level'] = update_data['security_level']
        
        # Perform update
        updated = await self._repo.update(username, update_data)
        
        if updated:
            logger.info("Updated user", username=username, fields=list(update_data.keys()))
            return self._to_response(updated)
        
        return None
    
    async def enable(self, username: str) -> bool:
        """Enable a user account."""
        result = await self._repo.update(username, {'enabled': True})
        if result:
            logger.info("Enabled user", username=username)
        return result is not None
    
    async def disable(self, username: str) -> bool:
        """Disable a user account."""
        result = await self._repo.update(username, {'enabled': False})
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
    
    async def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> bool:
        """
        Change a user's password with verification.
        
        Args:
            username: The username
            old_password: Current password (for verification)
            new_password: New password
            
        Returns:
            True if changed, False if verification failed
        """
        credential = await self._repo.get(username)
        if credential is None:
            return False
        
        # Verify old password
        if not self._repo.verify_password(old_password, credential.password_hash):
            logger.warning("Password change failed: wrong current password", username=username)
            return False
        
        # Update password
        new_hash = self._repo.hash_password(new_password)
        await self._repo.update(username, {'password_hash': new_hash})
        
        logger.info("Password changed", username=username)
        return True
    
    async def get_by_bind_port(self, port: int) -> Optional[UserResponse]:
        """Get user by custom bind port."""
        credential = await self._repo.get_by_bind_port(port)
        if credential:
            return self._to_response(credential)
        return None
    
    async def list_custom_ports(self) -> dict[str, int]:
        """Get all users with custom bind ports."""
        return await self._repo.list_with_custom_ports()
    
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
            "tiger", "ocean", "maple", "river", "storm", "eagle", "frost",
            "blaze", "coral", "drift", "ember", "grove", "haven", "lunar",
            "nexus", "oasis", "prism", "quartz", "ridge", "solar", "thorn",
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
        
        return ''.join(password_chars)
