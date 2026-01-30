"""
User repository for credential persistence.

Handles encrypted storage of user credentials using the existing
AuthManager infrastructure.
"""

import json
import os
import secrets
import base64
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..core.logging import get_logger
from ..models.user import Credential
from .base import Repository


logger = get_logger(__name__)


class UserRepository(Repository[Credential, str]):
    """
    Repository for user credential storage.
    
    Provides CRUD operations for user credentials with:
    - Argon2id password hashing
    - Fernet encryption at rest
    - Hot-reload support for credential changes
    """
    
    # Argon2id parameters (OWASP recommended)
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4
    
    def __init__(
        self,
        credentials_file: Path,
        master_key: Optional[str] = None,
        salt_file: Optional[Path] = None
    ):
        """
        Initialize the user repository.
        
        Args:
            credentials_file: Path to encrypted credentials file
            master_key: Master key for encryption
            salt_file: Path to salt file for key derivation
        """
        self.credentials_file = credentials_file
        self._credentials: dict[str, Credential] = {}
        
        # Password hasher
        self._hasher = PasswordHasher(
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
        )
        
        # Encryption
        self._salt_file = salt_file or credentials_file.parent / ".salt"
        self._fernet = self._derive_fernet_key(master_key) if master_key else None
        
        # Thread safety
        self._lock = threading.Lock()
        self._last_mtime: float = 0.0
        
        # Load existing credentials
        self._load()
    
    def _derive_fernet_key(self, master_key: str) -> Fernet:
        """Derive a Fernet key from the master key using PBKDF2."""
        if self._salt_file.exists():
            salt = self._salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(32)
            self._salt_file.parent.mkdir(parents=True, exist_ok=True)
            self._salt_file.write_bytes(salt)
            if os.name != 'nt':
                os.chmod(self._salt_file, 0o600)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return Fernet(key)
    
    def _load(self) -> None:
        """Load credentials from encrypted file."""
        if not self.credentials_file.exists():
            logger.info("No credentials file found, starting fresh")
            return
        
        try:
            encrypted_data = self.credentials_file.read_bytes()
            
            if self._fernet:
                decrypted_data = self._fernet.decrypt(encrypted_data)
                data = json.loads(decrypted_data.decode())
            else:
                data = json.loads(encrypted_data.decode())
            
            for username, cred_data in data.items():
                self._credentials[username] = Credential.from_dict(cred_data)
            
            self._last_mtime = self.credentials_file.stat().st_mtime
            logger.info("Loaded credentials", count=len(self._credentials))
            
        except Exception as e:
            logger.error("Failed to load credentials", error=str(e))
            raise
    
    def _save(self) -> None:
        """Save credentials to encrypted file."""
        with self._lock:
            data = {
                username: cred.to_dict()
                for username, cred in self._credentials.items()
            }
            json_data = json.dumps(data, indent=2)
            
            self.credentials_file.parent.mkdir(parents=True, exist_ok=True)
            
            if self._fernet:
                encrypted_data = self._fernet.encrypt(json_data.encode())
                self.credentials_file.write_bytes(encrypted_data)
            else:
                self.credentials_file.write_text(json_data)
            
            if os.name != 'nt':
                os.chmod(self.credentials_file, 0o600)
            
            self._last_mtime = self.credentials_file.stat().st_mtime
            logger.info("Saved credentials", count=len(self._credentials))
    
    def reload_if_changed(self) -> bool:
        """Reload credentials if file has been modified."""
        if not self.credentials_file.exists():
            return False
        
        try:
            current_mtime = self.credentials_file.stat().st_mtime
            if current_mtime > self._last_mtime:
                logger.info("Credentials file changed, reloading")
                self._credentials.clear()
                self._load()
                return True
        except Exception as e:
            logger.error("Failed to check/reload credentials", error=str(e))
        
        return False
    
    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2id."""
        return self._hasher.hash(password)
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash."""
        try:
            self._hasher.verify(password_hash, password)
            return True
        except (VerifyMismatchError, InvalidHash):
            return False
    
    def check_needs_rehash(self, password_hash: str) -> bool:
        """Check if password hash needs to be updated."""
        return self._hasher.check_needs_rehash(password_hash)
    
    # CRUD Operations
    
    async def create(self, entity: Credential) -> Credential:
        """Create a new user credential."""
        if entity.username in self._credentials:
            raise ValueError(f"User already exists: {entity.username}")
        
        self._credentials[entity.username] = entity
        self._save()
        logger.info("Created user", username=entity.username)
        return entity
    
    async def get(self, id: str) -> Optional[Credential]:
        """Get a user by username."""
        self.reload_if_changed()
        return self._credentials.get(id)
    
    async def list(self, skip: int = 0, limit: int = 100) -> list[Credential]:
        """List users with pagination."""
        self.reload_if_changed()
        users = list(self._credentials.values())
        return users[skip:skip + limit]
    
    async def update(self, id: str, data: dict) -> Optional[Credential]:
        """Update a user's fields."""
        if id not in self._credentials:
            return None
        
        cred = self._credentials[id]
        
        # Update fields from data dict
        for key, value in data.items():
            if hasattr(cred, key) and value is not None:
                setattr(cred, key, value)
        
        self._save()
        logger.info("Updated user", username=id)
        return cred
    
    async def delete(self, id: str) -> bool:
        """Delete a user."""
        if id not in self._credentials:
            return False
        
        del self._credentials[id]
        self._save()
        logger.info("Deleted user", username=id)
        return True
    
    async def count(self) -> int:
        """Count total users."""
        self.reload_if_changed()
        return len(self._credentials)
    
    async def exists(self, id: str) -> bool:
        """Check if a user exists."""
        self.reload_if_changed()
        return id in self._credentials
    
    # Additional user-specific methods
    
    async def get_by_bind_port(self, port: int) -> Optional[Credential]:
        """Get user by custom bind port."""
        self.reload_if_changed()
        for cred in self._credentials.values():
            if cred.bind_port == port:
                return cred
        return None
    
    async def list_with_custom_ports(self) -> dict[str, int]:
        """Get all users with custom bind ports."""
        self.reload_if_changed()
        return {
            username: cred.bind_port
            for username, cred in self._credentials.items()
            if cred.bind_port is not None
        }
    
    async def update_last_used(self, username: str) -> None:
        """Update last used timestamp (non-blocking)."""
        if username in self._credentials:
            self._credentials[username].last_used = datetime.utcnow()
            # Save in background thread
            thread = threading.Thread(target=self._save, daemon=True)
            thread.start()
