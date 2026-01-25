"""
Authentication module for Shadow9 SOCKS5 proxy.

Provides secure credential management using Argon2id hashing
and secure token generation.
"""

import secrets
import json
import os
import threading
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Credential:
    """Represents a user credential with all connection settings."""
    username: str
    password_hash: str
    created_at: str
    last_used: Optional[str] = None
    enabled: bool = True

    # Routing settings
    use_tor: bool = True  # Whether to route this user's traffic through Tor
    bridge_type: str = "none"  # none, obfs4, snowflake

    # Security settings
    security_level: str = "basic"  # none, basic, moderate, paranoid

    # Restrictions
    allowed_ports: Optional[list[int]] = None  # None = all ports allowed
    rate_limit: Optional[int] = None  # None = use server default

    # Per-user bind address (optional)
    bind_port: Optional[int] = None  # None = use shared server port


class AuthManager:
    """
    Manages authentication for the SOCKS5 proxy.

    Uses Argon2id for password hashing (recommended by OWASP)
    and provides secure credential storage.
    """

    # Argon2id parameters (OWASP recommended)
    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_COST = 65536  # 64 MB
    ARGON2_PARALLELISM = 4

    def __init__(self, credentials_file: Optional[Path] = None, master_key: Optional[str] = None):
        """
        Initialize the authentication manager.

        Args:
            credentials_file: Path to encrypted credentials file
            master_key: Master key for encrypting credentials at rest
        """
        if credentials_file is None:
            from .paths import get_credentials_file
            self.credentials_file = get_credentials_file()
        else:
            self.credentials_file = credentials_file
        self._credentials: dict[str, Credential] = {}

        # Initialize password hasher with secure parameters
        self._hasher = PasswordHasher(
            time_cost=self.ARGON2_TIME_COST,
            memory_cost=self.ARGON2_MEMORY_COST,
            parallelism=self.ARGON2_PARALLELISM,
        )

        # Setup encryption for credentials at rest
        if master_key:
            self._fernet = self._derive_fernet_key(master_key)
        else:
            self._fernet = None

        # Async save infrastructure
        self._save_lock = threading.Lock()
        self._pending_save = False
        self._save_thread: Optional[threading.Thread] = None

        # Track file modification time for hot-reload
        self._last_mtime: float = 0.0

        self._load_credentials()
        
        # Record initial mtime after loading
        if self.credentials_file.exists():
            self._last_mtime = self.credentials_file.stat().st_mtime

    def _derive_fernet_key(self, master_key: str) -> Fernet:
        """Derive a Fernet key from the master key using PBKDF2."""
        # Use a fixed salt for key derivation (stored with config)
        from .paths import get_paths
        salt_file = get_paths().salt_file

        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = secrets.token_bytes(32)
            salt_file.parent.mkdir(parents=True, exist_ok=True)
            salt_file.write_bytes(salt)
            # Restrict permissions on salt file
            if os.name != 'nt':  # Unix
                os.chmod(salt_file, 0o600)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP recommended
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
        return Fernet(key)

    def _load_credentials(self) -> None:
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
                # If no encryption, assume plain JSON (for development only)
                data = json.loads(encrypted_data.decode())

            for username, cred_data in data.items():
                self._credentials[username] = Credential(**cred_data)

            logger.info("Loaded credentials", count=len(self._credentials))

        except Exception as e:
            logger.error("Failed to load credentials", error=str(e))
            raise

    def reload_credentials(self) -> bool:
        """
        Reload credentials from file if it has been modified.
        
        This enables hot-reload of credentials when new users are added
        via CLI while the service is running.
        
        Returns:
            True if credentials were reloaded, False if no changes detected
        """
        if not self.credentials_file.exists():
            return False
        
        try:
            current_mtime = self.credentials_file.stat().st_mtime
            if current_mtime > self._last_mtime:
                logger.info("Credentials file changed, reloading", 
                           old_mtime=self._last_mtime, new_mtime=current_mtime)
                self._credentials.clear()
                self._load_credentials()
                self._last_mtime = current_mtime
                return True
        except Exception as e:
            logger.error("Failed to check/reload credentials", error=str(e))
        
        return False

    def _save_credentials(self) -> None:
        """Save credentials to encrypted file (blocking)."""
        with self._save_lock:
            data = {
                username: asdict(cred)
                for username, cred in self._credentials.items()
            }
            json_data = json.dumps(data, indent=2)

            self.credentials_file.parent.mkdir(parents=True, exist_ok=True)

            if self._fernet:
                encrypted_data = self._fernet.encrypt(json_data.encode())
                self.credentials_file.write_bytes(encrypted_data)
            else:
                self.credentials_file.write_text(json_data)

            # Restrict permissions on credentials file
            if os.name != 'nt':  # Unix
                os.chmod(self.credentials_file, 0o600)

            self._pending_save = False
            logger.info("Saved credentials", count=len(self._credentials))

    def _save_credentials_async(self) -> None:
        """Schedule credentials save in background thread (non-blocking).
        
        This method returns immediately and saves credentials in a background
        thread to avoid blocking connection handling.
        """
        self._pending_save = True
        
        # Don't start a new thread if one is already running
        if self._save_thread is not None and self._save_thread.is_alive():
            return
        
        def _do_save():
            try:
                self._save_credentials()
            except Exception as e:
                logger.error("Failed to save credentials in background", error=str(e))
        
        self._save_thread = threading.Thread(target=_do_save, daemon=True)
        self._save_thread.start()

    def flush_credentials(self) -> None:
        """Ensure all pending credential saves are completed.
        
        Call this during graceful shutdown to ensure no data is lost.
        """
        if self._pending_save:
            self._save_credentials()
        elif self._save_thread is not None and self._save_thread.is_alive():
            self._save_thread.join(timeout=5.0)

    def add_user(
        self,
        username: str,
        password: str,
        use_tor: bool = True,
        bridge_type: str = "none",
        security_level: str = "basic",
        allowed_ports: Optional[list[int]] = None,
        rate_limit: Optional[int] = None,
        bind_port: Optional[int] = None
    ) -> bool:
        """
        Add a new user with the given credentials.

        Args:
            username: The username (must be unique)
            password: The plaintext password (will be hashed)
            use_tor: Whether to route this user's traffic through Tor
            bridge_type: Tor bridge type (none, obfs4, snowflake)
            security_level: Security level (none, basic, moderate, paranoid)
            allowed_ports: List of allowed destination ports (None = all)
            rate_limit: Max requests per minute (None = server default)
            bind_port: Custom port for this user (None = shared server port)

        Returns:
            True if user was added, False if username exists
        """
        if not self._validate_username(username):
            raise ValueError("Invalid username format")

        if not self._validate_password(password):
            raise ValueError("Password does not meet security requirements")

        if security_level not in ("none", "basic", "moderate", "paranoid"):
            raise ValueError("Invalid security level. Must be: none, basic, moderate, paranoid")

        if bridge_type not in ("none", "obfs4", "snowflake"):
            raise ValueError("Invalid bridge type. Must be: none, obfs4, snowflake")

        if bind_port is not None and (bind_port < 1 or bind_port > 65535):
            raise ValueError("Invalid bind port. Must be 1-65535")

        if username in self._credentials:
            logger.warning("User already exists", username=username)
            return False

        password_hash = self._hasher.hash(password)

        self._credentials[username] = Credential(
            username=username,
            password_hash=password_hash,
            created_at=datetime.utcnow().isoformat(),
            use_tor=use_tor,
            bridge_type=bridge_type,
            security_level=security_level,
            allowed_ports=allowed_ports,
            rate_limit=rate_limit,
            bind_port=bind_port,
        )

        self._save_credentials()
        logger.info("Added new user", username=username)
        return True

    def remove_user(self, username: str) -> bool:
        """Remove a user from the system."""
        if username not in self._credentials:
            return False

        del self._credentials[username]
        self._save_credentials()
        logger.info("Removed user", username=username)
        return True

    def verify(self, username: str, password: str) -> bool:
        """
        Verify username and password combination.

        Uses constant-time comparison to prevent timing attacks.
        Automatically reloads credentials if the file has been modified
        (enables hot-reload when users are added via CLI).

        Args:
            username: The username to verify
            password: The plaintext password to verify

        Returns:
            True if credentials are valid, False otherwise
        """
        # Check for credential file updates (hot-reload for new users)
        self.reload_credentials()
        
        if username not in self._credentials:
            # Perform dummy hash to prevent timing attacks
            self._hasher.hash("dummy_password_for_timing")
            logger.warning("Authentication failed: unknown user", username=username)
            return False

        cred = self._credentials[username]

        if not cred.enabled:
            logger.warning("Authentication failed: user disabled", username=username)
            return False

        try:
            self._hasher.verify(cred.password_hash, password)

            # Check if rehash is needed (parameters changed)
            if self._hasher.check_needs_rehash(cred.password_hash):
                cred.password_hash = self._hasher.hash(password)
                self._save_credentials()  # Blocking save for security-critical update

            # Update last used timestamp (non-blocking save)
            cred.last_used = datetime.utcnow().isoformat()
            self._save_credentials_async()

            logger.info("Authentication successful", username=username)
            return True

        except VerifyMismatchError:
            logger.warning("Authentication failed: wrong password", username=username)
            return False
        except InvalidHash:
            logger.error("Invalid hash format in credentials", username=username)
            return False

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Change a user's password."""
        if not self.verify(username, old_password):
            return False

        if not self._validate_password(new_password):
            raise ValueError("New password does not meet security requirements")

        self._credentials[username].password_hash = self._hasher.hash(new_password)
        self._save_credentials()

        logger.info("Password changed", username=username)
        return True

    def generate_credentials(self) -> tuple[str, str]:
        """
        Generate secure random credentials.

        Returns:
            Tuple of (username, password)
        """
        username = f"user_{secrets.token_hex(8)}"
        # Generate password that meets all requirements
        password = self._generate_secure_password()
        return username, password

    def _generate_secure_password(self, length: int = 20) -> str:
        """
        Generate a password that meets security requirements.

        Ensures: uppercase, lowercase, digit, and special character.
        """
        import string

        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()-_=+"

        # Ensure at least one of each required type
        password_chars = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Fill remaining with random mix
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))

        # Shuffle to randomize positions
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    def get_user_tor_preference(self, username: str) -> Optional[bool]:
        """
        Get whether a user should have traffic routed through Tor.

        Args:
            username: The username to check

        Returns:
            True if Tor routing enabled, False if direct, None if user not found
        """
        if username not in self._credentials:
            return None
        return self._credentials[username].use_tor

    def set_user_tor_preference(self, username: str, use_tor: bool) -> bool:
        """
        Set whether a user should have traffic routed through Tor.

        Args:
            username: The username to update
            use_tor: Whether to enable Tor routing

        Returns:
            True if updated, False if user not found
        """
        if username not in self._credentials:
            return False

        self._credentials[username].use_tor = use_tor
        self._save_credentials()
        logger.info("Updated Tor preference", username=username, use_tor=use_tor)
        return True

    def list_users(self) -> list[str]:
        """List all registered usernames."""
        return list(self._credentials.keys())

    def get_user_info(self, username: str) -> Optional[dict]:
        """
        Get all information about a user.

        Args:
            username: The username to look up

        Returns:
            Dictionary with user info, or None if user not found
        """
        if username not in self._credentials:
            return None

        cred = self._credentials[username]
        return {
            "username": cred.username,
            "created_at": cred.created_at,
            "last_used": cred.last_used,
            "enabled": cred.enabled,
            "use_tor": cred.use_tor,
            "bridge_type": getattr(cred, 'bridge_type', 'none'),
            "security_level": getattr(cred, 'security_level', 'basic'),
            "allowed_ports": getattr(cred, 'allowed_ports', None),
            "rate_limit": getattr(cred, 'rate_limit', None),
            "bind_port": getattr(cred, 'bind_port', None),
        }

    def set_user_enabled(self, username: str, enabled: bool) -> bool:
        """
        Enable or disable a user.

        Args:
            username: The username to update
            enabled: Whether the user should be enabled

        Returns:
            True if updated, False if user not found
        """
        if username not in self._credentials:
            return False

        self._credentials[username].enabled = enabled
        self._save_credentials()
        logger.info("Updated user enabled status", username=username, enabled=enabled)
        return True

    def get_user_enabled(self, username: str) -> Optional[bool]:
        """
        Check if a user is enabled.

        Args:
            username: The username to check

        Returns:
            True if enabled, False if disabled, None if user not found
        """
        if username not in self._credentials:
            return None
        return self._credentials[username].enabled

    def get_user_security_level(self, username: str) -> Optional[str]:
        """
        Get a user's security level.

        Args:
            username: The username to check

        Returns:
            Security level string, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], 'security_level', 'basic')

    def set_user_security_level(self, username: str, level: str) -> bool:
        """
        Set a user's security level.

        Args:
            username: The username to update
            level: Security level (none, basic, moderate, paranoid)

        Returns:
            True if updated, False if user not found
        """
        if level not in ("none", "basic", "moderate", "paranoid"):
            raise ValueError("Invalid security level")

        if username not in self._credentials:
            return False

        self._credentials[username].security_level = level
        self._save_credentials()
        logger.info("Updated security level", username=username, level=level)
        return True

    def get_user_allowed_ports(self, username: str) -> Optional[list[int]]:
        """
        Get a user's allowed ports.

        Args:
            username: The username to check

        Returns:
            List of allowed ports, None for all ports, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], 'allowed_ports', None)

    def set_user_allowed_ports(self, username: str, ports: Optional[list[int]]) -> bool:
        """
        Set a user's allowed ports.

        Args:
            username: The username to update
            ports: List of allowed ports, or None for all ports

        Returns:
            True if updated, False if user not found
        """
        if username not in self._credentials:
            return False

        self._credentials[username].allowed_ports = ports
        self._save_credentials()
        logger.info("Updated allowed ports", username=username, ports=ports)
        return True

    def get_user_rate_limit(self, username: str) -> Optional[int]:
        """
        Get a user's rate limit.

        Args:
            username: The username to check

        Returns:
            Rate limit (requests/min), None for server default, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], 'rate_limit', None)

    def set_user_rate_limit(self, username: str, rate_limit: Optional[int]) -> bool:
        """
        Set a user's rate limit.

        Args:
            username: The username to update
            rate_limit: Max requests per minute, or None for server default

        Returns:
            True if updated, False if user not found
        """
        if username not in self._credentials:
            return False

        self._credentials[username].rate_limit = rate_limit
        self._save_credentials()
        logger.info("Updated rate limit", username=username, rate_limit=rate_limit)
        return True

    def get_user_bridge_type(self, username: str) -> Optional[str]:
        """
        Get a user's bridge type.

        Args:
            username: The username to check

        Returns:
            Bridge type string, or None if user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], 'bridge_type', 'none')

    def set_user_bridge_type(self, username: str, bridge_type: str) -> bool:
        """
        Set a user's bridge type.

        Args:
            username: The username to update
            bridge_type: Bridge type (none, obfs4, snowflake)

        Returns:
            True if updated, False if user not found
        """
        if bridge_type not in ("none", "obfs4", "snowflake"):
            raise ValueError("Invalid bridge type")

        if username not in self._credentials:
            return False

        self._credentials[username].bridge_type = bridge_type
        self._save_credentials()
        logger.info("Updated bridge type", username=username, bridge_type=bridge_type)
        return True

    def get_user_bind_port(self, username: str) -> Optional[int]:
        """
        Get a user's custom bind port.

        Args:
            username: The username to check

        Returns:
            Bind port, or None if using shared port or user not found
        """
        if username not in self._credentials:
            return None
        return getattr(self._credentials[username], 'bind_port', None)

    def set_user_bind_port(self, username: str, bind_port: Optional[int]) -> bool:
        """
        Set a user's custom bind port.

        Args:
            username: The username to update
            bind_port: Custom port (1-65535), or None for shared server port

        Returns:
            True if updated, False if user not found
        """
        if bind_port is not None and (bind_port < 1 or bind_port > 65535):
            raise ValueError("Invalid bind port. Must be 1-65535")

        if username not in self._credentials:
            return False

        self._credentials[username].bind_port = bind_port
        self._save_credentials()
        logger.info("Updated bind port", username=username, bind_port=bind_port)
        return True

    def get_users_with_custom_ports(self) -> dict[str, int]:
        """
        Get all users that have custom bind ports configured.

        Returns:
            Dictionary mapping username to bind port
        """
        return {
            username: cred.bind_port
            for username, cred in self._credentials.items()
            if getattr(cred, 'bind_port', None) is not None
        }

    def get_user_for_port(self, port: int) -> Optional[str]:
        """
        Get the username that has a specific custom bind port.

        Args:
            port: The port to look up

        Returns:
            Username if found, None otherwise
        """
        for username, cred in self._credentials.items():
            if getattr(cred, 'bind_port', None) == port:
                return username
        return None

    @staticmethod
    def _validate_username(username: str) -> bool:
        """Validate username format."""
        if not username or len(username) < 3 or len(username) > 64:
            return False
        # Allow alphanumeric, underscore, hyphen
        return all(c.isalnum() or c in "_-" for c in username)

    @staticmethod
    def _validate_password(password: str) -> bool:
        """
        Validate password meets security requirements.

        Requirements:
        - Minimum 12 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(password) < 12:
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        return has_upper and has_lower and has_digit and has_special


class SessionManager:
    """Manages authenticated sessions with tokens."""

    TOKEN_LIFETIME = timedelta(hours=24)

    def __init__(self):
        self._sessions: dict[str, tuple[str, datetime]] = {}

    def create_session(self, username: str) -> str:
        """Create a new session token for a user."""
        token = secrets.token_urlsafe(32)
        expires = datetime.utcnow() + self.TOKEN_LIFETIME
        self._sessions[token] = (username, expires)
        return token

    def validate_session(self, token: str) -> Optional[str]:
        """
        Validate a session token.

        Returns the username if valid, None otherwise.
        """
        if token not in self._sessions:
            return None

        username, expires = self._sessions[token]

        if datetime.utcnow() > expires:
            del self._sessions[token]
            return None

        return username

    def revoke_session(self, token: str) -> bool:
        """Revoke a session token."""
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False

    def revoke_all_sessions(self, username: str) -> int:
        """Revoke all sessions for a user."""
        to_remove = [
            token for token, (user, _) in self._sessions.items()
            if user == username
        ]
        for token in to_remove:
            del self._sessions[token]
        return len(to_remove)

    def cleanup_expired(self) -> int:
        """Remove expired sessions."""
        now = datetime.utcnow()
        to_remove = [
            token for token, (_, expires) in self._sessions.items()
            if now > expires
        ]
        for token in to_remove:
            del self._sessions[token]
        return len(to_remove)
