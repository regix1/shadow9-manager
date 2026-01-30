"""
Authentication service for proxy access control.

Handles user authentication, session management, and access control.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from ..core.logging import get_logger
# Credential type used implicitly via repository
from ..repositories.user_repository import UserRepository


logger = get_logger(__name__)


class Session:
    """Represents an authenticated session."""
    
    def __init__(
        self,
        session_id: str,
        username: str,
        created_at: datetime,
        expires_at: datetime
    ):
        self.session_id = session_id
        self.username = username
        self.created_at = created_at
        self.expires_at = expires_at
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.utcnow() > self.expires_at


class AuthService:
    """
    Authentication service for user verification.
    
    Provides:
    - Password verification with Argon2id
    - Session management
    - Rate limiting support
    - User preference retrieval
    """
    
    def __init__(
        self,
        repository: UserRepository,
        session_ttl: int = 3600
    ):
        """
        Initialize the auth service.
        
        Args:
            repository: User repository for credential access
            session_ttl: Session time-to-live in seconds
        """
        self._repo = repository
        self._session_ttl = session_ttl
        self._sessions: dict[str, Session] = {}
    
    async def authenticate(self, username: str, password: str) -> Optional[str]:
        """
        Authenticate a user and create a session.
        
        Args:
            username: The username
            password: The password
            
        Returns:
            Session ID if authenticated, None otherwise
        """
        # Get user credential
        credential = await self._repo.get(username)
        
        if credential is None:
            # Timing attack protection: hash dummy password
            self._repo.hash_password("dummy_password_for_timing")
            logger.warning("Auth failed: unknown user", username=username)
            return None
        
        if not credential.enabled:
            if credential.logging_enabled:
                logger.warning("Auth failed: user disabled", username=username)
            return None
        
        # Verify password
        if not self._repo.verify_password(password, credential.password_hash):
            if credential.logging_enabled:
                logger.warning("Auth failed: wrong password", username=username)
            return None
        
        # Check if rehash needed
        if self._repo.check_needs_rehash(credential.password_hash):
            new_hash = self._repo.hash_password(password)
            await self._repo.update(username, {'password_hash': new_hash})
        
        # Update last used
        await self._repo.update_last_used(username)
        
        # Create session
        session_id = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        session = Session(
            session_id=session_id,
            username=username,
            created_at=now,
            expires_at=now + timedelta(seconds=self._session_ttl)
        )
        self._sessions[session_id] = session
        
        if credential.logging_enabled:
            logger.info("Auth successful", username=username)
        
        return session_id
    
    async def verify(self, username: str, password: str) -> bool:
        """
        Verify credentials without creating a session.
        
        Args:
            username: The username
            password: The password
            
        Returns:
            True if credentials are valid
        """
        credential = await self._repo.get(username)
        
        if credential is None:
            self._repo.hash_password("dummy_password_for_timing")
            return False
        
        if not credential.enabled:
            return False
        
        return self._repo.verify_password(password, credential.password_hash)
    
    async def validate_session(self, session_id: str) -> Optional[str]:
        """
        Validate a session and return the username.
        
        Args:
            session_id: The session ID to validate
            
        Returns:
            Username if valid, None otherwise
        """
        session = self._sessions.get(session_id)
        
        if session is None:
            return None
        
        if session.is_expired:
            del self._sessions[session_id]
            return None
        
        return session.username
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: The session ID to revoke
            
        Returns:
            True if revoked, False if not found
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False
    
    def revoke_all_sessions(self, username: str) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            username: The username
            
        Returns:
            Number of sessions revoked
        """
        to_remove = [
            sid for sid, session in self._sessions.items()
            if session.username == username
        ]
        
        for sid in to_remove:
            del self._sessions[sid]
        
        return len(to_remove)
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired sessions.
        
        Returns:
            Number of sessions removed
        """
        now = datetime.utcnow()
        expired = [
            sid for sid, session in self._sessions.items()
            if session.expires_at < now
        ]
        
        for sid in expired:
            del self._sessions[sid]
        
        return len(expired)
    
    async def get_user_preferences(self, username: str) -> Optional[dict]:
        """
        Get user routing preferences for proxy operations.
        
        Args:
            username: The username
            
        Returns:
            Dictionary with user preferences, None if not found
        """
        credential = await self._repo.get(username)
        
        if credential is None:
            return None
        
        return {
            'use_tor': credential.use_tor,
            'bridge_type': credential.bridge_type.value if credential.bridge_type else 'none',
            'security_level': credential.security_level.value if credential.security_level else 'basic',
            'allowed_ports': credential.allowed_ports,
            'rate_limit': credential.rate_limit,
            'bind_port': credential.bind_port,
            'logging_enabled': credential.logging_enabled,
        }
