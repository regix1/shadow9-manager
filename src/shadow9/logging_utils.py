"""
User-aware logging utilities.

Provides logging wrappers that respect per-user logging preferences,
ensuring that users with logging disabled have no activity recorded.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

import structlog

if TYPE_CHECKING:
    from shadow9.auth import AuthManager

logger = structlog.get_logger(__name__)


class UserAwareLogger:
    """
    A logger wrapper that respects per-user logging preferences.

    When a user has logging disabled, any log calls for that user
    will be silently dropped - providing a server-side privacy guarantee.
    """

    def __init__(self, auth_manager: AuthManager, base_logger: Any = None):
        """
        Initialize the user-aware logger.

        Args:
            auth_manager: AuthManager instance to check user preferences
            base_logger: Optional base logger (defaults to module logger)
        """
        self._auth_manager = auth_manager
        self._logger = base_logger or logger

    def _should_log(self, username: Optional[str]) -> bool:
        """Check if logging is allowed for the given user."""
        if username is None:
            return True
        logging_enabled = self._auth_manager.get_user_logging_enabled(username)
        # Default to True if user not found or setting not present
        return logging_enabled if logging_enabled is not None else True

    def debug(self, event: str, username: Optional[str] = None, **kwargs: Any) -> None:
        """Log debug message if user allows logging."""
        if self._should_log(username):
            if username:
                self._logger.debug(event, username=username, **kwargs)
            else:
                self._logger.debug(event, **kwargs)

    def info(self, event: str, username: Optional[str] = None, **kwargs: Any) -> None:
        """Log info message if user allows logging."""
        if self._should_log(username):
            if username:
                self._logger.info(event, username=username, **kwargs)
            else:
                self._logger.info(event, **kwargs)

    def warning(self, event: str, username: Optional[str] = None, **kwargs: Any) -> None:
        """Log warning message if user allows logging."""
        if self._should_log(username):
            if username:
                self._logger.warning(event, username=username, **kwargs)
            else:
                self._logger.warning(event, **kwargs)

    def error(self, event: str, username: Optional[str] = None, **kwargs: Any) -> None:
        """Log error message if user allows logging."""
        if self._should_log(username):
            if username:
                self._logger.error(event, username=username, **kwargs)
            else:
                self._logger.error(event, **kwargs)

    def log_connection(
        self,
        event: str,
        username: Optional[str],
        client_addr: Optional[tuple[str, int]] = None,
        target: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """
        Log a connection event, respecting user logging preferences.

        This is the primary method for logging connection-related events
        that may contain sensitive user network data.

        Args:
            event: The log event description
            username: The authenticated username (if any)
            client_addr: Client IP and port tuple
            target: Target host:port being connected to
            **kwargs: Additional log context
        """
        if not self._should_log(username):
            return

        log_data = {**kwargs}
        if username:
            log_data["username"] = username
        if client_addr:
            log_data["client"] = f"{client_addr[0]}:{client_addr[1]}"
        if target:
            log_data["target"] = target

        self._logger.info(event, **log_data)


def create_user_logger(auth_manager: AuthManager) -> UserAwareLogger:
    """
    Create a user-aware logger instance.

    Args:
        auth_manager: The AuthManager to check user preferences

    Returns:
        A UserAwareLogger instance
    """
    return UserAwareLogger(auth_manager)
