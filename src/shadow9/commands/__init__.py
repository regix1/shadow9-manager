"""
Command modules for Shadow9 CLI.

Split into logical groupings:
- server: serve/stop commands
- user: user management commands
- utils: utility commands (init, check-tor, fetch, setup, status, update)
"""

from .server import register_server_commands
from .user import register_user_commands
from .utils import register_util_commands

__all__ = [
    "register_server_commands",
    "register_user_commands",
    "register_util_commands",
]
