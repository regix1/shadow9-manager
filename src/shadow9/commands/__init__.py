"""
Command modules for Shadow9 CLI.

Split into logical groupings:
- server: serve/stop commands
- user: user management commands
- service: systemd service management (Linux)
- utils: utility commands (init, check-tor, fetch, setup, status, update)
- api: API management commands
"""

from .server import register_server_commands
from .user import register_user_commands
from .service import register_service_commands
from .utils import register_util_commands
from .api import register_api_commands

__all__ = [
    "register_server_commands",
    "register_user_commands",
    "register_service_commands",
    "register_util_commands",
    "register_api_commands",
]
