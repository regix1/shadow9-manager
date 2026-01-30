"""
Shadow9 Repositories

Data access layer implementing the repository pattern.
"""

from .base import Repository
from .user_repository import UserRepository

__all__ = [
    "Repository",
    "UserRepository",
]
