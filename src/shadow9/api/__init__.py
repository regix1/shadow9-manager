"""
Shadow9 REST API

FastAPI-based REST API for programmatic access.
"""

from .app import create_app, create_enrollment_app
from .deps import get_user_service

__all__ = [
    "create_app",
    "create_enrollment_app",
    "get_user_service",
]
