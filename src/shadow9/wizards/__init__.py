"""
Shadow9 Wizards - Interactive CLI wizards for Shadow9.

This module contains all the interactive wizards used by the CLI.
"""

from .user_new import run_user_wizard
from .user_modify import run_user_modify_wizard
from .user_list import run_user_list_wizard
from .user_info import display_user_info
from .serve import run_serve_wizard, show_serve_preview
from .init_wizard import run_init_wizard, show_config_summary, show_master_key
from .api_setup import run_api_setup_wizard, display_api_config

__all__ = [
    # User creation
    "run_user_wizard",
    # User modification
    "run_user_modify_wizard",
    # User listing
    "run_user_list_wizard",
    # User info
    "display_user_info",
    # Server
    "run_serve_wizard",
    "show_serve_preview",
    # Init
    "run_init_wizard",
    "show_config_summary",
    "show_master_key",
    # API
    "run_api_setup_wizard",
    "display_api_config",
]
