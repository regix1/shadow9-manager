"""
Shadow9 Wizards - Interactive CLI wizards for Shadow9.

This module contains all the interactive wizards used by the CLI.
"""

from .user_new import run_user_wizard
from .user_modify import run_user_modify_wizard
from .user_remove import run_user_remove_wizard
from .user_list import run_user_list_wizard, _user_action_menu
from .user_info import run_user_info_wizard, display_user_info
from .user_enable_disable import run_user_enable_wizard, run_user_disable_wizard
from .serve import run_serve_wizard, show_serve_preview
from .init_wizard import run_init_wizard, show_config_summary, show_master_key

__all__ = [
    # User creation
    "run_user_wizard",
    # User modification
    "run_user_modify_wizard",
    # User removal
    "run_user_remove_wizard",
    # User listing
    "run_user_list_wizard",
    "_user_action_menu",
    # User info
    "run_user_info_wizard",
    "display_user_info",
    # User enable/disable
    "run_user_enable_wizard",
    "run_user_disable_wizard",
    # Server
    "run_serve_wizard",
    "show_serve_preview",
    # Init
    "run_init_wizard",
    "show_config_summary",
    "show_master_key",
]
