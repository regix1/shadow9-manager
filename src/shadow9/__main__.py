"""
Main entry point for running shadow9-manager as a module.

Usage:
    python -m shadow9 serve
    python -m shadow9 user add myuser
    python -m shadow9 check-tor
"""

from .cli import main

if __name__ == "__main__":
    main()
