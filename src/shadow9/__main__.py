"""
Main entry point for running shadow9-manager as a module.

Usage:
    python -m shadow9 socks5 serve
    python -m shadow9 socks5 user generate --username myuser
    python -m shadow9 socks5 check-tor
"""

from .cli import cli

if __name__ == "__main__":
    cli()
