"""
API Configuration Utilities.

Provides secure loading, saving, and management of API settings,
including encrypted API key storage.
"""

import base64
import os
import secrets
from pathlib import Path
from typing import Optional

import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .logging import get_logger
from ..paths import get_config_dir, load_master_key


logger = get_logger(__name__)


def _get_api_config_file() -> Path:
    """Get the path to the API configuration file."""
    return get_config_dir() / "api.yaml"


def _get_api_salt_file() -> Path:
    """Get the path to the API encryption salt file."""
    return get_config_dir() / ".api_salt"


def _derive_fernet_key(master_key: str) -> Fernet:
    """
    Derive a Fernet encryption key from the master key.
    
    Args:
        master_key: The master key for encryption
        
    Returns:
        Fernet instance for encryption/decryption
    """
    salt_file = _get_api_salt_file()
    
    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = secrets.token_bytes(32)
        salt_file.parent.mkdir(parents=True, exist_ok=True)
        salt_file.write_bytes(salt)
        if os.name != 'nt':
            os.chmod(salt_file, 0o600)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
    return Fernet(key)


def _encrypt_api_key(api_key: str, master_key: str) -> str:
    """
    Encrypt an API key using the master key.
    
    Args:
        api_key: The plaintext API key
        master_key: The master key for encryption
        
    Returns:
        Base64-encoded encrypted API key
    """
    fernet = _derive_fernet_key(master_key)
    encrypted = fernet.encrypt(api_key.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def _decrypt_api_key(encrypted_key: str, master_key: str) -> Optional[str]:
    """
    Decrypt an API key using the master key.
    
    Args:
        encrypted_key: The base64-encoded encrypted API key
        master_key: The master key for decryption
        
    Returns:
        Decrypted API key, or None if decryption fails
    """
    try:
        fernet = _derive_fernet_key(master_key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_key.encode())
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode()
    except (InvalidToken, Exception) as e:
        logger.error("Failed to decrypt API key", error=str(e))
        return None


def load_api_config() -> dict:
    """
    Load API configuration from config/api.yaml.
    
    Returns:
        Dictionary with API settings. Keys include:
        - enabled: bool
        - host: str  
        - port: int
        - api_key_encrypted: str (encrypted key, if present)
    """
    config_file = _get_api_config_file()
    
    if not config_file.exists():
        logger.debug("No API config file found, returning defaults")
        return {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 8080,
        }
    
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}
        
        logger.debug("Loaded API config", file=str(config_file))
        return data
        
    except Exception as e:
        logger.error("Failed to load API config", error=str(e))
        raise


def save_api_config(config: dict) -> None:
    """
    Save API configuration to config/api.yaml.
    
    Args:
        config: Dictionary with API settings to save
    """
    config_file = _get_api_config_file()
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(config_file, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)
        
        # Set restrictive permissions on non-Windows
        if os.name != 'nt':
            os.chmod(config_file, 0o600)
        
        logger.info("Saved API config", file=str(config_file))
        
    except Exception as e:
        logger.error("Failed to save API config", error=str(e))
        raise


def get_api_key() -> Optional[str]:
    """
    Get the current API key (decrypted).
    
    Loads the encrypted key from config and decrypts it using
    the master key from environment.
    
    Returns:
        Decrypted API key, or None if not configured or decryption fails
    """
    config = load_api_config()
    encrypted_key = config.get("api_key_encrypted")
    
    if not encrypted_key:
        return None
    
    master_key = load_master_key()
    if not master_key:
        logger.warning("Cannot decrypt API key: no master key available")
        return None
    
    return _decrypt_api_key(encrypted_key, master_key)


def set_api_key(key: str) -> None:
    """
    Set and save an API key (encrypted).
    
    Encrypts the key using the master key and saves it to the
    API config file.
    
    Args:
        key: The plaintext API key to store
        
    Raises:
        ValueError: If no master key is available
    """
    master_key = load_master_key()
    if not master_key:
        raise ValueError("Cannot encrypt API key: no master key available. "
                        "Set SHADOW9_MASTER_KEY environment variable.")
    
    encrypted_key = _encrypt_api_key(key, master_key)
    
    config = load_api_config()
    config["api_key_encrypted"] = encrypted_key
    save_api_config(config)
    
    logger.info("API key updated and encrypted")


def generate_api_key() -> str:
    """
    Generate a new secure API key.
    
    Returns:
        A URL-safe base64-encoded random key (32 bytes)
    """
    return secrets.token_urlsafe(32)


def clear_api_key() -> None:
    """
    Remove the API key from configuration.
    """
    config = load_api_config()
    if "api_key_encrypted" in config:
        del config["api_key_encrypted"]
        save_api_config(config)
        logger.info("API key cleared")
