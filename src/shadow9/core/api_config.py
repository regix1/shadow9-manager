"""
API Configuration Utilities.

Provides secure loading, saving, and management of API settings,
including encrypted API key storage.
"""

import base64
import secrets
from pathlib import Path
from typing import Optional

import yaml
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .logging import get_logger
from ..paths import get_config_dir, load_master_key, read_or_create_salt, write_file_safely


logger = get_logger(__name__)


def _get_api_config_file() -> Path:
    """Get the path to the API configuration file."""
    return get_config_dir() / "api.yaml"


def _get_api_salt_file() -> Path:
    """Get the path to the API encryption salt file."""
    return get_config_dir() / ".api_salt"


def _resolve_config_file(config_file: Optional[Path] = None) -> Path:
    """Resolve a caller-supplied config path, falling back to the default location."""
    return Path(config_file) if config_file else _get_api_config_file()


def _derive_fernet_key(master_key: str) -> Fernet:
    """
    Derive a Fernet encryption key from the master key.

    Args:
        master_key: The master key for encryption

    Returns:
        Fernet instance for encryption/decryption
    """
    salt = read_or_create_salt(_get_api_salt_file())

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


def load_api_config(config_file: Optional[Path] = None) -> dict:
    """
    Load API configuration from config/api.yaml.

    Args:
        config_file: Config file to read, or None for the default location

    Returns:
        Dictionary with API settings. Keys include:
        - enabled: bool
        - host: str
        - port: int
        - api_key_encrypted: str (encrypted key, if present)
    """
    path = _resolve_config_file(config_file)

    if not path.exists():
        logger.debug("No API config file found, returning defaults")
        return {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 8080,
        }

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        # Files written before the key was encrypted nest everything under "api"
        nested = data.pop("api", None)
        if isinstance(nested, dict):
            data = {**nested, **data}

        if data.get("key"):
            logger.warning(
                "API config holds an unencrypted key; run 'shadow9 api setup' to replace it",
                file=str(path),
            )

        logger.debug("Loaded API config", file=str(path))
        return data

    except Exception as e:
        logger.error("Failed to load API config", error=str(e))
        raise


def save_api_config(config: dict, config_file: Optional[Path] = None) -> None:
    """
    Save API configuration to config/api.yaml.

    Args:
        config: Dictionary with API settings to save
        config_file: Config file to write, or None for the default location
    """
    path = _resolve_config_file(config_file)

    try:
        serialized = yaml.safe_dump(config, default_flow_style=False, sort_keys=False)
        write_file_safely(path, serialized.encode())

        logger.info("Saved API config", file=str(path))

    except Exception as e:
        logger.error("Failed to save API config", error=str(e))
        raise


def get_api_key(config_file: Optional[Path] = None) -> Optional[str]:
    """
    Get the current API key (decrypted).

    Loads the encrypted key from config and decrypts it using
    the master key from environment.

    Args:
        config_file: Config file to read, or None for the default location

    Returns:
        Decrypted API key, or None if not configured or decryption fails
    """
    config = load_api_config(config_file)
    encrypted_key = config.get("api_key_encrypted")

    if not encrypted_key:
        # a key written before encryption was in use is still the live key
        return config.get("key")

    master_key = load_master_key()
    if not master_key:
        logger.warning("Cannot decrypt API key: no master key available")
        return None

    return _decrypt_api_key(encrypted_key, master_key)


def set_api_key(key: str, config_file: Optional[Path] = None) -> None:
    """
    Set and save an API key (encrypted).

    Encrypts the key using the master key and saves it to the
    API config file.

    Args:
        key: The plaintext API key to store
        config_file: Config file to write, or None for the default location

    Raises:
        ValueError: If no master key is available
    """
    master_key = load_master_key()
    if not master_key:
        raise ValueError(
            "Cannot encrypt API key: no master key available. "
            "Set SHADOW9_MASTER_KEY environment variable."
        )

    encrypted_key = _encrypt_api_key(key, master_key)

    config = load_api_config(config_file)
    config["api_key_encrypted"] = encrypted_key
    # drop any plaintext key the file carried in from before encryption
    config.pop("key", None)
    save_api_config(config, config_file)

    logger.info("API key updated and encrypted")


def generate_api_key() -> str:
    """
    Generate a new secure API key.

    Returns:
        A URL-safe base64-encoded random key (32 bytes)
    """
    return secrets.token_urlsafe(32)


def clear_api_key(config_file: Optional[Path] = None) -> None:
    """
    Remove the API key from configuration.

    Args:
        config_file: Config file to write, or None for the default location
    """
    config = load_api_config(config_file)
    encrypted = config.pop("api_key_encrypted", None)
    plaintext = config.pop("key", None)
    if encrypted or plaintext:
        save_api_config(config, config_file)
        logger.info("API key cleared")
