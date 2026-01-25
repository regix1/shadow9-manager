"""
Centralized path management for Shadow9.

This module provides a single source of truth for all file paths used by Shadow9.
It ensures consistent path resolution regardless of where commands are run from.

The install directory priority is:
1. SHADOW9_HOME environment variable (if set)
2. /opt/shadow9-manager (Linux system install)
3. ~/shadow9-manager (User install)
4. Package location (development/local install)
"""

import os
import sys
from pathlib import Path
from typing import Optional


class Shadow9Paths:
    """
    Centralized path manager for Shadow9.
    
    All paths are relative to a single root directory that is determined
    once and used consistently throughout the application.
    """
    
    _instance: Optional['Shadow9Paths'] = None
    _root: Optional[Path] = None
    
    # Standard directory names
    CONFIG_DIR = "config"
    USERS_DIR = "users"
    LOGS_DIR = "logs"
    
    # Standard file names
    ENV_FILE = ".env"
    CREDENTIALS_FILE = "credentials.enc"
    SALT_FILE = ".salt"
    CONFIG_FILE = "config.yaml"
    
    def __new__(cls):
        """Singleton pattern to ensure consistent paths across the application."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self) -> None:
        """Initialize the path manager by finding the root directory."""
        self._root = self._find_root()
        
        # Ensure critical directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.users_dir.mkdir(parents=True, exist_ok=True)
    
    def _find_root(self) -> Path:
        """
        Find the Shadow9 root directory.
        
        Priority order:
        1. SHADOW9_HOME environment variable
        2. /opt/shadow9-manager (if .env or config exists there)
        3. Current package location (if .env or config exists there)
        4. ~/shadow9-manager (user install location)
        5. Create at /opt/shadow9-manager (Linux) or ~/shadow9-manager (other)
        """
        # Check environment variable first
        if env_home := os.getenv("SHADOW9_HOME"):
            path = Path(env_home)
            if path.exists():
                return path.resolve()
        
        # Standard install locations to check
        check_locations = [
            Path("/opt/shadow9-manager"),                    # Linux system install
            Path("/root/shadow9-manager"),                   # Root user install
            self._get_package_location(),                    # Package/dev location
            Path.home() / "shadow9-manager",                 # User home install
        ]
        
        # Find first location that has .env or config directory
        for loc in check_locations:
            if loc and loc.exists():
                if (loc / self.ENV_FILE).exists() or (loc / self.CONFIG_DIR).exists():
                    return loc.resolve()
        
        # If nothing found, use the first writable location
        # Prefer /opt on Linux for system-wide install
        if sys.platform == "linux":
            default = Path("/opt/shadow9-manager")
        else:
            default = Path.home() / "shadow9-manager"
        
        # If package location exists and has files, prefer it
        pkg_loc = self._get_package_location()
        if pkg_loc and pkg_loc.exists():
            return pkg_loc.resolve()
        
        return default.resolve()
    
    def _get_package_location(self) -> Optional[Path]:
        """Get the package installation location (parent of src directory)."""
        # Go from src/shadow9/paths.py -> project root
        current = Path(__file__).resolve()
        # paths.py -> shadow9 -> src -> project_root
        project_root = current.parent.parent.parent
        
        # Verify it looks like a valid project root
        if (project_root / "src" / "shadow9").is_dir():
            return project_root
        
        return None
    
    @property
    def root(self) -> Path:
        """Get the Shadow9 root directory."""
        return self._root
    
    @property
    def config_dir(self) -> Path:
        """Get the config directory path."""
        return self._root / self.CONFIG_DIR
    
    @property
    def users_dir(self) -> Path:
        """Get the users directory path."""
        return self._root / self.USERS_DIR
    
    @property
    def logs_dir(self) -> Path:
        """Get the logs directory path."""
        return self._root / self.LOGS_DIR
    
    @property
    def env_file(self) -> Path:
        """Get the .env file path."""
        return self._root / self.ENV_FILE
    
    @property
    def credentials_file(self) -> Path:
        """Get the encrypted credentials file path."""
        return self.config_dir / self.CREDENTIALS_FILE
    
    @property
    def salt_file(self) -> Path:
        """Get the encryption salt file path."""
        return self.config_dir / self.SALT_FILE
    
    @property
    def config_file(self) -> Path:
        """Get the main config.yaml file path."""
        return self.config_dir / self.CONFIG_FILE
    
    def get_user_dir(self, username: str) -> Path:
        """
        Get the directory for a specific user.
        
        Args:
            username: The username
            
        Returns:
            Path to the user's directory
        """
        return self.users_dir / username
    
    def get_user_credentials_file(self, username: str) -> Path:
        """
        Get the plaintext credentials file for a user (optional save).
        
        Args:
            username: The username
            
        Returns:
            Path to the user's plaintext credentials file
        """
        return self.get_user_dir(username) / "credentials.txt"
    
    def get_user_config_file(self, username: str) -> Path:
        """
        Get the user-specific config file path.
        
        Args:
            username: The username
            
        Returns:
            Path to the user's config file
        """
        return self.get_user_dir(username) / "config.yaml"
    
    def ensure_user_dir(self, username: str) -> Path:
        """
        Ensure the user directory exists and return its path.
        
        Args:
            username: The username
            
        Returns:
            Path to the user's directory
        """
        user_dir = self.get_user_dir(username)
        user_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on Unix
        if os.name != 'nt':
            try:
                os.chmod(user_dir, 0o700)
            except Exception:
                pass
        
        return user_dir
    
    def save_user_credentials(
        self, 
        username: str, 
        password: str,
        routing: str,
        security: str,
        bind_port: Optional[int] = None,
        allowed_ports: Optional[list[int]] = None,
        rate_limit: Optional[int] = None
    ) -> Path:
        """
        Save user credentials to their user folder.
        
        Args:
            username: The username
            password: The plaintext password
            routing: The routing description (e.g., "Tor + obfs4")
            security: The security level
            bind_port: Optional custom bind port
            allowed_ports: Optional list of allowed ports
            rate_limit: Optional rate limit
            
        Returns:
            Path to the saved credentials file
        """
        from datetime import datetime
        
        self.ensure_user_dir(username)
        cred_file = self.get_user_credentials_file(username)
        
        content = f"""Shadow9 User Credentials
========================
Username: {username}
Password: {password}

Settings:
- Routing: {routing}
- Security: {security}
"""
        if bind_port:
            content += f"- Bind Port: {bind_port}\n"
        if allowed_ports:
            content += f"- Allowed Ports: {', '.join(map(str, allowed_ports))}\n"
        if rate_limit:
            content += f"- Rate Limit: {rate_limit} req/min\n"
        
        content += f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        cred_file.write_text(content)
        
        # Set restrictive permissions on Unix
        if os.name != 'nt':
            try:
                os.chmod(cred_file, 0o600)
            except Exception:
                pass
        
        return cred_file
    
    def delete_user_dir(self, username: str) -> bool:
        """
        Delete a user's directory and all its contents.
        
        Args:
            username: The username
            
        Returns:
            True if deleted, False if didn't exist
        """
        import shutil
        user_dir = self.get_user_dir(username)
        
        if user_dir.exists():
            shutil.rmtree(user_dir)
            return True
        return False
    
    def resolve_path(self, relative_path: str) -> Path:
        """
        Resolve a relative path against the root directory.
        
        Args:
            relative_path: Path relative to root, or absolute path
            
        Returns:
            Resolved absolute path
        """
        path = Path(relative_path)
        if path.is_absolute():
            return path
        return self._root / path
    
    def load_master_key(self) -> Optional[str]:
        """
        Load the master key from environment or .env file.
        
        Returns:
            The master key if found, None otherwise
        """
        # Check environment first
        if master_key := os.getenv("SHADOW9_MASTER_KEY"):
            return master_key
        
        # Check .env file
        if self.env_file.exists():
            try:
                for line in self.env_file.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("SHADOW9_MASTER_KEY="):
                        return line.split("=", 1)[1].strip()
            except Exception:
                pass
        
        return None
    
    def __repr__(self) -> str:
        return f"Shadow9Paths(root={self._root})"


# Module-level convenience functions
def get_paths() -> Shadow9Paths:
    """Get the singleton Shadow9Paths instance."""
    return Shadow9Paths()


def get_root() -> Path:
    """Get the Shadow9 root directory."""
    return get_paths().root


def get_credentials_file() -> Path:
    """Get the credentials file path."""
    return get_paths().credentials_file


def get_config_dir() -> Path:
    """Get the config directory path."""
    return get_paths().config_dir


def get_users_dir() -> Path:
    """Get the users directory path."""
    return get_paths().users_dir


def load_master_key() -> Optional[str]:
    """Load the master key."""
    return get_paths().load_master_key()
