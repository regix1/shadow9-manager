"""Tests for authentication module."""

import pytest
import tempfile
from pathlib import Path

from shadow9.auth import AuthManager


class TestAuthManager:
    """Tests for AuthManager."""

    def test_add_user(self, tmp_path):
        """Test adding a new user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        result = auth.add_user("testuser", "SecurePass123!@#")
        assert result is True
        assert "testuser" in auth.list_users()

    def test_add_duplicate_user(self, tmp_path):
        """Test adding a duplicate user fails."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.add_user("testuser", "AnotherPass123!@#")
        assert result is False

    def test_verify_correct_password(self, tmp_path):
        """Test verification with correct password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.verify("testuser", "SecurePass123!@#")
        assert result is True

    def test_verify_wrong_password(self, tmp_path):
        """Test verification with wrong password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.verify("testuser", "WrongPassword123!@#")
        assert result is False

    def test_verify_nonexistent_user(self, tmp_path):
        """Test verification for non-existent user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        result = auth.verify("nonexistent", "AnyPassword123!@#")
        assert result is False

    def test_remove_user(self, tmp_path):
        """Test removing a user."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        auth.add_user("testuser", "SecurePass123!@#")
        result = auth.remove_user("testuser")
        assert result is True
        assert "testuser" not in auth.list_users()

    def test_generate_credentials(self, tmp_path):
        """Test generating random credentials."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        username, password = auth.generate_credentials()
        assert len(username) > 0
        assert len(password) >= 12  # Minimum secure password length
        # Verify password meets requirements
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)
        assert any(not c.isalnum() for c in password)

    def test_invalid_username(self, tmp_path):
        """Test adding user with invalid username."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        with pytest.raises(ValueError):
            auth.add_user("ab", "SecurePass123!@#")  # Too short

    def test_weak_password(self, tmp_path):
        """Test adding user with weak password."""
        creds_file = tmp_path / "credentials.enc"
        auth = AuthManager(credentials_file=creds_file)

        with pytest.raises(ValueError):
            auth.add_user("testuser", "weak")

    def test_persistence(self, tmp_path):
        """Test that credentials persist across instances."""
        creds_file = tmp_path / "credentials.enc"

        # Create user with first instance
        auth1 = AuthManager(credentials_file=creds_file)
        auth1.add_user("testuser", "SecurePass123!@#")

        # Verify with second instance
        auth2 = AuthManager(credentials_file=creds_file)
        result = auth2.verify("testuser", "SecurePass123!@#")
        assert result is True

    def test_encrypted_persistence(self, tmp_path):
        """Test encrypted credential storage."""
        creds_file = tmp_path / "credentials.enc"
        master_key = "test_master_key_12345"

        # Create user with encryption
        auth1 = AuthManager(credentials_file=creds_file, master_key=master_key)
        auth1.add_user("testuser", "SecurePass123!@#")

        # Verify with same key
        auth2 = AuthManager(credentials_file=creds_file, master_key=master_key)
        result = auth2.verify("testuser", "SecurePass123!@#")
        assert result is True
