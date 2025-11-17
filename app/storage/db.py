from __future__ import annotations
"""MySQL database operations for user authentication with salted password hashing."""

import argparse
import os
from dataclasses import dataclass

# Mock database for testing without MySQL
_mock_users = {}


@dataclass
class DBConfig:
    """Database connection configuration."""
    host: str = os.getenv("DB_HOST", "127.0.0.1")
    port: int = int(os.getenv("DB_PORT", "3306"))
    user: str = os.getenv("DB_USER", "scuser")
    password: str = os.getenv("DB_PASSWORD", "scpass")
    db: str = os.getenv("DB_NAME", "securechat")


def get_conn(config: DBConfig | None = None):
    """Establish database connection using provided or default configuration."""
    # Mock implementation - no actual connection
    return None


def init_schema():
    """Initialize database schema with users table."""
    # Mock implementation - no actual schema creation
    print("[MOCK_DB] Schema initialized (no-op in mock mode)")


def create_user(user_email: str, user_name: str, user_password: str):
    """Create new user with salted password hash."""
    from app.common.utils import compute_sha256_hex
    
    # Generate random salt for password hashing
    password_salt = os.urandom(16)
    password_hash = compute_sha256_hex(password_salt + user_password.encode("utf-8"))

    # Store in mock database
    _mock_users[user_name] = {
        "email": user_email,
        "salt": password_salt,
        "pwd_hash": password_hash
    }
    print(f"[MOCK_DB] User '{user_name}' created successfully")


def verify_user(user_name: str, user_password: str) -> bool:
    """Verify user credentials against database."""
    from app.common.utils import compute_sha256_hex
    
    # Check mock database
    if user_name not in _mock_users:
        print(f"[MOCK_DB] User '{user_name}' not found")
        return False
    
    user_data = _mock_users[user_name]
    stored_salt = user_data["salt"]
    stored_password_hash = user_data["pwd_hash"]
    
    computed_hash = compute_sha256_hex(stored_salt + user_password.encode("utf-8"))
    verified = computed_hash == stored_password_hash
    print(f"[MOCK_DB] User '{user_name}' verification: {'SUCCESS' if verified else 'FAILED'}")
    return verified


def main():
    """Command-line interface for database operations."""
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--init", action="store_true", help="Initialize database schema")
    arguments = argument_parser.parse_args()
    
    if arguments.init:
        init_schema()
        print("Database schema initialized successfully.")


if __name__ == "__main__":
    main()