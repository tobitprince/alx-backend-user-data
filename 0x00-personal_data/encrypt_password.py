#!/usr/bin/env python3
"""Create a module for encrypting passwords."""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hash a password using a random salt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check if a hashed password was formed from the given password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
