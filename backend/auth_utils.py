import os
import hashlib
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional

# Load JWT settings from env
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-key-replace-in-prod-with-32-bytes")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Legacy SHA-256 password hashing
def hash_password_legacy(password: str, salt: str) -> str:
    hasher = hashlib.sha256()
    hasher.update((password + salt).encode('utf-8'))
    return hasher.hexdigest()

# Bcrypt password hashing
def hash_password_bcrypt(password: str) -> str:
    # bcrypt.hashpw expects bytes and returns bytes
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Verify a password, automatically checking if it's bcrypt or fallback sha256.
# If it's legacy sha256 and validates successfully, it will return (True, new_bcrypt_hash).
# Otherwise, returns (True, None) for successful bcrypt, or (False, None) for failure.
def verify_and_migrate_password(password: str, stored_hash: str, salt: str) -> Tuple[bool, Optional[str]]:
    # Bcrypt hashes start with $2a$, $2b$, or $2y$
    is_bcrypt = stored_hash.startswith('$2a$') or stored_hash.startswith('$2b$') or stored_hash.startswith('$2y$')
    
    if is_bcrypt:
        try:
            # bcrypt.checkpw expects bytes for both arguments
            matched = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
            return matched, None
        except Exception:
            return False, None
    else:
        # Fallback to legacy SHA-256
        legacy_hash = hash_password_legacy(password, salt)
        if legacy_hash == stored_hash:
            # Generate a new bcrypt hash for seamless migration
            new_hash = hash_password_bcrypt(password)
            return True, new_hash
        return False, None

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# Create refresh token
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# Decode and verify token
def decode_token(token: str) -> Optional[dict]:
    try:
        # jwt.decode automatically verifies signature and expiration time
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
