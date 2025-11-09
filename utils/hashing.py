"""Hashing utilities for APK and model files."""
import hashlib
from pathlib import Path
from typing import Optional


def sha256_file(file_path: str) -> Optional[str]:
    """
    Compute SHA256 hash of a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        Hex digest of SHA256 hash, or None if file doesn't exist
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def sha256_bytes(data: bytes) -> str:
    """
    Compute SHA256 hash of bytes.
    
    Args:
        data: Bytes to hash
        
    Returns:
        Hex digest of SHA256 hash
    """
    return hashlib.sha256(data).hexdigest()

