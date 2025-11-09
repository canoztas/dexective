"""I/O utilities for file operations."""
import os
import tempfile
import shutil
from pathlib import Path
from typing import Optional


def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def get_temp_dir(prefix: str = "dexective_") -> str:
    """
    Create a temporary directory.
    
    Args:
        prefix: Prefix for temp directory name
        
    Returns:
        Path to temporary directory
    """
    return tempfile.mkdtemp(prefix=prefix)


def cleanup_temp_dir(path: str) -> None:
    """Remove temporary directory."""
    if os.path.exists(path):
        shutil.rmtree(path, ignore_errors=True)


def safe_filename(name: str) -> str:
    """
    Convert string to safe filename.
    
    Args:
        name: Original name
        
    Returns:
        Safe filename string
    """
    return name.replace(".", "_").replace(" ", "_").replace(":", "_").replace("/", "_")

