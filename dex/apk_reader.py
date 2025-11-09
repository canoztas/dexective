"""APK reading and DEX extraction utilities."""
import zipfile
import os
from typing import List, Tuple, Optional
from pathlib import Path


def extract_dex_files(apk_path: str, output_dir: str) -> List[Tuple[str, str]]:
    """
    Extract all classes*.dex files from an APK.
    
    Args:
        apk_path: Path to APK file
        output_dir: Directory to extract DEX files to
        
    Returns:
        List of tuples (dex_filename, extracted_path) sorted by filename
        e.g., [("classes.dex", "/path/to/classes.dex"), ("classes2.dex", ...)]
    """
    extracted_files = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            # Get all .dex files, sorted by name
            dex_files = sorted([f for f in zf.namelist() if f.endswith('.dex') and 'classes' in f])
            
            if not dex_files:
                return []
            
            for dex_file in dex_files:
                # Security: Prevent path traversal attacks
                if '..' in dex_file or dex_file.startswith('/'):
                    continue
                
                extracted_path = zf.extract(dex_file, output_dir)
                extracted_files.append((dex_file, extracted_path))
        
        return extracted_files
    except Exception as e:
        raise RuntimeError(f"Failed to extract DEX from {apk_path}: {e}")


def get_apk_package_name(apk_path: str) -> Optional[str]:
    """
    Extract package name from APK using Androguard.
    
    Args:
        apk_path: Path to APK file
        
    Returns:
        Package name or None if extraction fails
    """
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path)
        return apk.get_package()
    except Exception:
        return None

