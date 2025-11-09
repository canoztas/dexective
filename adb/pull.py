"""ADB APK pulling utilities."""
import subprocess
import os
from typing import Optional
import logging
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.io import ensure_dir, safe_filename


def pull_apk(device_path: str, local_dir: str, package_name: str) -> Optional[str]:
    """
    Pull APK from device to local directory.
    
    Args:
        device_path: APK path on device (e.g., "/data/app/.../base.apk")
        local_dir: Local directory to save APK
        package_name: Package name for safe filename
        
    Returns:
        Local path to pulled APK, or None if pull fails
    """
    ensure_dir(local_dir)
    
    safe_name = safe_filename(package_name) + ".apk"
    local_path = os.path.join(local_dir, safe_name)
    
    try:
        result = subprocess.run(
            ['adb', 'pull', device_path, local_path],
            check=True,
            capture_output=True,
            timeout=60
        )
        
        if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
            return local_path
        else:
            logging.error(f"Pulled APK is empty or doesn't exist: {local_path}")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to pull {device_path}: {e.stderr.decode() if e.stderr else str(e)}")
        return None
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout pulling {device_path}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error pulling APK: {e}")
        return None

