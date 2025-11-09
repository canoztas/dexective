"""ADB device detection and package listing."""
import subprocess
from typing import List, Tuple, Optional
import logging


def check_adb_available() -> bool:
    """
    Check if ADB is available on PATH.
    
    Returns:
        True if ADB is available, False otherwise
    """
    try:
        subprocess.run(
            ['adb', 'version'],
            check=True,
            capture_output=True,
            timeout=5
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_device_connected() -> bool:
    """
    Check if an Android device is connected via ADB.
    
    Returns:
        True if device is connected, False otherwise
    """
    try:
        subprocess.run(
            ['adb', 'start-server'],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10
        )
        
        result = subprocess.run(
            ['adb', 'devices'],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        lines = result.stdout.strip().splitlines()
        # Check if any line contains 'device' (not 'offline' or 'unauthorized')
        devices = [l for l in lines[1:] if l.strip() and 'device' in l and 'offline' not in l and 'unauthorized' not in l]
        return len(devices) > 0
    except Exception as e:
        logging.error(f"Failed to check ADB device: {e}")
        return False


def list_packages(include_system: bool = False) -> List[Tuple[str, str]]:
    """
    List installed packages on connected device.
    
    Args:
        include_system: If True, include system packages
        
    Returns:
        List of tuples (package_name, apk_path)
        e.g., [("com.example.app", "/data/app/.../base.apk"), ...]
    """
    try:
        cmd = ['adb', 'shell', 'pm', 'list', 'packages', '-f']
        if not include_system:
            cmd.append('-3')  # Third-party only
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to list packages: {result.stderr}")
            return []
        
        packages = []
        for line in result.stdout.splitlines():
            if line.startswith('package:'):
                # Format: package:/data/app/.../base.apk=com.example.app
                parts = line[8:].split('=', 1)  # Remove 'package:' prefix
                if len(parts) == 2:
                    apk_path, package_name = parts
                    packages.append((package_name.strip(), apk_path.strip()))
        
        return packages
    except Exception as e:
        logging.error(f"Error listing packages: {e}")
        return []


def get_apk_path(package_name: str) -> Optional[str]:
    """
    Get APK path for a specific package.
    
    Args:
        package_name: Package name (e.g., "com.example.app")
        
    Returns:
        APK path on device, or None if not found
    """
    try:
        result = subprocess.run(
            ['adb', 'shell', 'pm', 'path', package_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.stdout.startswith('package:'):
            return result.stdout.strip().split(':', 1)[1]
        return None
    except Exception as e:
        logging.error(f"Failed to get APK path for {package_name}: {e}")
        return None

