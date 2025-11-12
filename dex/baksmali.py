"""Optional baksmali decompilation utilities."""
import os
import subprocess
import shutil
from typing import List, Dict, Optional
import logging


def decompile_class_with_baksmali(
    dex_path: str,
    class_descriptor: str,
    output_dir: str,
    baksmali_jar: str
) -> Optional[str]:
    """
    Decompile a single class from DEX using baksmali.
    
    Args:
        dex_path: Path to DEX file
        class_descriptor: Class descriptor (e.g., "Lcom/example/Foo;")
        output_dir: Output directory for smali files
        baksmali_jar: Path to baksmali.jar
        
    Returns:
        Path to generated smali file, or None on failure
    """
    try:
        # Convert class descriptor to file path
        # Lcom/example/Foo; -> com/example/Foo.smali
        if not class_descriptor.startswith('L') or not class_descriptor.endswith(';'):
            return None
        
        class_path = class_descriptor[1:-1]  # Remove L and ;
        smali_path = os.path.join(output_dir, f"{class_path}.smali")
        smali_dir = os.path.dirname(smali_path)
        
        # Create directory if needed
        os.makedirs(smali_dir, exist_ok=True)
        
        # Use baksmali to disassemble just this class
        # Note: baksmali doesn't have a direct "single class" option,
        # so we'll disassemble the whole DEX and then extract the file we need
        temp_smali_dir = os.path.join(output_dir, "temp_smali")
        os.makedirs(temp_smali_dir, exist_ok=True)
        
        command = ['java', '-jar', baksmali_jar, 'disassemble', dex_path, '-o', temp_smali_dir]
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # Find the smali file for this class
        expected_smali = os.path.join(temp_smali_dir, f"{class_path}.smali")
        if os.path.exists(expected_smali):
            # Move to final location
            os.makedirs(os.path.dirname(smali_path), exist_ok=True)
            if os.path.exists(smali_path):
                os.remove(smali_path)
            os.rename(expected_smali, smali_path)
            # Clean up temp directory
            shutil.rmtree(temp_smali_dir, ignore_errors=True)
            return smali_path
        
        # Clean up
        shutil.rmtree(temp_smali_dir, ignore_errors=True)
        return None
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Baksmali failed for {class_descriptor}: {e.stderr if e.stderr else str(e)}")
        return None
    except Exception as e:
        logging.error(f"Error decompiling {class_descriptor}: {e}")
        return None


def decompile_top_classes(
    dex_path: str,
    class_descriptors: List[str],
    output_dir: str,
    baksmali_jar: str
) -> Dict[str, str]:
    """
    Decompile top-K classes from DEX.
    
    Args:
        dex_path: Path to DEX file
        class_descriptors: List of class descriptors to decompile
        output_dir: Output directory for smali files
        baksmali_jar: Path to baksmali.jar
        
    Returns:
        Dictionary mapping class descriptors to smali file paths
    """
    class_to_smali = {}
    
    # First, decompile the entire DEX once
    temp_smali_dir = os.path.join(output_dir, "temp_smali")
    try:
        os.makedirs(temp_smali_dir, exist_ok=True)
        
        command = ['java', '-jar', baksmali_jar, 'disassemble', dex_path, '-o', temp_smali_dir]
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        # Extract only the classes we need
        for class_desc in class_descriptors:
            if not class_desc.startswith('L') or not class_desc.endswith(';'):
                continue
            
            class_path = class_desc[1:-1]  # Remove L and ;
            source_smali = os.path.join(temp_smali_dir, f"{class_path}.smali")
            
            if os.path.exists(source_smali):
                # Copy to final location
                dest_smali = os.path.join(output_dir, f"{class_path}.smali")
                dest_dir = os.path.dirname(dest_smali)
                os.makedirs(dest_dir, exist_ok=True)
                
                shutil.copy2(source_smali, dest_smali)
                class_to_smali[class_desc] = dest_smali
        
        # Clean up temp directory
        shutil.rmtree(temp_smali_dir, ignore_errors=True)
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Baksmali decompilation failed: {e.stderr if e.stderr else str(e)}")
        shutil.rmtree(temp_smali_dir, ignore_errors=True)
    except Exception as e:
        logging.error(f"Error during baksmali decompilation: {e}")
        shutil.rmtree(temp_smali_dir, ignore_errors=True)
    
    return class_to_smali


def decompile_dex_for_mapping(dex_path: str, output_dir: str, baksmali_jar: str) -> Optional[str]:
    """
    Decompile entire DEX to smali for class mapping purposes.
    
    Args:
        dex_path: Path to DEX file
        output_dir: Output directory for smali files
        baksmali_jar: Path to baksmali.jar
        
    Returns:
        Path to smali directory, or None on failure
    """
    smali_dir = os.path.join(output_dir, "smali")
    try:
        os.makedirs(smali_dir, exist_ok=True)
        
        command = ['java', '-jar', baksmali_jar, 'disassemble', dex_path, '-o', smali_dir]
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=600
        )
        
        return smali_dir if os.path.exists(smali_dir) else None
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Baksmali decompilation failed for mapping: {e.stderr if e.stderr else str(e)}")
        return None
    except Exception as e:
        logging.error(f"Error during baksmali decompilation for mapping: {e}")
        return None


def check_baksmali_available(baksmali_jar: str) -> bool:
    """
    Check if baksmali is available and working.
    
    Args:
        baksmali_jar: Path to baksmali.jar
        
    Returns:
        True if baksmali is available, False otherwise
    """
    if not os.path.exists(baksmali_jar):
        return False
    
    try:
        # Check if Java is available
        subprocess.run(['java', '-version'], check=True, capture_output=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False

