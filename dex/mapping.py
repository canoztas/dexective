"""Pixel to byte offset to class mapping utilities."""
import numpy as np
import os
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import logging

# Suppress androguard logs
logging.getLogger('androguard').setLevel(logging.ERROR)
logging.getLogger('androguard.core').setLevel(logging.ERROR)
logging.getLogger('androguard.core.axml').setLevel(logging.ERROR)
logging.getLogger('androguard.core.bytecodes').setLevel(logging.ERROR)

try:
    from intervaltree import IntervalTree
    INTERVALTREE_AVAILABLE = True
except ImportError:
    INTERVALTREE_AVAILABLE = False
    logging.warning("intervaltree not available, using fallback implementation")

try:
    from androguard.core.bytecodes import dvm
    from androguard.core.bytecodes.apk import APK
    ANDROGUARD_AVAILABLE = True
except (ImportError, AttributeError, ModuleNotFoundError) as e:
    ANDROGUARD_AVAILABLE = False
    logging.warning(f"Androguard not available, class mapping will be limited: {e}")


class PixelMap:
    """
    Maps pixels in a DEX image to byte offsets.
    
    For a DEX file of length L bytes:
    - Image size S = ceil(sqrt(L))
    - Pixel (r, c) maps to byte offset i = r*S + c
    - If i >= L, the pixel is padding (no byte mapping)
    """
    
    def __init__(self, dex_bytes: bytes, dex_filename: str):
        """
        Initialize PixelMap for a DEX file.
        
        Args:
            dex_bytes: Raw DEX file bytes
            dex_filename: Name of the DEX file (e.g., "classes.dex")
        """
        self.dex_bytes = dex_bytes
        self.dex_filename = dex_filename
        self.L = len(dex_bytes)
        self.S = int(np.ceil(np.sqrt(self.L)))
        
    def pixel_to_offset(self, row: int, col: int) -> Optional[int]:
        """
        Convert pixel coordinates to byte offset.
        
        Args:
            row: Row index in image
            col: Column index in image
            
        Returns:
            Byte offset (0-indexed) or None if pixel is padding
        """
        if row < 0 or row >= self.S or col < 0 or col >= self.S:
            return None
        
        offset = row * self.S + col
        if offset >= self.L:
            return None  # Padding pixel
        
        return offset
    
    def offset_to_pixel(self, offset: int) -> Optional[Tuple[int, int]]:
        """
        Convert byte offset to pixel coordinates.
        
        Args:
            offset: Byte offset (0-indexed)
            
        Returns:
            (row, col) tuple or None if offset is out of range
        """
        if offset < 0 or offset >= self.L:
            return None
        
        row = offset // self.S
        col = offset % self.S
        return (row, col)


class SmaliClassMapper:
    """
    Maps byte offsets to class names using decompiled Smali files.
    This is the legacy approach that works by:
    1. Decompiling the entire DEX to Smali
    2. Creating a sorted list of smali files with cumulative byte sizes
    3. Mapping byte offsets to smali files based on cumulative size
    """
    
    def __init__(self, smali_dir: str, blacklist: Optional[List[str]] = None):
        """
        Initialize SmaliClassMapper from a directory of smali files.
        
        Args:
            smali_dir: Directory containing decompiled smali files
            blacklist: Optional list of blacklisted class path patterns
        """
        self.smali_dir = smali_dir
        self.blacklist = blacklist or []
        self.smali_list = self._build_smali_list()
    
    def _is_blacklisted(self, class_path: str) -> bool:
        """Check if a class path is blacklisted."""
        norm = class_path.replace('/', '\\').lower()
        return any(p.lower() in norm for p in self.blacklist)
    
    def _build_smali_list(self) -> List[Dict]:
        """Build sorted list of smali files with cumulative byte sizes."""
        smali_files_metadata = []
        
        if not os.path.exists(self.smali_dir):
            logging.warning(f"Smali directory does not exist: {self.smali_dir}")
            return []
        
        for root, _, files in os.walk(self.smali_dir):
            for file in files:
                if file.endswith('.smali'):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.smali_dir)
                    cls_name_path = os.path.splitext(rel_path)[0].replace(os.sep, '/')
                    # Convert to class descriptor format: com/example/Foo -> Lcom/example/Foo;
                    if not cls_name_path.startswith('L'):
                        cls_name_path = 'L' + cls_name_path + ';'
                    
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content_bytes = len(f.read().encode('utf-8'))
                        if content_bytes > 0:
                            smali_files_metadata.append({
                                'path': full_path,
                                'class_name': cls_name_path,
                                'size': content_bytes,
                                'blacklisted': self._is_blacklisted(cls_name_path)
                            })
                    except Exception as e:
                        logging.warning(f"Error processing smali file {full_path}: {e}")
        
        # Sort by path to ensure consistent ordering
        smali_files_metadata.sort(key=lambda x: x['path'])
        
        # Calculate cumulative sizes
        cum_size = 0
        for info in smali_files_metadata:
            info['cumulative'] = cum_size
            cum_size += info['size']
        
        logging.info(f"SmaliClassMapper: Found {len(smali_files_metadata)} smali files, total size: {cum_size} bytes")
        return smali_files_metadata
    
    def offset_to_class(self, offset: int) -> Optional[str]:
        """
        Map byte offset to class name based on smali file cumulative sizes.
        
        Args:
            offset: Byte offset in DEX file
            
        Returns:
            Class name (descriptor format) or None
        """
        # Find which smali file contains this offset
        for info in self.smali_list:
            if info['cumulative'] <= offset < info['cumulative'] + info['size']:
                return info['class_name'] if not info['blacklisted'] else None
        return None


class ClassMapper:
    """
    Maps byte offsets to class names using Androguard.
    Falls back to Smali-based mapping if Androguard is not available.
    """
    
    def __init__(self, dex_path: str, dex_bytes: bytes, dex_filename: str, smali_dir: Optional[str] = None, blacklist: Optional[List[str]] = None):
        """
        Initialize ClassMapper for a DEX file.
        
        Args:
            dex_path: Path to DEX file
            dex_bytes: Raw DEX file bytes
            dex_filename: Name of the DEX file
            smali_dir: Optional directory with decompiled smali files (for fallback)
            blacklist: Optional list of blacklisted class path patterns
        """
        self.dex_path = dex_path
        self.dex_bytes = dex_bytes
        self.dex_filename = dex_filename
        self.smali_dir = smali_dir
        self.blacklist = blacklist or []
        self.interval_tree = self._build_interval_tree()
        self.smali_mapper = None
        
        # If interval tree is empty and smali_dir is provided, use smali-based mapping
        if (not self.interval_tree or 
            (INTERVALTREE_AVAILABLE and isinstance(self.interval_tree, IntervalTree) and len(self.interval_tree) == 0) or
            (isinstance(self.interval_tree, dict) and len(self.interval_tree) == 0)):
            if smali_dir and os.path.exists(smali_dir):
                logging.info("Interval tree is empty, falling back to Smali-based mapping")
                self.smali_mapper = SmaliClassMapper(smali_dir, blacklist)
    
    def _build_interval_tree(self):
        """Build interval tree mapping byte offsets to class names."""
        # Always try to import dvm, even if module-level import failed
        # (sometimes imports fail at module load but work at runtime)
        try:
            from androguard.core.bytecodes import dvm as dvm_module
        except (ImportError, AttributeError, ModuleNotFoundError) as e:
            if not ANDROGUARD_AVAILABLE:
                logging.warning(f"Androguard not available, cannot build class mapping: {e}")
            else:
                logging.warning(f"Failed to import dvm module (unexpected): {e}")
            return self._build_fallback_tree()
        
        try:
            # Parse DEX with Androguard
            d = dvm_module.DalvikVMFormat(self.dex_bytes)
            
            if INTERVALTREE_AVAILABLE:
                tree = IntervalTree()
            else:
                tree = {}
            
            class_count = 0
            interval_count = 0
            
            # Iterate through all classes
            for class_def in d.get_classes():
                class_name = class_def.get_name()
                if not class_name:
                    continue
                
                class_count += 1
                
                # Get class definition offset (from DEX header)
                # This is the offset of the class_def_item in the class_defs section
                class_idx = class_def.get_class_idx()
                if class_idx is not None:
                    # Try to get the actual offset from the DEX structure
                    # Androguard stores offsets relative to the DEX file
                    try:
                        # Get class data item offset
                        class_data_off = class_def.get_class_data_off()
                        if class_data_off and class_data_off > 0 and class_data_off < len(self.dex_bytes):
                            # Map a larger region around class data (increase from 100 to 500 bytes)
                            class_data_size = 500
                            start = class_data_off
                            end = min(start + class_data_size, len(self.dex_bytes))
                            if INTERVALTREE_AVAILABLE:
                                tree[start:end] = class_name
                            else:
                                tree[(start, end)] = class_name
                            interval_count += 1
                    except Exception:
                        pass
                
                # Get method code items - these are more reliable
                for method in class_def.get_methods():
                    try:
                        code = method.get_code()
                        if code:
                            code_off = code.get_begin()
                            code_size = code.get_length()
                            if code_off and code_size and code_off < len(self.dex_bytes):
                                start = code_off
                                end = min(start + code_size, len(self.dex_bytes))
                                if INTERVALTREE_AVAILABLE:
                                    tree[start:end] = class_name
                                else:
                                    # For dict fallback, check for overlaps and merge
                                    # Simple approach: just add it
                                    tree[(start, end)] = class_name
                                interval_count += 1
                    except Exception:
                        continue
            
            # Log statistics
            if class_count > 0:
                logging.info(f"ClassMapper: Found {class_count} classes, created {interval_count} intervals")
            else:
                logging.warning("ClassMapper: No classes found in DEX file")
            
            return tree
        except Exception as e:
            logging.warning(f"Failed to build interval tree with Androguard: {e}")
            return self._build_fallback_tree()
    
    def _build_fallback_tree(self):
        """Fallback: create a simple mapping structure."""
        if INTERVALTREE_AVAILABLE:
            return IntervalTree()
        else:
            return {}
    
    def offset_to_class(self, offset: int) -> Optional[str]:
        """
        Map byte offset to class name.
        
        Args:
            offset: Byte offset in DEX file
            
        Returns:
            Class name (descriptor format) or None
        """
        if offset < 0 or offset >= len(self.dex_bytes):
            return None
        
        # Try Androguard-based mapping first
        if INTERVALTREE_AVAILABLE:
            if isinstance(self.interval_tree, IntervalTree):
                intervals = self.interval_tree[offset]
                if intervals:
                    # Return the first matching class
                    return list(intervals)[0].data
        else:
            # Fallback: check intervals manually
            for (start, end), class_name in self.interval_tree.items():
                if start <= offset < end:
                    return class_name
        
        # Fallback to Smali-based mapping if available
        if self.smali_mapper:
            return self.smali_mapper.offset_to_class(offset)
        
        return None
    
    def get_class_intervals(self) -> Dict[str, List[Tuple[int, int]]]:
        """
        Get all class intervals.
        
        Returns:
            Dictionary mapping class names to lists of (start, end) intervals
        """
        result = defaultdict(list)
        
        if INTERVALTREE_AVAILABLE and isinstance(self.interval_tree, IntervalTree):
            for interval in self.interval_tree:
                result[interval.data].append((interval.begin, interval.end))
        else:
            for (start, end), class_name in self.interval_tree.items():
                result[class_name].append((start, end))
        
        return dict(result)


def compute_class_scores(
    heatmap: np.ndarray,
    pixel_map: PixelMap,
    class_mapper: ClassMapper,
    dex_filename: str
) -> Dict[str, float]:
    """
    Compute per-class scores from heatmap.
    
    Args:
        heatmap: Normalized heatmap array (same size as image)
        pixel_map: PixelMap for the DEX
        class_mapper: ClassMapper for the DEX
        dex_filename: Name of the DEX file
        
    Returns:
        Dictionary mapping class names to max heatmap scores
    """
    class_scores = defaultdict(float)
    
    # Resize heatmap if needed to match image size
    if heatmap.shape != (pixel_map.S, pixel_map.S):
        import cv2
        heatmap = cv2.resize(heatmap, (pixel_map.S, pixel_map.S), interpolation=cv2.INTER_LINEAR)
    
    # Check interval tree statistics
    if hasattr(class_mapper, 'interval_tree'):
        if INTERVALTREE_AVAILABLE and isinstance(class_mapper.interval_tree, IntervalTree):
            tree_size = len(class_mapper.interval_tree)
        elif isinstance(class_mapper.interval_tree, dict):
            tree_size = len(class_mapper.interval_tree)
        else:
            tree_size = 0
    else:
        tree_size = 0
    
    pixels_checked = 0
    pixels_mapped = 0
    
    # Iterate through all pixels
    for r in range(pixel_map.S):
        for c in range(pixel_map.S):
            offset = pixel_map.pixel_to_offset(r, c)
            if offset is None:
                continue  # Padding pixel
            
            pixels_checked += 1
            heat_value = float(heatmap[r, c])
            class_name = class_mapper.offset_to_class(offset)
            
            if class_name:
                pixels_mapped += 1
                # Take max heat value for each class
                class_scores[class_name] = max(class_scores[class_name], heat_value)
    
    # Log statistics
    if pixels_checked > 0:
        mapping_rate = (pixels_mapped / pixels_checked * 100) if pixels_checked > 0 else 0
        logging.info(f"compute_class_scores: Checked {pixels_checked} pixels, mapped {pixels_mapped} ({mapping_rate:.1f}%) to classes (interval tree size: {tree_size})")
        if pixels_mapped == 0 and tree_size > 0:
            logging.warning("compute_class_scores: Interval tree has intervals but no pixels mapped - possible offset mismatch")
    else:
        logging.warning("compute_class_scores: No pixels checked")
    
    return dict(class_scores)

