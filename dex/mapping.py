"""Pixel to byte offset to class mapping utilities."""
import numpy as np
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
import logging

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
except ImportError:
    ANDROGUARD_AVAILABLE = False
    logging.warning("Androguard not available, class mapping will be limited")


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


class ClassMapper:
    """
    Maps byte offsets to class names using Androguard.
    """
    
    def __init__(self, dex_path: str, dex_bytes: bytes, dex_filename: str):
        """
        Initialize ClassMapper for a DEX file.
        
        Args:
            dex_path: Path to DEX file
            dex_bytes: Raw DEX file bytes
            dex_filename: Name of the DEX file
        """
        self.dex_path = dex_path
        self.dex_bytes = dex_bytes
        self.dex_filename = dex_filename
        self.interval_tree = self._build_interval_tree()
    
    def _build_interval_tree(self):
        """Build interval tree mapping byte offsets to class names."""
        if not ANDROGUARD_AVAILABLE:
            return self._build_fallback_tree()
        
        try:
            # Parse DEX with Androguard
            d = dvm.DalvikVMFormat(self.dex_bytes)
            
            if INTERVALTREE_AVAILABLE:
                tree = IntervalTree()
            else:
                tree = {}
            
            # Iterate through all classes
            for class_def in d.get_classes():
                class_name = class_def.get_name()
                if not class_name:
                    continue
                
                # Get class data item offset
                class_data_off = class_def.get_class_data_off()
                if class_data_off and class_data_off > 0:
                    # Estimate class data size (approximate)
                    class_data_size = 100  # Conservative estimate
                    start = class_data_off
                    end = min(start + class_data_size, len(self.dex_bytes))
                    if INTERVALTREE_AVAILABLE:
                        tree[start:end] = class_name
                    else:
                        tree[(start, end)] = class_name
                
                # Get method code items
                for method in class_def.get_methods():
                    code = method.get_code()
                    if code:
                        code_off = code.get_begin()
                        code_size = code.get_length()
                        if code_off and code_size:
                            start = code_off
                            end = min(start + code_size, len(self.dex_bytes))
                            if INTERVALTREE_AVAILABLE:
                                tree[start:end] = class_name
                            else:
                                # Merge overlapping intervals
                                tree[(start, end)] = class_name
            
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
    
    # Iterate through all pixels
    for r in range(pixel_map.S):
        for c in range(pixel_map.S):
            offset = pixel_map.pixel_to_offset(r, c)
            if offset is None:
                continue  # Padding pixel
            
            heat_value = float(heatmap[r, c])
            class_name = class_mapper.offset_to_class(offset)
            
            if class_name:
                # Take max heat value for each class
                class_scores[class_name] = max(class_scores[class_name], heat_value)
    
    return dict(class_scores)

