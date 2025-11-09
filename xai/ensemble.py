"""Ensemble methods for combining multiple XAI heatmaps."""
import numpy as np
from typing import List, Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.images import normalize_heatmap


def ensemble_max(heatmaps: List[np.ndarray]) -> Optional[np.ndarray]:
    """
    Combine heatmaps using pixel-wise maximum.
    
    Args:
        heatmaps: List of normalized heatmaps (all should be same size)
        
    Returns:
        Ensemble heatmap normalized to [0, 1], or None if input is empty
    """
    if not heatmaps:
        return None
    
    # Ensure all heatmaps are same size
    target_shape = heatmaps[0].shape
    for i, hm in enumerate(heatmaps):
        if hm.shape != target_shape:
            import cv2
            heatmaps[i] = cv2.resize(hm, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_LINEAR)
    
    # Pixel-wise maximum
    ensemble = np.maximum.reduce(heatmaps)
    return normalize_heatmap(ensemble)


def ensemble_mean(heatmaps: List[np.ndarray]) -> Optional[np.ndarray]:
    """
    Combine heatmaps using pixel-wise mean.
    
    Args:
        heatmaps: List of normalized heatmaps (all should be same size)
        
    Returns:
        Ensemble heatmap normalized to [0, 1], or None if input is empty
    """
    if not heatmaps:
        return None
    
    # Ensure all heatmaps are same size
    target_shape = heatmaps[0].shape
    for i, hm in enumerate(heatmaps):
        if hm.shape != target_shape:
            import cv2
            heatmaps[i] = cv2.resize(hm, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_LINEAR)
    
    # Pixel-wise mean
    ensemble = np.mean(heatmaps, axis=0)
    return normalize_heatmap(ensemble)

