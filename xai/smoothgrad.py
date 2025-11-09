"""SmoothGrad implementation."""
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.images import normalize_heatmap
from xai.saliency import vanilla_saliency


def smoothgrad(
    model: keras.Model,
    input_tensor: np.ndarray,
    target_class_idx: int = 0,
    num_samples: int = 25,
    noise_scale: float = 0.1
) -> Optional[np.ndarray]:
    """
    Generate SmoothGrad saliency map (averaged over noisy samples).
    
    Args:
        model: Keras model
        input_tensor: Input tensor (batch, H, W, C)
        target_class_idx: Index of target class
        num_samples: Number of noisy samples to average
        noise_scale: Standard deviation of noise (as fraction of input range)
        
    Returns:
        SmoothGrad heatmap normalized to [0, 1], or None on error
    """
    try:
        input_range = input_tensor.max() - input_tensor.min()
        noise_std = noise_scale * input_range
        
        saliency_maps = []
        
        for _ in range(num_samples):
            # Add noise
            noise = np.random.normal(0, noise_std, input_tensor.shape)
            noisy_input = input_tensor + noise
            # Clip to valid range
            noisy_input = np.clip(noisy_input, 0, 1)
            
            # Compute saliency for noisy input
            saliency = vanilla_saliency(model, noisy_input, target_class_idx)
            if saliency is not None:
                saliency_maps.append(saliency)
        
        if not saliency_maps:
            return None
        
        # Average saliency maps
        smooth_saliency = np.mean(saliency_maps, axis=0)
        return normalize_heatmap(smooth_saliency)
    
    except Exception as e:
        print(f"Error generating SmoothGrad: {e}")
        return None

