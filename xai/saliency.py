"""Vanilla Saliency Map implementation."""
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.images import normalize_heatmap


def vanilla_saliency(
    model: keras.Model,
    input_tensor: np.ndarray,
    target_class_idx: int = 0
) -> Optional[np.ndarray]:
    """
    Generate vanilla saliency map (gradient of target class w.r.t. input).
    
    Args:
        model: Keras model
        input_tensor: Input tensor (batch, H, W, C)
        target_class_idx: Index of target class (0 for malicious)
        
    Returns:
        Saliency heatmap normalized to [0, 1], or None on error
    """
    try:
        input_var = tf.Variable(input_tensor, dtype=tf.float32)
        
        with tf.GradientTape() as tape:
            tape.watch(input_var)
            predictions = model(input_var)
            target_score = predictions[:, target_class_idx]
        
        gradients = tape.gradient(target_score, input_var)
        
        if gradients is None:
            return None
        
        # Take absolute value and reduce across channels
        saliency = tf.abs(gradients)
        if saliency.shape[-1] > 1:
            saliency = tf.reduce_max(saliency, axis=-1)
        else:
            saliency = tf.squeeze(saliency, axis=-1)
        
        saliency_np = saliency.numpy()[0]  # Remove batch dimension
        return normalize_heatmap(saliency_np)
    
    except Exception as e:
        print(f"Error generating vanilla saliency: {e}")
        return None

