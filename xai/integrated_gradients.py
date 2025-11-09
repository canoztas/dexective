"""Integrated Gradients implementation."""
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import Optional
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.images import normalize_heatmap


def integrated_gradients(
    model: keras.Model,
    input_tensor: np.ndarray,
    target_class_idx: int = 0,
    baseline: Optional[np.ndarray] = None,
    steps: int = 50
) -> Optional[np.ndarray]:
    """
    Generate Integrated Gradients attribution map.
    
    Args:
        model: Keras model
        input_tensor: Input tensor (batch, H, W, C)
        target_class_idx: Index of target class
        baseline: Baseline input (default: zeros)
        steps: Number of integration steps
        
    Returns:
        Integrated Gradients heatmap normalized to [0, 1], or None on error
    """
    try:
        if baseline is None:
            baseline = np.zeros_like(input_tensor)
        
        input_var = tf.Variable(input_tensor, dtype=tf.float32)
        baseline_var = tf.Variable(baseline, dtype=tf.float32)
        
        # Create interpolated inputs
        alphas = np.linspace(0.0, 1.0, steps)
        gradients_sum = None
        
        for alpha in alphas:
            interpolated = baseline_var + alpha * (input_var - baseline_var)
            
            with tf.GradientTape() as tape:
                tape.watch(interpolated)
                predictions = model(interpolated)
                target_score = predictions[:, target_class_idx]
            
            gradients = tape.gradient(target_score, interpolated)
            
            if gradients is None:
                continue
            
            if gradients_sum is None:
                gradients_sum = gradients
            else:
                gradients_sum += gradients
        
        if gradients_sum is None:
            return None
        
        # Riemann sum approximation
        integrated_grad = (input_var - baseline_var) * (gradients_sum / steps)
        
        # Take absolute value and reduce across channels
        integrated_grad = tf.abs(integrated_grad)
        if integrated_grad.shape[-1] > 1:
            integrated_grad = tf.reduce_max(integrated_grad, axis=-1)
        else:
            integrated_grad = tf.squeeze(integrated_grad, axis=-1)
        
        ig_np = integrated_grad.numpy()[0]  # Remove batch dimension
        return normalize_heatmap(ig_np)
    
    except Exception as e:
        print(f"Error generating Integrated Gradients: {e}")
        return None

