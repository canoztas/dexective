"""Grad-CAM++ implementation."""
import numpy as np
import tensorflow as tf
from tensorflow import keras
from typing import Optional
import cv2
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.images import normalize_heatmap

try:
    from tf_keras_vis.gradcam_plus_plus import GradcamPlusPlus
    from tf_keras_vis.utils.model_modifiers import ReplaceToLinear
    from tf_keras_vis.utils.scores import CategoricalScore
    TF_KERAS_VIS_AVAILABLE = True
except ImportError:
    TF_KERAS_VIS_AVAILABLE = False


def gradcampp(
    model: keras.Model,
    input_tensor: np.ndarray,
    last_conv_layer: str,
    target_class_idx: int = 0
) -> Optional[np.ndarray]:
    """
    Generate Grad-CAM++ heatmap.
    
    Args:
        model: Keras model
        input_tensor: Input tensor (batch, H, W, C)
        last_conv_layer: Name of last convolutional layer
        target_class_idx: Index of target class
        
    Returns:
        Grad-CAM++ heatmap normalized to [0, 1], or None on error
    """
    if TF_KERAS_VIS_AVAILABLE:
        try:
            score = CategoricalScore([target_class_idx])
            visualizer = GradcamPlusPlus(model, model_modifier=ReplaceToLinear(), clone=False)
            cam = visualizer(score, input_tensor, penultimate_layer=last_conv_layer)
            
            if cam is None or cam.size == 0:
                return None
            
            heatmap = np.squeeze(cam[0])
            
            # Upscale to input size if needed
            target_h, target_w = input_tensor.shape[1], input_tensor.shape[2]
            if heatmap.shape != (target_h, target_w):
                heatmap = cv2.resize(heatmap, (target_w, target_h), interpolation=cv2.INTER_LINEAR)
            
            return normalize_heatmap(heatmap)
        except Exception as e:
            print(f"Error generating Grad-CAM++: {e}")
            return None
    else:
        # Fallback implementation
        return _gradcampp_manual(model, input_tensor, last_conv_layer, target_class_idx)


def _gradcampp_manual(
    model: keras.Model,
    input_tensor: np.ndarray,
    last_conv_layer: str,
    target_class_idx: int = 0
) -> Optional[np.ndarray]:
    """Manual Grad-CAM++ implementation if tf-keras-vis is not available."""
    try:
        # Get the convolutional layer
        conv_layer = model.get_layer(last_conv_layer)
        if not isinstance(conv_layer, keras.layers.Conv2D):
            return None
        
        # Create a model that outputs both conv features and predictions
        conv_output = conv_layer.output
        predictions = model.output
        
        grad_model = keras.Model(
            inputs=model.input,
            outputs=[conv_output, predictions]
        )
        
        input_var = tf.Variable(input_tensor, dtype=tf.float32)
        
        with tf.GradientTape() as tape2:
            with tf.GradientTape() as tape1:
                tape1.watch(input_var)
                conv_outputs, predictions = grad_model(input_var)
                target_score = predictions[:, target_class_idx]
            
            # First-order gradients
            grads = tape1.gradient(target_score, conv_outputs)
            
            # Second-order gradients
            grads2 = tape2.gradient(grads, conv_outputs)
        
        # Grad-CAM++ weights
        alpha = tf.nn.relu(grads) / (tf.reduce_sum(tf.nn.relu(grads), axis=[1, 2], keepdims=True) + 1e-7)
        weights = alpha * tf.nn.relu(grads2)
        weights = tf.reduce_sum(weights, axis=[1, 2], keepdims=True)
        
        # Weighted combination of feature maps
        cam = tf.reduce_sum(weights * conv_outputs, axis=-1)
        cam = tf.nn.relu(cam)
        
        # Normalize and resize
        cam_np = cam.numpy()[0]
        cam_np = normalize_heatmap(cam_np)
        
        # Upscale to input size
        target_h, target_w = input_tensor.shape[1], input_tensor.shape[2]
        if cam_np.shape != (target_h, target_w):
            cam_np = cv2.resize(cam_np, (target_w, target_h), interpolation=cv2.INTER_LINEAR)
        
        return normalize_heatmap(cam_np)
    
    except Exception as e:
        print(f"Error in manual Grad-CAM++: {e}")
        return None

