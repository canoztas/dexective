"""Score-CAM implementation."""
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
    from tf_keras_vis.scorecam import ScoreCAM
    from tf_keras_vis.utils.model_modifiers import ReplaceToLinear
    from tf_keras_vis.utils.scores import CategoricalScore
    TF_KERAS_VIS_AVAILABLE = True
except ImportError:
    TF_KERAS_VIS_AVAILABLE = False


def scorecam(
    model: keras.Model,
    input_tensor: np.ndarray,
    last_conv_layer: str,
    target_class_idx: int = 0,
    max_maps: int = 128
) -> Optional[np.ndarray]:
    """
    Generate Score-CAM heatmap.
    
    Args:
        model: Keras model
        input_tensor: Input tensor (batch, H, W, C)
        last_conv_layer: Name of last convolutional layer
        target_class_idx: Index of target class
        max_maps: Maximum number of feature maps to sample (for performance)
        
    Returns:
        Score-CAM heatmap normalized to [0, 1], or None on error
    """
    if TF_KERAS_VIS_AVAILABLE:
        try:
            score = CategoricalScore([target_class_idx])
            visualizer = ScoreCAM(model, model_modifier=ReplaceToLinear(), clone=False)
            cam = visualizer(score, input_tensor, penultimate_layer=last_conv_layer, max_N=max_maps)
            
            if cam is None or cam.size == 0:
                return None
            
            heatmap = np.squeeze(cam[0])
            
            # Upscale to input size if needed
            target_h, target_w = input_tensor.shape[1], input_tensor.shape[2]
            if heatmap.shape != (target_h, target_w):
                heatmap = cv2.resize(heatmap, (target_w, target_h), interpolation=cv2.INTER_LINEAR)
            
            return normalize_heatmap(heatmap)
        except Exception as e:
            print(f"Error generating Score-CAM: {e}")
            return None
    else:
        # Fallback implementation
        return _scorecam_manual(model, input_tensor, last_conv_layer, target_class_idx, max_maps)


def _scorecam_manual(
    model: keras.Model,
    input_tensor: np.ndarray,
    last_conv_layer: str,
    target_class_idx: int = 0,
    max_maps: int = 128
) -> Optional[np.ndarray]:
    """Manual Score-CAM implementation if tf-keras-vis is not available."""
    try:
        # Get the convolutional layer
        conv_layer = model.get_layer(last_conv_layer)
        if not isinstance(conv_layer, keras.layers.Conv2D):
            return None
        
        # Create a model that outputs conv features
        conv_output = conv_layer.output
        feature_model = keras.Model(inputs=model.input, outputs=conv_output)
        
        # Get feature maps
        features = feature_model(input_tensor)
        num_maps = features.shape[-1]
        
        # Sample maps if too many
        if num_maps > max_maps:
            indices = np.random.choice(num_maps, max_maps, replace=False)
            features = tf.gather(features, indices, axis=-1)
            num_maps = max_maps
        else:
            indices = np.arange(num_maps)
        
        # Get baseline prediction
        baseline_pred = model.predict(input_tensor, verbose=0)
        baseline_score = float(baseline_pred[0, target_class_idx])
        
        # Process each feature map
        scores = []
        feature_maps = []
        
        for i in range(num_maps):
            # Extract single feature map
            feature_map = features[0, :, :, i].numpy()
            
            # Normalize to [0, 1]
            fmin, fmax = feature_map.min(), feature_map.max()
            if fmax - fmin > 1e-10:
                feature_map = (feature_map - fmin) / (fmax - fmin)
            
            # Upsample to input size
            target_h, target_w = input_tensor.shape[1], input_tensor.shape[2]
            if feature_map.shape != (target_h, target_w):
                feature_map = cv2.resize(feature_map, (target_w, target_h), interpolation=cv2.INTER_LINEAR)
            
            # Create masked input
            if input_tensor.shape[-1] == 1:
                masked_input = input_tensor * feature_map[..., None]
            else:
                masked_input = input_tensor * feature_map[..., None]
            
            # Forward pass
            masked_pred = model.predict(masked_input, verbose=0)
            masked_score = float(masked_pred[0, target_class_idx])
            
            # Score gain (ReLU to ensure non-negative)
            score_gain = max(0, masked_score - baseline_score)
            
            scores.append(score_gain)
            feature_maps.append(feature_map)
        
        # Weighted combination
        scores = np.array(scores)
        if scores.sum() < 1e-10:
            return None
        
        weights = scores / (scores.sum() + 1e-10)
        cam = np.zeros_like(feature_maps[0])
        
        for weight, feature_map in zip(weights, feature_maps):
            cam += weight * feature_map
        
        return normalize_heatmap(cam)
    
    except Exception as e:
        print(f"Error in manual Score-CAM: {e}")
        return None

