"""Image processing utilities for DEX to image conversion."""
import numpy as np
from typing import Tuple, Optional
import cv2


def bytes_to_image(dex_bytes: bytes) -> Tuple[np.ndarray, int]:
    """
    Convert DEX bytes to grayscale image.
    
    Args:
        dex_bytes: Raw DEX file bytes
        
    Returns:
        Tuple of (image array, original byte length)
        Image is a square grayscale array with zero-padding.
    """
    if not dex_bytes:
        return None, 0
    
    L = len(dex_bytes)
    S = int(np.ceil(np.sqrt(L)))
    padded_length = S * S
    
    dex_array = np.frombuffer(dex_bytes, dtype=np.uint8)
    dex_array = np.pad(dex_array, (0, padded_length - len(dex_array)), 'constant')
    
    return dex_array.reshape((S, S)), L


def normalize_heatmap(heatmap: np.ndarray) -> np.ndarray:
    """
    Normalize heatmap to [0, 1] range.
    
    Args:
        heatmap: Input heatmap array
        
    Returns:
        Normalized heatmap in [0, 1] range
    """
    if heatmap.size == 0:
        return heatmap
    
    hmin, hmax = heatmap.min(), heatmap.max()
    if hmax - hmin < 1e-10:
        return np.zeros_like(heatmap)
    
    return (heatmap - hmin) / (hmax - hmin)


def resize_for_model(image: np.ndarray, target_shape: Tuple[int, int]) -> np.ndarray:
    """
    Resize image to match model input shape.
    
    Args:
        image: Input grayscale image
        target_shape: (height, width) target dimensions
        
    Returns:
        Resized image
    """
    if len(image.shape) == 2:
        return cv2.resize(image, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_LINEAR)
    else:
        return cv2.resize(image, (target_shape[1], target_shape[0]), interpolation=cv2.INTER_LINEAR)


def prepare_model_input(image: np.ndarray, model_input_shape: Tuple[int, ...]) -> np.ndarray:
    """
    Prepare image for model inference.
    
    Args:
        image: Grayscale image (H, W)
        model_input_shape: Model input shape (batch, H, W, channels)
        
    Returns:
        Preprocessed batch tensor ready for model
    """
    # Resize if needed
    target_h, target_w = model_input_shape[1], model_input_shape[2]
    if image.shape[0] != target_h or image.shape[1] != target_w:
        image = resize_for_model(image, (target_h, target_w))
    
    # Normalize to [0, 1]
    model_input = image.astype('float32') / 255.0
    
    # Add channel dimension if needed
    if len(model_input.shape) == 2:
        model_input = model_input[..., None]
    
    # Handle RGB models
    if model_input_shape[-1] == 3 and model_input.shape[-1] == 1:
        model_input = np.repeat(model_input, 3, axis=-1)
    
    # Add batch dimension
    return np.expand_dims(model_input, axis=0)

