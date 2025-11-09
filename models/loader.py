"""Model loading and inspection utilities."""
import os
import tensorflow as tf
from tensorflow import keras
from typing import Optional, Tuple, List
import logging

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
tf.get_logger().setLevel('ERROR')


def load_keras_model(model_path: str, compile: bool = False) -> Optional[keras.Model]:
    """
    Load a Keras model from file.
    
    Args:
        model_path: Path to model file (.h5, .keras, etc.)
        compile: Whether to compile the model
        
    Returns:
        Loaded Keras model, or None if loading fails
    """
    try:
        model = keras.models.load_model(model_path, compile=compile)
        if compile:
            model.compile(optimizer='adam', loss='binary_crossentropy')
        return model
    except Exception as e:
        logging.error(f"Failed to load model from {model_path}: {e}")
        return None


def find_last_conv_layer(model: keras.Model) -> Optional[str]:
    """
    Find the last convolutional layer in a model.
    
    Args:
        model: Keras model
        
    Returns:
        Name of last convolutional layer, or None if not found
    """
    for layer in reversed(model.layers):
        if isinstance(layer, (keras.layers.Conv2D, keras.layers.Conv1D)):
            return layer.name
    return None


def get_model_input_shape(model: keras.Model) -> Tuple[int, ...]:
    """
    Get model input shape (excluding batch dimension).
    
    Args:
        model: Keras model
        
    Returns:
        Input shape tuple (H, W, C)
    """
    if model.input_shape:
        # input_shape is (batch, H, W, C) or (batch, ...)
        return tuple(model.input_shape[1:])
    return tuple()


def get_model_info(model: keras.Model, model_path: str) -> dict:
    """
    Extract model metadata.
    
    Args:
        model: Keras model
        model_path: Path to model file
        
    Returns:
        Dictionary with model information
    """
    input_shape = get_model_input_shape(model)
    return {
        "path": model_path,
        "input_shape": list(input_shape),
        "layers": len(model.layers),
    }

