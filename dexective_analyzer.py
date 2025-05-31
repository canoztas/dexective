#!/usr/bin/env python3
import os
import zipfile
import numpy as np
import subprocess
import cv2
import tensorflow as tf
from tensorflow import keras
from tf_keras_vis.scorecam import ScoreCAM
from tf_keras_vis.gradcam import Gradcam
from tf_keras_vis.gradcam_plus_plus import GradcamPlusPlus
from tf_keras_vis.saliency import Saliency
from tf_keras_vis.utils.model_modifiers import ReplaceToLinear
from tf_keras_vis.utils.scores import CategoricalScore
import matplotlib.pyplot as plt
import argparse
import shutil
from sklearn.cluster import DBSCAN
import logging
from typing import Optional, Tuple, List, Dict, Any
from collections import defaultdict
import pathlib
import glob

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Androguard Import ---
try:
    from androguard.core.bytecodes import dvm
except ImportError:
    logging.warning("Androguard is not installed. DEX order and domain mapping will not be extracted.")
    dvm = None

# --- Static Configurations (Blacklist, Family Params) ---
# NOTE: These are kept from your original script. The per-family configs will be used
# if the input APK path matches a known family structure, otherwise 'default' is used.
blacklist: List[str] = [
    'android\\support', 'com\\google\\android', 'com/google/android', 'android/support', 'com\\android\\',
    'com/android/', 'com\\google\\', 'com/google/', 'android\\annotation', 'android/annotation',
    'android\\net\\http\\', 'android/net/http/', 'org\\apache\\', 'org/apache/', 'Xbox\\', 'Xbox/',
    'android\\malware', 'android/malware', 'android\\net\\compatibility', 'android/net/compatibility',
    'com\\greensoft', "com/greensoft"
]

FAMILY_STATS = {
    "apofer.b": {"avg_mal": 45.40, "avg_total": 437.73}, "gepew.b": {"avg_mal": 26.90, "avg_total": 511.40},
    "agent.bz": {"avg_mal": 13.93, "avg_total": 397.07}, "wapnor.a": {"avg_mal": 1.00, "avg_total": 26.00},
    "fakeinst.a": {"avg_mal": 6.38, "avg_total": 77.08}, "opfake.bo": {"avg_mal": 15.07, "avg_total": 66.47},
    "agent.aax": {"avg_mal": 9.27, "avg_total": 96.33},
}

FAMILY_PARAMS_CONFIG = {
    "default": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.08, "intersection_count": 1, "topk_buffer": 2, "use_dbscan": True, "dbscan_eps": 80, "dbscan_min_samples": 200, "heatmap_blob_percentile_floor": 50, "min_blob_area": 30, "max_blob_area": 3000 },
    "apofer.b": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.05, "intersection_count": 1, "topk_buffer": 10, "use_dbscan": True, "dbscan_eps": 80, "dbscan_min_samples": 250, "heatmap_blob_percentile_floor": 40, "min_blob_area": 25, "max_blob_area": 4500 },
    "gepew.b": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.055, "intersection_count": 1, "topk_buffer": 5, "use_dbscan": False, "dbscan_eps": 10, "dbscan_min_samples": 10, "heatmap_blob_percentile_floor": 30, "min_blob_area": 30, "max_blob_area": 4800 },
    "agent.bz": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.06, "intersection_count": 1, "topk_buffer": 3, "use_dbscan": True, "dbscan_eps": 75, "dbscan_min_samples": 150, "heatmap_blob_percentile_floor": 50, "min_blob_area": 30, "max_blob_area": 2500 },
    "wapnor.a": { "xai_methods_to_use": ['scorecam'], "cutoff": 0.10, "intersection_count": 1, "topk_buffer": 0, "use_dbscan": True, "dbscan_eps": 40, "dbscan_min_samples": 40, "heatmap_blob_percentile_floor": 70, "min_blob_area": 3, "max_blob_area": 40 },
    "fakeinst.a": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.06, "intersection_count": 1, "topk_buffer": 1, "use_dbscan": True, "dbscan_eps": 70, "dbscan_min_samples": 100, "heatmap_blob_percentile_floor": 60, "min_blob_area": 35, "max_blob_area": 1000 },
    "opfake.bo": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.06, "intersection_count": 1, "topk_buffer": 6, "use_dbscan": True, "dbscan_eps": 75, "dbscan_min_samples": 150, "heatmap_blob_percentile_floor": 40, "min_blob_area": 25, "max_blob_area": 700 },
    "agent.aax": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'], "cutoff": 0.100, "intersection_count": 2, "topk_buffer": 1, "use_dbscan": False, "dbscan_eps": 10, "dbscan_min_samples": 10, "heatmap_blob_percentile_floor": 55, "min_blob_area": 35, "max_blob_area": 1400 }
}

# --- CORE ANALYSIS LOGIC (Functions from your script, unchanged) ---

def get_params_for_apk(apk_full_path: str, base_apk_dir: str, family_stats_dict: dict, family_params_config_dict: dict) -> Dict[str, Any]:
    default_config = family_params_config_dict["default"].copy()
    family_name_to_use = "default"
    family_key_used_for_config = "default"
    try:
        # Attempt to infer family if APK is in a subdirectory of base_apk_dir
        relative_path = pathlib.Path(apk_full_path).relative_to(base_apk_dir)
        if relative_path.parts: # Check if there are any parts (i.e., not directly in base_apk_dir)
            family_key_candidate = relative_path.parts[0]
            if family_key_candidate in family_params_config_dict:
                family_name_to_use = family_key_candidate
                family_key_used_for_config = family_key_candidate
    except (ValueError, IndexError):
        # This happens if apk_full_path is not under base_apk_dir or structure doesn't match
        logging.debug(f"Could not infer family from path {apk_full_path} relative to {base_apk_dir}. Using default config.")

    config = family_params_config_dict.get(family_name_to_use, default_config).copy()
    config["family_key_used"] = family_key_used_for_config # Record which config key was matched
    stats = family_stats_dict.get(family_name_to_use)

    # Dynamic Top-K calculation based on family stats and buffer
    if stats and 'avg_mal' in stats and 'topk_buffer' in config:
        config["topk"] = max(1, int(stats['avg_mal']) + config["topk_buffer"])
    elif "topk_buffer" in config: # Fallback if family stats are not available but topk_buffer is
        config["topk"] = config["topk_buffer"] + default_config.get("topk_buffer", 5)
    # Ensure all default keys are present
    for key, default_value in default_config.items():
        config.setdefault(key, default_value)

    logging.debug(f"Using config for family '{config['family_key_used']}': {config}")
    return config

def is_blacklisted(class_path: str) -> bool:
    normalized_path = class_path.replace('/', '\\').lower()
    return any(pattern.lower() in normalized_path for pattern in blacklist)

def pixel_to_byte_index(pixel_coords: Tuple[int, int], image_shape: Tuple[int, int]) -> int:
    row = min(max(0, pixel_coords[0]), image_shape[0] - 1)
    col = min(max(0, pixel_coords[1]), image_shape[1] - 1)
    return row * image_shape[1] + col

def integrated_gradients(model: keras.Model, input_tensor: np.ndarray, baseline: Optional[np.ndarray] = None, target_index: int = 0, steps: int = 50) -> np.ndarray:
    input_tensor_tf = tf.cast(input_tensor, tf.float32)
    baseline_tf = tf.zeros_like(input_tensor_tf) if baseline is None else tf.cast(baseline, tf.float32)
    scaled_inputs = [baseline_tf + (float(i) / steps) * (input_tensor_tf - baseline_tf) for i in range(steps + 1)]
    grads_list = []
    for scaled_input in scaled_inputs:
        with tf.GradientTape() as tape:
            tape.watch(scaled_input)
            predictions = model(scaled_input)
            score = predictions[:, target_index]
        grad = tape.gradient(score, scaled_input)
        if grad is not None:
            grads_list.append(grad)
    if not grads_list:
        logging.error("Integrated Gradients failed to produce gradients.")
        return np.zeros_like(input_tensor)
    avg_grads = tf.reduce_mean(tf.stack(grads_list), axis=0)
    return ((input_tensor_tf - baseline_tf) * avg_grads).numpy()

def extract_dex(apk_path: str, output_dir: str) -> List[str]:
    extracted_files = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            dex_files = [f for f in zf.namelist() if f.endswith('.dex')]
            if not dex_files:
                logging.warning(f"No .dex files found in '{os.path.basename(apk_path)}'.")
                return []
            for dex_file in dex_files:
                if '..' in dex_file or dex_file.startswith(('/', '\\')):
                    logging.warning(f"Skipping potentially unsafe DEX path: {dex_file}")
                    continue
                extracted_files.append(zf.extract(dex_file, output_dir))
        return extracted_files
    except Exception as e:
        logging.error(f"Failed to extract DEX from {apk_path}: {e}")
        return []

def dex_to_image(dex_path: str) -> Tuple[Optional[np.ndarray], Optional[bytes]]:
    try:
        with open(dex_path, 'rb') as f:
            dex_bytes = f.read()
        if not dex_bytes:
            logging.warning(f"DEX file is empty: {dex_path}")
            return None, None
        size = int(np.ceil(np.sqrt(len(dex_bytes))))
        padded_length = size * size
        dex_array = np.frombuffer(dex_bytes, dtype=np.uint8)
        dex_array = np.pad(dex_array, (0, padded_length - len(dex_array)), 'constant')
        return dex_array.reshape((size, size)), dex_bytes
    except Exception as e:
        logging.error(f"Failed to convert DEX to image for {dex_path}: {e}")
        return None, None

def decompile_dex_baksmali(dex_path: str, output_dir: str, baksmali_jar: str) -> bool:
    try:
        os.makedirs(output_dir, exist_ok=True)
        command = ['java', '-jar', baksmali_jar, 'disassemble', dex_path, '-o', output_dir]
        logging.info(f"Running Baksmali: {' '.join(command)}")
        proc = subprocess.run(command, check=True, capture_output=True, text=True, timeout=600)
        logging.info(f"Successfully decompiled {os.path.basename(dex_path)}.")
        return True
    except FileNotFoundError:
        logging.error("`java` or `baksmali.jar` not found. Please ensure Java is in your PATH and the path to baksmali.jar is correct.")
        return False
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error(f"Baksmali failed for {os.path.basename(dex_path)}: {e.stderr if hasattr(e, 'stderr') else e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred during decompilation: {e}")
        return False

def get_sorted_smali_list(smali_dir: str, dex_order: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    smali_files_metadata = []
    for root, _, files in os.walk(smali_dir):
        for file in files:
            if file.endswith('.smali'):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, smali_dir)
                cls_name_path = os.path.splitext(rel_path)[0].replace(os.sep, '\\')
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content_bytes = len(f.read().encode('utf-8'))
                    if content_bytes > 0:
                        idx = dex_order.index(cls_name_path) if dex_order and cls_name_path in dex_order else float('inf')
                        smali_files_metadata.append({
                            'path': full_path, 'class_name': cls_name_path, 'size': content_bytes,
                            'blacklisted': is_blacklisted(cls_name_path), 'dex_index': idx
                        })
                except Exception as e:
                    logging.warning(f"Error processing smali file {full_path}: {e}")

    smali_files_metadata.sort(key=lambda x: (x['dex_index'], x['path']))
    cum_size = 0
    for info in smali_files_metadata:
        info['cumulative'] = cum_size
        cum_size += info['size']
    return smali_files_metadata

def build_domain_mapping(dex_bytes: bytes) -> List[Dict[str, Any]]:
    if not dvm or not dex_bytes:
        return []
    mapping = []
    try:
        dex_obj = dvm.DalvikVMFormat(dex_bytes)
        for cls in dex_obj.get_classes():
            name_std = cls.get_name()[1:-1].replace('/', '\\') if cls.get_name().startswith('L') and cls.get_name().endswith(';') else cls.get_name().replace('/', '\\')
            for meth in cls.get_methods():
                code = meth.get_code()
                if code:
                    offset = getattr(code, 'offset', code.get_off() if hasattr(code, 'get_off') else None)
                    if offset is not None:
                        mapping.append({'class_name': name_std, 'method_name': meth.get_name(), 'offset': offset})
    except Exception as e:
        logging.warning(f"Androguard failed to build domain mapping: {e}")
    return mapping

def find_candidate_class(smali_list: List[Dict[str, Any]], offset: int, domain_map: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    if domain_map:
        closest_entry = min(domain_map, key=lambda x: abs(x['offset'] - offset), default=None)
        if closest_entry:
            for smali_info in smali_list:
                if closest_entry['class_name'] == smali_info['class_name'] and not smali_info.get('blacklisted', False):
                    return smali_info['class_name']
                # If the exact match is blacklisted, we might need a fallback or nearby non-blacklisted class.
                # For simplicity, we'll currently just return None and let the cumulative search handle it if direct map is blacklisted.

    for info in smali_list:
        if info['cumulative'] <= offset < info['cumulative'] + info['size']:
            if not info.get('blacklisted', False):
                return info['class_name']
            else: # The directly mapped class is blacklisted, search for nearest non-blacklisted
                original_index = smali_list.index(info)
                # Search backwards
                for i in range(original_index - 1, -1, -1):
                    if not smali_list[i].get('blacklisted', False):
                        return smali_list[i]['class_name']
                # Search forwards
                for i in range(original_index + 1, len(smali_list)):
                    if not smali_list[i].get('blacklisted', False):
                        return smali_list[i]['class_name']
                return None # All nearby are blacklisted or no other classes
    return None

def generate_heatmap(method_name: str, model: keras.Model, input_tensor: np.ndarray, target_layer_name: Optional[str] = None, score_index: int = 0) -> Optional[np.ndarray]:
    score_function = CategoricalScore([score_index])
    needs_linear_replacement = hasattr(model.layers[-1], 'activation') and model.layers[-1].activation not in [tf.keras.activations.linear, None]

    vis_class_map = {
        'scorecam': ScoreCAM, 'gradcam': Gradcam, 'gradcam++': GradcamPlusPlus,
        'vanilla_saliency': Saliency, 'smoothgrad': Saliency, 'integrated_gradients': "local"
    }
    if method_name not in vis_class_map:
        logging.error(f"Unknown XAI method: {method_name}"); return None

    try:
        if method_name == 'integrated_gradients':
            ig_raw = integrated_gradients(model, input_tensor, target_index=score_index)
            if ig_raw.ndim > 2 : # if channels exist
                 cam_result = np.mean(np.abs(np.squeeze(ig_raw)), axis=-1)
            else:
                 cam_result = np.abs(np.squeeze(ig_raw))
        else:
            VisualizerClass = vis_class_map[method_name]
            vis_args = {'model': model, 'clone': False}
            if method_name in ['gradcam', 'gradcam++'] and needs_linear_replacement:
                vis_args['model_modifier'] = ReplaceToLinear()
            
            visualizer = VisualizerClass(**vis_args)
            call_args = {'score': score_function, 'seed_input': input_tensor}
            if method_name in ['scorecam', 'gradcam', 'gradcam++']:
                if not target_layer_name: logging.error(f"Target layer needed for {method_name}"); return None
                call_args['penultimate_layer'] = target_layer_name
            if method_name == 'smoothgrad':
                call_args['smooth_samples'] = 20; call_args['smooth_noise'] = 0.20

            s_map = visualizer(**call_args)
            # Squeeze to remove batch dimension, then handle channel if present for saliency maps
            s_map_squeezed = np.squeeze(s_map)
            cam_result = np.max(np.abs(s_map_squeezed), axis=-1) if s_map_squeezed.ndim == 3 else s_map_squeezed


        if cam_result is None or cam_result.ndim != 2:
            logging.warning(f"{method_name} produced invalid heatmap shape: {cam_result.shape if cam_result is not None else 'None'}")
            return None
        
        return cv2.normalize(cam_result, None, 0, 1, cv2.NORM_MINMAX, dtype=cv2.CV_32F) if not np.all(cam_result == cam_result.flat[0]) else cam_result
    except Exception as e:
        logging.error(f"Error in {method_name} heatmap generation: {e}", exc_info=True); return None

def process_heatmap_for_mapping(heatmap: np.ndarray, orig_shape: Tuple[int, int], smali_list: list, domain_map: list, params: dict) -> Dict[str, float]:
    if heatmap is None or heatmap.size == 0: return {}
    
    heatmap_resized = cv2.resize(heatmap, (orig_shape[1], orig_shape[0]), interpolation=cv2.INTER_LINEAR)
    
    dyn_thresh = np.mean(heatmap_resized[heatmap_resized > 0]) if np.any(heatmap_resized > 0) else 0.0
    _, binary_map = cv2.threshold(heatmap_resized, dyn_thresh, 1, cv2.THRESH_BINARY)
    binary_map = binary_map.astype(np.uint8)
    
    class_scores_map = defaultdict(list)

    if params["use_dbscan"]:
        pts = np.column_stack(np.where(binary_map > 0))
        if pts.shape[0] > params["dbscan_min_samples"]: # Ensure enough points for DBSCAN
            try:
                labels = DBSCAN(eps=params["dbscan_eps"], min_samples=params["dbscan_min_samples"]).fit(pts).labels_
                for pt_idx, label in enumerate(labels):
                    if label != -1: # Ignore noise points
                        y, x = pts[pt_idx]
                        offset = pixel_to_byte_index((y, x), orig_shape)
                        cls_name = find_candidate_class(smali_list, offset, domain_map)
                        if cls_name: # Already filtered by find_candidate_class
                            class_scores_map[cls_name].append(heatmap_resized[y, x])
            except Exception as e:
                logging.error(f"DBSCAN failed: {e}. Falling back to connected components if enabled, or skipping heatmap.")
                if not params.get("fallback_to_cc_on_dbscan_fail", False): # Add a param for this
                    return {} # Or handle differently
                # Fallback logic for CC would go here if DBSCAN fails and fallback is true
        else:
            logging.debug("Not enough points for DBSCAN, skipping.")

    else: # Connected Components
        num_labels, labels_map, stats, centroids = cv2.connectedComponentsWithStats(binary_map, 8, cv2.CV_32S)
        for i in range(1, num_labels): # Skip background label 0
            area = stats[i, cv2.CC_STAT_AREA]
            # Check against percentile floor for blob intensity
            blob_pixels = (labels_map == i)
            blob_mean_intensity = heatmap_resized[blob_pixels].mean()
            
            # Compute threshold based on non-zero heatmap values if available
            heatmap_positive_values = heatmap_resized[heatmap_resized > 0]
            if heatmap_positive_values.size > 0:
                intensity_threshold = np.percentile(heatmap_positive_values, params["heatmap_blob_percentile_floor"])
            else: # If heatmap has no positive values (e.g. all zeros or negative)
                intensity_threshold = 0 # effectively skip this check or handle as an edge case

            if params["min_blob_area"] <= area <= params["max_blob_area"] and blob_mean_intensity >= intensity_threshold:
                # Use centroid provided by connectedComponentsWithStats for more stable mapping
                centroid_x, centroid_y = int(centroids[i][0]), int(centroids[i][1])
                offset = pixel_to_byte_index((centroid_y, centroid_x), orig_shape)
                cls_name = find_candidate_class(smali_list, offset, domain_map)
                if cls_name:
                    class_scores_map[cls_name].append(blob_mean_intensity)

    return {cls: float(np.mean(scores)) for cls, scores in class_scores_map.items() if scores}


def process_single_apk(apk_path: str, args: argparse.Namespace, model: keras.Model, last_conv_layer: Optional[str]):
    apk_base_name = os.path.basename(apk_path)
    safe_apk_name = pathlib.Path(apk_path).stem.replace('.', '_').replace(' ', '_')
    temp_processing_dir = os.path.join(args.output_dir, f'tmp_{safe_apk_name}')
    
    try:
        os.makedirs(temp_processing_dir, exist_ok=True)
        logging.info(f"Processing APK: {apk_path}")

        extracted_dex_paths = extract_dex(apk_path, temp_processing_dir)
        if not extracted_dex_paths:
            logging.error(f"No DEX files extracted from {apk_base_name}. Aborting analysis for this APK.")
            return

        dex_img, dex_bytes = dex_to_image(extracted_dex_paths[0])
        if dex_img is None or dex_bytes is None:
            logging.error(f"Failed to convert DEX to image for {apk_base_name}. Aborting analysis for this APK.")
            return

        current_apk_config = get_params_for_apk(apk_path, os.path.dirname(apk_path), FAMILY_STATS, FAMILY_PARAMS_CONFIG)
        
        model_input_shape_hw = (model.input_shape[1], model.input_shape[2])
        resized_dex = cv2.resize(dex_img, model_input_shape_hw, interpolation=cv2.INTER_AREA if dex_img.shape[0] > model_input_shape_hw[0] else cv2.INTER_LINEAR)
        model_in_data = resized_dex.astype('float32') / 255.0
        
        if model.input_shape[-1] == 3:
            model_in_data = np.repeat(model_in_data[..., None], 3, axis=-1)
        elif model.input_shape[-1] == 1 and model_in_data.ndim == 2:
             model_in_data = model_in_data[..., None]

        model_in_data = np.expand_dims(model_in_data, axis=0) # Add batch dimension
        
        mal_score = float(model.predict(model_in_data, verbose=0)[0, 0])

        if mal_score < 0.5: # Configurable threshold?
            logging.info(f"Skipping {apk_base_name}: Classified as Benign (Score: {mal_score:.4f}).")
            return

        logging.info(f"APK {apk_base_name} is MALICIOUS (Score: {mal_score:.4f}). Proceeding with XAI localization.")

        smali_out_dir = os.path.join(temp_processing_dir, 'smali')
        if not decompile_dex_baksmali(extracted_dex_paths[0], smali_out_dir, args.baksmali):
            logging.error(f"Failed to decompile DEX for {apk_base_name}. Aborting XAI for this APK.")
            return

        dex_class_order, domain_map = None, None
        if dvm and dex_bytes:
            try:
                dex_vm = dvm.DalvikVMFormat(dex_bytes)
                dex_class_order = [c.get_name()[1:-1].replace('/', '\\') for c in dex_vm.get_classes() if c.get_name().startswith('L')]
                domain_map = build_domain_mapping(dex_bytes)
            except Exception as e:
                logging.warning(f"Error during Androguard processing for {apk_base_name}: {e}")


        smali_list = get_sorted_smali_list(smali_out_dir, dex_class_order)
        if not smali_list:
            logging.warning(f"No Smali classes found after decompilation for {apk_base_name}.")
            return # Cannot map if no smali files

        all_xai_class_scores = {}
        methods_to_run = current_apk_config.get("xai_methods_to_use", args.methods) # User CLI args override config
        
        for method in methods_to_run:
            target_layer_for_cam = last_conv_layer if method in ['scorecam', 'gradcam', 'gradcam++'] else None
            heatmap = generate_heatmap(method, model, model_in_data, target_layer_for_cam)
            if heatmap is not None:
                plt.imsave(os.path.join(args.output_dir, f"{safe_apk_name}_{method}_heatmap.png"), heatmap, cmap='jet')
                class_scores = process_heatmap_for_mapping(heatmap, dex_img.shape, smali_list, domain_map, current_apk_config)
                if class_scores:
                    all_xai_class_scores[method] = class_scores
            else:
                logging.warning(f"Heatmap generation failed for method {method} on {apk_base_name}.")


        if not all_xai_class_scores:
            logging.warning(f"No suspicious classes identified by any XAI method for {apk_base_name}.")
            return

        class_counts = defaultdict(int)
        agg_scores = defaultdict(list)
        for method_scores in all_xai_class_scores.values():
            for cls, score in method_scores.items():
                class_counts[cls] += 1
                agg_scores[cls].append(score)

        final_agg_scores = {cls: max(scores) for cls, scores in agg_scores.items()}
        
        intersect_candidates = {cls for cls, count in class_counts.items() if count >= current_apk_config["intersection_count"]}
        sorted_by_score = sorted(final_agg_scores.items(), key=lambda item: item[1], reverse=True)
        topk_candidates = {cls for cls, _ in sorted_by_score[:current_apk_config["topk"]]}
        cutoff_candidates = {cls for cls, score in final_agg_scores.items() if score >= current_apk_config["cutoff"]}
        
        final_candidates_set = intersect_candidates | topk_candidates | cutoff_candidates
        final_candidates_sorted = sorted(list(final_candidates_set), key=lambda c: final_agg_scores.get(c, 0.0), reverse=True)

        results_file = os.path.join(args.output_dir, f"report_{safe_apk_name}.txt")
        with open(results_file, 'w', encoding='utf-8') as f:
            f.write(f"# DexEctive Analysis Report for: {apk_base_name}\n")
            f.write(f"# Original Path: {apk_path}\n")
            f.write(f"# Malware Score: {mal_score:.4f}\n")
            f.write(f"# Family Config Used: {current_apk_config['family_key_used']}\n")
            f.write(f"# Effective XAI Methods Used: {', '.join(methods_to_run)}\n")
            f.write(f"# Parameters: TopK={current_apk_config['topk']}, Cutoff={current_apk_config['cutoff']}, Intersection={current_apk_config['intersection_count']}\n\n")
            f.write("--- Identified Malicious Candidate Classes ---\n")
            if not final_candidates_sorted:
                f.write("No suspicious candidates identified by the current rules.\n")
            else:
                for cand_cls in final_candidates_sorted:
                    score_val = final_agg_scores.get(cand_cls, 0.0)
                    method_count = class_counts.get(cand_cls, 0)
                    present_in_methods = [m for m, s in all_xai_class_scores.items() if cand_cls in s]
                    score_info = f"(Max Agg. Score: {score_val:.4f}, Detected by {method_count}/{len(methods_to_run)} methods: {', '.join(present_in_methods)})"
                    f.write(f"- {cand_cls} {score_info}\n")
        
        logging.info(f"Successfully processed {apk_base_name}. Report saved to {results_file}")

    except Exception as e:
        logging.error(f"A critical error occurred while processing {apk_base_name}: {e}", exc_info=True)
    finally:
        if os.path.exists(temp_processing_dir):
            try:
                shutil.rmtree(temp_processing_dir)
            except Exception as e_clean:
                logging.error(f"Failed to clean up temp directory {temp_processing_dir}: {e_clean}")

# --- ADB Helper Functions ---
def check_adb():
    try:
        subprocess.run(['adb', 'start-server'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.run(['adb', 'devices'], check=True, capture_output=True, text=True)
        # A bit more robust check for connected devices
        lines = result.stdout.strip().splitlines()
        if len(lines) > 1 and any('device' in line for line in lines[1:]):
            return True
        logging.error("No device connected or authorized. Please connect a device and enable USB debugging.")
        return False
    except FileNotFoundError:
        logging.error("ADB is not installed or not in your system's PATH."); return False
    except subprocess.CalledProcessError:
        logging.error("ADB command failed. Ensure it's working correctly."); return False

def get_apk_path_from_device(package_name: str) -> Optional[str]:
    try:
        logging.info(f"Querying path for package: {package_name}")
        result = subprocess.run(['adb', 'shell', 'pm', 'path', package_name], check=True, capture_output=True, text=True)
        path_line = result.stdout.strip()
        if not path_line.startswith('package:'):
            logging.error(f"Could not find path for package '{package_name}'. Is it installed?"); return None
        return path_line.split(':', 1)[1]
    except subprocess.CalledProcessError:
        logging.error(f"Failed to get path for package '{package_name}'."); return None

def pull_apk_from_device(device_path: str, local_dir: str) -> Optional[str]:
    apk_filename = os.path.basename(device_path)
    local_path = os.path.join(local_dir, apk_filename)
    try:
        logging.info(f"Pulling APK from '{device_path}' to '{local_path}'")
        subprocess.run(['adb', 'pull', device_path, local_path], check=True, capture_output=True)
        if os.path.exists(local_path):
            return local_path
        logging.error(f"APK pull seemed to succeed but file not found at {local_path}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to pull APK: {e.stderr.strip() if e.stderr else e}"); return None


def find_last_conv_layer(model: keras.Model) -> Optional[str]:
    for layer in reversed(model.layers):
        if isinstance(layer, (keras.layers.Conv2D, tf.keras.layers.Conv2D)): # Check for tf.keras.layers as well
            return layer.name
    logging.warning("No Conv2D layer found in the model. CAM-based methods might not work as expected.")
    return None


# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(
        description="DexEctive: An XAI-based tool for localizing malicious code in Android applications.", # Updated name
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help="Available commands")

    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument('-m', '--model', required=True, help="Path to the trained Keras model (.h5 file).")
    base_parser.add_argument('-b', '--baksmali', required=True, help="Path to the baksmali.jar file.")
    base_parser.add_argument('-o', '--output-dir', required=True, help="Directory to save analysis reports and heatmaps.")
    base_parser.add_argument(
        '--methods', nargs='+', default=None, # Default to None to let config decide first
        choices=['gradcam', 'gradcam++', 'scorecam', 'vanilla_saliency', 'smoothgrad', 'integrated_gradients'],
        help="List of XAI methods to use (overrides family/default config). Default is from config."
    )

    parser_file = subparsers.add_parser('file', parents=[base_parser], help="Analyze a single local APK file.")
    parser_file.add_argument('apk_path', help="Path to the APK file to analyze.")

    parser_adb = subparsers.add_parser('adb', parents=[base_parser], help="Pull and analyze an app from a connected Android device.")
    parser_adb.add_argument('package_name', help="The package name of the app to analyze (e.g., 'com.example.app').")

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    try:
        model = keras.models.load_model(args.model)
        logging.info(f"Successfully loaded model from {args.model}")
    except Exception as e:
        logging.error(f"Failed to load model: {e}"); return

    last_conv_layer = find_last_conv_layer(model)
    # No early exit if None, generate_heatmap handles methods not needing it

    apk_to_process = None
    if args.command == 'file':
        if not os.path.exists(args.apk_path):
            logging.error(f"APK file not found: {args.apk_path}"); return
        apk_to_process = args.apk_path
    elif args.command == 'adb':
        if not check_adb(): return
        device_path = get_apk_path_from_device(args.package_name)
        if not device_path: return
        adb_pull_dir = os.path.join(args.output_dir, 'adb_pulled_apks')
        os.makedirs(adb_pull_dir, exist_ok=True)
        apk_to_process = pull_apk_from_device(device_path, adb_pull_dir)
        if not apk_to_process: return
    
    if apk_to_process:
        process_single_apk(apk_to_process, args, model, last_conv_layer)

if __name__ == "__main__":
    main()
