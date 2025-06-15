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

# --- Setup Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Static Configurations ---
blacklist: List[str] = [
    'android\\support', 'com\\google\\android', 'com/google/android', 'android/support',
    'com\\android\\', 'com/android/', 'com\\google\\', 'com/google/', 'android\\annotation',
    'android/annotation', 'android\\net\\http\\', 'android/net/http/', 'org\\apache\\',
    'org/apache/', 'Xbox\\', 'Xbox/', 'android\\malware', 'android/malware',
    'android\\net\\compatibility', 'android/net/compatibility', 'com\\greensoft', 'com/greensoft'
]

FAMILY_STATS = {
    "apofer.b": {"avg_mal": 45.40, "avg_total": 437.73},
    "gepew.b": {"avg_mal": 26.90, "avg_total": 511.40},
    "agent.bz": {"avg_mal": 13.93, "avg_total": 397.07},
    "wapnor.a": {"avg_mal": 1.00,  "avg_total": 26.00},
    "fakeinst.a": {"avg_mal": 6.38,  "avg_total": 77.08},
    "opfake.bo": {"avg_mal": 15.07, "avg_total": 66.47},
    "agent.aax": {"avg_mal": 9.27,  "avg_total": 96.33},
}

FAMILY_PARAMS_CONFIG = {
    "default": { "xai_methods_to_use": ['gradcam++', 'scorecam', 'integrated_gradients'],
                 "cutoff": 0.08,  "intersection_count": 1, "topk_buffer": 2,
                 "use_dbscan": True, "dbscan_eps": 80, "dbscan_min_samples": 200,
                 "heatmap_blob_percentile_floor": 50, "min_blob_area": 30, "max_blob_area": 3000},
    # ... other family-specific configs as before ...
}

try:
    from androguard.core.bytecodes import dvm
except ImportError:
    logging.warning("Androguard not installed; domain mapping disabled.")
    dvm = None

# --- Helper Functions ---
def is_blacklisted(class_path: str) -> bool:
    norm = class_path.replace('/', '\\').lower()
    return any(p.lower() in norm for p in blacklist)

def pixel_to_byte_index(pixel: Tuple[int,int], shape: Tuple[int,int]) -> int:
    r,c = min(max(0,pixel[0]),shape[0]-1), min(max(0,pixel[1]),shape[1]-1)
    return r*shape[1] + c

# (Include integrated_gradients, extract_dex, dex_to_image,
#  decompile_dex_baksmali, get_sorted_smali_list, build_domain_mapping,
#  find_candidate_class, generate_heatmap, process_heatmap_for_mapping,
#  get_params_for_apk exactly as in your original script)

# For brevity, assume those functions are defined here unchanged...

# --- ADB Helpers ---
def check_adb() -> bool:
    try:
        subprocess.run(['adb','start-server'], check=True, stdout=subprocess.DEVNULL)
        out = subprocess.run(['adb','devices'], check=True, capture_output=True, text=True)
        lines = out.stdout.strip().splitlines()
        return len(lines)>1 and any('device' in l for l in lines[1:])
    except Exception:
        logging.error("ADB not available or no device connected.")
        return False


def get_apk_path_from_device(pkg: str) -> Optional[str]:
    try:
        res = subprocess.run(['adb','shell','pm','path',pkg], check=True, capture_output=True, text=True)
        if res.stdout.startswith('package:'):
            return res.stdout.strip().split(':',1)[1]
    except Exception:
        logging.error(f"Failed to find path for {pkg}")
    return None


def pull_apk_from_device(dev_path: str, local_dir: str) -> Optional[str]:
    fname = os.path.basename(dev_path)
    dest = os.path.join(local_dir, fname)
    try:
        subprocess.run(['adb','pull',dev_path,dest], check=True, capture_output=True)
        return dest if os.path.exists(dest) else None
    except Exception:
        logging.error(f"Failed to pull {dev_path}")
        return None

# --- New: Scan All Packages ---
def scan_all_packages(args: argparse.Namespace, model: keras.Model, last_conv_layer: Optional[str]):
    if not check_adb(): return
    res = subprocess.run(['adb','shell','pm','list','packages'], check=True, capture_output=True, text=True)
    pkgs = [l.split(':',1)[1] for l in res.stdout.splitlines() if l.startswith('package:')]
    logging.info(f"Found {len(pkgs)} packages.")
    pull_dir = os.path.join(args.output_dir,'adb_pulled_apks')
    os.makedirs(pull_dir, exist_ok=True)
    for pkg in pkgs:
        logging.info(f"Processing {pkg}...")
        dev_path = get_apk_path_from_device(pkg)
        if not dev_path: continue
        apk_local = pull_apk_from_device(dev_path, pull_dir)
        if apk_local:
            process_single_apk(apk_local, args, model, last_conv_layer)

# --- Main CLI ---
def main():
    parser = argparse.ArgumentParser(
        description="DexEctive: XAI-based malicious APK localization"
    )
    base = argparse.ArgumentParser(add_help=False)
    base.add_argument('-m','--model',required=True)
    base.add_argument('-b','--baksmali',required=True)
    base.add_argument('-o','--output-dir',required=True)
    base.add_argument('--methods', nargs='+', default=None,
        choices=['gradcam','gradcam++','scorecam','vanilla_saliency','smoothgrad','integrated_gradients'])

    subs = parser.add_subparsers(dest='command', required=True)
    f1 = subs.add_parser('file', parents=[base], help='Analyze single APK')
    f1.add_argument('apk_path')
    f2 = subs.add_parser('adb', parents=[base], help='Analyze one installed package')
    f2.add_argument('package_name')
    f3 = subs.add_parser('adb-all', parents=[base], help='Analyze all installed packages')

    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    try:
        model = keras.models.load_model(args.model)
        logging.info("Model loaded.")
    except Exception as e:
        logging.error(f"Model load failed: {e}"); return

    last_conv = None
    for l in reversed(model.layers):
        if isinstance(l, (keras.layers.Conv2D, tf.keras.layers.Conv2D)):
            last_conv = l.name; break
    logging.info(f"Last conv layer: {last_conv}")

    if args.command == 'file':
        process_single_apk(args.apk_path, args, model, last_conv)
    elif args.command == 'adb':
        if check_adb():
            devp = get_apk_path_from_device(args.package_name)
            if devp:
                lp = os.path.join(args.output_dir,'adb_pulled_apks'); os.makedirs(lp, exist_ok=True)
                apk = pull_apk_from_device(devp, lp)
                if apk: process_single_apk(apk, args, model, last_conv)
    elif args.command == 'adb-all':
        scan_all_packages(args, model, last_conv)

if __name__ == "__main__":
    main()
