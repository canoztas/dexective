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
import shutil
from typing import Optional, Tuple, List, Dict, Any
from collections import defaultdict
import pathlib

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.theme import Theme
from pyfiglet import Figlet
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# --- Setup Rich and Typer ---
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "highlight": "bold magenta",
})
console = Console(record=True, theme=custom_theme)

app = typer.Typer(
    name="dexecutive",
    help="A tool for XAI-based malicious class localization in Android APKs.",
    rich_markup_mode="markdown",
    no_args_is_help=True
)
analyze_app = typer.Typer(name="analyze", help="Run full analysis with XAI localization.")
scan_app = typer.Typer(name="scan", help="Run a quick scan for malware without localization.")
app.add_typer(analyze_app)
app.add_typer(scan_app)


# --- Static Configurations ---
IGNORE_SCAN = ('com.google.android', 'com.android', 'com.android.vending')
blacklist: List[str] = [
    'android\\support', 'com\\google\\android', 'com/google/android', 'android/support',
    'com\\android\\', 'com/android/', 'com\\google\\', 'com/google/', 'android\\annotation',
    'android/annotation', 'android\\net\\http\\', 'android/net/http/', 'org\\apache\\',
    'org/apache/', 'Xbox\\', 'Xbox/', 'android\\malware', 'android/malware'
]
try:
    from androguard.core.bytecodes import dvm
except ImportError:
    console.log("[warning]Androguard not installed; domain mapping will be disabled.[/warning]")
    dvm = None


# --- Helper & Processing Functions ---

def is_blacklisted(class_path: str) -> bool:
    norm = class_path.replace('/', '\\').lower()
    return any(p.lower() in norm for p in blacklist)

def pixel_to_byte_index(pixel: Tuple[int,int], shape: Tuple[int,int]) -> int:
    r,c = min(max(0,pixel[0]),shape[0]-1), min(max(0,pixel[1]),shape[1]-1)
    return r*shape[1] + c

def extract_dex(apk_path: str, output_dir: str) -> List[str]:
    extracted_files = []
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            dex_files = [f for f in zf.namelist() if f.endswith('.dex')]
            if not dex_files:
                return []
            for dex_file in dex_files:
                # Security: Prevent path traversal attacks.
                if '..' in dex_file or dex_file.startswith('/'):
                    continue
                extracted_files.append(zf.extract(dex_file, output_dir))
        return extracted_files
    except Exception as e:
        console.log(f"Failed to extract DEX from {apk_path}: {e}", style="error")
        return []

def dex_to_image(dex_path: str) -> Tuple[Optional[np.ndarray], Optional[bytes]]:
    try:
        with open(dex_path, 'rb') as f:
            dex_bytes = f.read()
        if not dex_bytes: return None, None
        size = int(np.ceil(np.sqrt(len(dex_bytes))))
        padded_length = size * size
        dex_array = np.frombuffer(dex_bytes, dtype=np.uint8)
        dex_array = np.pad(dex_array, (0, padded_length - len(dex_array)), 'constant')
        return dex_array.reshape((size, size)), dex_bytes
    except Exception as e:
        console.log(f"Failed to convert DEX to image for {dex_path}: {e}", style="error")
        return None, None

def decompile_dex_baksmali(dex_path: str, output_dir: str, baksmali_jar: str) -> bool:
    try:
        os.makedirs(output_dir, exist_ok=True)
        command = ['java', '-jar', baksmali_jar, 'disassemble', dex_path, '-o', output_dir]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=600)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        console.log(f"Baksmali failed for {os.path.basename(dex_path)}: {e.stderr if hasattr(e, 'stderr') else e}", style="error")
        return False
    except Exception as e:
        console.log(f"An unexpected error occurred during decompilation: {e}", style="error")
        return False

def get_sorted_smali_list(smali_dir: str) -> List[Dict[str, Any]]:
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
                        smali_files_metadata.append({
                            'path': full_path, 'class_name': cls_name_path, 'size': content_bytes,
                            'blacklisted': is_blacklisted(cls_name_path)
                        })
                except Exception as e:
                    console.log(f"Error processing smali file {full_path}: {e}", style="warning")
    smali_files_metadata.sort(key=lambda x: x['path'])
    cum_size = 0
    for info in smali_files_metadata:
        info['cumulative'] = cum_size
        cum_size += info['size']
    return smali_files_metadata

def find_candidate_class(smali_list: List[Dict[str, Any]], offset: int) -> Optional[str]:
    for info in smali_list:
        if info['cumulative'] <= offset < info['cumulative'] + info['size']:
            return info['class_name'] if not info['blacklisted'] else None
    return None

def generate_heatmap(method_name: str, model: keras.Model, input_tensor: np.ndarray, last_conv_layer: str) -> Optional[np.ndarray]:
    score = CategoricalScore([0])
    try:
        visualizer = GradcamPlusPlus(model, model_modifier=ReplaceToLinear(), clone=False)
        cam = visualizer(score, input_tensor, penultimate_layer=last_conv_layer)
        if cam is None or cam.size == 0: return None
        heatmap = np.squeeze(cam[0])
        return cv2.normalize(heatmap, None, 0, 255, cv2.NORM_MINMAX)
    except Exception as e:
        console.log(f"Error generating {method_name} heatmap: {e}", style="error")
        return None

def check_adb() -> bool:
    try:
        subprocess.run(['adb','start-server'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out = subprocess.run(['adb','devices'], check=True, capture_output=True, text=True)
        lines = out.stdout.strip().splitlines()
        is_device_present = len(lines) > 1 and any('device' in l for l in lines[1:])
        if not is_device_present: console.log("ADB device not found.", style="error")
        return is_device_present
    except Exception:
        console.log("ADB not available or no device connected.", style="error")
        return False

def get_apk_path_from_device(pkg: str) -> Optional[str]:
    try:
        res = subprocess.run(['adb','shell','pm','path',pkg], check=True, capture_output=True, text=True)
        if res.stdout.startswith('package:'):
            return res.stdout.strip().split(':',1)[1]
    except Exception:
        console.log(f"Failed to find path for package [highlight]'{pkg}'[/highlight] on device.", style="error")
    return None

def pull_apk_from_device(dev_path: str, local_dir: str, package_name: str) -> Optional[str]:
    safe_fname = package_name.replace(":", "_").replace("/", "_") + ".apk"
    dest = os.path.join(local_dir, safe_fname)
    try:
        subprocess.run(['adb','pull', dev_path, dest], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return dest if os.path.exists(dest) else None
    except Exception as e:
        console.log(f"Failed to pull {dev_path} for package {package_name}: {e}", style="error")
        return None

def get_prediction_and_data(apk_path: str, model: keras.Model) -> Tuple[Optional[float], str, Optional[np.ndarray], Optional[bytes], Optional[np.ndarray]]:
    apk_base_name = os.path.basename(apk_path)
    temp_dir = pathlib.Path(apk_path).parent / f"tmp_{pathlib.Path(apk_path).stem}"
    os.makedirs(temp_dir, exist_ok=True)

    try:
        extracted_dex_paths = extract_dex(apk_path, str(temp_dir))
        if not extracted_dex_paths: return None, apk_base_name, None, None, None

        dex_img, dex_bytes = dex_to_image(extracted_dex_paths[0])
        if dex_img is None: return None, apk_base_name, None, None, None

        model_input_shape_hw = (model.input_shape[1], model.input_shape[2])
        resized_dex = cv2.resize(dex_img, model_input_shape_hw, interpolation=cv2.INTER_AREA)
        model_in_data = resized_dex.astype('float32') / 255.0

        if model.input_shape[-1] == 3:
            model_in_data = np.repeat(model_in_data[..., None], 3, axis=-1)
        else:
            model_in_data = model_in_data[..., None]
        
        model_in_data_batch = np.expand_dims(model_in_data, axis=0)
        mal_score = float(model.predict(model_in_data_batch, verbose=0)[0, 0])
        
        return mal_score, apk_base_name, dex_img, dex_bytes, model_in_data_batch
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def process_single_apk(apk_path: str, output_dir: str, baksmali_jar: str, model: keras.Model, last_conv_layer: Optional[str], progress: Optional[Progress] = None, task_id=None):
    apk_base_name = os.path.basename(apk_path)
    if progress and task_id is not None:
        progress.update(task_id, description=f"Analyzing [highlight]{apk_base_name}[/highlight]")
    else:
        console.log(f"--- Starting full analysis for [highlight]{apk_base_name}[/highlight] ---")
    
    safe_apk_name = pathlib.Path(apk_path).stem.replace('.', '_').replace(' ', '_')
    
    mal_score, _, dex_img, dex_bytes, model_in_data = get_prediction_and_data(apk_path, model)

    if mal_score is None:
        console.log(f"Could not process [highlight]{apk_base_name}[/highlight].", style="error")
    elif mal_score < 0.5:
        console.log(f"✔️ [success]Benign[/success]: [highlight]{apk_base_name}[/highlight] (Score: {mal_score:.4f}). Skipping localization.", style="success")
    else:
        console.log(f"❌ [error]Malicious[/error]: [highlight]{apk_base_name}[/highlight] (Score: [bold red]{mal_score:.4f}[/bold red]). Starting localization.", style="warning")
        
        temp_dir = os.path.join(output_dir, f"tmp_{safe_apk_name}")
        os.makedirs(temp_dir, exist_ok=True)
        temp_dex_path = os.path.join(temp_dir, "classes.dex")
        with open(temp_dex_path, "wb") as f:
            f.write(dex_bytes)

        console.log("Decompiling with Baksmali...")
        smali_out_dir = os.path.join(temp_dir, 'smali')
        if not decompile_dex_baksmali(temp_dex_path, smali_out_dir, baksmali_jar):
            shutil.rmtree(temp_dir)
            if progress and task_id: progress.update(task_id, advance=1)
            return
        smali_list = get_sorted_smali_list(smali_out_dir)

        if not last_conv_layer:
            console.log("[warning]No convolutional layer found, cannot run CAM-based methods.[/warning]")
        else:
            console.log("Generating XAI heatmaps...")
            heatmap = generate_heatmap('gradcam++', model, model_in_data, last_conv_layer)
            if heatmap is not None:
                heatmap_path = os.path.join(output_dir, f"{safe_apk_name}_heatmap.png")
                cv2.imwrite(heatmap_path, heatmap)
                console.log(f"Saved heatmap to [info]{heatmap_path}[/info]")

                threshold = np.percentile(heatmap, 99)
                hot_pixels = np.argwhere(heatmap >= threshold)
                suspicious_classes = set()
                for y, x in hot_pixels:
                    orig_y = int(y * dex_img.shape[0] / heatmap.shape[0])
                    orig_x = int(x * dex_img.shape[1] / heatmap.shape[1])
                    byte_offset = pixel_to_byte_index((orig_y, orig_x), dex_img.shape)
                    cls = find_candidate_class(smali_list, byte_offset)
                    if cls: suspicious_classes.add(cls)

                console.rule(f"[bold green]Localization Report for {apk_base_name}[/bold green]")
                report_path = os.path.join(output_dir, f"report_{safe_apk_name}.txt")
                with open(report_path, 'w') as f:
                    f.write(f"Analysis Report for: {apk_path}\nMalware Score: {mal_score:.4f}\n\nSuspicious Classes:\n")
                    table = Table(title="Suspicious Classes")
                    table.add_column("Class Name", style="cyan")
                    if suspicious_classes:
                        for cls in sorted(list(suspicious_classes)):
                            table.add_row(cls); f.write(f"- {cls}\n")
                    else:
                        table.add_row("No specific classes identified in top 1% of heatmap."); f.write("None\n")
                    console.print(table)
                console.log(f"Full report saved to [info]{report_path}[/info]")
        
        shutil.rmtree(temp_dir, ignore_errors=True)

    if progress and task_id:
        progress.update(task_id, advance=1)

def scan_single_apk(apk_path: str, model: keras.Model, progress: Optional[Progress] = None, task_id=None):
    if not apk_path:
        if progress and task_id: progress.update(task_id, advance=1)
        return

    mal_score, reported_name, _, _, _ = get_prediction_and_data(apk_path, model)
    
    if progress and task_id is not None:
        progress.update(task_id, description=f"Scanning [highlight]{reported_name}[/highlight]")

    if mal_score is None:
        console.log(f"Could not process [highlight]{reported_name}[/highlight].", style="error")
    elif mal_score < 0.5:
        console.log(f" [success]Benign[/success]: [highlight]{reported_name}[/highlight] (Score: {mal_score:.4f})")
    else:
        console.log(f" [error]Malicious[/error]: [highlight]{reported_name}[/highlight] (Score: [bold red]{mal_score:.4f}[/bold red])")

    if progress and task_id is not None:
        progress.update(task_id, advance=1)

def load_model_and_find_layer(model_path: str) -> Tuple[Optional[keras.Model], Optional[str]]:
    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        tf.get_logger().setLevel('ERROR')
        model = keras.models.load_model(model_path, compile=False)
        model.compile(optimizer='adam', loss='binary_crossentropy')
        console.log(f"Model [info]'{model_path}'[/info] loaded successfully.", style="success")
    except Exception as e:
        console.log(f"Model load failed: {e}", style="error")
        return None, None
    last_conv = None
    for l in reversed(model.layers):
        if isinstance(l, (keras.layers.Conv2D)):
            last_conv = l.name; break
    if last_conv: console.log(f"Found last convolutional layer: [highlight]{last_conv}[/highlight]")
    else: console.log("Could not find a Conv2D layer in the model.", style="warning")
    return model, last_conv

# --- Typer CLI Command Definitions ---
model_option = typer.Option(..., "--model", "-m", exists=True, help="Path to the trained Keras model.")
output_dir_option = typer.Option("dexecutive_out", "--output-dir", "-o", help="Directory for reports and artifacts.")
baksmali_option = typer.Option(..., "--baksmali", "-b", exists=True, help="Path to baksmali.jar.")

@analyze_app.command("file", help="Run full localization on a single APK file.")
def analyze_file_cmd(apk_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the APK file."), model_path: pathlib.Path = model_option, baksmali_jar: pathlib.Path = baksmali_option, output_dir: pathlib.Path = output_dir_option):
    model, last_conv = load_model_and_find_layer(str(model_path))
    if not model: return
    os.makedirs(output_dir, exist_ok=True)
    process_single_apk(str(apk_path), str(output_dir), str(baksmali_jar), model, last_conv)

### NEW COMMANDS ###
@analyze_app.command("adb", help="Run full localization on a single installed package.")
def analyze_adb_cmd(package_name: str = typer.Argument(..., help="The package name (e.g., com.example.app)."), model_path: pathlib.Path = model_option, baksmali_jar: pathlib.Path = baksmali_option, output_dir: pathlib.Path = output_dir_option):
    model, last_conv = load_model_and_find_layer(str(model_path))
    if not model or not check_adb(): return
    os.makedirs(output_dir, exist_ok=True)
    dev_path = get_apk_path_from_device(package_name)
    if dev_path:
        pull_dir = os.path.join(output_dir, 'adb_pulled_apks'); os.makedirs(pull_dir, exist_ok=True)
        apk_local_path = pull_apk_from_device(dev_path, pull_dir, package_name)
        if apk_local_path:
            process_single_apk(apk_local_path, str(output_dir), str(baksmali_jar), model, last_conv)

@analyze_app.command("adb-all", help="Run full localization on ALL non-system packages on a device.")
def analyze_adb_all_cmd(model_path: pathlib.Path = model_option, baksmali_jar: pathlib.Path = baksmali_option, output_dir: pathlib.Path = output_dir_option):
    model, last_conv = load_model_and_find_layer(str(model_path))
    if not model or not check_adb(): return
    try:
        res = subprocess.run(['adb','shell','pm','list','packages', '-3'], check=True, capture_output=True, text=True)
    except Exception as e:
        console.log(f"[error]Failed to list packages: {e}[/error]"); return
    pkgs = [l.split(':',1)[1].strip() for l in res.stdout.splitlines() if l.startswith('package:')]
    pkgs_to_scan = [pkg for pkg in pkgs if not any(pkg.startswith(p) for p in IGNORE_SCAN)]
    console.log(f"Found {len(pkgs_to_scan)} third-party packages to analyze.")
    pull_dir = os.path.join(output_dir,'adb_pulled_apks'); os.makedirs(pull_dir, exist_ok=True)
    with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("{task.percentage:>3.0f}%"),TimeElapsedColumn(),console=console) as progress:
        analysis_task = progress.add_task("[blue]Analyzing packages...", total=len(pkgs_to_scan))
        for pkg in pkgs_to_scan:
            dev_path = get_apk_path_from_device(pkg)
            if not dev_path:
                progress.update(analysis_task, advance=1); continue
            apk_local = pull_apk_from_device(dev_path, pull_dir, pkg)
            if apk_local:
                process_single_apk(apk_local, str(output_dir), str(baksmali_jar), model, last_conv, progress, analysis_task)
            else:
                progress.update(analysis_task, advance=1)

# --- Scan commands ---
@scan_app.command("file", help="Quickly scan a single APK file.")
def scan_file_cmd(apk_path: pathlib.Path = typer.Argument(..., exists=True, help="Path to the APK file."), model_path: pathlib.Path = model_option, output_dir: pathlib.Path = output_dir_option):
    model, _ = load_model_and_find_layer(str(model_path))
    if not model: return
    os.makedirs(output_dir, exist_ok=True)
    scan_single_apk(str(apk_path), model)

@scan_app.command("adb-all", help="Quickly scan ALL non-system packages on a device.")
def scan_adb_all_cmd(model_path: pathlib.Path = model_option, output_dir: pathlib.Path = output_dir_option):
    model, _ = load_model_and_find_layer(str(model_path))
    if not model or not check_adb(): return
    try:
        res = subprocess.run(['adb','shell','pm','list','packages', '-3'], check=True, capture_output=True, text=True)
    except Exception as e:
        console.log(f"[error]Failed to list packages: {e}[/error]"); return
    pkgs = [l.split(':',1)[1].strip() for l in res.stdout.splitlines() if l.startswith('package:')]
    pkgs_to_scan = [pkg for pkg in pkgs if not any(pkg.startswith(p) for p in IGNORE_SCAN)]
    console.log(f"Found {len(pkgs_to_scan)} third-party packages to scan.")
    pull_dir = os.path.join(output_dir,'adb_pulled_apks'); os.makedirs(pull_dir, exist_ok=True)
    with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("{task.percentage:>3.0f}%"),TimeElapsedColumn(),console=console) as progress:
        scan_task = progress.add_task("[green]Scanning packages...", total=len(pkgs_to_scan))
        for pkg in pkgs_to_scan:
            dev_path = get_apk_path_from_device(pkg)
            if not dev_path:
                progress.update(scan_task, advance=1); continue
            apk_local = pull_apk_from_device(dev_path, pull_dir, pkg)
            scan_single_apk(apk_local, model, progress, scan_task)

def main_entry():
    f = Figlet(font='slant')
    console.print(f"[bold green]{f.renderText('dexective')}[/bold green]")
    console.print(Panel("AI-Powered Android Malware Scanner & Malicious Class Localizer", expand=False, border_style="dim"))
    app()

if __name__ == "__main__":
    main_entry()
