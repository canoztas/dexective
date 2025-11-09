#!/usr/bin/env python3
"""Main CLI entry point for dexective."""
import os
import sys
from pathlib import Path
from typing import List, Optional
import numpy as np
import cv2
from collections import defaultdict

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.theme import Theme
from pyfiglet import Figlet

# Import our modules - add parent directory to path
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from models.loader import load_keras_model, find_last_conv_layer, get_model_input_shape
from dex.apk_reader import extract_dex_files, get_apk_package_name
from dex.mapping import PixelMap, ClassMapper, compute_class_scores
from dex.baksmali import decompile_top_classes, check_baksmali_available
from utils.images import bytes_to_image, prepare_model_input
from utils.hashing import sha256_file, sha256_bytes
from utils.io import ensure_dir, get_temp_dir, cleanup_temp_dir, safe_filename
from xai.gradcampp import gradcampp
from xai.scorecam import scorecam
from xai.saliency import vanilla_saliency
from xai.smoothgrad import smoothgrad
from xai.integrated_gradients import integrated_gradients
from xai.ensemble import ensemble_max
from reports.json_reporter import generate_analysis_json, save_json_report, generate_adb_scan_summary
from adb.device import check_adb_available, check_device_connected, list_packages
from adb.pull import pull_apk

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Setup Rich console
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "highlight": "bold magenta",
})
console = Console(record=True, theme=custom_theme)

app = typer.Typer(
    name="dexective",
    help="AI-Powered Android Malware Scanner & Malicious Class Localizer",
    rich_markup_mode="markdown",
    no_args_is_help=True
)


def analyze_apk(
    apk_path: str,
    model: any,
    model_path: str,
    last_conv_layer: Optional[str],
    xai_methods: List[str],
    xai_ensemble: str,
    threshold: float,
    top_k: int,
    output_dir: str,
    save_heatmap: bool,
    save_per_method: bool = False,
    emit_smali: bool = False,
    baksmali_jar: Optional[str] = None
) -> Optional[dict]:
    """
    Analyze a single APK with multi-DEX support.
    
    Returns:
        Dictionary with analysis results, or None on failure
    """
    temp_dir = get_temp_dir()
    
    try:
        # Extract DEX files
        dex_files = extract_dex_files(apk_path, temp_dir)
        if not dex_files:
            console.log(f"No DEX files found in {apk_path}", style="error")
            return None
        
        # Get APK metadata
        apk_sha256 = sha256_file(apk_path) or "unknown"
        package_name = get_apk_package_name(apk_path)
        analyzed_dex = [f[0] for f in dex_files]  # DEX filenames
        
        # Process each DEX
        all_class_scores = defaultdict(lambda: {"score": 0.0, "dex": None})
        all_heatmaps = []
        per_dex_heatmaps = []  # Store heatmaps per DEX for ensemble
        model_input_shape = get_model_input_shape(model)
        prediction = 0.0
        is_malicious = False
        first_dex_bytes = None
        
        # First pass: get prediction from first DEX
        if dex_files:
            first_dex_path = dex_files[0][1]
            with open(first_dex_path, 'rb') as f:
                first_dex_bytes = f.read()
            first_dex_image, _ = bytes_to_image(first_dex_bytes)
            if first_dex_image is not None:
                first_model_input = prepare_model_input(first_dex_image, model.input_shape)
                prediction = float(model.predict(first_model_input, verbose=0)[0, 0])
                is_malicious = prediction >= threshold
        
        # Second pass: generate XAI heatmaps for all DEX files if malicious
        if is_malicious and last_conv_layer:
            for dex_filename, dex_path in dex_files:
                # Read DEX bytes
                with open(dex_path, 'rb') as f:
                    dex_bytes = f.read()
                
                # Convert to image
                dex_image, original_length = bytes_to_image(dex_bytes)
                if dex_image is None:
                    continue
                
                # Prepare model input
                model_input = prepare_model_input(dex_image, model.input_shape)
                
                pixel_map = PixelMap(dex_bytes, dex_filename)
                class_mapper = ClassMapper(dex_path, dex_bytes, dex_filename)
                
                dex_method_heatmaps = {}
                
                for method in xai_methods:
                    heatmap = None
                    
                    if method == "gradcampp":
                        heatmap = gradcampp(model, model_input, last_conv_layer)
                    elif method == "scorecam":
                        heatmap = scorecam(model, model_input, last_conv_layer)
                    elif method == "saliency":
                        heatmap = vanilla_saliency(model, model_input)
                    elif method == "smoothgrad":
                        heatmap = smoothgrad(model, model_input)
                    elif method == "ig":
                        heatmap = integrated_gradients(model, model_input)
                    
                    if heatmap is not None:
                        dex_method_heatmaps[method] = heatmap
                        all_heatmaps.append(heatmap)
                        
                        # Compute class scores for this method
                        class_scores = compute_class_scores(
                            heatmap, pixel_map, class_mapper, dex_filename
                        )
                        
                        # Aggregate across methods and DEX files (max)
                        for class_name, score in class_scores.items():
                            if score > all_class_scores[class_name]["score"]:
                                all_class_scores[class_name] = {
                                    "score": score,
                                    "dex": dex_filename
                                }
                
                per_dex_heatmaps.append((dex_filename, dex_method_heatmaps, pixel_map, class_mapper))
            
            # Create ensemble if requested (after processing all DEX files)
            if xai_ensemble == "max" and all_heatmaps:
                ensemble_heatmap = ensemble_max(all_heatmaps)
                if ensemble_heatmap is not None:
                    # Recompute class scores from ensemble for each DEX and take max
                    for dex_filename, _, pixel_map, class_mapper in per_dex_heatmaps:
                        # Resize ensemble to match this DEX's image size
                        ensemble_resized = cv2.resize(
                            ensemble_heatmap,
                            (pixel_map.S, pixel_map.S),
                            interpolation=cv2.INTER_LINEAR
                        )
                        ensemble_scores = compute_class_scores(
                            ensemble_resized, pixel_map, class_mapper, dex_filename
                        )
                        for class_name, score in ensemble_scores.items():
                            if score > all_class_scores[class_name]["score"]:
                                all_class_scores[class_name] = {
                                    "score": score,
                                    "dex": dex_filename
                                }
        
        # Format class scores for JSON
        class_score_list = [
            {
                "class": class_name,
                "score": float(info["score"]),
                "dex": info["dex"]
            }
            for class_name, info in all_class_scores.items()
        ]
        
        # Sort by score descending and take top-K
        class_score_list.sort(key=lambda x: x["score"], reverse=True)
        class_score_list = class_score_list[:top_k]
        
        # Decompile top classes with baksmali if requested
        class_to_smali = {}
        if emit_smali and baksmali_jar:
            if not check_baksmali_available(baksmali_jar):
                console.log("Baksmali is not available. Please ensure Java is installed and baksmali.jar exists.", style="error")
            else:
                console.log(f"Decompiling top {len(class_score_list)} classes with baksmali...")
                smali_output_dir = os.path.join(output_dir, apk_sha256, "smali")
                ensure_dir(smali_output_dir)
                
                # Group classes by DEX file
                dex_to_classes = {}
                for cls_info in class_score_list:
                    dex_name = cls_info["dex"]
                    if dex_name not in dex_to_classes:
                        dex_to_classes[dex_name] = []
                    dex_to_classes[dex_name].append(cls_info["class"])
                
                # Decompile classes from each DEX
                for dex_filename, dex_path in dex_files:
                    if dex_filename in dex_to_classes:
                        classes_to_decompile = dex_to_classes[dex_filename]
                        smali_map = decompile_top_classes(
                            dex_path,
                            classes_to_decompile,
                            smali_output_dir,
                            baksmali_jar
                        )
                        class_to_smali.update(smali_map)
                
                # Add smali paths to class_score_list
                for cls_info in class_score_list:
                    class_desc = cls_info["class"]
                    if class_desc in class_to_smali:
                        # Make path relative to output_dir
                        smali_path = class_to_smali[class_desc]
                        rel_path = os.path.relpath(smali_path, output_dir)
                        cls_info["smali"] = rel_path
        
        # Generate JSON report
        report = generate_analysis_json(
            apk_path=apk_path,
            model_path=model_path,
            model=model,
            apk_sha256=apk_sha256,
            package_name=package_name,
            analyzed_dex=analyzed_dex,
            xai_methods=xai_methods,
            xai_ensemble=xai_ensemble,
            last_conv_layer=last_conv_layer,
            is_malicious=is_malicious,
            prediction_score=prediction,
            class_scores=class_score_list,
            top_k=top_k,
            image_side=int(np.ceil(np.sqrt(len(first_dex_bytes)))) if first_dex_bytes else 0,
            pad=True,
            seed=None
        )
        
        # Save JSON
        json_path = os.path.join(output_dir, f"{apk_sha256}.json")
        save_json_report(report, json_path)
        console.log(f"Saved JSON report to [info]{json_path}[/info]")
        
        # Save heatmap if requested
        if save_heatmap and all_heatmaps:
            if xai_ensemble == "max":
                ensemble_hm = ensemble_max(all_heatmaps)
                if ensemble_hm is not None:
                    heatmap_path = os.path.join(output_dir, f"{apk_sha256}_ensemble.png")
                    cv2.imwrite(heatmap_path, (ensemble_hm * 255).astype(np.uint8))
                    console.log(f"Saved ensemble heatmap to [info]{heatmap_path}[/info]")
            
            if save_per_method:
                heatmap_dir = os.path.join(output_dir, "heatmaps", apk_sha256)
                ensure_dir(heatmap_dir)
                # This would require storing method_heatmaps per DEX, simplified here
                console.log(f"Per-method heatmaps would be saved to [info]{heatmap_dir}[/info]")
        
        return {
            "package": package_name,
            "apk_sha256": apk_sha256,
            "is_malicious": is_malicious,
            "prediction_score": prediction,
            "top_classes": class_score_list[:5]
        }
    
    finally:
        cleanup_temp_dir(temp_dir)


@app.command("analyze")
def analyze_cmd(
    apk: Path = typer.Argument(..., exists=True, help="Path to APK file"),
    model: Path = typer.Option(..., "--model", "-m", exists=True, help="Path to Keras model"),
    output: Path = typer.Option("out", "--output", "-o", help="Output directory"),
    xai: str = typer.Option("gradcampp", "--xai", help="Comma-separated XAI methods: gradcampp,scorecam,saliency,smoothgrad,ig"),
    xai_ensemble: str = typer.Option("max", "--xai-ensemble", help="Ensemble method: max or none"),
    last_conv_layer: Optional[str] = typer.Option(None, "--last-conv-layer", help="Override last conv layer name"),
    threshold: float = typer.Option(0.5, "--threshold", help="Malware threshold"),
    top_k: int = typer.Option(100, "--top-k", help="Number of top classes to include"),
    heatmap: bool = typer.Option(False, "--heatmap", help="Save heatmap PNG"),
    json: bool = typer.Option(True, "--json/--no-json", help="Save JSON report"),
    emit_smali: bool = typer.Option(False, "--emit-smali", help="Decompile top classes to Smali (requires --baksmali)"),
    baksmali: Optional[Path] = typer.Option(None, "--baksmali", help="Path to baksmali.jar (required for --emit-smali)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Analyze a single APK file."""
    # Parse XAI methods
    xai_methods = [m.strip().lower() for m in xai.split(",") if m.strip()]
    
    # Load model
    console.log(f"Loading model from [info]{model}[/info]...")
    keras_model = load_keras_model(str(model), compile=True)
    if not keras_model:
        console.log("Failed to load model", style="error")
        raise typer.Exit(1)
    
    # Find last conv layer
    if not last_conv_layer:
        last_conv_layer = find_last_conv_layer(keras_model)
        if not last_conv_layer:
            console.log("No convolutional layer found. XAI methods may not work.", style="warning")
    
    # Validate baksmali options
    if emit_smali and not baksmali:
        console.log("--emit-smali requires --baksmali. Please provide path to baksmali.jar.", style="error")
        raise typer.Exit(1)
    
    if emit_smali and baksmali and not baksmali.exists():
        console.log(f"Baksmali jar not found: {baksmali}", style="error")
        raise typer.Exit(1)
    
    # Create output directory
    ensure_dir(str(output))
    
    # Analyze
    result = analyze_apk(
        apk_path=str(apk),
        model=keras_model,
        model_path=str(model),
        last_conv_layer=last_conv_layer,
        xai_methods=xai_methods,
        xai_ensemble=xai_ensemble,
        threshold=threshold,
        top_k=top_k,
        output_dir=str(output),
        save_heatmap=heatmap,
        save_per_method=False,
        emit_smali=emit_smali,
        baksmali_jar=str(baksmali) if baksmali else None
    )
    
    if result:
        if result["is_malicious"]:
            console.log(f"❌ [error]Malicious[/error]: {apk.name} (Score: {result['prediction_score']:.4f})", style="error")
        else:
            console.log(f"✔️ [success]Benign[/success]: {apk.name} (Score: {result['prediction_score']:.4f})", style="success")
    else:
        console.log("Analysis failed", style="error")
        raise typer.Exit(1)


@app.command("adb-scan")
def adb_scan_cmd(
    output: Path = typer.Option("out", "--output", "-o", help="Output directory"),
    model: Path = typer.Option(..., "--model", "-m", exists=True, help="Path to Keras model"),
    include_system: bool = typer.Option(False, "--include-system", help="Include system packages"),
    limit: Optional[int] = typer.Option(None, "--limit", help="Limit number of apps to scan"),
    xai: str = typer.Option("gradcampp", "--xai", help="Comma-separated XAI methods"),
    xai_ensemble: str = typer.Option("max", "--xai-ensemble", help="Ensemble method"),
    last_conv_layer: Optional[str] = typer.Option(None, "--last-conv-layer", help="Override last conv layer"),
    threshold: float = typer.Option(0.5, "--threshold", help="Malware threshold"),
    top_k: int = typer.Option(100, "--top-k", help="Number of top classes"),
    heatmap: bool = typer.Option(False, "--heatmap", help="Save heatmaps"),
    emit_smali: bool = typer.Option(False, "--emit-smali", help="Decompile top classes to Smali (requires --baksmali)"),
    baksmali: Optional[Path] = typer.Option(None, "--baksmali", help="Path to baksmali.jar (required for --emit-smali)"),
    workers: int = typer.Option(1, "--workers", help="Number of parallel workers"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """Scan all apps on connected Android device."""
    # Check ADB
    if not check_adb_available():
        console.log("ADB is not available. Please install Android Debug Bridge.", style="error")
        raise typer.Exit(1)
    
    if not check_device_connected():
        console.log("No Android device connected. Please connect a device via ADB.", style="error")
        raise typer.Exit(1)
    
    # Load model
    console.log(f"Loading model from [info]{model}[/info]...")
    keras_model = load_keras_model(str(model), compile=True)
    if not keras_model:
        console.log("Failed to load model", style="error")
        raise typer.Exit(1)
    
    # Find last conv layer
    if not last_conv_layer:
        last_conv_layer = find_last_conv_layer(keras_model)
    
    # Parse XAI methods
    xai_methods = [m.strip().lower() for m in xai.split(",") if m.strip()]
    
    # List packages
    console.log("Listing packages...")
    packages = list_packages(include_system=include_system)
    
    if limit:
        packages = packages[:limit]
    
    console.log(f"Found [highlight]{len(packages)}[/highlight] packages to scan")
    
    # Create output directory
    ensure_dir(str(output))
    pull_dir = os.path.join(str(output), "adb_pulled_apks")
    ensure_dir(pull_dir)
    
    # Process packages
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[blue]Scanning packages...", total=len(packages))
        
        for package_name, device_path in packages:
            progress.update(task, description=f"Scanning [highlight]{package_name}[/highlight]")
            
            # Pull APK
            apk_path = pull_apk(device_path, pull_dir, package_name)
            if not apk_path:
                progress.update(task, advance=1)
                continue
            
            # Validate baksmali options
            if emit_smali and not baksmali:
                console.log("--emit-smali requires --baksmali. Skipping smali decompilation.", style="warning")
                emit_smali = False
            
            # Analyze
            result = analyze_apk(
                apk_path=apk_path,
                model=keras_model,
                model_path=str(model),
                last_conv_layer=last_conv_layer,
                xai_methods=xai_methods,
                xai_ensemble=xai_ensemble,
                threshold=threshold,
                top_k=top_k,
                output_dir=str(output),
                save_heatmap=heatmap,
                save_per_method=False,
                emit_smali=emit_smali,
                baksmali_jar=str(baksmali) if baksmali and baksmali.exists() else None
            )
            
            if result:
                results.append(result)
            
            progress.update(task, advance=1)
    
    # Generate summary
    summary = generate_adb_scan_summary(results)
    summary_path = os.path.join(str(output), "adb_scan_summary.json")
    save_json_report(summary, summary_path)
    console.log(f"Saved scan summary to [info]{summary_path}[/info]")
    
    console.log(f"\n[success]Scan complete![/success]")
    console.log(f"  Total apps: {len(results)}")
    console.log(f"  Malicious: {summary['malicious_count']}")


def main():
    """Main entry point."""
    f = Figlet(font='slant')
    console.print(f"[bold green]{f.renderText('dexective')}[/bold green]")
    console.print(Panel("AI-Powered Android Malware Scanner & Malicious Class Localizer", expand=False, border_style="dim"))
    app()


if __name__ == "__main__":
    main()

