"""JSON report generation."""
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.hashing import sha256_file
from models.loader import get_model_info


def generate_analysis_json(
    apk_path: str,
    model_path: str,
    model: Any,  # keras.Model
    apk_sha256: str,
    package_name: Optional[str],
    analyzed_dex: List[str],
    xai_methods: List[str],
    xai_ensemble: str,
    last_conv_layer: Optional[str],
    is_malicious: bool,
    prediction_score: float,
    class_scores: List[Dict[str, Any]],
    top_k: int,
    image_side: int,
    pad: bool,
    seed: Optional[int] = None
) -> Dict[str, Any]:
    """
    Generate JSON report for analysis results.
    
    Args:
        apk_path: Path to analyzed APK
        model_path: Path to model file
        model: Keras model object
        apk_sha256: SHA256 hash of APK
        package_name: Package name (if available)
        analyzed_dex: List of DEX filenames analyzed
        xai_methods: List of XAI methods used
        xai_ensemble: Ensemble method ("max", "none", etc.)
        last_conv_layer: Name of last convolutional layer
        is_malicious: Whether APK is classified as malicious
        prediction_score: Malware prediction score (0-1)
        class_scores: List of class score dicts with "class", "score", "dex" keys
        top_k: Number of top classes included
        image_side: Image side length used
        pad: Whether padding was used
        seed: Random seed (if used)
        
    Returns:
        Dictionary ready for JSON serialization
    """
    model_info = get_model_info(model, model_path)
    model_sha256 = sha256_file(model_path) or "unknown"
    
    # Sort classes by score descending and ensure uniqueness
    unique_classes = {}
    for cls_info in class_scores:
        class_name = cls_info["class"]
        if class_name not in unique_classes or cls_info["score"] > unique_classes[class_name]["score"]:
            unique_classes[class_name] = cls_info
    
    sorted_classes = sorted(
        unique_classes.values(),
        key=lambda x: x["score"],
        reverse=True
    )[:top_k]
    
    return {
        "tool": {
            "name": "dexective",
            "version": "1.0.0"
        },
        "model": {
            "path": model_path,
            "hash": model_sha256,
            "input_shape": model_info.get("input_shape", [])
        },
        "apk": {
            "path": apk_path,
            "sha256": apk_sha256,
            "package": package_name,
            "analyzed_dex": analyzed_dex
        },
        "xai": {
            "methods": xai_methods,
            "ensemble": xai_ensemble,
            "last_conv_layer": last_conv_layer
        },
        "prediction": {
            "is_malicious": is_malicious,
            "score": float(prediction_score)
        },
        "classes": sorted_classes,
        "top_k": top_k,
        "generated": datetime.utcnow().isoformat() + "Z",
        "provenance": {
            "seed": seed,
            "image_side": image_side,
            "pad": pad
        }
    }


def save_json_report(report: Dict[str, Any], output_path: str) -> None:
    """
    Save JSON report to file.
    
    Args:
        report: Report dictionary
        output_path: Path to save JSON file
    """
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)


def generate_adb_scan_summary(
    results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate summary JSON for ADB scan.
    
    Args:
        results: List of analysis results, each with keys:
                 package, apk_sha256, is_malicious, top_classes (list of dicts)
        
    Returns:
        Summary dictionary
    """
    return {
        "tool": {
            "name": "dexective",
            "version": "1.0.0"
        },
        "scan_type": "adb_scan",
        "total_apps": len(results),
        "malicious_count": sum(1 for r in results if r.get("is_malicious", False)),
        "generated": datetime.utcnow().isoformat() + "Z",
        "apps": [
            {
                "package": r.get("package", "unknown"),
                "apk_sha256": r.get("apk_sha256", "unknown"),
                "is_malicious": r.get("is_malicious", False),
                "prediction_score": r.get("prediction_score", 0.0),
                "top_classes": r.get("top_classes", [])[:5]  # Top 5 classes
            }
            for r in results
        ]
    }

