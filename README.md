# dexective: Visual Malware Localization & Scanning Tool
[![Demo Video](images/dexective.png)](https://www.youtube.com/watch?v=13ysN18IwLA)


**dexective** is a command-line tool for analyzing Android applications (`.apk` files). It transforms DEX files into grayscale images, classifies them with a CNN, and—if malicious—applies multiple Explainable AI (XAI) techniques to pinpoint the exact classes responsible.

![Dexective Demo](images/dexective.gif)

![Heatmap](images/heatmap.png)
---

## 📷 Workflow Overview

<details>
<summary>Click to expand</summary>

1. **Multi-DEX Extraction**  
   Extract all `classes*.dex` files from the APK (classes.dex, classes2.dex, etc.)

2. **DEX → Image**  
   Convert each DEX file's bytes into a 2D grayscale image using deterministic mapping.

3. **CNN Classification**  
   Classify the DEX image as **Benign** or **Malicious**.

4. **XAI Localization**  
   If malicious, run multiple XAI methods (Grad-CAM++, Score-CAM, Saliency, SmoothGrad, Integrated Gradients) to generate heatmaps highlighting suspicious regions.

5. **Pixel → Byte → Class Mapping**  
   Map "hot" pixels back to byte offsets, then to specific Java classes using Androguard.

![Detection Heatmap](images/dex_image.png)  
*Figure: DEX image by Dexective.*

![Detection Heatmap](images/detection_heatmap.png)  
*Figure: Hotspots on the DEX image detected by Dexective.*

</details>

---

## 🚀 Features

- **Multi-DEX Support**: Automatically handles APKs with multiple DEX files
- **Multiple XAI Methods**: 
  - Grad-CAM++
  - Score-CAM
  - Vanilla Saliency
  - SmoothGrad
  - Integrated Gradients
- **Ensemble Methods**: Combine multiple XAI heatmaps (max, mean)
- **Androguard-Based Mapping**: Precise pixel-to-class mapping using byte offset intervals
- **ADB Device Scanning**: Scan all apps on a connected Android device
- **JSON Output**: Structured JSON reports with full analysis results
- **Rich CLI**: Beautiful progress bars and colorized output

---

## 📋 Prerequisites

- **Python 3.10+**
- **ADB** (for `adb-scan` command) - must be on PATH
- **Keras `.h5` model** for classification
- **Java + baksmali.jar** (optional, only required for `--emit-smali`)

Install dependencies:

```bash
pip install -r requirements.txt
```

Key libraries:
- `tensorflow`, `tf-keras-vis`
- `typer`, `rich`, `pyfiglet`
- `opencv-python`, `numpy`
- `androguard`, `intervaltree`
- `tqdm`

**Note**: Baksmali is **optional** and only needed if you want to decompile classes to Smali format. The default class mapping uses Androguard and works without Java/baksmali.

---

## 📥 Installation

```bash
git clone https://github.com/canoztas/dexective.git
cd dexective
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 💻 Usage

### Analyze a Single APK

```bash
# Basic analysis (no baksmali required)
dexective analyze --apk samples/malware.apk \
  --model /path/to/model.h5 \
  --xai gradcampp,scorecam,saliency,smoothgrad,ig \
  --xai-ensemble max \
  --top-k 100 \
  --json \
  --heatmap \
  --output out/

# With Smali decompilation (requires baksmali)
dexective analyze --apk samples/malware.apk \
  --model /path/to/model.h5 \
  --xai gradcampp,saliency \
  --xai-ensemble max \
  --top-k 50 \
  --emit-smali \
  --baksmali /path/to/baksmali.jar \
  --output out/
```

**Options:**
- `--apk`: Path to APK file (required)
- `--model`: Path to Keras model file (required)
- `--output`: Output directory (default: `out`)
- `--xai`: Comma-separated XAI methods: `gradcampp`, `scorecam`, `saliency`, `smoothgrad`, `ig` (default: `gradcampp`)
- `--xai-ensemble`: Ensemble method: `max` or `none` (default: `max`)
- `--last-conv-layer`: Override automatic last conv layer detection
- `--threshold`: Malware threshold (default: 0.5)
- `--top-k`: Number of top classes to include in JSON (default: 100)
- `--heatmap`: Save heatmap PNG files
- `--json`: Save JSON report (default: enabled)
- `--emit-smali`: Decompile top classes to Smali format (requires `--baksmali`)
- `--baksmali`: Path to baksmali.jar (required for `--emit-smali`)
- `--verbose`: Verbose output

### Scan All Apps on Android Device

```bash
# Basic scan (no baksmali required)
dexective adb-scan \
  --model /path/to/model.h5 \
  --output device_scan/ \
  --limit 30 \
  --xai gradcampp,saliency \
  --xai-ensemble max \
  --heatmap

# With Smali decompilation
dexective adb-scan \
  --model /path/to/model.h5 \
  --output device_scan/ \
  --limit 20 \
  --xai scorecam \
  --xai-ensemble max \
  --emit-smali \
  --baksmali /path/to/baksmali.jar
```

**Options:**
- `--model`: Path to Keras model file (required)
- `--output`: Output directory (default: `out`)
- `--include-system`: Include system packages (default: third-party only)
- `--limit`: Limit number of apps to scan
- `--xai`: Comma-separated XAI methods
- `--xai-ensemble`: Ensemble method
- `--threshold`: Malware threshold (default: 0.5)
- `--top-k`: Number of top classes (default: 100)
- `--heatmap`: Save heatmap PNG files
- `--emit-smali`: Decompile top classes to Smali format (requires `--baksmali`)
- `--baksmali`: Path to baksmali.jar (required for `--emit-smali`)
- `--workers`: Number of parallel workers (default: 1)
- `--verbose`: Verbose output

---

## 📂 Output Structure

### Single APK Analysis

```
out/
├─ <apk_sha256>.json              # Full analysis report
├─ <apk_sha256>_ensemble.png      # Ensemble heatmap (if --heatmap)
├─ <apk_sha256>/                   # Directory (if --emit-smali)
│  └─ smali/                       # Decompiled Smali files
│     └─ com/example/
│        └─ MaliciousClass.smali
└─ heatmaps/                       # Per-method heatmaps (if enabled)
   └─ <apk_sha256>/
      ├─ gradcampp.png
      ├─ scorecam.png
      └─ ...
```

### ADB Scan

```
device_scan/
├─ adb_pulled_apks/               # Pulled APK files
│  ├─ com.example.app.apk
│  └─ ...
├─ adb_scan_summary.json          # Summary of all scanned apps
├─ <sha2561>.json                 # Individual app reports
├─ <sha2562>.json
└─ ...
```

---

## 📄 JSON Output Schema

```json
{
  "tool": {
    "name": "dexective",
    "version": "1.0.0"
  },
  "model": {
    "path": "/path/to/model.h5",
    "hash": "<sha256>",
    "input_shape": [224, 224, 1]
  },
  "apk": {
    "path": "/path/to/app.apk",
    "sha256": "<sha256>",
    "package": "com.example.app",
    "analyzed_dex": ["classes.dex", "classes2.dex"]
  },
  "xai": {
    "methods": ["gradcampp", "scorecam", "saliency"],
    "ensemble": "max",
    "last_conv_layer": "conv2d_5"
  },
  "prediction": {
    "is_malicious": true,
    "score": 0.87
  },
  "classes": [
      {
        "class": "Lcom/example/MaliciousClass;",
        "score": 0.93,
        "dex": "classes2.dex",
        "smali": "<apk_sha>/smali/com/example/MaliciousClass.smali"
      },
    {
      "class": "Lcom/example/SuspiciousClass;",
      "score": 0.88,
      "dex": "classes.dex"
    }
  ],
  "top_k": 100,
  "generated": "2024-01-15T10:30:00Z",
  "provenance": {
    "seed": null,
    "image_side": 1024,
    "pad": true
  }
}
```

---

## 🔧 XAI Methods

- **Grad-CAM++**: Gradient-weighted Class Activation Mapping with improved localization
- **Score-CAM**: Score-weighted Class Activation Mapping using forward passes
- **Vanilla Saliency**: Gradient of target class w.r.t. input
- **SmoothGrad**: Averaged saliency over noisy samples (default: 25 samples, σ=0.1)
- **Integrated Gradients**: Path-integrated gradients from baseline to input (default: 50 steps)

All heatmaps are normalized to [0, 1] range. The ensemble method takes the pixel-wise maximum (or mean) across selected methods.

---

## 🗺️ Class Mapping

Dexective uses **Androguard** (default) to build interval trees mapping byte offsets to class names:

1. For each DEX file, extract class data and method code item byte ranges
2. Build an interval tree for fast offset-to-class lookup
3. For each "hot" pixel in the heatmap:
   - Map pixel (r, c) → byte offset
   - Query interval tree → class name
4. Aggregate scores across DEX files using maximum per class

**Baksmali is optional** and only used when `--emit-smali` is specified. When enabled, it decompiles only the top-K classes to Smali format for human-readable inspection. The default class mapping works entirely with Androguard and requires no Java/baksmali dependency.

If Androguard is unavailable, a fallback implementation is used (with reduced accuracy).

---

## ⚙️ Configuration

### Model Requirements

- Input: Grayscale image (will be resized to model's expected input shape)
- Output: Single sigmoid output (malware probability)
- Architecture: Must contain at least one convolutional layer for XAI methods

### Performance Tips

- Use `--limit` when scanning many apps
- Score-CAM can be slow with many feature maps; it automatically samples up to 128 maps
- SmoothGrad uses 25 samples by default; reduce for faster processing
- Integrated Gradients uses 50 steps by default

---

## 📖 License

MIT
