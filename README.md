# dexective: Visual Malware Localization & Scanning Tool

[![Demo Video](https://img.youtube.com/vi/13ysN18IwLA/0.jpg)](https://youtu.be/13ysN18IwLA)

**Watch the demo video: [https://youtu.be/13ysN18IwLA](https://youtu.be/13ysN18IwLA)**

**dexective** is a command-line tool that **classifies Android APKs as benign or malicious**, and **if malicious, localizes the exact classes responsible** using Explainable AI (XAI) techniques.

![Dexective Demo](images/dexective.gif)

![Heatmap](images/heatmap.png)

---

## 🎯 Core Functionality

1. **Malware Classification**: Transforms DEX files into grayscale images and uses a CNN to classify as **Benign** or **Malicious**
2. **Class Localization**: If malicious, applies multiple XAI methods to generate heatmaps and maps them back to specific Java/Kotlin classes

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/canoztas/dexective.git
cd dexective
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Download Pre-trained Model

Download `localize-hot-pixels.h5` from [Releases](https://github.com/canoztas/dexective/releases):

```bash
# Option 1: Direct download from GitHub Releases
# Option 2: Using wget/curl (replace v1.0.0 with actual version)
wget https://github.com/canoztas/dexective/releases/download/v1.0.0/localize-hot-pixels.h5
```

### Basic Usage

```bash
# Analyze APK and localize malicious classes
dexective analyze --apk malware.apk \
  --model localize-hot-pixels.h5 \
  --xai gradcampp,scorecam,saliency,smoothgrad,ig \
  --xai-ensemble max \
  --top-k 100 \
  --json \
  --heatmap \
  --output out/
```

---

## 📋 Prerequisites

- **Python 3.10+**
- **Java + baksmali.jar** (recommended for class mapping)
- **Keras `.h5` model** (download from [Releases](https://github.com/canoztas/dexective/releases))
- **ADB** (optional, for `adb-scan` command)

**Note**: Baksmali is **recommended** for accurate class mapping. Androguard is used as a fallback if baksmali is unavailable.

---

## 💻 Usage Examples

### Analyze Single APK

```bash
# With baksmali (recommended)
dexective analyze --apk malware.apk \
  --model localize-hot-pixels.h5 \
  --xai gradcampp,scorecam,saliency \
  --xai-ensemble max \
  --top-k 100 \
  --emit-smali \
  --baksmali baksmali-2.5.2.jar \
  --output out/

# Without baksmali (uses Androguard fallback)
dexective analyze --apk malware.apk \
  --model localize-hot-pixels.h5 \
  --xai gradcampp,saliency \
  --top-k 50 \
  --output out/
```

### Scan Android Device

```bash
dexective adb-scan \
  --model localize-hot-pixels.h5 \
  --output device_scan/ \
  --limit 30 \
  --xai gradcampp,saliency \
  --emit-smali \
  --baksmali baksmali-2.5.2.jar
```

**Key Options:**
- `--apk`: Path to APK file
- `--model`: Path to Keras model (required)
- `--xai`: XAI methods: `gradcampp`, `scorecam`, `saliency`, `smoothgrad`, `ig`
- `--top-k`: Number of top suspicious classes to report (default: 100)
- `--emit-smali`: Decompile top classes to Smali (recommended)
- `--baksmali`: Path to baksmali.jar (recommended)

---

## 🗺️ How It Works: Mapping AI Results to Code

Dexective maps XAI heatmaps back to actual classes through this pipeline:

```
XAI Heatmap → Pixel Coordinates → Byte Offsets → Class Names → Smali Code
```

### Process

1. **DEX → Image**: Convert DEX bytes to 2D grayscale image
2. **CNN Classification**: Classify as benign or malicious
3. **XAI Heatmaps**: If malicious, generate heatmaps highlighting suspicious regions
4. **Pixel → Byte**: Map heatmap pixels to DEX byte offsets
5. **Byte → Class**: Map byte offsets to class names using:
   - **Baksmali (Recommended)**: Decompiles DEX to Smali, maps offsets to classes
   - **Androguard (Fallback)**: Uses interval tree for byte-to-class mapping
6. **Score Aggregation**: Aggregate scores across methods/DEX files, select top-K classes
7. **Smali Output**: Decompile top-K classes for inspection

### Example

```
Heatmap pixel (100, 200) with value 0.95
  ↓ Byte offset = 102,600
  ↓ Class: Lcom/example/MaliciousClass;
  ↓ Score: 0.95 (ranked #1)
  ↓ Decompiled to: out/<sha256>/smali/com/example/MaliciousClass.smali
```

---

## 📂 Output

```
out/
├─ <apk_sha256>.json              # Analysis report with top-K classes
├─ <apk_sha256>_ensemble.png      # Heatmap visualization
└─ <apk_sha256>/smali/            # Decompiled Smali files (if --emit-smali)
   └─ com/example/MaliciousClass.smali
```

The JSON report includes:
- Classification result (benign/malicious with score)
- Top-K suspicious classes with scores
- DEX file information
- XAI method details

---

## 🔧 XAI Methods

- **Grad-CAM++**: Gradient-weighted Class Activation Mapping
- **Score-CAM**: Score-weighted Class Activation Mapping
- **Vanilla Saliency**: Gradient-based saliency maps
- **SmoothGrad**: Averaged saliency over noisy samples
- **Integrated Gradients**: Path-integrated gradients

All methods are combined using ensemble (max or mean) for robust localization.

---

## 📖 License

MIT
