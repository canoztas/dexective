# Dexective: Visual Malware Localization Tool

**Dexective** is a command-line tool for analyzing Android applications (`.apk` files) to identify—and finely localize—potentially malicious code. It transforms the app’s `classes.dex` into a grayscale image, classifies it with a CNN, and, for malicious samples, applies an ensemble of Explainable AI (XAI) techniques to pinpoint the exact Smali classes responsible.

<details>
<summary>📷 Workflow Overview</summary>

1. **DEX → Image**: Convert `classes.dex` bytes into a 2D grayscale image.  
2. **CNN Classification**: Pre-trained model labels it **Benign** or **Malicious**.  
3. **XAI Localization**: If malicious, run multiple XAI methods (Grad-CAM++, ScoreCAM, Integrated Gradients, etc.) to generate heatmaps.  
4. **Heatmap → Smali**: Map hot pixels back to Smali classes via byte‑offset resolution and (optionally) DBSCAN clustering.

![Detection Heatmap](images/detection_heatmap.png)  
*Figure: Dexective identifies suspicious regions on the DEX–image.*

![Localization Example](images/localization_example.png)  
*Figure: Highlighted Smali classes in the code window.*
</details>

---

## 🚀 Features

- **Static-Only**: No need to execute the APK; pure static analysis.  
- **Deep Learning**: High-accuracy CNN classification on DEX–images.  
- **Fine-Grained Localization**: Pinpoint exact Smali classes, not just the APK.  
- **XAI Ensemble**: Combine Grad-CAM++, ScoreCAM, Integrated Gradients, SmoothGrad, and more.  
- **Flexible Input Modes**:  
  - `file`: Analyze a local `.apk` file.  
  - `adb`: Pull & analyze one installed package via ADB.  
  - `adb-all`: Pull & analyze *all* installed packages on a connected device.  
- **Per-Family Tuning**: Custom thresholds & methods for known malware families.  
- **Rich Reports**: Text-based summaries and PNG heatmaps for each XAI method.

---

## 📋 Prerequisites

- **Python 3.8+**  
- **Java JRE** (for `baksmali.jar`)  
- **Android Debug Bridge (ADB)** (for `adb` modes)  
- **TensorFlow 2.x** and **tf-keras-vis**  
- **OpenCV** (`opencv-python`)  
- **scikit-learn**, **matplotlib**, **androguard**  
- A pre-trained Keras `.h5` model for DEX–image classification.  
- `baksmali.jar` for Smali decompilation.

---

## 📥 Installation

```bash
git clone https://github.com/canoztas/dexective.git
cd dexective
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Place your `model.h5` and `baksmali.jar` in a folder of your choice (or the repo root).

---

## 💻 Usage

Run `dexective.py` with one of three modes:

### 1️⃣ Local File Mode
```bash
python dexective.py file \
  --model path/to/model.h5 \
  --baksmali path/to/baksmali.jar \
  --output-dir ./results \
  /path/to/sample.apk
```

### 2️⃣ Single-APK via ADB
```bash
python dexective.py adb \
  --model path/to/model.h5 \
  --baksmali path/to/baksmali.jar \
  --output-dir ./results \
  com.example.app
```

### 3️⃣ All-APK via ADB-All
```bash
python dexective.py adb-all \
  --model path/to/model.h5 \
  --baksmali path/to/baksmali.jar \
  --output-dir ./results
```

**Common Options:**
- `--methods`: Override XAI methods (choices: `gradcam`, `gradcam++`, `scorecam`, `vanilla_saliency`, `smoothgrad`, `integrated_gradients`).  

---

## 📂 Output Structure

For each malicious APK, `results/` will contain:

- `report_<apk_name>.txt`: Ranked list of suspicious classes + method counts + scores.  
- `<apk_name>_<method>_heatmap.png`: Heatmaps per XAI method.  

Example:
```
results/
├─ report_sample.txt
├─ sample_gradcam++_heatmap.png
├─ sample_scorecam_heatmap.png
└─ sample_integrated_gradients_heatmap.png
```

---

## ⚙️ Per‑Family Configuration

Located in `dexective.py > FAMILY_PARAMS_CONFIG`. If an APK’s path includes a known family key (e.g. `agent.aax/`), those thresholds & methods apply; otherwise the `default` config is used. CLI `--methods` always overrides.

---

## 📖 License

[MIT](LICENSE)
