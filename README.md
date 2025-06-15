Dexective: Visual Malware Localization & Scanning Tool

Dexective is a command-line tool for analyzing Android applications (.apk files). It operates in two modes: a scan mode for rapid classification and a deep analyze mode to identify and finely localize potentially malicious code.

It transforms the app’s classes.dex into a grayscale image, classifies it with a CNN, and, for malicious samples in analyze mode, applies an ensemble of Explainable AI (XAI) techniques to pinpoint the exact Smali classes responsible.

DEX → Image: Convert classes.dex bytes into a 2D grayscale image.

CNN Classification: A pre-trained model labels the image as Benign or Malicious. This is the final step for the scan mode.

XAI Localization (Analyze Mode): If malicious, run XAI methods (e.g., Grad-CAM++) to generate heatmaps identifying critical regions.

Heatmap → Smali (Analyze Mode): Map the “hot” pixels from the heatmaps back to the specific Smali classes responsible for the malicious prediction.

Figure: Dexective identifies suspicious regions on the DEX–image.

Figure: Highlighted Smali classes in the code window.

🚀 Features

Dual-Mode Operation

scan: For rapid Benign/Malicious classification of many apps.

analyze: For deep, fine-grained localization of malicious classes using XAI.

Static-Only: No need to execute the APK; pure static analysis.

Deep Learning Classification: High-accuracy CNN model for DEX–image analysis.

Modern CLI: User-friendly interface with richly formatted tables, progress bars, and color-coded output powered by Typer and Rich.

Flexible Input Modes: Analyze apps from a local file, a single installed adb package, or adb-all for every third-party app on a device.

XAI-Powered Localization: Uses Grad-CAM++ to pinpoint exact Smali classes, not just the APK.

Rich Reports: Generates text-based summaries and PNG heatmaps for each malicious app analyzed.

📋 Prerequisites

Python 3.8+

Android Debug Bridge (ADB) (for adb and adb-all modes)

Java JRE (only required for the analyze command)

A pre-trained Keras .h5 model for DEX–image classification

baksmali.jar for Smali decompilation (only required for the analyze command)

Key Python libraries (install via pip install -r requirements.txt):

tensorflow

tf-keras-vis

typer & rich

opencv-python

scikit-learn, matplotlib, pyfiglet

androguard (optional, for advanced mapping)

📥 Installation

git clone https://github.com/your-username/dexective.git
cd dexective
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Place your model.h5 and baksmali.jar in the repo root or a folder of your choice.

💻 Usage

Dexective is run using two main sub-commands: scan for quick checks and analyze for deep localization.

1️⃣ Quick Scanning (Fast Classification)

This mode quickly determines if an APK is benign or malicious without performing localization. It does not require baksmali.jar.

Scan a local file:

python dexecutive.py scan file \
  --model path/to/model.h5 \
  /path/to/sample.apk

Scan all apps on a connected device:

python dexecutive.py scan adb-all \
  --model path/to/model.h5 \
  --output-dir ./scan_results

Output is printed directly to the console.

2️⃣ Full Analysis (XAI Localization)

This mode performs localization on malicious samples. It requires the --baksmali argument.

Analyze a local file:

python dexecutive.py analyze file \
  --model path/to/model.h5 \
  --baksmali path/to/baksmali.jar \
  --output-dir ./analysis_results \
  /path/to/malicious_sample.apk

Analyze all apps on a connected device:

python dexexecutive.py analyze adb-all \
  --model path/to/model.h5 \
  --baksmali path/to/baksmali.jar \
  --output-dir ./analysis_results

📂 Output Structure (Analyze Mode)

For each malicious APK found, the analyze command’s output directory contains:

analysis_results/
├─ adb_pulled_apks/
│  └─ com.malicious.app.apk
├─ report_com.malicious.app.txt      # Ranked list of suspicious classes
└─ com.malicious.app_heatmap.png     # Grad-CAM++ heatmap image

📖 License

MIT
