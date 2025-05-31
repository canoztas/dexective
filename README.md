# dexective: Visual Malware Localization Tool

dexective is a command-line tool for analyzing Android applications (`.apk` files) to identify and localize potentially malicious code. It leverages a powerful deep learning (CNN) model and an ensemble of Explainable AI (XAI) techniques to pinpoint suspicious classes within the app's `classes.dex` file.

The core methodology is based on the research paper: *NOT YET READY*.

The tool works by:
1.  Converting an app's `classes.dex` file into a grayscale image.
2.  Using a pre-trained CNN model to classify the image as `Benign` or `Malicious`.
3.  If malicious, it employs XAI methods (like Grad-CAM++, ScoreCAM, and Integrated Gradients) to generate heatmaps highlighting the pixels that most influenced the decision.
4.  These "hot" pixels are mapped back to the original Smali code, identifying the specific classes responsible for the malicious prediction.

## Features

-   **Static Analysis:** No need to run the app; works directly on the APK.
-   **Deep Learning Powered:** Uses a CNN for high-accuracy malware detection.
-   **Fine-Grained Localization:** Pinpoints suspicious Smali classes, not just the entire APK.
-   **Multiple XAI Methods:** Ensembles results from several state-of-the-art explanation methods for robust localization.
-   **Flexible Input:**
    -   Analyze a local `.apk` file.
    -   Pull and analyze an installed app directly from a connected Android device via ADB.
-   **Detailed Reporting:** Generates human-readable reports and visual heatmaps for each analyzed app.
-   **Configurable Analysis:** Allows overriding default XAI methods and leverages per-family configurations if APKs are structured accordingly.

## Prerequisites

Before you begin, ensure you have the following installed and configured:

1.  **Python 3.8+**
2.  **Java Runtime Environment (JRE):** Required to run `baksmali`.
3.  **Android Debug Bridge (ADB):** Required *only* for analyzing apps from a connected device. It must be in your system's PATH.
4.  **A Pre-trained Keras Model:** You need a `.h5` model file trained for the DEX-image classification task.
5.  **Baksmali:** The `baksmali.jar` file for decompiling DEX files.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone[ [https://github.com/your-username/dexective.git](https://github.com/your-username/dexective.git)](https://github.com/canoztas/dexective/) # Or your actual repo name
    cd dexective
    ```

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install Python dependencies:**
    A `requirements.txt` file is provided for easy installation.
    ```bash
    pip install -r requirements.txt
    ```

4.  **Place required files:**
    -   Place your pre-trained Keras model (e.g., `model.h5`) in a location accessible by the script.
    -   Place the `baksmali.jar` file in a location accessible by the script.
    You will specify their paths when running the tool.

## Usage

The tool is operated from the command line using `dexective_analyzer.py` and has two main modes: `file` and `adb`.

### General Help

To see all available commands and options:
```bash
python dexective_analyzer.py -h
```

### 1. Analyzing a Local APK File

Use the `file` command to analyze an `.apk` file on your computer.

**Syntax:**
```bash
python dexective_analyzer.py file [OPTIONS] <path_to_apk>
```

**Example:**
```bash
python dexective_analyzer.py file \
    --model /path/to/your/model.h5 \
    --baksmali /path/to/your/baksmali.jar \
    --output-dir ./analysis_results \
    /path/to/your/malicious.apk
```

### 2. Analyzing an App from a Connected Device (ADB)

Use the `adb` command to automatically pull and analyze an app from a connected Android device.

**Prerequisites for ADB mode:**
-   Your Android device must have **USB Debugging** enabled.
-   You must authorize the connection on your device when prompted.
-   The `adb` command must be in your system's PATH.

**Syntax:**
```bash
python dexective_analyzer.py adb [OPTIONS] <package_name>
```

**Example:**
```bash
# Analyze the app with package name 'com.example.suspiciousapp'
python dexective_analyzer.py adb \
    --model /path/to/your/model.h5 \
    --baksmali /path/to/your/baksmali.jar \
    --output-dir ./analysis_results \
    com.example.suspiciousapp
```

### Command-Line Arguments

-   `apk_path` / `package_name`: The target for the analysis.
-   `-m, --model`: (Required) Path to the `.h5` model file.
-   `-b, --baksmali`: (Required) Path to the `baksmali.jar` file.
-   `-o, --output-dir`: (Required) Directory where reports and images will be saved.
-   `--methods`: (Optional) A space-separated list of XAI methods to use. Overrides the default/family configuration.
    -   Choices: `gradcam`, `gradcam++`, `scorecam`, `vanilla_saliency`, `smoothgrad`, `integrated_gradients`.
    -   Example: `--methods gradcam++ scorecam`

## Output

For each APK identified as malicious, the tool will generate the following in your specified output directory:

1.  **Report File (`report_<apk_name_sanitized>.txt`):** A text file containing:
    -   The final malware score.
    -   A ranked list of the most suspicious Smali classes.
    -   Details on the aggregated score and XAI methods that identified each class.

2.  **Heatmap Images (`<apk_name_sanitized>_<xai_method>_heatmap.png`):**
    -   Visual heatmaps for each XAI method used, showing which parts of the DEX file image were most influential.

## Per-Family Configuration

The tool includes built-in configurations (XAI methods, thresholds, etc.) optimized for specific malware families (`FAMILY_PARAMS_CONFIG` in the script).
-   If an APK is located in a subdirectory whose name matches a known family key (e.g., `/path/to/apks/agent.aax/sample.apk`), the specific configuration for `agent.aax` will be used.
-   Otherwise, the `default` configuration is applied.
-   The `--methods` command-line argument will override any configuration.

## Requirements

Ensure you have the following Python packages installed (see `requirements.txt`):
-   `numpy`
-   `tensorflow`
-   `tf-keras-vis`
-   `scikit-learn`
-   `matplotlib`
-   `opencv-python`
-   `androguard`

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
