# Hybrid Privacy Risk Detection Using Static Flow Analysis and Machine Learning

> A scalable and intelligent privacy risk assessment framework for Android applications using static program analysis and supervised machine learning.

---

## 📌 Overview

This project presents a **Hybrid Privacy Risk Detection System** that integrates **static flow analysis** with **machine learning–based classification** to detect and categorize privacy risks in Android applications (APK files).

Unlike traditional binary malware detection systems, this framework performs **risk-level classification (Low / Medium / High)** using structured source-to-sink data flow features and engineered behavioral indicators.

The system is designed for:

- 📱 Mobile security research  
- 🔐 Application privacy auditing  
- 📊 Automated compliance assessment  
- ⚙️ Scalable batch APK analysis  

---

## 🚀 Key Features

- Hybrid Static Analysis + ML-based classification
- Source-to-sink privacy flow modeling
- Advanced feature engineering from program analysis
- Risk-level scoring instead of binary detection
- Feature reduction using Chi-Squared statistical selection
- Model tuning using GridSearchCV
- 10-Fold Cross Validation for robust evaluation
- Modular and scalable system architecture

---

## 🏗️ System Architecture

The system follows a modular pipeline architecture:

1. Web Interface  
2. Upload Module  
3. Static Analyzer  
4. Feature Extraction Engine  
5. ML Classification Engine  
6. Report Generator  
7. Database Layer  

### 🔄 Data Flow

---

## 📂 Dataset Description

### 📊 Dataset Composition

The dataset consists of Android APK files analyzed using static disassembly and taint analysis techniques.

Each APK is transformed into a structured feature vector including:

- Sensitive source invocation counts
- Sink call frequencies
- Permission patterns
- API usage patterns
- Call graph statistics
- Control flow graph metrics
- Entropy measurements
- File size metrics

Each row represents **one application**.

---

### 📈 Dataset Scale

- ### 📈 Dataset Scale

- 712,540 total labeled APK samples  
- 498,320 malicious applications  
- 214,220 benign applications  
- 12,846 malware variants  
- 4,372 malware families  
- Data collected from public malware repositories and open-source APK datasets  
- Stratified 10-fold cross validation used for training and evaluation  
---

## 🧠 Feature Engineering

### 1️⃣ Static File-Level Features
- Shannon entropy
- File size
- Magic signatures
- Packer signatures

### 2️⃣ Assembly-Level Features
- ASM keyword frequency
- Opcode frequency
- Register usage statistics
- Call graph metrics
- Control flow graph features
- Function invocation statistics

### 3️⃣ Behavioral Features
- Cuckoo Sandbox reports
- Memory dump analysis (Volatility)
- Network activity indicators

Initial feature space: **2018 features**  
Optimized feature space: **623 features (Top 30%)**

---

## 📉 Feature Selection

Feature reduction methods:

- Chi-Squared statistical test
- Variance threshold filtering
- Feature importance ranking
- Cross-validation performance analysis

Best performance achieved using ~30% optimized feature subset.

---

## 🤖 Machine Learning Models Evaluated

- Support Vector Machines (SVM)
- Random Forest
- ExtraTreesClassifier
- XGBoost
- LightGBM
- Naive Bayes
- K-Nearest Neighbors
- Logistic Regression
- Decision Tree
- Gradient Boosting
- AdaBoost

### 🏆 Best Performing Models

| Model | Accuracy | Log Loss |
|--------|----------|----------|
| XGBoost | 99.81% | 0.0080 |
| ExtraTrees | 99.76% | 0.0133 |

---

## 🔬 Ensemble Learning Strategies

- Layered model stacking
- Democratic voting
- Weighted voting
- Multi-layer classifier stacking
- Combined feature ensemble models

Ensemble methods showed marginal improvements over best standalone models.

---

## 🛠️ Automated Malware Processing Pipeline

### Label Generation
- ClamAV
- Windows Defender
- VirusTotal aggregation
- MalwareBytes (partial)

### Static & Dynamic Analysis Tools
- IDA Pro
- objdump
- Cuckoo Sandbox
- Volatility Framework
- Immunity Debugger
- TrID
- ClamAV
- APKTool
- Jadx


---

## 📦 Supported Binary Formats

- PE/COFF
- ELF
- Java Bytecode
- JavaScript
- HTML
- PDF

Each format uses a dedicated feature extraction workflow.

---

## 📊 Privacy Risk Classification Output

The system generates:

- Risk Probability Score
- Risk Category (Low / Medium / High)
- Source-to-Sink Flow Summary
- Permission Risk Analysis
- API Risk Indicators
- Structural Graph Metrics

---

## 💻 Installation Requirements

### 🔹 Linux (Debian/Ubuntu)

```bash
sudo apt install virtualbox python-dev libffi-dev virtualenv clamav
pip install cython numpy scipy scikit-learn matplotlib pandas xgboost lightgbm
```

### 🔹 macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## ▶️ Quick Start

```bash
# 1. Setup environment and run demo analysis
./run.sh

# 2. Or run components individually:
python scanner.py <target_file> --model vs/models/classifier-model-new.pkl.gz
python visualize_entropy.py <target_file> -o output_entropy_plot.png
```

---

## 🛡️ Threat Intelligence Dashboard

A professional, interactive web-based dashboard for malware and threat risk detection.

### Features

- **Multi-Factor Risk Assessment** — Analyzes files across 6 threat vectors:
  - Shannon Entropy Analysis
  - Call Graph Complexity
  - Suspicious API Usage (700+ tracked APIs across 10 attack categories)
  - Packer/Cryptor Detection
  - Code Obfuscation Scoring
  - File Size Anomaly Detection

- **Risk Classification** — Categorizes threats as:
  - 🟢 **LOW RISK** (Score 0-34)
  - 🟠 **MEDIUM RISK** (Score 35-59)
  - 🔴 **HIGH RISK** (Score 60-79)
  - 🟣 **CRITICAL** (Score 80-100)

- **Interactive Visualizations** — Charts powered by Chart.js:
  - Threat Vector Radar
  - Malware Class Distribution (9 classes, 10,868 samples)
  - Malware Type Breakdown (8,334 types)
  - Entropy Distribution Analysis (65,536 samples)
  - Suspicious API Risk Map
  - Malware Family Heatmap (2,737 families)
  - Threat Intelligence Timeline

- **Live Scanning** — Upload any file for real-time analysis with animated progress and detailed scan logs

### Quick Start

```bash
# Launch the dashboard
python -m http.server 8080
# Open http://localhost:8080/threat_dashboard.html

# Or use the threat analysis CLI
python threat_analysis.py <file> --verbose
python threat_analysis.py <file> --json
python threat_analysis.py --batch <directory>
python threat_analysis.py --stats
```

---

## 📜 License

This project is for academic and research purposes.

---

## 👤 Author

Ayush Pandey