
# 🔐 Phishing URL Detection System

An **AI-driven application** designed to detect phishing URLs using machine learning.
It features a **Python-based Flask backend API** and an **interactive HTML/CSS/JavaScript frontend** for real-time analysis.
This project addresses the challenge of identifying deceptive URLs to protect users from cyber threats.

---

## 🚀 Key Features

* **Advanced AI Model** – Uses an ensemble of ML models: *Random Forest, XGBoost, LightGBM*.
* **Feature-Rich Analysis** – Extracts and analyzes over **87 lexical and host-based features**.
* **RESTful Backend API** – Flask-based API that serves the ML model for easy integration.
* **Interactive Frontend** – Modern interface (HTML/CSS/JS) for real-time URL safety checks.
* **Fallback Mechanism** – Includes a basic client-side analysis engine if the backend API is unavailable.
* **Modular Codebase** – Separate scripts for model training and backend server.

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask, Pandas, Scikit-learn, XGBoost, LightGBM, tldextract
* **Frontend:** HTML, CSS, JavaScript
* **Dataset:** `dataset_phishing.csv`

---

## 📦 Prerequisites

* Python **3.7+**
* `pip` (Python package manager)

---

## ⚙️ Setup & Installation

### 1. Project Files

Ensure all files are in your project directory:

* `phishing_dataset.py` → Model training script
* `flask_backend_api.py` → Backend API server
* `Phishing Detection App.html` → Frontend application
* `dataset_phishing.csv` → Training dataset

---


### 2. Install Required Packages

```bash
pip install Flask Flask-Cors pandas numpy scikit-learn xgboost lightgbm tldextract
```

---

## ▶️ Running the Application

### Step 1: Train the Machine Learning Model

Generate the ML model (`phishing_model_predefined.pkl`):

```bash
python phishing_dataset.py
```

---

### Step 2: Start the Backend API Server

Run the Flask server (keep this terminal window open):

```bash
python flask_backend_api.py
```

---

### Step 3: Open the Frontend

Double-click:

```
Phishing Detection App.html
```

➡️ The status indicator will show **“AI Model Connected”** once the backend is running.
You can now begin analyzing URLs.

---

## 🌐 Browser Extension Integration

You can integrate the backend API with a **Chrome/Edge extension** for seamless real-time protection.

### Installation (Chrome/Edge)

1. Open your browser’s extension management page:

   * **Chrome:** `chrome://extensions/`
   * **Edge:** `edge://extensions/`
2. Enable **Developer mode** (toggle switch).
3. Click **Load unpacked**.
4. Select the **phishing-detector** project folder.
5. The `Phishing Detector extension` will now appear in your extensions list.

   * Pin it to your toolbar for quick access.

---

