# PhishGuard — Phishing Link Detection System

> A machine learning-based phishing URL detection system built in R, trained on 822,010 URLs and deployed as a real-time web application.

---

## Overview

PhishGuard is an end-to-end phishing URL detection system that uses machine learning to classify any URL as **Phishing** or **Legitimate** in real time. Rather than analysing webpage content, the system extracts 33 structural and statistical features directly from the URL string itself, making it fast, lightweight, and content-independent.

The system was built entirely in R, trained on a large-scale labelled dataset of over 822,000 URLs, and deployed as an interactive web application using the Shiny framework.

---

## Features

-  Real-time URL classification — results in under 1 second
-  Confidence score with visual confidence bar
-  4 ML models trained and benchmarked
-  Model comparison with Accuracy, Precision, Recall, F1, and AUC-ROC
-  Confusion matrices, ROC curves, and feature importance charts
-  Interactive web app (PhishGuard) built with Shiny
-  All models saved for reuse without retraining

---

##  Project Structure

```
PhishGuard/
│
├── phishing_detection_v2.R   # Main training script (feature engineering + 4 ML models)
├── predict_url_v2.R          # Interactive CLI prediction script
├── app.R                     # Shiny web application (PhishGuard)
├── best_model_xgb.model      # Saved XGBoost model (best performer)
├── rf_model.rds              # Saved Random Forest model
├── lr_model.rds              # Saved Logistic Regression model
├── liblinear_model.rds       # Saved LiblineaR model
├── y_test.rds                # Test set labels
├── results.rds               # Final comparison table
└── new_data_urls.csv         # Dataset (822,010 labelled URLs)
```

---

##  Requirements

### R Packages
```r
install.packages(c(
  "tidyverse", "caret", "randomForest", "xgboost",
  "LiblineaR", "e1071", "glmnet", "stringr",
  "pROC", "tictoc", "ggplot2", "shiny", "data.table"
))
```

### System Requirements
- R version 4.0+
- RStudio (recommended)
- Minimum 8GB RAM (16GB recommended for full 822k dataset)

---

## Dataset

| Property | Value |
|---|---|
| Total URLs | 822,010 |
| Phishing (0) | 394,927 |
| Legitimate (1) | 427,083 |
| Features Extracted | 33 |
| Train Split | 70% (~575,407 URLs) |
| Test Split | 30% (~246,603 URLs) |

---

## Feature Engineering

33 features are extracted from each raw URL string, grouped into 6 categories:

| Category | Features |
|---|---|
| **Structural** | URL length, dots, slashes, hyphens, underscores, special characters, digits |
| **Protocol** | HTTPS/HTTP presence, double slash detection |
| **Domain-level** | Domain length, subdomain count, domain hyphens, digit ratio in domain, IP as domain |
| **Security Signals** | Trusted domain check, suspicious TLD, brand impersonation, URL encoding |
| **Keyword-based** | Suspicious keywords in domain only (login, verify, secure, etc.) |
| **Statistical** | URL entropy, digit ratio, path length, query string length |

---

## Models & Results

Four machine learning models were trained and evaluated:

| Model | Accuracy | Precision | Recall | F1 Score | AUC-ROC |
|---|---|---|---|---|---|
| Logistic Regression | 83.06% | 0.8068 | 0.8859 | 0.8445 | 0.905 |
| Random Forest | **92.29%** | **0.8996** | **0.9584** | **0.9281** | 0.962 |
| XGBoost | 90.98% | 0.8840 | 0.9511 | 0.9163 | **0.971** |
| LiblineaR | 83.05% | 0.8068 | 0.8859 | 0.8445 | 0.905 |

**Best Model: XGBoost** — selected based on highest AUC-ROC of **0.971**

---

## How to Run

### 1. Train the Models
```r
# Set working directory to project folder
setwd("D:/PhishGuard")

# Run the training script
source("phishing_detection_v2.R")
```
>  Training takes approximately 1–2 hours on a standard laptop with 16GB RAM.

### 2. Predict a Single URL (CLI)
```r
setwd("D:/PhishGuard")
source("predict_url_v2.R")

# Enter URL when prompted:
# Enter URL: https://paypal-secure-login.tk
# Result: PHISHING (Confidence: 94.3%)
```

### 3. Launch the Web App
```r
setwd("D:/PhishGuard")
shiny::runApp("app.R")
```
The PhishGuard web app will open in your browser automatically.

### 4. Reload Saved Models (skip retraining)
```r
library(xgboost); library(LiblineaR); library(caret); library(pROC)

xgb_model       <- xgb.load("best_model_xgb.model")
rf_model        <- readRDS("rf_model.rds")
lr_model        <- readRDS("lr_model.rds")
liblinear_model <- readRDS("liblinear_model.rds")
y_test          <- readRDS("y_test.rds")
results         <- readRDS("results.rds")
```

---

## PhishGuard Web App

The PhishGuard Shiny application provides a clean, real-time interface for URL classification:

- Paste any URL into the input box
- Click **SCAN URL**
- Instantly receive a **PHISHING** or **LEGITIMATE** result with confidence score
- Session counters track total scanned, phishing detected, and legitimate URLs

---

## Why These Models?

| Model | Reason |
|---|---|
| **Logistic Regression** | Fast interpretable baseline; identifies linear relationships between features and labels |
| **Random Forest** | Handles non-linear patterns, robust to noise, provides feature importance scores |
| **XGBoost** | Iteratively corrects errors, best for subtle deceptive URLs, state-of-the-art on tabular data |
| **LiblineaR** | Scalable linear SVM; trains on 560k+ rows in minutes, practical for large datasets |

---

## Future Work

- Integrate WHOIS and domain age lookup as additional features
- Connect to Google Safe Browsing API or VirusTotal for real-time cross-validation
- Experiment with character-level CNNs and LSTMs for raw URL classification
- Deploy as a browser extension for passive real-time protection
- Connect PhishGuard to live threat feeds (PhishTank, OpenPhish) for continuous updates
- Retrain periodically with fresh data as phishing tactics evolve

---

## Author

| Name | Program | Institution |
|---|---|---|
| Navaneeth | M.Tech (Integrated) – CSE with Business Analytics | VIT Chennai |

---

## 📄 License

This project was developed for academic purposes at Vellore Institute of Technology, Chennai.

---

## References

1. I. Fette, N. Sadeh, and A. Tomasic, "Learning to detect phishing emails," WWW 2007.
2. M. Prabhakar et al., "Detection of phishing websites using a machine learning algorithm," IJESR, 2020.
3. M. Abdolrazzagh-Nezhad and N. Langarib, "Phishing detection techniques: A review," JOCAI, 2025.
4. A. Abuadbba et al., "Towards robust machine learning-based phishing URL detectors," arXiv:2204.00985, 2022.
5. S. K. Ahammad et al., "Phishing URL detection using machine learning methods," Adv. Eng. Softw., 2022.
