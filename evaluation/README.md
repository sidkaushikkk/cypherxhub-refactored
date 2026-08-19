# CypherX Detection Benchmark & Evaluation System

A reproducible, deterministic benchmark suite designed to evaluate the detection performance, accuracy, precision, recall, and false-positive rates of the CypherX security engine.

---

## 🚀 Running the Benchmark

```bash
# Run the detection engine benchmark
npm run benchmark
```

or directly:

```bash
node evaluation/evaluate.js
```

---

## 📊 Core Performance Metrics

The evaluation suite calculates standard statistical and cybersecurity metrics:

### 1. Confusion Matrix
| | Predicted **BENIGN** | Predicted **MALICIOUS** |
| :--- | :---: | :---: |
| **Actual BENIGN** | **True Negative ($TN$)** | **False Positive ($FP$)** *(False Alarm)* |
| **Actual MALICIOUS** | **False Negative ($FN$)** *(Missed Threat)* | **True Positive ($TP$)** |

### 2. Formulas & Definitions
- **Accuracy**: $\frac{TP + TN}{Total}$ — Overall correct predictions across all samples.
- **Precision**: $\frac{TP}{TP + FP}$ — Of all URLs flagged as threats, the proportion that were genuinely malicious.
- **Recall (Sensitivity)**: $\frac{TP}{TP + FN}$ — Of all true threats in the dataset, the proportion successfully detected.
- **F1 Score**: $2 \cdot \frac{Precision \cdot Recall}{Precision + Recall}$ — Harmonic balance between Precision and Recall.
- **False Positive Rate (FPR)**: $\frac{FP}{FP + TN}$ — Proportion of legitimate websites incorrectly flagged as dangerous.
- **False Negative Rate (FNR)**: $\frac{FN}{TP + FN}$ — Proportion of malicious threats that evaded detection.

---

## 🔍 Risk Score Threshold Sensitivity Sweep

The evaluation engine performs a parametric threshold sweep across risk scores (`>= 30`, `>= 40`, `>= 50`, `>= 60`, `>= 70`, `>= 80`) to observe how changing the operational detection threshold impacts Precision vs. Recall.

---

## ⚠️ Important Limitations & Seed Benchmark Status

1. **Seed Dataset (`CURATED_SEED_DATASET`)**:
   - The initial seed dataset contains balanced, representative threat patterns and legitimate edge-case URLs designed for heuristic validation and regression tracking.
   - High scores on this curated seed dataset verify that specific heuristic rules function as designed; **they do NOT claim real-world accuracy across the open internet**.

2. **Ground Truth Independence**:
   - Ground truth labels (`BENIGN` / `MALICIOUS`) are assigned independently of CypherX's internal risk engine predictions.

3. **Deterministic Hermetic Execution**:
   - External reputation checks (Google Safe Browsing) are fixed to a clean baseline during the benchmark so results evaluate local detection intelligence without external network fluctuations or quota constraints.

---

## 🔮 Future Benchmark Extensions

To measure real-world performance at enterprise scale, future benchmark iterations will ingest:
- **100,000+ Verified Benign URLs** from the Tranco / Cisco Umbrella Top 1M list.
- **10,000+ Active Phishing Campaigns** from live feeds (OpenPhish, PhishTank, URLScan).
- **Time-Separated Holdout Splits** to evaluate zero-day defense against newly registered domain patterns.
