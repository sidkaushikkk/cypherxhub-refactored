# CypherX Evaluation Datasets

This directory contains curated evaluation datasets used for benchmark testing of the CypherX detection engine.

## ⚠️ Important Disclaimer: Seed Dataset Status

The seed datasets in this directory (`benign.json` and `malicious.json`) are labeled as **`CURATED_SEED_DATASET`**. 

> **NOTICE:** This seed dataset is an initial smoke-test and regression benchmark. It is designed to verify detection heuristics across distinct threat categories. It does NOT represent a statistically random or production-scale distribution of real-world internet traffic, and benchmark scores obtained from this dataset must not be claimed as overall real-world accuracy.

---

## 📋 Schema Format

Each dataset file is a JSON array of record objects:

```json
{
  "url": "https://example.com/login",
  "label": "BENIGN",
  "category": "legitimate_login",
  "source": "CURATED_SEED_DATASET"
}
```

### Supported Ground Truth Labels
- `BENIGN`: Valid, legitimate web resources that should not be blocked or flagged.
- `MALICIOUS`: Deceptive, phishing, or malicious URL patterns that should be detected.

### Categories
- **Benign**: `normal_website`, `legitimate_login`, `legitimate_payment`, `query_parameters`, `security_keywords`, `developer_urls`.
- **Malicious**: `known_blacklist`, `typosquatting`, `authority_userinfo_deception`, `ip_host`, `punycode_homograph`, `suspicious_tld`, `open_redirect`, `excessive_subdomains`, `credential_phishing_heuristic`.

---

## 🔮 Future Real-World Dataset Expansion

To transition from seed benchmarks to comprehensive real-world validation, future dataset pipelines will integrate:
1. **Tranco / Majestic Million Top 10k** for verified benign samples.
2. **OpenPhish / PhishTank Verified Feeds** for active campaign feeds.
3. **Time-separated and Campaign-separated Splits** to measure zero-day generalization.
