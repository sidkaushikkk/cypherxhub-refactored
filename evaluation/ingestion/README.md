# CypherX Dataset Ingestion & Quality Control Engine

This directory contains the automated ingestion, normalization, deduplication, conflict resolution, and quality control pipeline for the CypherX evaluation system.

---

## 🛠️ Components

1. **`ingest.js`**:
   - Compiles ground-truth records from Tranco, OpenPhish, PhishTank, and URLhaus.
   - Runs raw records through the data quality pipeline.
   - Generates split partitions (`development`, `validation`, `test`) based on temporal timestamps.
   - Writes clean datasets to `evaluation/datasets/real-world/` and writes dataset quality metadata to `metadata.json`.

2. **`normalize.js`**:
   - Validates HTTP and HTTPS URL syntax.
   - Rejects unsupported schemes (`javascript:`, `file:`, `data:`, `ftp:`).
   - Normalizes protocol and hostname casing while preserving path/query structure.
   - Standardizes schema records and validates ground-truth labels (`BENIGN`, `MALICIOUS`).

3. **`dataQuality.js`**:
   - **Deduplication**: Multi-source matching where identical URLs across sources are merged, preserving multi-source provenance (`sources: ["phishtank", "openphish"]`).
   - **Conflict Resolution**: Identifies and flags any URL that exists as both `BENIGN` and `MALICIOUS`. Conflicted URLs are excluded from benchmark calculations.
   - **Temporal Partitioning**: Orders records chronologically by collection timestamp and partitions into `development` (60%), `validation` (20%), and `test` (20%).
   - **Sampling Modes**: Generates balanced subsets (50% benign / 50% malicious) or prevalence-oriented natural distributions.

---

## 🚀 Running Ingestion

To re-generate or refresh the real-world evaluation dataset:

```bash
npm run benchmark:ingest
```
*(or `node evaluation/ingestion/ingest.js`)*
