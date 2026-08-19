# 🛡️ CypherX — Real-Time Threat Intelligence & Security Engine

**CypherX** is an enterprise-grade cybersecurity platform engineered for real-time threat analysis of URL links, QR code payloads, and uploaded file binaries.

---

## ⚡ P1 Detection Intelligence & Reliability Engine

The CypherX backend features a modular, layered detection intelligence engine:

### 🔬 9-Layer URL & Domain Threat Inspection Pipeline

```text
Input URL
   ↓
1. Normalization & Protocol Validation (Scheme, Trailing Dots, Encoding)
   ↓
2. Protocol Security Analysis (HTTP vs HTTPS, Unsafe Protocol Detection)
   ↓
3. Authority & Userinfo Deception Analysis (@ Symbol Authority Trick)
   ↓
4. Hostname & IP Analysis (IPv4/v6 Host Detection, Length, Hyphen Density)
   ↓
5. Subdomain & TLD Analysis (TLD Risk Heuristics, Nesting Depth)
   ↓
6. Punycode & Homograph Unicode Analysis (xn-- IDN, Cyrillic/Greek Lookalikes)
   ↓
7. Typosquatting & Brand Similarity Analysis (Levenshtein Distance, Leetspeak, Brand Catalog)
   ↓
8. Path & Query Parameter Obfuscation (Non-standard Ports, Open Redirect Params, Percent Encoding)
   ↓
9. External Threat Intelligence & Reputation (Local Blacklist DB + Google Safe Browsing API)
   ↓
Contextual Risk Engine Verdict (Status, Score 0-100, Confidence, Reasons, Recommendation)
```

---

## 📐 Threat Taxonomy & Evidence-Based Risk Engine

CypherX uses a strict 4-tier indicator severity hierarchy:

| Severity Level | Baseline Weight | Description / Examples |
| :--- | :--- | :--- |
| **CRITICAL** | `80 - 100` | Known Blacklist match, Google Safe Browsing Malicious flag, Extension vs Magic Byte Mismatch. |
| **HIGH** | `40 - 65` | Deceptive `@` Userinfo trick, Raw IP Host, Brand Typosquatting / Impersonation, Script Payload. |
| **MEDIUM** | `20 - 30` | Suspicious TLD, Punycode `xn--`, Homograph characters, Nested Redirect query parameters, Non-standard Port. |
| **LOW** | `10 - 15` | Unencrypted HTTP, Excessive percent encoding, Security keyword match, Long URL length. |

### 🎯 Key False-Positive Control & Evidence Mechanics
- **Non-Linear Score Dampening**: Weak `LOW` signals are dampened so clean URLs with multiple minor traits (e.g. HTTP + 1 hyphen + keyword) never trigger false `DANGEROUS` alerts.
- **Strict Score Capping**: Overall risk score is bounded within `0 – 100`.
- **Independent Confidence Rating**: Confidence is explicitly classified as `LOW`, `MEDIUM`, or `HIGH` based on indicator count and critical threat intelligence matches.
- **Decoupled IP Host Heuristics**: IP address hostnames are evaluated separately from domain subdomain depth rules.

---

## 🛠️ Automated Testing & Observability

CypherX includes a comprehensive, hermetic test suite leveraging native Node.js testing:

```bash
# Run all unit and integration test suites
npm test
```

### 🧪 Test Coverage
- **URL Layer Tests**: Protocols, userinfo extraction, IP hosts, homograph Unicode, query parameters.
- **Typosquatting Tests**: Levenshtein distance, leetspeak substitution, brand catalog impersonation, false-positive protection for clean brand domains.
- **Risk Engine Tests**: Non-linear dampening, score capping, evidence weighting, output contract verification.
- **File Scanner Tests**: Magic byte headers (PE, ELF, PDF, ZIP, PNG, JPEG), extension spoofing, double extension evasion.
- **Safe Browsing Service Tests**: Mocks for `CLEAN`, `MALICIOUS`, timeout, and network errors.
- **API Integration Tests**: Express route endpoints (`POST /api/scan-url`, `POST /api/scan-file`, `GET /api/health`).

---

## 📊 Structured Logging & Tracing

All API HTTP transactions and threat scans emit structured logs containing:
- `requestId` (`X-Request-ID` correlation header)
- `scanType` (`URL`, `FILE`, `QR`)
- `status` and `riskScore`
- Execution duration in milliseconds
- Key and credential redaction for Safe Browsing API keys and passwords.

---

## ⚠️ Explicit Engine Limitations

- **Heuristic Threat Inspection**: CypherX performs binary header signature inspection and static heuristics; it is not yet a full antivirus sandbox or dynamic URL web page renderer.
- **File Signature Analysis**: Extension mismatch checks verify binary headers against file extensions, but absence of a known threat does not guarantee safety.
- **External Intelligence Fallbacks**: If external threat intelligence APIs (e.g., Google Safe Browsing) are offline or unconfigured, the system reports `UNAVAILABLE` or `ERROR` without failing silent or claiming false safety.

---

## 📁 Project Architecture

```text
├── server/
│   ├── config/env.js              # Environment secrets & configuration
│   ├── engine/
│   │   ├── indicators.js          # Threat indicator taxonomy & weights
│   │   └── riskEngine.js          # Contextual non-linear risk engine
│   ├── middleware/
│   │   ├── errorHandler.js        # Centralized HTTP error handler
│   │   ├── loggerMiddleware.js    # Structured request tracing & correlation
│   │   ├── rateLimiter.js         # Express rate limiters
│   │   ├── security.js            # Helmet & CORS policy configuration
│   │   └── upload.js              # Multer file upload handler
│   ├── routes/
│   │   ├── health.routes.js       # Health monitoring endpoint
│   │   └── scan.routes.js         # Unified scan routes (/api/scan-url, /api/scan-file)
│   ├── services/
│   │   ├── fileScanner.js         # Magic byte & file payload inspector
│   │   ├── safeBrowsing.js        # Google Safe Browsing API client
│   │   └── urlScanner.js          # 9-Layer URL scanning pipeline
│   ├── utils/
│   │   ├── hashing.js             # SHA-256 hash generation
│   │   ├── logger.js              # Structured logger
│   │   ├── typosquatting.js       # Levenshtein & brand similarity engine
│   │   └── url.js                 # Layered URL parser & homograph analyzer
│   └── server.js                  # Modular Express application
├── tests/
│   ├── integration/               # API route integration tests
│   └── unit/                      # Isolated unit tests
├── index.html                     # Landing page
├── scan-url.html                  # URL scanner tool UI
├── scan-qr.html                   # QR code scanner UI
├── script.js                      # Frontend API integration & UI state management
└── package.json                   # Dependencies & npm scripts
```

---

## 📄 License & Attribution

&copy; Sidhant Kaushik. All rights reserved.
Designed and developed by Sidhant Kaushik.
