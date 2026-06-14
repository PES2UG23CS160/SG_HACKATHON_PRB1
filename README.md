# Identity Sprawl & Privilege Abuse Detection

```
██╗██████╗ ███████╗███╗   ██╗████████╗██╗████████╗██╗   ██╗
██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██║╚══██╔══╝╚██╗ ██╔╝
██║██║  ██║█████╗  ██╔██╗ ██║   ██║   ██║   ██║    ╚████╔╝
██║██║  ██║██╔══╝  ██║╚██╗██║   ██║   ██║   ██║     ╚██╔╝
██║██████╔╝███████╗██║ ╚████║   ██║   ██║   ██║      ██║
╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝   ╚═╝      ╚═╝
THREAT INTELLIGENCE PLATFORM
```

> **Enterprise Challenge:** Hybrid identity environments create identity sprawl — stale users, excessive privileges, orphaned service accounts. Modern breaches exploit identity weaknesses 80% more than malware.

---

## 📊 Detection Performance

Evaluated against **300 labeled users** and **900 labeled events** (ground truth provided).

### Results

| Category | Precision | Recall | F1 Score | Status |
|----------|-----------|--------|----------|--------|
| User Anomaly Detection | **97.2%** | **100.0%** | **0.99** | ✅ PASS |
| Event Anomaly Detection | **87.3%** | **82.8%** | **0.85** | ✅ PASS |

### vs Target

| Metric | Target | Achieved | Delta |
|--------|--------|----------|-------|
| User Precision | > 75% | **97.2%** | +22pp |
| User Recall | > 70% | **100.0%** | +30pp |
| Event Precision | > 75% | **87.3%** | +12pp |
| Event Recall | > 70% | **82.8%** | +12pp |

### What this means
- **0 missed critical users** — every stale admin, orphaned account, and over-privileged user was caught
- **97.2% user precision** — nearly zero false alarms for account-level risks
- **87.3% event precision** — 9 out of 10 flagged events are genuinely suspicious
- Overall accuracy across 1,200 data points: **96%**

> Baseline naive approach (flag all night access): Precision 40%, Recall 35%
> Our system: **2.4x better precision, 2.4x better recall**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DATA PIPELINE                             │
│                                                             │
│  sample_data/          generate_data.py                     │
│  ├── identity_users.csv  ──►  users_labels.csv              │
│  └── identity_events.csv ──►  events_labels.csv             │
│                                                             │
│                    DETECTION ENGINE                          │
│                                                             │
│  detector.py                                                │
│  ├── IsolationForest (users,  contamination=0.16)           │
│  ├── IsolationForest (events, contamination=0.41)           │
│  ├── Hard rule overrides (stale admin, orphaned, bulk USB)  │
│  ├── Context exclusions (CTO, new hire, contractor, oncall) │
│  └── ──► flagged_users.csv + flagged_events.csv             │
│                                                             │
│                    LLM EXPLAINER                             │
│                                                             │
│  explainer.py                                               │
│  ├── Groq API (llama-3.3-70b-versatile)                     │
│  ├── Top 20 users + Top 20 events                           │
│  ├── Blast radius per flagged user                          │
│  └── ──► explanations.json                                  │
│                                                             │
│                    SOC DASHBOARD                             │
│                                                             │
│  app.py (Flask)                                             │
│  ├── GET /              — Command Center                     │
│  ├── GET /users         — User Risk Table (filterable)       │
│  ├── GET /events        — Event Log (filterable)             │
│  ├── GET /user/<id>     — User Deep Dive + Blast Radius      │
│  ├── GET /graph         — Privilege Sprawl Graph             │
│  ├── GET /live          — Live Threat Feed                   │
│  └── GET /api/live-feed — JSON endpoint (auto-refresh)      │
│                                                             │
│                    EVALUATION                                │
│                                                             │
│  evaluate.py ──► audit_report.md                            │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic data + ground truth labels
python generate_data.py

# 3. Run anomaly detection engine
python detector.py

# 4. Generate LLM explanations (requires GROQ_API_KEY)
# Windows:
set GROQ_API_KEY=your_key_here
# Mac/Linux:
export GROQ_API_KEY=your_key_here

python explainer.py

# 5. Launch SOC dashboard
python app.py
# → Open http://localhost:5000

# 6. Run evaluation + generate audit report
python evaluate.py
```

---

## Key Features

### 🔍 ML-Powered Detection (IsolationForest)
Learns what normal behavior looks like per user and per event. Flags statistical outliers automatically — no manual rule writing needed for every edge case.

### ⚡ Hard Rule Overrides
Business logic layered on top of ML to guarantee critical cases are never missed:
- Admin account inactive > 60 days → **FORCE CRITICAL**
- Bulk export (>10k rows) to USB/external email → **FORCE CRITICAL**
- Restricted data to external destination → **FORCE HIGH**
- Off-hours access to restricted data → **FORCE HIGH**

### 🛡️ Context-Aware False Positive Suppression
Recognizes legitimate exceptions and never flags them:
- **CTO/CISO** — broad access by design
- **New hires** (<30 days) — unusual access patterns expected
- **Contractors** — short tenure is normal
- **On-call IT** — after-hours access is legitimate
- **Finance month-end** — bulk queries last 3 days of month are expected

### 💥 Blast Radius Simulation
For every flagged user, shows the business impact if their account is compromised:
- Systems attacker can reach
- Estimated records exposed
- GDPR fine exposure (up to €20M)
- Whether attacker can cover their tracks (SIEM access)

### 🤖 LLM-Powered Explanations (Groq / Llama 3.3)
Every alert comes with a human-readable explanation using exact numbers, not generic text. Maps to compliance frameworks automatically.

### 📡 Live Threat Feed
Real-time streaming event feed with sound alerts for CRITICAL events. Terminal aesthetic with auto-refresh every 5 seconds.

### 🕸️ Privilege Sprawl Graph
Interactive network diagram showing users → systems access relationships. Red nodes = flagged users. Instantly visualizes identity sprawl.

---

## Detection Features

### User Features
| Feature | Description | Risk Signal |
|---------|-------------|-------------|
| `days_inactive` | Days since last login | >60 = high risk |
| `privilege_encoded` | viewer/editor/admin/superadmin | Higher = more risk |
| `num_systems` | Number of systems with access | >5 = sprawl |
| `is_contractor` | Contractor flag | Context modifier |
| `is_new_hire` | Hired <30 days ago | Context modifier |
| `has_admin_inactive` | Admin + inactive >60d | Hard override |
| `is_orphaned` | Disabled but still has access | Hard override |
| `is_overprivileged` | Low role + high-value system | Hard override |

### Event Features
| Feature | Description | Risk Signal |
|---------|-------------|-------------|
| `hour_of_day` | Hour of access | <6 or >20 = suspicious |
| `is_after_hours` | Outside 8am-7pm | Context flag |
| `is_weekend` | Weekend access | Context flag |
| `rowcount` | Records accessed | >10k = bulk export |
| `is_bulk` | rowcount > 10,000 | Hard override |
| `sensitivity_encoded` | Data sensitivity level | Higher = more risk |
| `is_external_dest` | Going outside org | Always risky |
| `is_cross_dept` | Accessing other dept data | Suspicious |
| `is_restricted_to_external` | Restricted + external | CRITICAL |
| `rowcount_zscore` | Per-user statistical outlier | Deviation from baseline |

---

## Compliance Frameworks

| Framework | Requirement | Coverage |
|-----------|-------------|----------|
| **NIST AC-2** | Account Management | Stale & orphaned accounts |
| **GDPR Art.32** | Technical security measures | Data export monitoring |
| **SOX 302** | Internal controls over financial data | Cross-dept GL/Finance access |

---

## Standout Features vs Other Teams

| Feature | Us | Typical Team |
|---------|-----|-------------|
| ML + Hard Rules hybrid | ✅ | Rules only |
| Context-aware exceptions | ✅ | Flag everything |
| Blast radius simulation | ✅ | ❌ |
| LLM explanations with exact numbers | ✅ | Generic text |
| Live feed with sound alerts | ✅ | ❌ |
| Privilege sprawl graph | ✅ | ❌ |
| 97%+ precision | ✅ | ~60-70% typical |

---

## Production Scale Strategy

```
Raw Events (millions/day)
         │
         ▼
    Apache Kafka
    (real-time event streaming)
         │
         ▼
    Spark Streaming
    (feature extraction + IsolationForest scoring)
         │
         ▼
    Redis (risk score cache, TTL=5min)
         │
         ▼
    Dashboard API (Flask / FastAPI)
         │
         ▼
    SIEM Integration (Splunk / Microsoft Sentinel)
```

**Estimated throughput:** 100k users, 10M events/day at <200ms latency per score.
**Current demo scale:** 300 users, 900 events, processes in <5 seconds locally.

---

## File Structure

```
identity_threat/
├── generate_data.py     # Synthetic data + ground truth label generation
├── detector.py          # IsolationForest + hard rules anomaly detection
├── explainer.py         # Groq LLM risk assessments + blast radius
├── app.py               # Flask SOC dashboard (dark theme)
├── evaluate.py          # Precision/recall evaluation + audit report
├── requirements.txt
└── README.md

sample_data/
├── identity_users.csv           # 300 user accounts
├── identity_events.csv          # 900 access events
├── identity_users_labels.csv    # Ground truth — users
├── identity_events_labels.csv   # Ground truth — events
├── flagged_users.csv            # Detector output — risky users
├── flagged_events.csv           # Detector output — risky events
└── explanations.json            # Groq LLM explanations + blast radius
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Detection Engine | Python, scikit-learn (IsolationForest) |
| Data Processing | Pandas, NumPy |
| LLM Explanations | Groq API (llama-3.3-70b-versatile) — free tier |
| Dashboard | Flask, Plotly |
| Graph Visualization | NetworkX, Plotly |
| Compliance Mapping | Custom rule engine |

---

## Limitations & Future Work

- **Synthetic data** — real deployment needs live API connectors (Okta, Azure AD, AWS IAM)
- **Baseline window** — uses full dataset as baseline; production needs rolling 30-day window
- **LLM rate limits** — Groq free tier limited to 30 req/min; production uses batch processing
- **No persistent storage** — alerts reset on restart; production needs PostgreSQL + alert history
- **Single node** — production scales with Kafka + Spark as shown above
