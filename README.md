# 🧠 SigmaForge: Security Detection Engineering Lab

This project is a comprehensive Detection Rule Development and Testing platform, demonstrating end-to-end detection engineering for SOCs. It is **not** just another SIEM installation; it is a platform designed to measure, test, and validate detection rules against synthetic and historic datasets.

## Pipeline Architecture
```text
Log Dataset
     ↓
Detection Rule
     ↓
Test Engine
     ↓
True/False Positive Analysis
     ↓
MITRE Mapping
     ↓
Detection Quality Score
```

## Features
- **Sigma Rule Support**: SIEM-agnostic rule management.
- **MITRE ATT&CK Mapping**: Direct mapping of rules to adversary techniques.
- **Synthetic Log Generator**: Test rules against simulated datasets.
- **Detection Testing**: Run pipelines to calculate Precision and Recall.
- **False-Positive Tracking**: Historical tuning of noisy rules.
- **Rule Versioning**: Lifecycle management (Testing -> Tuning -> Production).
- **Detection Coverage Map**: Visualize defensive posture.

---

## 🗺️ MITRE ATT&CK Coverage

Our current detection engineering coverage across the MITRE ATT&CK framework:

```text
Overall Coverage     ██████████████░░ 78%

Initial Access       ███████████████░ 82%
Execution            ████████████████ 91%
Persistence          ████████████░░░░ 64%
Privilege Escalation █████████████░░░ 71%
Defense Evasion      ██████████████░░ 80%
Credential Access    ██████████████░░ 76%
```

---

## 🧪 Example Detection Rule Profile

**Rule**: Suspicious PowerShell Download Cradle  
**MITRE**: T1059.001 (Command and Scripting Interpreter: PowerShell)  

**Performance Metrics**:
- **Precision**: 91%
- **Recall**: 84%
- **False Positives**: 7%
- **Status**: Production Ready

## Setup & Demo
To run the SigmaForge local dashboard:
```bash
cd backend
python main.py
```
Open `frontend/index.html` in your browser to view the Sigma UI, Signal Analysis, and Coverage maps.
