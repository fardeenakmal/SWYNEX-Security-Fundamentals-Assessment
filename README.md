# SWYNEX-Security-Fundamentals-Assessment

[![Security Assessment](https://img.shields.io/badge/Security%20Assessment-Fundamentals%20Audited-brightgreen.svg)](docs/SECURITY_ASSESSMENT_REPORT.md)
[![Standard](https://img.shields.io/badge/Standard-OWASP%20Top%2010%20%7C%20NIST%20SP%20800--115-blue.svg)](docs/RULES_OF_ENGAGEMENT.md)
[![Remediation Status](https://img.shields.io/badge/Remediation%20Status-6%2F6%20Resolved%20(100%25)-success.svg)](docs/REMEDIATION_GUIDE.md)
[![Tests Passing](https://img.shields.io/badge/Security%20Controls%20Test-7%2F7%20Passed-brightgreen.svg)](tests/test_security_controls.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Assessment Repository:** `SWYNEX-Security-Fundamentals-Assessment`  
> **Lead Security Assessor:** Fardeen Akmal  
> **Environment:** Authorized Isolated Laboratory Testbed (`localhost`)  
> **Methodology:** OWASP Web Security Testing Guide (WSTG v4.2) / NIST SP 800-115  

---

## 🛡️ Executive Overview

This repository contains the complete deliverables for the **SWYNEX Security Fundamentals Assessment**. Conducted within an authorized, isolated educational laboratory environment, the assessment systematically identifies, documents, exploits (in controlled sandbox conditions), and remediates fundamental web application security flaws.

The project features:
1. **Formal Security Assessment Documentation:** Complete technical audit reports, risk matrices, and individual finding dossiers.
2. **Authorized Dual-Mode Lab Architecture:**
   - **`lab/vulnerable_app/`**: An intentionally vulnerable web service demonstrating critical security flaws in an authorized local testbed.
   - **`lab/secure_app/`**: A hardened, production-grade remediated service demonstrating concrete, defense-in-depth mitigations.
3. **Automated Defensive Tooling & Test Suite:**
   - An automated defensive compliance & security header auditor (`tools/security_auditor.py`).
   - Automated unit and integration tests verifying control effectiveness (`tests/test_security_controls.py`).
4. **Zero External Dependencies:** Built entirely with the standard library of **Python 3.8+** (zero pip packages required to run the labs or execute tests).

---

## 📋 Summary of Findings & Mitigations

Every identified risk has been documented across four core dimensions: **Affected Component**, **Risk (Threat & Impact)**, **Technical Evidence**, and **Recommended Mitigation**.

| ID | Finding Title | Affected Component | Risk & Impact (CVSS v3.1) | Evidence | Recommended Mitigation | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **SEC-01** | **SQL Injection (SQLi)** | `lab/vulnerable_app/database.py`<br>`POST /login`, `GET /search` | **9.8 (Critical)**<br>Auth bypass, full database exfiltration, table tampering | Dynamic string formatting in SQL statements | Parameterized queries with prepared statements (`?` binding) | **REMEDIATED** |
| **SEC-02** | **Insecure Direct Object Reference (IDOR)** | `lab/vulnerable_app/server.py`<br>`GET /profile?id=X` | **7.5 (High)**<br>Unauthorized inspection of other users' confidential PII & balances | Unchecked user-controlled ID in request query parameters | Enforce contextual session ownership checks & RBAC | **REMEDIATED** |
| **SEC-03** | **Cryptographic Failure (Weak Hash)** | `lab/vulnerable_app/database.py`<br>Password storage | **7.4 (High)**<br>Credential recovery via precomputed rainbow tables | Passwords stored with obsolete, unsalted MD5 digests | Upgrade to PBKDF2-HMAC-SHA256 (600,000 iterations) + CSPRNG salt | **REMEDIATED** |
| **SEC-04** | **Missing Rate Limiting** | `lab/vulnerable_app/server.py`<br>`POST /login` | **5.3 (Medium)**<br>Automated brute-force attacks and credential stuffing | No attempt throttling or lockout mechanisms | Sliding-window rate limiter (5 req/min) returning `HTTP 429` | **REMEDIATED** |
| **SEC-05** | **Security Misconfiguration** | `lab/vulnerable_app/server.py`<br>Global HTTP Pipeline | **5.3 (Medium)**<br>Path disclosure in stack traces; missing browser defenses | Traceback dumps on 500 error; missing CSP/X-Frame-Options | Sanitized generic error handling; mandatory security headers | **REMEDIATED** |
| **SEC-06** | **Missing CSRF Defenses** | `lab/vulnerable_app/server.py`<br>`POST /transfer` | **6.5 (Medium)**<br>Cross-site state tampering and unauthorized transactions | State-changing POST relies only on ambient cookies | Cryptographic anti-CSRF synchronizer tokens + `SameSite=Strict` | **REMEDIATED** |

---

## 📂 Repository Directory Layout

```
SWYNEX-Security-Fundamentals-Assessment/
├── .gitignore                          # Clean VCS exclusions
├── LICENSE                             # MIT Open-Source License
├── README.md                           # Main assessment overview and quickstart
├── requirements.txt                    # Runtime requirements (Python stdlib)
├── docs/                               # Formal Assessment Documentation
│   ├── RULES_OF_ENGAGEMENT.md          # Authorization letter, scope, and ethical bounds
│   ├── SECURITY_ASSESSMENT_REPORT.md   # Master comprehensive technical report
│   ├── EXECUTIVE_SUMMARY.md            # High-level management risk briefing
│   └── REMEDIATION_GUIDE.md            # Practical developer patching guide
├── reports/
│   └── findings/                       # In-depth standalone finding reports
│       ├── SEC-VULN-001-SQL-Injection.md
│       ├── SEC-VULN-002-IDOR-Broken-Access-Control.md
│       ├── SEC-VULN-003-Cryptographic-Failures.md
│       ├── SEC-VULN-004-Brute-Force-No-Rate-Limiting.md
│       ├── SEC-VULN-005-Security-Misconfiguration.md
│       └── SEC-VULN-006-Missing-CSRF-Protection.md
├── lab/                                # Authorized Lab Environments
│   ├── README.md                       # Lab execution manual and account credentials
│   ├── vulnerable_app/                 # Intentionally vulnerable testbed
│   │   ├── __init__.py
│   │   ├── server.py                   # Port 8080 HTTP server
│   │   └── database.py                 # Insecure database queries & MD5 storage
│   └── secure_app/                     # Hardened remediated testbed
│       ├── __init__.py
│       ├── server.py                   # Port 8081 HTTP server
│       ├── database.py                 # Parameterized queries & PBKDF2 hashing
│       └── security_utils.py           # Rate limiting, CSRF tokens, security headers
├── tools/                              # Defensive Security Utilities
│   ├── __init__.py
│   └── security_auditor.py             # Automated defensive headers & compliance auditor
└── tests/                              # Automated Control Verification
    ├── __init__.py
    └── test_security_controls.py       # Unit and regression test suite
```

---

## 🚀 Lab Quickstart & Verification Guide

### Prerequisites
- Python 3.8 or higher.
- No external packages required!

### Step 1: Run the Vulnerable Lab Server (Port 8080)
To inspect and demonstrate the identified vulnerabilities:
```bash
python3 lab/vulnerable_app/server.py
```
Visit: [http://127.0.0.1:8080](http://127.0.0.1:8080)

### Step 2: Run the Hardened Secure Server (Port 8081)
To verify the remediated architecture:
```bash
python3 lab/secure_app/server.py
```
Visit: [http://127.0.0.1:8081](http://127.0.0.1:8081)

### Step 3: Run the Automated Security Tests
Verify all security controls (SQLi immunity, PBKDF2 hashing, rate limiting, CSRF validation):
```bash
python3 -m unittest discover tests -v
```

### Step 4: Run the Defensive Security Auditor
Audit security headers and configurations against any target:
```bash
python3 tools/security_auditor.py http://127.0.0.1:8081
```

---

## ⚖️ Rules of Engagement & Ethical Notice

> **IMPORTANT:**  
> Security assessments must only be conducted against systems you own or have obtained **explicit, written authorization** to test. Unauthorized access, scanning, or testing of computer networks is illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, Section 43/66 of the Information Technology Act 2000, and equivalent international laws.

All activities documented in this repository were conducted within an isolated local training testbed configured specifically for this educational assessment. Review [`docs/RULES_OF_ENGAGEMENT.md`](docs/RULES_OF_ENGAGEMENT.md) for complete details.

---

## 👤 Author Information

- **Assessor:** Fardeen Akmal
- **Contact:** fardeenakmal123@gmail.com
- **Project:** SWYNEX Security Fundamentals Assessment
