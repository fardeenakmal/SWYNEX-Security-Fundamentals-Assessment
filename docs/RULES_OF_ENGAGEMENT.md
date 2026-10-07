# SWYNEX Security Fundamentals Assessment - Rules of Engagement (RoE)

## 1. Document Control & Authorization Memo

| Document Attribute | Specification |
| :--- | :--- |
| **Project Name** | SWYNEX Security Fundamentals Assessment |
| **Document Classification** | Confidential - Authorized Security Assessment |
| **Lead Security Assessor** | Fardeen Akmal |
| **Assessment Target** | SWYNEX Educational Lab Environment |
| **Authorization Framework** | Explicit Lab Environment Authorization (Isolated Sandbox) |
| **Assessment Methodology** | OWASP Web Security Testing Guide (WSTG v4.2) / NIST SP 800-115 |
| **Standard Baseline** | OWASP Top 10:2021 Security Fundamentals |

---

## 2. Statement of Explicit Authorization

> **MANDATORY POLICY STATEMENT:**  
> Security testing against any computing system, application, or network without prior explicit, written authorization from the system owner is strictly prohibited by law (e.g., Computer Fraud and Abuse Act [CFAA], Information Technology Act 2000, and equivalent regional cyber legislation).

This security fundamentals assessment was planned, scoped, and conducted **exclusively** within an isolated, local training testbed configured specifically for educational evaluation and vulnerability discovery. No unauthorized external networks, production infrastructure, third-party APIs, or external hosts were subjected to testing.

---

## 3. Scope Definition

### 3.1 In-Scope Assets
The following endpoints and components were explicitly authorized for assessment:

| Asset Name | Target Protocol / Address | Description |
| :--- | :--- | :--- |
| **Vulnerable Training Lab** | `http://127.0.0.1:8080/` | Intentionally vulnerable assessment testbed |
| **Authentication Service** | `http://127.0.0.1:8080/login` | Login and credential handling routines |
| **Profile & ID Management** | `http://127.0.0.1:8080/profile` | User profile retrieval and access control layer |
| **Audit Log Search** | `http://127.0.0.1:8080/search` | Database search functionality |
| **Fund Transfer API** | `http://127.0.0.1:8080/transfer` | Transaction state-changing endpoint |
| **Remediated Hardened Lab** | `http://127.0.0.1:8081/` | Reference patched application for verification |

### 3.2 Out-of-Scope Assets
The following systems and activities were strictly designated as **OUT OF SCOPE**:
- Any production systems, staging servers, or cloud hosting providers.
- Denial of Service (DoS/DDoS) stress tests against host network interfaces.
- Physical security, social engineering, or phishing against real users.
- Third-party dependency supply-chain poisoning.

---

## 4. Assessment Rules & Ethical Boundaries

1. **Non-Destructive Testing:**  
   All testing was carried out using non-destructive, non-disruptive auditing techniques. No permanent data corruption or hostile disruption was executed.
2. **Data Privacy & Handling:**  
   All test records, database entries, and audit logs created during the assessment contained simulated, synthetic training data. No real Personally Identifiable Information (PII) or financial data was utilized.
3. **Evidence Integrity:**  
   Vulnerability evidence was gathered using source code tracing, non-destructive parameter testing, and configuration audits.
4. **Remediation Requirement:**  
   Every identified security vulnerability must be paired with verified remediation instructions and defensive counter-measures.

---

## 5. Assessor Contact Information

- **Assessor:** Fardeen Akmal
- **Email:** fardeenakmal123@gmail.com
- **Repository:** `SWYNEX-Security-Fundamentals-Assessment`
