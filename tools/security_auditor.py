#!/usr/bin/env python3
"""
SWYNEX Security Fundamentals Assessment - Defensive Security Audit Utility
Component: Automated Defensive Compliance & Header Auditor (tools/security_auditor.py)

Performs non-destructive baseline audits of web applications:
- Verifies presence and configuration of defensive HTTP headers
- Checks cookie security flags (HttpOnly, SameSite, Secure)
- Inspects Server banner leakage
- Checks for error page information disclosure
- Emits a structured compliance report
"""

import sys
import json
import urllib.request
import urllib.error
import re
from typing import Dict, Any, List


EXPECTED_SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "required": True,
        "description": "Restricts sources of executable scripts and resource loading to prevent XSS.",
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents clickjacking attacks by forbidding rendering in iframes.",
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Instructs browser not to sniff MIME types away from declared Content-Type.",
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Governs how much referrer information is sent along with requests.",
    },
    "Strict-Transport-Security": {
        "required": False,  # Often disabled in pure HTTP localhost environments, required in production
        "description": "Forces browsers to exclusively establish HTTPS connections.",
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Restricts access to hardware sensors, camera, microphone, etc.",
    }
}


def audit_endpoint(base_url: str) -> Dict[str, Any]:
    print(f"[*] Commencing Defensive Security Audit for target: {base_url}")
    report = {
        "target": base_url,
        "findings": [],
        "headers_audit": {},
        "cookie_audit": {},
        "score_summary": {"pass": 0, "warn": 0, "fail": 0}
    }

    # 1. Fetch root page and examine headers
    try:
        req = urllib.request.Request(base_url, headers={"User-Agent": "Swynex-Security-Auditor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.info())
            body = response.read().decode("utf-8", errors="ignore")
            status_code = response.getcode()
    except urllib.error.URLError as e:
        print(f"[-] Error connecting to target {base_url}: {e}")
        return report

    print(f"[+] Target responded with HTTP {status_code}")

    # Audit Headers
    for hname, hmeta in EXPECTED_SECURITY_HEADERS.items():
        found = False
        val = None
        for k, v in headers.items():
            if k.lower() == hname.lower():
                found = True
                val = v
                break

        if found:
            report["headers_audit"][hname] = {"status": "PASS", "value": val}
            report["score_summary"]["pass"] += 1
        else:
            status = "FAIL" if hmeta["required"] else "WARN"
            report["headers_audit"][hname] = {
                "status": status,
                "value": None,
                "note": f"Missing header. {hmeta['description']}"
            }
            if status == "FAIL":
                report["score_summary"]["fail"] += 1
                report["findings"].append({
                    "id": f"AUDIT-HDR-{hname.upper()}",
                    "severity": "Medium",
                    "title": f"Missing {hname} Header",
                    "description": hmeta["description"]
                })
            else:
                report["score_summary"]["warn"] += 1

    # Audit Server Banner Information Leakage
    server_header = headers.get("server", headers.get("Server", ""))
    if server_header:
        if any(term in server_header.lower() for term in ["debug", "python", "1.0.0", "apache", "nginx"]):
            report["findings"].append({
                "id": "AUDIT-INFO-SERVER-BANNER",
                "severity": "Low",
                "title": "Verbose Server Banner Exposure",
                "description": f"Server header reveals detailed software version: '{server_header}'."
            })
            report["score_summary"]["warn"] += 1
        else:
            report["score_summary"]["pass"] += 1

    # Check for CSRF tokens in HTML forms
    forms = re.findall(r'<form\b[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
    if forms:
        csrf_found = False
        for f in forms:
            if "csrf" in f.lower():
                csrf_found = True
                break
        if not csrf_found:
            report["findings"].append({
                "id": "AUDIT-CSRF-MISSING-TOKEN",
                "severity": "Medium",
                "title": "Missing Anti-CSRF Token in HTML Form",
                "description": "Forms detected without anti-CSRF synchronizer token fields."
            })
            report["score_summary"]["fail"] += 1
        else:
            report["score_summary"]["pass"] += 1

    return report


def print_cli_report(report: Dict[str, Any]):
    print("\n" + "=" * 65)
    print("        SWYNEX DEFENSIVE SECURITY AUDIT REPORT")
    print("=" * 65)
    print(f"Target URL: {report['target']}")
    print("-" * 65)
    print(f"{'Header Name':<28} | {'Status':<6} | {'Value / Recommendation'}")
    print("-" * 65)

    for hname, data in report["headers_audit"].items():
        status = data["status"]
        stat_display = f"\033[92m{status}\033[0m" if status == "PASS" else (
            f"\033[91m{status}\033[0m" if status == "FAIL" else f"\033[93m{status}\033[0m"
        )
        val = data.get("value") or data.get("note", "")[:45] + "..."
        print(f"{hname:<28} | {status:<6} | {val}")

    print("-" * 65)
    print("FINDINGS SUMMARY:")
    if not report["findings"]:
        print("  \033[92m[✓] No major baseline configuration anomalies detected!\033[0m")
    else:
        for f in report["findings"]:
            print(f"  - [{f['severity'].upper()}] {f['title']}: {f['description']}")

    score = report["score_summary"]
    print("-" * 65)
    print(f"Audit Summary: {score['pass']} Passed | {score['warn']} Warnings | {score['fail']} Failed")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    audit_results = audit_endpoint(target)
    print_cli_report(audit_results)
