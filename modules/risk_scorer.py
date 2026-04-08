"""
NetScan Pro - Risk Scorer Module
Real risk scoring based on findings, open ports, and service exposure.

Score breakdown (max 100):
  - Per CVE finding:    Critical=25, High=15, Medium=8, Low=3
  - Per Web finding:    Critical=20, High=12, Medium=6, Low=2
  - Dangerous services: RDP/Telnet/SMB open = +10 each (cap +20)
  - No findings at all: 0 (not "secure" — just no data)
"""

# Ports that significantly raise risk if exposed
HIGH_RISK_PORTS = {
    23:    ("Telnet", 10),
    445:   ("SMB", 10),
    3389:  ("RDP", 10),
    5900:  ("VNC", 8),
    21:    ("FTP", 6),
    1433:  ("MSSQL", 8),
    3306:  ("MySQL exposed", 6),
    27017: ("MongoDB exposed", 8),
    6379:  ("Redis exposed", 8),
    5432:  ("PostgreSQL exposed", 5),
}

CVE_WEIGHTS  = {"Critical": 25, "High": 15, "Medium": 8,  "Low": 3}
WEB_WEIGHTS  = {"Critical": 20, "High": 12, "Medium": 6,  "Low": 2}


def score_host(host: dict, web_findings: list, cve_findings: list) -> dict:
    ip    = host.get("ip", "")
    score = 0
    notes = []

    # ── CVE findings ─────────────────────────────────────────────────────────
    host_cves = [f for f in cve_findings if f.get("host_ip") == ip]
    for f in host_cves:
        w = CVE_WEIGHTS.get(f.get("severity", "Low"), 3)
        score += w
    if host_cves:
        notes.append(f"{len(host_cves)} CVE finding(s)")

    # ── Web findings ──────────────────────────────────────────────────────────
    host_web = [f for f in web_findings if f.get("host_ip") == ip]
    for f in host_web:
        w = WEB_WEIGHTS.get(f.get("severity", "Low"), 2)
        score += w
    if host_web:
        notes.append(f"{len(host_web)} web finding(s)")

    # ── Dangerous open ports ──────────────────────────────────────────────────
    port_penalty = 0
    for port_info in host.get("ports", []):
        pnum = port_info.get("port")
        if pnum in HIGH_RISK_PORTS:
            svc_name, penalty = HIGH_RISK_PORTS[pnum]
            port_penalty += penalty
            notes.append(f"{svc_name} exposed (port {pnum})")
    score += min(port_penalty, 20)   # cap port penalty at 20

    score = min(score, 100)

    # ── Label ─────────────────────────────────────────────────────────────────
    if score >= 75:
        label, color = "Critical", "#e74c3c"
    elif score >= 50:
        label, color = "High",     "#e67e22"
    elif score >= 25:
        label, color = "Medium",   "#f1c40f"
    elif score > 0:
        label, color = "Low",      "#2ecc71"
    else:
        label, color = "None",     "#95a5a6"

    return {
        "ip":    ip,
        "score": score,
        "label": label,
        "color": color,
        "notes": notes
    }


def score_all_hosts(hosts: list, web_findings: list, cve_findings: list) -> list:
    """Return risk scores for all hosts, highest first."""
    return sorted(
        [score_host(h, web_findings, cve_findings) for h in hosts],
        key=lambda x: x["score"],
        reverse=True
    )
