"""
NetScan Pro - Web Dashboard (Flask)
Full featured dashboard with auth, CSV export, comparison,
risk scoring, scheduling, email delivery, and more.
"""

from flask import (Flask, render_template, request, jsonify,
                   send_file, abort, redirect, url_for, session,
                   make_response)
import os
import io
import csv
import threading
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from datetime import datetime
from modules.database import Database
from modules.logger import get_logger
from modules.risk_scorer import score_all_hosts
from auth import auth, login_required

logger = get_logger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "netscampro-secret-2025-change-me")
app.register_blueprint(auth)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
PORT = int(os.environ.get("PORT", 5000))
os.makedirs(OUTPUT_DIR, exist_ok=True)

active_scans = {}


# ── ROUTES ───────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    db = Database()
    db.fix_stale_sessions()  # Auto-fix stuck running sessions
    sessions = db.get_all_sessions()
    severity_counts = db.get_severity_counts()
    total_findings = db.get_total_findings()
    db.close()
    return render_template("dashboard.html", sessions=sessions,
                           severity_counts=severity_counts,
                           total_findings=total_findings,
                           page="home", title="NetScan Pro Dashboard",
                           username=session.get("username", "admin"))


@app.route("/scan/new", methods=["GET"])
@login_required
def new_scan():
    return render_template("new_scan.html", page="new_scan", title="New Scan")


@app.route("/scan/run", methods=["POST"])
@login_required
def run_scan():
    data = request.get_json()
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "Target IP or CIDR is required."}), 400

    # ── Duplicate scan guard ──────────────────────────────────────────────────
    # Prevent launching a second scan against the same target if one is running
    for sid, scan in active_scans.items():
        if scan.get("target") == target and scan.get("status") == "running":
            return jsonify({
                "error": f"A scan against '{target}' is already running (session {sid}). "
                         "Wait for it to finish or check the dashboard."
            }), 409

    from modules.network_scanner import NetworkScanner
    from modules.web_scanner import WebScanner
    from modules.web_tester import WebTester
    from modules.cve_scanner import CVEScanner
    from modules.report_generator import ReportGenerator

    db = Database()
    session_id = db.create_session(target)
    db.close()

    active_scans[session_id] = {
        "status": "running", "log": [], "target": target,
        "report_paths": [], "progress": 0,
        "hosts_found": 0, "web_count": 0, "cve_count": 0
    }

    def _log(msg):
        active_scans[session_id]["log"].append(f"[{_ts()}] {msg}")

    def _set_progress(pct, msg=None):
        active_scans[session_id]["progress"] = pct
        if msg:
            _log(msg)

    def _run():
        try:
            db = Database()
            _log(f"Scan started for target: {target}")
            _set_progress(3)

            # ── Network scan with live progress callback ──────────────────────
            _log("Running Network Scanner...")

            def net_progress(pct, msg):
                # Maps scanner's 5–30% range into our 5–28% range
                mapped = 5 + int(pct * 0.46)
                active_scans[session_id]["progress"] = min(mapped, 28)
                _log(msg)

            scanner = NetworkScanner(
                target=target,
                port_range=data.get("port_range", "1-1024"),
                scan_type=data.get("scan_type", "quick"),
                progress_callback=net_progress
            )
            hosts = scanner.run()
            db.save_hosts(session_id, hosts)
            active_scans[session_id]["hosts_found"] = len(hosts)
            _set_progress(30, f"Network scan complete — {len(hosts)} host(s), "
                              f"{sum(len(h.get('ports',[])) for h in hosts)} open port(s) total.")

            if not hosts:
                _log("WARNING: No hosts found. Check target, DNS, and network connectivity.")

            # ── Web + CVE in parallel ─────────────────────────────────────────
            _log("Launching Web Scanner + CVE Scanner simultaneously...")
            web_findings = []
            cve_findings = []

            def run_web():
                try:
                    _log("Web Scanner: checking security headers...")
                    header_scanner = WebScanner(hosts=hosts)
                    header_results = header_scanner.run()
                    _log(f"Web Scanner: {len(header_results)} header issue(s). Starting vuln tests...")

                    vuln_tester = WebTester(hosts=hosts)
                    vuln_results = vuln_tester.run()
                    combined = header_results + vuln_results
                    web_findings.extend(combined)

                    # Incremental save so dashboard counts update live
                    if combined:
                        db2 = Database()
                        db2.save_web_findings(session_id, combined)
                        db2.close()

                    active_scans[session_id]["web_count"] = len(combined)
                    _log(f"Web scan done — Headers: {len(header_results)} | Vulns: {len(vuln_results)}")
                except Exception as e:
                    _log(f"Web scan error: {e}")

            def run_cve():
                try:
                    _log("CVE Scanner: mapping services to known CVEs...")
                    cve_scanner = CVEScanner(hosts=hosts)
                    results = cve_scanner.run()
                    cve_findings.extend(results)

                    # Incremental save
                    if results:
                        db3 = Database()
                        db3.save_cve_findings(session_id, results)
                        db3.close()

                    active_scans[session_id]["cve_count"] = len(results)
                    _log(f"CVE scan done — {len(results)} finding(s).")
                except Exception as e:
                    _log(f"CVE scan error: {e}")

            _set_progress(32)
            web_thread = threading.Thread(target=run_web, daemon=True)
            cve_thread = threading.Thread(target=run_cve, daemon=True)
            web_thread.start()
            cve_thread.start()

            # Update progress while threads run
            import time
            for pct in range(33, 74, 3):
                if not web_thread.is_alive() and not cve_thread.is_alive():
                    break
                time.sleep(1.5)
                active_scans[session_id]["progress"] = pct

            web_thread.join()
            cve_thread.join()

            _set_progress(75, f"All scans done — Web: {len(web_findings)} | CVE: {len(cve_findings)}")

            # Findings already saved incrementally inside run_web() and run_cve()
            # No double-save needed

            # ── Report ────────────────────────────────────────────────────────
            _set_progress(80, "Generating report...")
            gen = ReportGenerator(
                session_id=session_id, target=target,
                hosts=hosts, web_findings=web_findings,
                cve_findings=cve_findings,
                output_format=data.get("output_format", "both")
            )
            paths = gen.generate()
            active_scans[session_id]["report_paths"] = paths
            db.complete_session(session_id)

            if data.get("email"):
                _send_report_email(data["email"], target, session_id, paths)
                _log(f"Report emailed to {data['email']}")

            db.close()
            for p in paths:
                _log(f"Report saved: {os.path.basename(p)}")

            active_scans[session_id]["status"]   = "completed"
            active_scans[session_id]["progress"] = 100
            _log("Scan completed successfully.")

        except Exception as e:
            active_scans[session_id]["status"]   = "error"
            active_scans[session_id]["progress"] = 0
            _log(f"ERROR: {str(e)}")
            logger.error(f"Scan error: {e}")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"session_id": session_id, "status": "started"})


@app.route("/scan/<session_id>/status")
@login_required
def scan_status(session_id):
    if session_id not in active_scans:
        return jsonify({"status": "not_found", "log": [], "progress": 0})
    scan = active_scans[session_id]
    return jsonify({
        "status":       scan["status"],
        "log":          scan["log"],
        "progress":     scan.get("progress", 0),
        "report_paths": [os.path.basename(p) for p in scan.get("report_paths", [])],
        "hosts_found":  scan.get("hosts_found", 0),
        "web_count":    scan.get("web_count", 0),
        "cve_count":    scan.get("cve_count", 0),
    })


@app.route("/scan/<session_id>")
@login_required
def view_scan(session_id):
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    hosts           = db.get_hosts(session_id)
    web_findings    = db.get_web_findings(session_id)
    cve_findings    = db.get_cve_findings(session_id)
    severity_counts = db.get_severity_counts(session_id)
    total_findings  = db.get_total_findings(session_id)
    db.close()

    # Risk scoring
    risk_scores = score_all_hosts(hosts, web_findings, cve_findings)

    return render_template(
        "scan_detail.html",
        session=sess, hosts=hosts,
        web_findings=web_findings, cve_findings=cve_findings,
        severity_counts=severity_counts, total_findings=total_findings,
        risk_scores=risk_scores,
        page="results", title=f"Scan {session_id}"
    )


@app.route("/scan/<session_id>/delete", methods=["POST"])
@login_required
def delete_scan(session_id):
    db = Database()
    if not db.get_session(session_id):
        return jsonify({"error": "Not found"}), 404
    db.delete_session(session_id)
    db.close()
    return jsonify({"success": True})


@app.route("/report/<filename>")
@login_required
def download_report(filename):
    filepath = os.path.join(OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        abort(404)
    return send_file(filepath, as_attachment=True)


# ── EXPORT CSV ───────────────────────────────────────────

@app.route("/export/csv")
@login_required
def export_csv():
    """Export all scan sessions as a CSV file."""
    db = Database()
    sessions = db.get_all_sessions()
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Session ID", "Target", "Started At", "Completed At", "Status"])
    for s in sessions:
        writer.writerow([s["id"], s["target"], s["started_at"],
                         s.get("completed_at", ""), s["status"]])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=netscampro_sessions.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


@app.route("/export/<session_id>/csv")
@login_required
def export_session_csv(session_id):
    """Export all findings for a specific session as CSV."""
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    web = db.get_web_findings(session_id)
    cve = db.get_cve_findings(session_id)
    db.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["=== WEB FINDINGS ==="])
    writer.writerow(["Host IP", "URL", "Vulnerability", "Severity", "Description", "Recommendation"])
    for f in web:
        writer.writerow([f["host_ip"], f["url"], f["vuln_type"],
                         f["severity"], f["description"], f["recommendation"]])

    writer.writerow([])
    writer.writerow(["=== CVE FINDINGS ==="])
    writer.writerow(["Host IP", "Port", "Service", "CVE ID", "CVSS Score", "Severity", "Reference"])
    for f in cve:
        writer.writerow([f["host_ip"], f["port"], f["service"],
                         f["cve_id"], f["cvss_score"], f["severity"], f["reference"]])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=netscanpro_{session_id}_findings.csv"
    response.headers["Content-Type"] = "text/csv"
    return response


# ── SCAN COMPARISON ───────────────────────────────────────

@app.route("/compare")
@login_required
def compare():
    db = Database()
    sessions = db.get_all_sessions()
    db.close()
    return render_template("compare.html", sessions=sessions,
                           page="compare", title="Compare Scans")


@app.route("/api/compare")
@login_required
def api_compare():
    """Return comparison data for two sessions."""
    sid1 = request.args.get("s1")
    sid2 = request.args.get("s2")
    if not sid1 or not sid2:
        return jsonify({"error": "Two session IDs required"}), 400

    db = Database()
    def get_data(sid):
        s = db.get_session(sid)
        if not s:
            return None
        return {
            "session":        s,
            "severity_counts": db.get_severity_counts(sid),
            "total_findings": db.get_total_findings(sid),
            "host_count":     len(db.get_hosts(sid)),
            "web_count":      len(db.get_web_findings(sid)),
            "cve_count":      len(db.get_cve_findings(sid)),
        }

    data1 = get_data(sid1)
    data2 = get_data(sid2)
    db.close()

    if not data1 or not data2:
        return jsonify({"error": "Session not found"}), 404

    return jsonify({"session1": data1, "session2": data2})


# ── CVE TREND ─────────────────────────────────────────────

@app.route("/api/cve-trend")
@login_required
def api_cve_trend():
    """Return CVE finding counts per session for trend chart."""
    db = Database()
    sessions = db.get_all_sessions()
    trend = []
    for s in sessions[-10:]:  # Last 10 sessions
        counts = db.get_severity_counts(s["id"])
        trend.append({
            "session_id": s["id"],
            "target":     s["target"],
            "date":       s["started_at"][:10],
            "critical":   counts["Critical"],
            "high":       counts["High"],
            "medium":     counts["Medium"],
            "low":        counts["Low"],
            "total":      sum(counts.values())
        })
    db.close()
    return jsonify(trend)


# ── REMEDIATION CHECKLIST ─────────────────────────────────

@app.route("/scan/<session_id>/checklist")
@login_required
def remediation_checklist(session_id):
    """Generate a downloadable remediation checklist."""
    db = Database()
    sess = db.get_session(session_id)
    if not sess:
        abort(404)
    web_findings = db.get_web_findings(session_id)
    cve_findings = db.get_cve_findings(session_id)
    db.close()
    return render_template("checklist.html",
                           session=sess,
                           web_findings=web_findings,
                           cve_findings=cve_findings)


# ── EMAIL DELIVERY ────────────────────────────────────────

def _send_report_email(recipient: str, target: str, session_id: str, report_paths: list):
    """Send scan report via email using SMTP."""
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    if not smtp_user or not smtp_pass:
        logger.warning("SMTP credentials not configured. Email not sent.")
        return

    try:
        msg = MIMEMultipart()
        msg["From"]    = smtp_user
        msg["To"]      = recipient
        msg["Subject"] = f"NetScan Pro Report — {target} [{session_id}]"

        body = f"""NetScan Pro — Automated Vulnerability Assessment Report

Target:     {target}
Session ID: {session_id}
Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please find the attached penetration test report.

---
NetScan Pro | FUPRE Final Year Project | Obeh Emmanuel Onoriode
⚠ This report is confidential. Authorized use only.
"""
        msg.attach(MIMEText(body, "plain"))

        # Attach PDF report if available
        for path in report_paths:
            if path.endswith(".pdf") and os.path.exists(path):
                with open(path, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header("Content-Disposition",
                                    f"attachment; filename={os.path.basename(path)}")
                    msg.attach(part)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, recipient, msg.as_string())

        logger.info(f"Report emailed to {recipient}")
    except Exception as e:
        logger.error(f"Email failed: {e}")


# ── API ───────────────────────────────────────────────────

@app.route("/api/severity-counts")
@login_required
def api_severity_counts():
    db = Database()
    counts   = db.get_severity_counts()
    total    = db.get_total_findings()
    sessions = db.get_all_sessions()
    db.close()
    return jsonify({
        "severity_counts": counts,
        "total_findings":  total,
        "session_count":   len(sessions),
        "completed": len([s for s in sessions if s["status"] == "completed"]),
        "running":   len([s for s in sessions if s["status"] == "running"]),
        "errors":    len([s for s in sessions if s["status"] == "error"])
    })


@app.route("/api/sessions")
@login_required
def api_sessions():
    db = Database()
    sessions = db.get_all_sessions()
    db.close()
    return jsonify(sessions)


def _ts():
    return datetime.now().strftime("%H:%M:%S")
