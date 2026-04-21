#!/usr/bin/env python3
"""
CyberScan Pro - Automated Network & Web Application Vulnerability Assessment Tool
Author: Obeh Emmanuel Onoriode
Matric Number: Cos/9581/2022
Institution: FUPRE
"""

import argparse
import sys
import threading
from datetime import datetime
from modules.network_scanner import NetworkScanner
from modules.web_scanner import WebScanner
from modules.web_tester import WebTester
from modules.cve_scanner import CVEScanner
from modules.report_generator import ReportGenerator
from modules.database import Database
from modules.logger import get_logger

logger = get_logger(__name__)

BANNER = r"""
   ____      _               ____                  ____
  / ___|   _| |__   ___ _ __/ ___|  ___ __ _ _ __ |  _ \ _ __ ___
 | |  | | | | '_ \ / _ \ '__\___ \ / __/ _` | '_ \| |_) | '__/ _ \
 | |__| |_| | |_) |  __/ |   ___) | (_| (_| | | | |  __/| | | (_) |
  \____\__, |_.__/ \___|_|  |____/ \___\__,_|_| |_|_|   |_|  \___/
       |___/
  Automated Vulnerability Assessment Tool | FUPRE FYP
  Author: Obeh Emmanuel Onoriode
  Matric Number: Cos/9581/2022 | Use responsibly & ethically only.
"""


def parse_args():
    parser = argparse.ArgumentParser(
        prog="cyberscanpro",
        description="CyberScan Pro - Automated Network & Web Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -t 192.168.1.0/24
  python main.py -t 192.168.1.10 --ports 1-65535
  python main.py -t 192.168.1.10 --scan-type full --output both
  python main.py --dashboard
        """
    )

    parser.add_argument("-t", "--target",
                        help="Target IP address or CIDR range (e.g. 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range to scan (default: 1-1024). Example: --ports 1-65535")
    parser.add_argument("--scan-type", choices=["quick", "full", "stealth"],
                        default="quick", help="Scan intensity: quick, full, stealth")
    parser.add_argument("--output", choices=["pdf", "html", "both"], default="both",
                        help="Output report format (default: both)")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch the CyberScan Pro web dashboard")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port for the web dashboard (default: 5000)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")

    return parser.parse_args()


def run_scan(args):
    """Execute the full scan pipeline."""
    print(BANNER)

    if not args.target:
        logger.error("No target specified. Use -t <IP or CIDR>.")
        sys.exit(1)

    target = args.target

    print(f"  [*] Target      : {target}")
    print(f"  [*] Port Range  : {args.ports}")
    print(f"  [*] Scan Type   : {args.scan_type}")
    print(f"  [*] Web Testing : ON (Header Scanner + Vulnerability Tester)")
    print(f"  [*] CVE Lookup  : ON")
    print(f"  [*] Output      : {args.output.upper()}")
    print(f"  [*] Started     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    db = Database()
    session_id = db.create_session(target)
    logger.info(f"Scan session created: {session_id}")

    # ── STEP 1: Network Scan ──────────────────────────────
    print("  [1/3] Running Network Scanner...")
    scanner = NetworkScanner(target=target, port_range=args.ports,
                             scan_type=args.scan_type, verbose=args.verbose)
    hosts = scanner.run()
    db.save_hosts(session_id, hosts)
    print(f"        Found {len(hosts)} live host(s).\n")

    # ── STEP 2: Web + CVE simultaneously ─────────────────
    print("  [2/3] Running Web Scanner + CVE Scanner simultaneously...")

    web_findings = []
    cve_findings = []
    web_errors   = []
    cve_errors   = []

    def run_web():
        try:
            # Both web modules run back-to-back inside this thread
            header_scanner = WebScanner(hosts=hosts, verbose=args.verbose)
            header_results = header_scanner.run()

            vuln_tester = WebTester(hosts=hosts, verbose=args.verbose)
            vuln_results = vuln_tester.run()

            combined = header_results + vuln_results
            web_findings.extend(combined)
            print(f"        [Web] Header issues: {len(header_results)} | "
                  f"Vuln findings: {len(vuln_results)}")
        except Exception as e:
            web_errors.append(str(e))
            logger.error(f"Web scan error: {e}")

    def run_cve():
        try:
            cve_scanner = CVEScanner(hosts=hosts, verbose=args.verbose)
            results = cve_scanner.run()
            cve_findings.extend(results)
            print(f"        [CVE] Mapped {len(results)} CVE finding(s).")
        except Exception as e:
            cve_errors.append(str(e))
            logger.error(f"CVE scan error: {e}")

    # Launch both in parallel threads
    web_thread = threading.Thread(target=run_web, name="WebScanner")
    cve_thread = threading.Thread(target=run_cve, name="CVEScanner")

    web_thread.start()
    cve_thread.start()

    # Wait for both to finish before continuing
    web_thread.join()
    cve_thread.join()

    # Save results
    db.save_web_findings(session_id, web_findings)
    db.save_cve_findings(session_id, cve_findings)

    if web_errors:
        print(f"        [Web] Completed with errors: {web_errors[0]}")
    if cve_errors:
        print(f"        [CVE] Completed with errors: {cve_errors[0]}")

    print(f"\n        Total web findings : {len(web_findings)}")
    print(f"        Total CVE findings : {len(cve_findings)}\n")

    # ── STEP 3: Report Generation ─────────────────────────
    print("  [3/3] Generating Report...")
    report_gen = ReportGenerator(
        session_id=session_id,
        target=target,
        hosts=hosts,
        web_findings=web_findings,
        cve_findings=cve_findings,
        output_format=args.output
    )
    report_paths = report_gen.generate()

    print()
    print("  ✓ Scan complete!")
    for path in report_paths:
        print(f"  ✓ Report saved: {path}")
    print()


def launch_dashboard(port):
    """Launch the Flask web dashboard."""
    from dashboard import app
    print(BANNER)
    print(f"  [*] Launching CyberScan Pro Dashboard on http://localhost:{port}")
    print(f"  [*] Press CTRL+C to stop.\n")
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    args = parse_args()

    if args.sync:
        import requests, json
        from modules.database import Database
        db = Database()
        sessions = db.get_all_sessions()
        if not sessions:
            print("[!] No local scan sessions found to sync.")
            sys.exit(1)
        # Sync the most recent completed session
        last = next((s for s in sessions if s["status"] == "completed"), sessions[0])
        sid = last["id"]
        payload = {
            "session_id":   sid,
            "target":       last["target"],
            "started_at":   last.get("started_at",""),
            "completed_at": last.get("completed_at",""),
            "hosts":        db.get_hosts(sid),
            "web_findings": db.get_web_findings(sid),
            "cve_findings": db.get_cve_findings(sid),
        }
        db.close()
        url = args.sync.rstrip("/") + "/api/sync"
        headers = {"Content-Type": "application/json"}
        if args.sync_key:
            headers["X-API-Key"] = args.sync_key
        print(f"[*] Syncing session {sid} ({last['target']}) to {url}...")
        try:
            r = requests.post(url, json=payload, headers=headers, timeout=30)
            data = r.json()
            if data.get("success"):
                print(f"[+] Sync successful! View at {args.sync}/scan/{sid}")
            else:
                print(f"[!] Sync failed: {data.get('error')}")
        except Exception as e:
            print(f"[!] Sync error: {e}")
        sys.exit(0)

    if args.dashboard:
        launch_dashboard(args.port)
    else:
        run_scan(args)
