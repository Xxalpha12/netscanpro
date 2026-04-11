# modules/web_scanner.py
import requests
from modules.logger import get_logger

logger = get_logger(__name__)

# Suppress SSL warnings for lab environments
requests.packages.urllib3.disable_warnings()


class WebScanner:
    """
    HTTP Security Header Scanner.
    Checks for missing security headers on discovered web hosts.
    Returns findings in the standard DB format for database.save_web_findings().
    """

    HEADER_CHECKS = [
        (
            "X-Frame-Options",
            "Missing X-Frame-Options header — site may be vulnerable to Clickjacking.",
            "Low",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to server response headers."
        ),
        (
            "Content-Security-Policy",
            "Missing Content-Security-Policy header — increases XSS risk.",
            "Medium",
            "Define a strict CSP policy to restrict resource loading sources."
        ),
        (
            "X-XSS-Protection",
            "Missing X-XSS-Protection header — browser XSS filter not enforced.",
            "Low",
            "Add 'X-XSS-Protection: 1; mode=block' to response headers."
        ),
        (
            "X-Content-Type-Options",
            "Missing X-Content-Type-Options — MIME sniffing attacks possible.",
            "Low",
            "Add 'X-Content-Type-Options: nosniff' to response headers."
        ),
        (
            "Strict-Transport-Security",
            "Missing HSTS header — connections may be downgraded to HTTP.",
            "Medium",
            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        (
            "Referrer-Policy",
            "Missing Referrer-Policy — sensitive URL data may leak to third parties.",
            "Low",
            "Add 'Referrer-Policy: no-referrer-when-downgrade' or stricter."
        ),
    ]

    def __init__(self, hosts, verbose=False):
        self.hosts = hosts
        self.verbose = verbose

    def run(self):
        """
        Scan all web-facing ports on discovered hosts for missing security headers.
        Returns a flat list of findings in the standard DB format.
        """
        findings = []
        web_ports = {80, 443, 8080, 8443, 8000, 8888}

        for host in self.hosts:
            ip = host["ip"]
            for port_info in host.get("ports", []):
                port = port_info["port"]
                service = port_info.get("service", "")

                # Only target HTTP/HTTPS ports
                if port not in web_ports and "http" not in service.lower():
                    continue

                scheme = "https" if port in {443, 8443} else "http"
                url = f"{scheme}://{ip}:{port}"

                host_findings = self._check_headers(url, ip)
                findings.extend(host_findings)

                if self.verbose and host_findings:
                    logger.info(f"  {url} → {len(host_findings)} header issue(s) found")

        # Deduplicate by host_ip + vuln_type
        seen = set()
        deduped = []
        for f in findings:
            key = (f["host_ip"], f["vuln_type"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def _check_headers(self, url, ip):
        """
        Fetch the URL and check for missing security headers.
        Returns a list of finding dicts compatible with database.save_web_findings().
        """
        findings = []
        try:
            r = requests.get(url, timeout=5, verify=False)
            headers = r.headers

            for header, description, severity, recommendation in self.HEADER_CHECKS:
                if header not in headers:
                    findings.append({
                        "host_ip":        ip,
                        "url":            url,
                        "vuln_type":      f"Missing Security Header: {header}",
                        "severity":       severity,
                        "description":    description,
                        "evidence":       f"Header '{header}' absent from HTTP response. "
                                          f"Status: {r.status_code}, Server: {headers.get('Server', 'N/A')}",
                        "recommendation": recommendation
                    })
        except requests.RequestException as e:
            if self.verbose:
                logger.warning(f"  Could not reach {url}: {e}")

        return findings
