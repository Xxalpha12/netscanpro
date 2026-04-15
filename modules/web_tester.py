"""
NetScan Pro - Web Application Tester Module
Crawls web applications on discovered hosts and tests for
common OWASP Top 10 vulnerabilities.

Vulnerabilities tested:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Directory Traversal
  - Open Redirect
  - CSRF (missing token detection)
  - Sensitive file exposure

Usage (internal):
    tester = WebTester(hosts=hosts)
    findings = tester.run()
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from modules.logger import get_logger

logger = get_logger(__name__)

# Disable SSL warnings for internal testing environments
requests.packages.urllib3.disable_warnings()


# ── PAYLOAD LIBRARIES ────────────────────────────────────

SQLI_PAYLOADS = [
    # Classic error-based
    "'", "''", "';--", "' OR '1'='1", "' OR '1'='1'--",
    "' OR 1=1--", "' OR 1=1#", '\" OR \"1\"=\"1',
    "1; DROP TABLE users--", "1' AND 1=1--",
    # Union-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    # Blind boolean-based
    "' AND 1=1--", "' AND 1=2--",
    "' AND SLEEP(2)--", "1; WAITFOR DELAY '0:0:2'--",
    # Stacked queries
    "'; SELECT * FROM users--",
]

# Time-based blind SQLi payloads (separate for timing detection)
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(3)--",
]

XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # Attribute injection
    "'\"><script>alert(1)</script>",
    "\"\"><img src=x onerror=alert(1)>",
    # JavaScript protocol
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    # Filter bypass
    "<ScRiPt>alert(1)</ScRiPt>",
    "<%2fscript>",
    "<svg/onload=alert(1)>",
]

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/admin", "/administrator", "/phpmyadmin", "/backup",
    "/robots.txt", "/sitemap.xml", "/.htaccess",
    "/server-status", "/api/v1/users", "/debug"
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite_",
    "sqlstate", "syntax error", "unclosed quotation",
    "pg_query", "warning: mysql", "you have an error in your sql",
    "supplied argument is not a valid mysql", "invalid query",
    "mysql_num_rows", "mysql_fetch_array", "pg_exec",
    "supplied argument is not", "column count doesn",
    "error in your sql syntax", "unexpected end of sql",
    "division by zero", "invalid column name",
    "microsoft ole db provider", "odbc sql server driver",
    "ora-", "pls-", "db2 sql error", "quoted string not properly"
]


class WebTester:
    """
    Tests web applications running on discovered hosts
    for common security vulnerabilities.
    """

    def __init__(self, hosts: list, verbose: bool = False, timeout: int = 5):
        self.hosts = hosts
        self.verbose = verbose
        self.timeout = timeout
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "NetScanPro/1.0 (Authorized Security Assessment)"
        })
        self.session.verify = False  # For self-signed certs in lab environments

    def run(self) -> list:
        """Run all web tests against all discovered web hosts."""
        web_targets = self._extract_web_targets()

        if not web_targets:
            logger.info("No web services found on discovered hosts.")
            return []

        logger.info(f"Testing {len(web_targets)} web target(s)...")

        for target in web_targets:
            base_url = target["url"]
            ip = target["ip"]
            logger.info(f"  Testing: {base_url}")

            # Crawl the app to discover pages and forms
            pages, forms = self._crawl(base_url)

            # Run all test suites
            self._test_sqli(ip, pages, forms)
            self._test_sqli_blind(ip, pages, forms)
            self._test_xss(ip, pages, forms)
            self._test_xss_forms(ip, forms)
            self._test_traversal(ip, pages)
            self._test_sensitive_files(ip, base_url)
            self._test_csrf(ip, forms)
            self._test_open_redirect(ip, pages)

        logger.info(f"Web testing complete. {len(self.findings)} finding(s).")
        return self.findings

    # ── CRAWL ────────────────────────────────────────────

    def _extract_web_targets(self) -> list:
        """Extract URLs from the host list for web testing."""
        targets = []
        web_ports = {80, 443, 8080, 8443, 8000, 8888}

        for host in self.hosts:
            for port in host.get("ports", []):
                pnum = port.get("port")
                svc = port.get("service", "")
                if pnum in web_ports or "http" in svc.lower():
                    scheme = "https" if pnum in {443, 8443} else "http"
                    # Use hostname if available (better for virtual hosting)
                    host_addr = host.get("hostname", host["ip"])
                    if host_addr in ("N/A", "Unknown", "", None):
                        host_addr = host["ip"]
                    # Use standard port if 80/443, otherwise include port
                    if (scheme == "http" and pnum == 80) or (scheme == "https" and pnum == 443):
                        url = f"{scheme}://{host_addr}"
                    else:
                        url = f"{scheme}://{host_addr}:{pnum}"
                    targets.append({"ip": host["ip"], "url": url})
                    break
        return targets

    def _crawl(self, base_url: str, max_pages: int = 20) -> tuple:
        """
        Crawl the web app starting from base_url.
        Returns (list of page URLs, list of form dicts).
        """
        visited = set()
        to_visit = [base_url]
        forms = []

        while to_visit and len(visited) < max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue

            try:
                response = self.session.get(url, timeout=self.timeout)
                visited.add(url)
            except requests.RequestException:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # Collect links
            for tag in soup.find_all("a", href=True):
                href = urljoin(base_url, tag["href"])
                if href.startswith(base_url) and href not in visited:
                    to_visit.append(href)

            # Collect forms
            for form in soup.find_all("form"):
                forms.append({
                    "page_url": url,
                    "action":   urljoin(url, form.get("action", "")),
                    "method":   form.get("method", "get").lower(),
                    "inputs":   [
                        {"name": i.get("name", ""), "type": i.get("type", "text")}
                        for i in form.find_all("input")
                        if i.get("name")
                    ],
                    "has_csrf_token": any(
                        "csrf" in str(i).lower() or "token" in str(i).lower()
                        for i in form.find_all("input")
                    )
                })

        if self.verbose:
            logger.info(f"    Crawled {len(visited)} page(s), found {len(forms)} form(s).")

        return list(visited), forms

    # ── SQL INJECTION ─────────────────────────────────────

    def _test_sqli(self, ip: str, pages: list, forms: list):
        """Test URL parameters and form fields for SQL injection."""

        # Test URL query parameters
        for url in pages:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in params:
                for payload in SQLI_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        if any(err in r.text.lower() for err in SQLI_ERRORS):
                            self._add_finding(
                                host_ip=ip, url=test_url,
                                vuln_type="SQL Injection",
                                severity="High",
                                description=f"SQL error triggered in parameter '{param}' with payload: {payload}",
                                evidence=r.text[:300],
                                recommendation="Use parameterized queries / prepared statements. Never concatenate user input into SQL."
                            )
                            break
                    except requests.RequestException:
                        continue

        # Test form fields
        for form in forms:
            for input_field in form["inputs"]:
                if input_field["type"] in ("submit", "hidden", "button"):
                    continue
                for payload in SQLI_PAYLOADS[:3]:  # Limit for forms
                    data = {i["name"]: payload for i in form["inputs"]}
                    try:
                        if form["method"] == "post":
                            r = self.session.post(form["action"], data=data, timeout=self.timeout)
                        else:
                            r = self.session.get(form["action"], params=data, timeout=self.timeout)

                        if any(err in r.text.lower() for err in SQLI_ERRORS):
                            self._add_finding(
                                host_ip=ip, url=form["action"],
                                vuln_type="SQL Injection",
                                severity="High",
                                description=f"SQL error in form field '{input_field['name']}'.",
                                evidence=r.text[:300],
                                recommendation="Use parameterized queries. Validate and sanitize all form inputs."
                            )
                            break
                    except requests.RequestException:
                        continue

    # ── TIME-BASED BLIND SQLi ────────────────────────────

    def _test_sqli_blind(self, ip: str, pages: list, forms: list):
        """Test for time-based blind SQL injection."""
        import time

        for url in pages:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in params:
                for payload in SQLI_TIME_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        start = time.time()
                        r = self.session.get(test_url, timeout=10)
                        elapsed = time.time() - start

                        # If response took 3+ seconds, likely time-based SQLi
                        if elapsed >= 3:
                            self._add_finding(
                                host_ip=ip, url=test_url,
                                vuln_type="Blind SQL Injection (Time-Based)",
                                severity="Critical",
                                description=f"Time-based blind SQLi in '{param}'. Response delayed {elapsed:.1f}s with payload: {payload}",
                                evidence=f"Response time: {elapsed:.2f}s (normal < 1s)",
                                recommendation="Use parameterized queries. Never concatenate user input into SQL statements."
                            )
                            break
                    except requests.RequestException:
                        continue

    # ── CROSS-SITE SCRIPTING ──────────────────────────────

    def _test_xss(self, ip: str, pages: list, forms: list):
        """Test for reflected XSS in URL parameters and form fields."""

        for url in pages:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in params:
                for payload in XSS_PAYLOADS[:3]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        if payload in r.text:
                            self._add_finding(
                                host_ip=ip, url=test_url,
                                vuln_type="Cross-Site Scripting (XSS)",
                                severity="Medium",
                                description=f"Reflected XSS in parameter '{param}'.",
                                evidence=f"Payload reflected: {payload}",
                                recommendation="Encode all output. Use Content-Security-Policy headers."
                            )
                            break
                    except requests.RequestException:
                        continue

    # ── XSS IN FORM FIELDS ───────────────────────────────

    def _test_xss_forms(self, ip: str, forms: list):
        """Test XSS specifically in form fields via POST."""
        for form in forms:
            for input_field in form["inputs"]:
                if input_field["type"] in ("submit", "hidden", "button", "file"):
                    continue
                for payload in XSS_PAYLOADS[:5]:
                    data = {i["name"]: "test" for i in form["inputs"]}
                    data[input_field["name"]] = payload
                    try:
                        if form["method"] == "post":
                            r = self.session.post(form["action"], data=data,
                                                  timeout=self.timeout)
                        else:
                            r = self.session.get(form["action"], params=data,
                                                 timeout=self.timeout)

                        if payload in r.text:
                            self._add_finding(
                                host_ip=ip, url=form["action"],
                                vuln_type="Cross-Site Scripting (XSS) — Form Field",
                                severity="High",
                                description=f"Reflected XSS in form field '{input_field['name']}'. Payload reflected in response.",
                                evidence=f"Payload: {payload}",
                                recommendation="Encode all output. Validate and sanitize inputs. Use Content-Security-Policy."
                            )
                            break
                    except requests.RequestException:
                        continue

    # ── DIRECTORY TRAVERSAL ───────────────────────────────

    def _test_traversal(self, ip: str, pages: list):
        """Test for path traversal via URL parameters."""
        traversal_indicators = ["root:x:", "[fonts]", "[boot loader]", "daemon:"]

        for url in pages:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param in params:
                for payload in TRAVERSAL_PAYLOADS:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        r = self.session.get(test_url, timeout=self.timeout)
                        if any(ind in r.text for ind in traversal_indicators):
                            self._add_finding(
                                host_ip=ip, url=test_url,
                                vuln_type="Directory Traversal",
                                severity="High",
                                description=f"Path traversal in parameter '{param}'. Possible file read.",
                                evidence=r.text[:300],
                                recommendation="Validate file paths. Use allowlists. Restrict server file access."
                            )
                            break
                    except requests.RequestException:
                        continue

    # ── SENSITIVE FILE EXPOSURE ───────────────────────────

    def _test_sensitive_files(self, ip: str, base_url: str):
        """Check for exposed sensitive files and directories."""
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    self._add_finding(
                        host_ip=ip, url=url,
                        vuln_type="Sensitive File Exposure",
                        severity="Medium",
                        description=f"Sensitive path accessible: {path}",
                        evidence=f"HTTP 200 OK — {len(r.text)} bytes returned.",
                        recommendation=f"Restrict access to {path}. Use .htaccess or server config rules."
                    )
            except requests.RequestException:
                continue

    # ── CSRF ─────────────────────────────────────────────

    def _test_csrf(self, ip: str, forms: list):
        """Detect forms missing CSRF tokens."""
        for form in forms:
            if form["method"] == "post" and not form["has_csrf_token"]:
                self._add_finding(
                    host_ip=ip, url=form["action"],
                    vuln_type="Missing CSRF Token",
                    severity="Medium",
                    description=f"POST form at {form['action']} has no CSRF token.",
                    evidence="No csrf/token hidden input found in form.",
                    recommendation="Implement CSRF tokens on all state-changing forms. Use SameSite cookie attribute."
                )

    # ── OPEN REDIRECT ─────────────────────────────────────

    def _test_open_redirect(self, ip: str, pages: list):
        """Test for open redirect vulnerabilities."""
        redirect_params = ["redirect", "url", "next", "return", "goto", "dest", "destination"]
        test_url_payload = "https://evil.com"

        for url in pages:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                if param.lower() in redirect_params:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param] = test_url_payload
                    new_query = urlencode(test_params)
                    test_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        r = self.session.get(test_url, timeout=self.timeout,
                                             allow_redirects=False)
                        location = r.headers.get("Location", "")
                        if "evil.com" in location:
                            self._add_finding(
                                host_ip=ip, url=test_url,
                                vuln_type="Open Redirect",
                                severity="Low",
                                description=f"Open redirect via parameter '{param}'.",
                                evidence=f"Redirect to: {location}",
                                recommendation="Validate redirect URLs against an allowlist. Reject external URLs."
                            )
                    except requests.RequestException:
                        continue

    # ── HELPER ───────────────────────────────────────────

    def _add_finding(self, host_ip, url, vuln_type, severity,
                     description, evidence, recommendation):
        """Add a finding to the findings list (deduplication included)."""
        # Simple dedup: skip if same host + vuln_type + url already recorded
        for f in self.findings:
            if f["host_ip"] == host_ip and f["vuln_type"] == vuln_type and f["url"] == url:
                return

        finding = {
            "host_ip":       host_ip,
            "url":           url,
            "vuln_type":     vuln_type,
            "severity":      severity,
            "description":   description,
            "evidence":      evidence,
            "recommendation": recommendation
        }
        self.findings.append(finding)
        logger.info(f"    [{severity.upper()}] {vuln_type} — {url}")
