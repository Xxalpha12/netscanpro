# modules/cve_scanner.py
import requests
import time
from modules.logger import get_logger

logger = get_logger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_DELAY = 0.6   # Respect NVD rate limit (~5 req/sec without API key)
MAX_CVES = 5


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    if score > 0.0:   return "Low"
    return "None"


class CVEScanner:
    """
    Lookup CVEs for discovered services using the NVD REST API v2.
    Returns findings in the standard DB format for database.save_cve_findings().
    """

    def __init__(self, hosts, verbose=False):
        self.hosts = hosts
        self.verbose = verbose
        self.cache = {}  # Avoid duplicate API calls for same service/version

    def run(self):
        """
        Iterate over all hosts and ports, query NVD for each service,
        and return a flat list of CVE findings.
        """
        findings = []

        for host in self.hosts:
            ip = host.get("ip")
            for port_info in host.get("ports", []):
                service = port_info.get("service", "")
                version = port_info.get("version", "")
                port    = port_info.get("port")

                # Skip generic/unknown services
                if not service or service.lower() in ("unknown", "n/a", "tcpwrapped", ""):
                    continue

                query = f"{service} {version}".strip()
                cves  = self._lookup_cve(query)

                for cve in cves:
                    finding = {
                        "host_ip":     ip,
                        "port":        port,
                        "service":     query,
                        "cve_id":      cve["cve_id"],
                        "cvss_score":  cve["cvss_score"],
                        "severity":    cve["severity"],
                        "description": cve["description"],
                        "reference":   cve["reference"]
                    }
                    findings.append(finding)

                    if self.verbose:
                        logger.info(
                            f"  [{cve['severity']}] {cve['cve_id']} — "
                            f"{ip}:{port} ({service}) CVSS: {cve['cvss_score']}"
                        )

        # Deduplicate by cve_id + host_ip + port
        seen = set()
        deduped = []
        for f in findings:
            key = (f["cve_id"], f["host_ip"], f["port"])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(f"CVE scan complete. {len(deduped)} finding(s).")
        return deduped

    def _lookup_cve(self, query: str) -> list:
        """Query NVD API for CVEs matching a service/version keyword string."""
        if query in self.cache:
            return self.cache[query]

        params = {"keywordSearch": query, "resultsPerPage": MAX_CVES}

        try:
            time.sleep(REQUEST_DELAY)
            r = requests.get(NVD_API_URL, params=params, timeout=10)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            if self.verbose:
                logger.warning(f"  NVD API failed for '{query}': {e}")
            self.cache[query] = []
            return []

        results = []
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            parsed = self._parse_cve(cve_data)
            if parsed:
                results.append(parsed)

        self.cache[query] = results
        return results

    def _parse_cve(self, cve_data: dict) -> dict:
        """Parse a single NVD CVE entry into a standardized dict."""
        cve_id = cve_data.get("id", "N/A")

        # English description
        description = "No description available."
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", description)
                break

        # CVSS score — try v3.1, v3.0, then v2
        cvss_score = 0.0
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_data.get("metrics", {}).get(key)
            if metrics:
                cvss_score = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
                break

        # Reference URL
        refs = cve_data.get("references", [])
        reference = refs[0].get("url") if refs else \
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        return {
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "severity":    _cvss_to_severity(cvss_score),
            "description": description[:500],
            "reference":   reference
        }
