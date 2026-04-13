"""
NetScan Pro - Subdomain Discovery Module
Discovers subdomains using:
  1. Free HackerTarget API
  2. Common subdomain wordlist bruteforce
  3. DNS zone transfer attempt
"""

import socket
import requests
from modules.logger import get_logger

logger = get_logger(__name__)

requests.packages.urllib3.disable_warnings()

# Common subdomains to check
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
    "admin", "api", "dev", "staging", "test", "portal",
    "vpn", "remote", "blog", "shop", "store", "app",
    "m", "mobile", "static", "cdn", "media", "images",
    "login", "secure", "webmail", "dashboard", "cpanel",
    "whm", "autodiscover", "autoconfig", "mx", "email",
    "support", "help", "docs", "wiki", "git", "gitlab",
    "jenkins", "jira", "confluence", "monitor", "status"
]


class SubdomainScanner:
    """
    Discovers subdomains for a target domain.
    Works on Render free tier — uses HTTP/DNS only, no raw sockets.
    """

    def __init__(self, target: str, verbose: bool = False, timeout: int = 5):
        self.target  = self._extract_domain(target)
        self.verbose = verbose
        self.timeout = timeout
        self.found   = []

    def run(self) -> list:
        """Run all subdomain discovery methods and return results."""
        if not self.target or self._is_ip(self.target):
            logger.info("Subdomain scan skipped — target is an IP address.")
            return []

        logger.info(f"Starting subdomain discovery for: {self.target}")

        # Method 1: HackerTarget API (free, no key needed)
        self._hackertarget_lookup()

        # Method 2: DNS bruteforce with common wordlist
        self._dns_bruteforce()

        # Deduplicate
        seen = set()
        deduped = []
        for s in self.found:
            if s["subdomain"] not in seen:
                seen.add(s["subdomain"])
                deduped.append(s)

        logger.info(f"Subdomain discovery complete. {len(deduped)} subdomain(s) found.")
        return deduped

    def _hackertarget_lookup(self):
        """Query HackerTarget's free API for known subdomains."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
            r = requests.get(url, timeout=self.timeout)
            if r.status_code == 200 and "error" not in r.text.lower():
                for line in r.text.strip().split("\n"):
                    if "," in line:
                        subdomain, ip = line.split(",", 1)
                        subdomain = subdomain.strip()
                        ip = ip.strip()
                        if subdomain and self.target in subdomain:
                            self.found.append({
                                "subdomain": subdomain,
                                "ip":        ip,
                                "method":    "HackerTarget API"
                            })
                            if self.verbose:
                                logger.info(f"  Found: {subdomain} → {ip}")
        except Exception as e:
            logger.warning(f"HackerTarget API failed: {e}")

    def _dns_bruteforce(self):
        """Try resolving common subdomains via DNS."""
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(fqdn)
                self.found.append({
                    "subdomain": fqdn,
                    "ip":        ip,
                    "method":    "DNS Bruteforce"
                })
                if self.verbose:
                    logger.info(f"  Found: {fqdn} → {ip}")
            except socket.gaierror:
                pass  # Subdomain doesn't exist

    def _extract_domain(self, target: str) -> str:
        """Extract base domain from URL or hostname."""
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            target = urlparse(target).hostname or target
        # Remove www prefix
        if target.startswith("www."):
            target = target[4:]
        return target

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
