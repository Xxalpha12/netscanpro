"""
NetScan Pro - Network Scanner Module
Supports IP addresses, CIDR ranges, domain names, and URLs.
Automatically falls back to socket scanning if nmap is unavailable.
"""

import socket
import re
from urllib.parse import urlparse
from modules.logger import get_logger

logger = get_logger(__name__)

# Try nmap
try:
    import nmap
    nm_test = nmap.PortScanner()
    nm_test.scan("127.0.0.1", arguments="-p 80 --open")
    NMAP_AVAILABLE = True
    logger.info("nmap detected — using full nmap scanner.")
except Exception:
    NMAP_AVAILABLE = False
    logger.warning("nmap not available — using socket fallback.")


COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 8888, 27017
]

SERVICE_MAP = {
    21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp",
    53:"dns", 80:"http", 110:"pop3", 135:"msrpc",
    139:"netbios-ssn", 143:"imap", 443:"https",
    445:"microsoft-ds", 3306:"mysql", 3389:"rdp",
    5432:"postgresql", 5900:"vnc", 6379:"redis",
    8080:"http-alt", 8443:"https-alt", 8888:"http-alt",
    27017:"mongodb"
}


def resolve_target(target: str) -> tuple:
    """
    Resolve any target format to (ip, hostname, original).
    Supports: IP, CIDR, domain, http://..., https://...
    Returns (resolved_ip, hostname, is_cidr)
    """
    original = target.strip()

    # Strip URL scheme if present
    if original.startswith(("http://", "https://")):
        parsed = urlparse(original)
        hostname = parsed.hostname or parsed.netloc.split(":")[0]
    else:
        hostname = original

    # Check if CIDR range
    is_cidr = "/" in hostname and not hostname.startswith("http")
    if is_cidr:
        return hostname, hostname, True

    # Check if already an IP
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if ip_pattern.match(hostname):
        return hostname, hostname, False

    # DNS resolution
    try:
        resolved_ip = socket.gethostbyname(hostname)
        logger.info(f"Resolved {hostname} → {resolved_ip}")
        return resolved_ip, hostname, False
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for '{hostname}': {e}")
        return hostname, hostname, False


class NetworkScanner:

    SCAN_PROFILES = {
        "quick":   "-Pn -sV --top-ports 100 -T4",
        "full":    "-Pn -sV -sC -O -p- -T4",
        "stealth": "-Pn -sS -sV -T2 -f"
    }

    def __init__(self, target: str, port_range: str = "1-1024",
                 scan_type: str = "quick", verbose: bool = False):
        self.original_target = target
        self.port_range  = port_range
        self.scan_type   = scan_type
        self.verbose     = verbose
        self.hosts       = []

        # Resolve target
        self.resolved_ip, self.hostname, self.is_cidr = resolve_target(target)
        logger.info(f"Target resolved: {target} → {self.resolved_ip}")

    def run(self) -> list:
        if NMAP_AVAILABLE:
            return self._scan_with_nmap()
        else:
            return self._scan_with_sockets()

    # ── NMAP ─────────────────────────────────────────────

    def _scan_with_nmap(self) -> list:
        import nmap
        nm   = nmap.PortScanner()
        args = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["quick"])
        if self.scan_type != "quick":
            args += f" -p {self.port_range}"

        scan_target = self.resolved_ip if not self.is_cidr else self.original_target
        logger.info(f"nmap scan: {scan_target} args='{args}'")

        try:
            nm.scan(hosts=scan_target, arguments=args)
        except Exception as e:
            logger.error(f"nmap failed: {e}. Falling back to sockets.")
            return self._scan_with_sockets()

        hosts = []
        for ip in nm.all_hosts():
            host_data = self._parse_nmap_host(nm, ip)
            hosts.append(host_data)

        logger.info(f"nmap complete. {len(hosts)} host(s) found.")
        self.hosts = hosts
        return hosts

    def _parse_nmap_host(self, nm, ip: str) -> dict:
        host = nm[ip]
        hostname = self.hostname if self.hostname != ip else host.hostname() or "N/A"

        os_name = "Unknown"
        if "osmatch" in host and host["osmatch"]:
            os_name = host["osmatch"][0].get("name", "Unknown")

        ports = []
        for proto in host.all_protocols():
            for port_num in sorted(host[proto].keys()):
                port_info = host[proto][port_num]
                ports.append({
                    "port":     port_num,
                    "protocol": proto,
                    "state":    port_info.get("state", "unknown"),
                    "service":  port_info.get("name", "unknown"),
                    "version":  f"{port_info.get('product','')} {port_info.get('version','')}".strip() or "N/A"
                })

        return {
            "ip": ip, "hostname": hostname,
            "os": os_name, "status": host.state(),
            "ports": ports
        }

    # ── SOCKET FALLBACK ───────────────────────────────────

    def _scan_with_sockets(self) -> list:
        """
        TCP connect scanner with proper timeouts.
        Works on cloud environments without nmap.
        Supports domains, URLs, and IPs.
        """
        target_ip = self.resolved_ip.split("/")[0]  # Handle CIDR
        logger.info(f"Socket scan: {target_ip} (resolved from {self.original_target})")

        port_list = self._build_port_list()
        open_ports = []

        for port in port_list:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2 second timeout per port
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    service = SERVICE_MAP.get(port, "unknown")
                    # Try to grab banner for version info
                    version = self._grab_banner(target_ip, port, service)
                    open_ports.append({
                        "port":     port,
                        "protocol": "tcp",
                        "state":    "open",
                        "service":  service,
                        "version":  version
                    })
                    if self.verbose:
                        logger.info(f"  Open: {port}/tcp ({service})")
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        hostname = self.hostname if self.hostname != target_ip else "N/A"

        host = {
            "ip":       target_ip,
            "hostname": hostname,
            "os":       "Unknown (socket scan)",
            "status":   "up" if open_ports else "unknown",
            "ports":    open_ports
        }

        self.hosts = [host]
        logger.info(f"Socket scan complete. {len(open_ports)} open port(s) on {target_ip}.")
        return [host]

    def _grab_banner(self, ip: str, port: int, service: str) -> str:
        """Try to grab a service banner for version info."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            if service in ("http", "http-alt"):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            sock.close()
            # Extract useful part
            for line in banner.split("\n"):
                if any(kw in line.lower() for kw in ("server:", "ssh-", "220 ", "ftp")):
                    return line.strip()[:60]
        except Exception:
            pass
        return "N/A"

    def _build_port_list(self) -> list:
        if self.scan_type == "quick":
            return COMMON_PORTS
        try:
            start, end = self.port_range.split("-")
            end = min(int(end), 1024)  # Cap on cloud
            return list(range(int(start), end + 1))
        except ValueError:
            return COMMON_PORTS

    def get_web_hosts(self) -> list:
        web_hosts = []
        web_ports = {80, 443, 8080, 8443, 8000, 8888}
        for host in self.hosts:
            for port in host.get("ports", []):
                if port["port"] in web_ports or "http" in port.get("service", "").lower():
                    web_hosts.append({
                        "ip":     host["ip"],
                        "port":   port["port"],
                        "scheme": "https" if port["port"] in {443, 8443} else "http",
                        "service": port.get("service")
                    })
                    break
        return web_hosts
