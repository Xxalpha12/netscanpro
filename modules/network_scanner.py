"""
NetScan Pro - Network Scanner Module
Threaded port scanning with DNS resolution, URL/domain/CIDR support,
banner grabbing, and graceful CIDR limits.
"""

import socket
import ipaddress
import threading
from urllib.parse import urlparse
from modules.logger import get_logger

logger = get_logger(__name__)

MAX_CIDR_HOSTS   = 50    # Safety cap for CIDR scans on Render / Termux
SOCKET_TIMEOUT   = 2     # Seconds per port connection attempt
BANNER_TIMEOUT   = 1     # Seconds to wait for service banner
MAX_THREADS      = 100   # Concurrent threads for port scanning

# ── NMAP CHECK ────────────────────────────────────────────────────────────────

try:
    import nmap
    _nm = nmap.PortScanner()
    _nm.scan("127.0.0.1", arguments="-p 80 --open -Pn")
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False
    logger.warning("nmap not found — using threaded socket fallback.")


# ── SCANNER ───────────────────────────────────────────────────────────────────

class NetworkScanner:

    SCAN_PROFILES = {
        "quick":   "-Pn -sV --top-ports 100 -T4",
        "full":    "-Pn -sV -sC -O -T4",
        "stealth": "-Pn -sS -sV -T2 -f"
    }

    def __init__(self, target: str, port_range: str = "1-1024",
                 scan_type: str = "quick", verbose: bool = False,
                 progress_callback=None):
        self.original_target   = target.strip()
        self.port_range        = port_range
        self.scan_type         = scan_type
        self.verbose           = verbose
        self.progress_callback = progress_callback   # optional fn(pct, msg)
        self.hosts             = []
        self.hostname, self.target = self._resolve_target(self.original_target)

    # ── PUBLIC ────────────────────────────────────────────────────────────────

    def run(self) -> list:
        if not self.target:
            logger.error(f"Could not resolve: {self.original_target}")
            return []

        logger.info(f"Target: {self.original_target}  →  {self.target}")
        self._progress(5, f"Target resolved to {self.target}")

        if NMAP_AVAILABLE:
            return self._scan_with_nmap()
        else:
            logger.info("Using threaded socket scanner.")
            return self._scan_with_sockets()

    def get_web_hosts(self) -> list:
        web_ports = {80, 443, 8080, 8443, 8000, 8888}
        result = []
        for host in self.hosts:
            for port in host["ports"]:
                if port["port"] in web_ports or "http" in str(port.get("service", "")).lower():
                    result.append({
                        "ip":     host["ip"],
                        "port":   port["port"],
                        "scheme": "https" if port["port"] in {443, 8443} else "http"
                    })
        return result

    # ── TARGET RESOLUTION ─────────────────────────────────────────────────────

    def _resolve_target(self, raw: str):
        """
        Accepts IP, CIDR, bare hostname, or full URL.
        Returns (hostname, resolved_ip_or_cidr).
        """
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed   = urlparse(raw)
            hostname = parsed.hostname or raw
        else:
            hostname = raw.split("/")[0]

        # Valid IP or CIDR — no DNS needed
        try:
            ipaddress.ip_network(hostname, strict=False)
            return hostname, hostname
        except ValueError:
            pass

        # Hostname — DNS resolve
        try:
            ip = socket.gethostbyname(hostname)
            logger.info(f"DNS: {hostname} → {ip}")
            return hostname, ip
        except socket.gaierror as e:
            logger.error(f"DNS failed for '{hostname}': {e}")
            return hostname, None

    # ── NMAP SCAN ─────────────────────────────────────────────────────────────

    def _scan_with_nmap(self) -> list:
        nm   = nmap.PortScanner()
        args = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["quick"])
        args += " -p-" if self.scan_type == "full" else f" -p {self.port_range}"

        logger.info(f"Nmap: {args}")
        self._progress(10, "Nmap scan started...")

        try:
            nm.scan(hosts=self.target, arguments=args)
        except Exception as e:
            logger.error(f"Nmap failed: {e}")
            return []

        hosts = []
        total = len(nm.all_hosts()) or 1
        for i, host_ip in enumerate(nm.all_hosts()):
            host_data = {
                "ip":       host_ip,
                "hostname": self.hostname if self.hostname != host_ip else (nm[host_ip].hostname() or "N/A"),
                "status":   nm[host_ip].state(),
                "os":       "Unknown",
                "ports":    []
            }

            if nm[host_ip].get("osmatch"):
                host_data["os"] = nm[host_ip]["osmatch"][0]["name"]

            for proto in nm[host_ip].all_protocols():
                for port in nm[host_ip][proto].keys():
                    p = nm[host_ip][proto][port]
                    host_data["ports"].append({
                        "port":     port,
                        "protocol": proto,
                        "state":    p.get("state"),
                        "service":  p.get("name", "unknown"),
                        "version":  f"{p.get('product','')} {p.get('version','')}".strip() or "N/A"
                    })

            hosts.append(host_data)
            pct = 10 + int((i + 1) / total * 20)
            self._progress(pct, f"Scanned {host_ip} — {len(host_data['ports'])} port(s) open")

        logger.info(f"Nmap done. {len(hosts)} host(s).")
        self.hosts = hosts
        return hosts

    # ── THREADED SOCKET SCAN ──────────────────────────────────────────────────

    def _scan_with_sockets(self) -> list:
        """
        Threaded TCP connect scan.
        Up to MAX_THREADS concurrent connections — dramatically faster than sequential.
        CIDR ranges are capped at MAX_CIDR_HOSTS to avoid timeout on free hosting.
        """
        # Build IP list
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            if len(ips) > MAX_CIDR_HOSTS:
                logger.warning(f"CIDR has {len(ips)} hosts — capping at {MAX_CIDR_HOSTS} for performance.")
                ips = ips[:MAX_CIDR_HOSTS]
        except ValueError:
            ips = [self.target]

        # Parse port range
        try:
            start, end = map(int, self.port_range.split("-"))
        except ValueError:
            start, end = 1, 1024

        ports = list(range(start, end + 1))
        total_work = len(ips) * len(ports)
        done_count = [0]
        lock = threading.Lock()

        all_hosts = []

        for ip_idx, ip in enumerate(ips):
            open_ports = []
            port_lock  = threading.Lock()
            semaphore  = threading.Semaphore(MAX_THREADS)

            def scan_port(p, ip=ip):
                with semaphore:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(SOCKET_TIMEOUT)
                    try:
                        if sock.connect_ex((ip, p)) == 0:
                            service = self._guess_service(p)
                            banner  = self._grab_banner(sock, p)
                            with port_lock:
                                open_ports.append({
                                    "port":     p,
                                    "protocol": "tcp",
                                    "state":    "open",
                                    "service":  service,
                                    "version":  banner or "N/A"
                                })
                    except (socket.timeout, OSError):
                        pass
                    finally:
                        sock.close()
                    with lock:
                        done_count[0] += 1

            # Launch all port threads for this IP
            threads = [threading.Thread(target=scan_port, args=(p,), daemon=True) for p in ports]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            pct = 10 + int((ip_idx + 1) / len(ips) * 20)
            self._progress(pct, f"Scanned {ip} — {len(open_ports)} open port(s)")

            if open_ports:
                open_ports.sort(key=lambda x: x["port"])
                all_hosts.append({
                    "ip":       ip,
                    "hostname": self.hostname if ip == self.target else "N/A",
                    "os":       "Unknown",
                    "status":   "up",
                    "ports":    open_ports
                })

        logger.info(f"Socket scan done. {len(all_hosts)} host(s) with open ports.")
        self.hosts = all_hosts
        return all_hosts

    # ── BANNER GRAB ───────────────────────────────────────────────────────────

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            if port in {80, 8080, 8000, 8888}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            elif port == 443:
                return "HTTPS"
            elif port == 22:
                pass  # SSH sends banner unprompted
            sock.settimeout(BANNER_TIMEOUT)
            raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
            return raw.split("\n")[0][:80] if raw else ""
        except Exception:
            return ""

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _progress(self, pct: int, msg: str):
        if self.progress_callback:
            self.progress_callback(pct, msg)

    @staticmethod
    def _guess_service(port: int) -> str:
        svc = {
            21: "ftp",      22: "ssh",      23: "telnet",
            25: "smtp",     53: "dns",      80: "http",
            110: "pop3",    143: "imap",    443: "https",
            445: "smb",     3306: "mysql",  3389: "rdp",
            5432: "postgresql", 6379: "redis",
            8080: "http-alt", 8443: "https-alt",
            8000: "http-alt", 8888: "http-alt",
            27017: "mongodb"
        }
        return svc.get(port, "unknown")
