"""
NetScan Pro - Network Scanner Module
Performs host discovery, port scanning, service detection,
and OS fingerprinting using python-nmap and Scapy.
"""

import socket
from modules.logger import get_logger

logger = get_logger(__name__)

try:
    import nmap
    nm_test = nmap.PortScanner()
    nm_test.scan("127.0.0.1", arguments="-p 80 --open")
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False
    logger.warning("nmap binary not found - using socket fallback.")

class NetworkScanner:

    SCAN_PROFILES = {
        "quick": "-Pn -sV --top-ports 100 -T4",
        "full": "-Pn -sV -sC -O -T4",  # ports handled separately
        "stealth": "-Pn -sS -sV -T2 -f"
    }

    def __init__(self, target: str, port_range: str = "1-1024",
                 scan_type: str = "quick", verbose: bool = False):

        self.target = target
        self.port_range = port_range
        self.scan_type = scan_type
        self.verbose = verbose
        self.hosts = []

    def run(self) -> list:

        if NMAP_AVAILABLE:
            return self._scan_with_nmap()
        else:
            logger.warning("Nmap not available. Falling back to socket scan.")
            return self._scan_with_sockets()

    # ----------------------------------------------------
    # NMAP SCAN
    # ----------------------------------------------------

    def _scan_with_nmap(self):

        nm = nmap.PortScanner()

        args = self.SCAN_PROFILES.get(self.scan_type, self.SCAN_PROFILES["quick"])

        # Port handling logic
        if self.scan_type == "full":
            args += " -p-"  # scan ALL ports

        elif self.scan_type in ["quick", "stealth"]:
            args += f" -p {self.port_range}"

        logger.info(f"Starting nmap scan: target={self.target}, args='{args}'")

        try:
            nm.scan(hosts=self.target, arguments=args)
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return []

        hosts = []

        for host in nm.all_hosts():

            host_data = {
                "ip": host,
                "hostname": nm[host].hostname() or "N/A",
                "status": nm[host].state(),
                "os": "Unknown",
                "ports": []
            }

            # OS detection
            if "osmatch" in nm[host] and nm[host]["osmatch"]:
                host_data["os"] = nm[host]["osmatch"][0]["name"]

            # Ports
            for proto in nm[host].all_protocols():

                ports = nm[host][proto].keys()

                for port in ports:

                    p = nm[host][proto][port]

                    host_data["ports"].append({
                        "port": port,
                        "protocol": proto,
                        "state": p.get("state"),
                        "service": p.get("name"),
                        "product": p.get("product", ""),
                        "version": p.get("version", "")
                    })

            hosts.append(host_data)

            if self.verbose:
                logger.info(f"{host} | {len(host_data['ports'])} open ports")

        logger.info(f"Nmap scan complete. {len(hosts)} host(s) found.")

        self.hosts = hosts
        return hosts

    # ----------------------------------------------------
    # SOCKET FALLBACK
    # ----------------------------------------------------

    def _scan_with_sockets(self):

        logger.info(f"Starting socket scan on {self.target}")

        try:
            start, end = map(int, self.port_range.split("-"))
        except ValueError:
            start, end = 1, 1024

        ports = range(start, end + 1)

        open_ports = []

        for port in ports:

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)

                if sock.connect_ex((self.target, port)) == 0:

                    open_ports.append({
                        "port": port,
                        "protocol": "tcp",
                        "state": "open",
                        "service": self._guess_service(port),
                        "version": "N/A"
                    })

                    if self.verbose:
                        logger.info(f"Open port: {port}")

                sock.close()

            except Exception:
                pass

        host = {
            "ip": self.target,
            "hostname": "N/A",
            "os": "Unknown",
            "status": "up",
            "ports": open_ports
        }

        self.hosts = [host]
        return [host]

    # ----------------------------------------------------
    # HELPERS
    # ----------------------------------------------------

    def get_web_hosts(self):

        web_hosts = []

        web_ports = {80, 443, 8080, 8443, 8000, 8888}

        for host in self.hosts:

            for port in host["ports"]:

                if port["port"] in web_ports or "http" in str(port["service"]).lower():

                    web_hosts.append({
                        "ip": host["ip"],
                        "port": port["port"],
                        "scheme": "https" if port["port"] in [443, 8443] else "http"
                    })

        return web_hosts

    def _guess_service(self, port):

        common = {
            21: "ftp",
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp"
        }

        return common.get(port, "unknown")
