import sys
import socket
import ipaddress
import subprocess
import argparse
import struct
import time
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP, UDP, ICMP, SCTP, sr, conf
import threading
import random
import os

# Suppress Scapy warnings
conf.verb = 0

# Default settings
DEFAULT_PORTS = "80,443,22,21,23,25,110,143,3389"
TIMEOUT = 2.0
MAX_THREADS = 50

# Simple service signature database
SERVICE_SIGNATURES = {
    80: {"HTTP/1.": "http", "Apache": "apache", "nginx": "nginx"},
    443: {"HTTP/1.": "https", "SSL": "ssl"},
    22: {"SSH": "ssh"},
    21: {"FTP": "ftp"}
}

# Basic OS signature database (simplified)
OS_SIGNATURES = {
    "ttl=64,window=5840": "Linux",
    "ttl=128,window=8192": "Windows"
}

def get_local_ip() -> Optional[str]:
    """Retrieve the local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except socket.error:
        return None

def get_subnet(ip: str) -> Optional[ipaddress.IPv4Network]:
    """Calculate the subnet range."""
    try:
        return ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return None

def ping_host(host: str, method: str = "tcp") -> bool:
    """Check if a host is alive using specified method (icmp, tcp, arp)."""
    try:
        if method == "icmp":
            packet = IP(dst=host)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            return response is not None
        elif method == "tcp":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                return s.connect_ex((host, 80)) == 0
        elif method == "arp":
            packet = sr1(IP(dst=host)/ICMP(), timeout=1, verbose=0)
            return packet is not None
    except (socket.error, OSError):
        return False

def scan_port(host: str, port: int, scan_type: str = "tcp_connect", timeout: float = TIMEOUT, source_port: Optional[int] = None) -> Optional[Tuple[int, str]]:
    """Scan a single port using specified scan type."""
    try:
        if scan_type == "tcp_syn" and os.geteuid() == 0:
            packet = IP(dst=host)/TCP(dport=port, sport=source_port or random.randint(1024, 65535), flags="S")
            response = sr1(packet, timeout=timeout, verbose=0)
            if response and response.haslayer(TCP) and response[TCP].flags & 0x12 == 0x12:  # SYN/ACK
                return port, "open"
        elif scan_type == "tcp_connect":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if source_port:
                    s.bind(("", source_port))
                result = s.connect_ex((host, port))
                if result == 0:
                    return port, "open"
        elif scan_type == "udp":
            packet = IP(dst=host)/UDP(dport=port)
            response = sr1(packet, timeout=timeout, verbose=0)
            if response and response.haslayer(UDP):
                return port, "open"
            elif response and response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
                return port, "closed"
        elif scan_type == "sctp":
            packet = IP(dst=host)/SCTP(dport=port)/SCTPChunkInit()
            response = sr1(packet, timeout=timeout, verbose=0)
            if response and response.haslayer(SCTP):
                return port, "open"
    except (socket.error, OSError):
        pass
    return None

def get_service_banner(host: str, port: int) -> Optional[str]:
    """Grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            if port in {80, 443}:
                s.send(b"GET / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            for sig, service in SERVICE_SIGNATURES.get(port, {}).items():
                if sig in banner:
                    return service
            return banner[:50] or "unknown"
    except socket.error:
        return None

def detect_os(host: str) -> Optional[str]:
    """Basic OS detection via TCP/IP fingerprinting."""
    try:
        packet = IP(dst=host)/TCP(dport=80, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            ttl = response[IP].ttl
            window = response[TCP].window
            signature = f"ttl={ttl},window={window}"
            return OS_SIGNATURES.get(signature, "unknown")
    except OSError:
        return None

def traceroute(host: str, max_hops: int = 30) -> List[str]:
    """Perform a basic traceroute to map network path."""
    hops = []
    for ttl in range(1, max_hops + 1):
        packet = IP(dst=host, ttl=ttl)/ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            break
        hops.append(response[IP].src)
        if response[IP].src == host:
            break
    return hops

def scan_host(host: str, ports: List[int], scan_type: str, service_detection: bool, timeout: float, source_port: Optional[int], decoys: List[str]) -> Dict:
    """Scan a host with specified options."""
    result = {"host": host, "ports": [], "os": None, "status": "up"}
    packets = []
    for port in ports:
        if decoys:
            for decoy in decoys:
                packets.append(IP(dst=host, src=decoy)/TCP(dport=port, flags="S"))
        else:
            packets.append(IP(dst=host)/TCP(dport=port, sport=source_port or random.randint(1024, 65535), flags="S"))
    
    if packets and scan_type == "tcp_syn" and os.geteuid() == 0:
        responses, _ = sr(packets, timeout=timeout, verbose=0)
        for _, response in responses:
            if response and response.haslayer(TCP) and response[TCP].flags & 0x12 == 0x12:
                port = response[TCP].dport
                service = get_service_banner(host, port) if service_detection else "open"
                result["ports"].append((port, service))
    else:
        with ThreadPoolExecutor(max_threads=MAX_THREADS) as executor:
            futures = [executor.submit(scan_port, host, port, scan_type, timeout, source_port) for port in ports]
            for future in futures:
                scan_result = future.result()
                if scan_result:
                    port, _ = scan_result
                    service = get_service_banner(host, port) if service_detection else "open"
                    result["ports"].append((port, service))
    
    if service_detection:
        result["os"] = detect_os(host)
    
    return result

def parse_ports(port_str: str) -> List[int]:
    """Parse port range or list."""
    ports = set()
    try:
        for part in port_str.replace(" ", "").split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
            else:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
    except ValueError:
        raise ValueError("Invalid port specification")
    return sorted(ports)

def format_results(results: List[Dict], traceroute_data: Optional[Dict] = None) -> str:
    """Format scan results."""
    output = []
    for result in results:
        host = result["host"]
        output.append(f"{host}:")
        if result["os"]:
            output.append(f"OS: {result['os']}")
        if result["ports"]:
            output.append("PORT    SERVICE")
            output.append("-" * 20)
            for port, service in sorted(result["ports"], key=lambda x: x[0]):
                output.append(f"{port:<7} {service}")
        else:
            output.append("No open ports found")
        output.append("")
    
    if traceroute_data:
        for host, hops in traceroute_data.items():
            output.append(f"Traceroute to {host}:")
            output.append(" -> ".join(hops or ["No response"]))
            output.append("")
    
    return "\n".join(output)

def save_xml_output(results: List[Dict], filename: str):
    """Save results in XML format."""
    root = ET.Element("xscan")
    for result in results:
        host_elem = ET.SubElement(root, "host", address=result["host"])
        status = ET.SubElement(host_elem, "status", state=result["status"])
        if result["os"]:
            ET.SubElement(host_elem, "os", name=result["os"])
        ports_elem = ET.SubElement(host_elem, "ports")
        for port, service in result["ports"]:
            port_elem = ET.SubElement(ports_elem, "port", number=str(port))
            ET.SubElement(port_elem, "service", name=service)
    tree = ET.ElementTree(root)
    tree.write(filename)

class CustomHelpParser(argparse.ArgumentParser):
    """Custom parser for newbie-friendly help message."""
    def _print_message(self, message, file=None):
        if message:
            help_text = """
XScan: Advanced Network Scanner
==============================
XScan maps networks, scans ports, detects services, and more, like Nmap.

Usage:
  python3 xscan.py [target] [options]

Arguments:
  target    IP, subnet (e.g., '192.168.1.0/24'), or 'local' for local network

Options:
  -sP            Ping scan to find active hosts
  -sS            TCP SYN scan (requires root)
  -sT            TCP Connect scan
  -sU            UDP scan
  -sY            SCTP scan
  -p, --ports    Ports to scan (e.g., '80,443', '1-100'). Default: common ports
  -sV            Enable service/version detection
  -O             Enable OS detection
  -sC            Run default scripts (or use --script for specific scripts)
  --script       Run specific Nmap NSE scripts (requires Nmap)
  -D             Decoy IPs for evasion (e.g., '192.168.1.2,RND:5')
  --source-port  Set source port for scans
  -f             Enable packet fragmentation (requires root)
  --traceroute   Perform traceroute for network mapping
  -T             Timing template (0=paranoid, 4=aggressive). Default: 3
  -o, --output   Save results to a file (text or XML with .xml extension)
  -t, --timeout  Socket timeout in seconds (default: 2.0)
  -h, --help     Show this help message

Examples:
  Find active hosts:
    python3 xscan.py local -sP
  Scan ports with service detection:
    python3 xscan.py 192.168.1.1 -p 80,443 -sV
  Perform stealth SYN scan:
    sudo python3 xscan.py 192.168.1.1 -sS
  Run vulnerability scripts:
    python3 xscan.py 192.168.1.0/24 --script vuln
  Save results in XML:
    python3 xscan.py 192.168.1.1 -o results.xml

Tips:
- Run as admin (sudo) for SYN scans, OS detection, or fragmentation.
- Use small port ranges (e.g., -p 80,443) for faster scans.
- Install Scapy (pip install scapy) and Nmap for full features.
- Scan only networks you own or have permission for.
"""
            print(help_text, file=file or sys.stdout)

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = CustomHelpParser(add_help=False)
    parser.add_argument("target", help="IP, subnet, or 'local'")
    parser.add_argument("-sP", action="store_true", help="Ping scan only")
    parser.add_argument("-sS", action="store_true", help="TCP SYN scan")
    parser.add_argument("-sT", action="store_true", help="TCP Connect scan")
    parser.add_argument("-sU", action="store_true", help="UDP scan")
    parser.add_argument("-sY", action="store_true", help="SCTP scan")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument("-sV", action="store_true", help="Service detection")
    parser.add_argument("-O", action="store_true", help="OS detection")
    parser.add_argument("-sC", action="store_true", help="Default scripts")
    parser.add_argument("--script", help="Specific NSE scripts")
    parser.add_argument("-D", help="Decoy IPs")
    parser.add_argument("--source-port", type=int, help="Source port")
    parser.add_argument("-f", action="store_true", help="Packet fragmentation")
    parser.add_argument("--traceroute", action="store_true", help="Traceroute")
    parser.add_argument("-T", type=int, choices=range(5), default=3, help="Timing template")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT, help="Socket timeout")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    return parser.parse_args()

def main():
    """Main function to run the network scanner."""
    print("\n=== XScan ===")
    
    args = parse_args()
    
    if args.help:
        parse_args().print_help()
        return

    # Resolve target
    if args.target == "local":
        local_ip = get_local_ip()
        if not local_ip:
            print("Error: Could not retrieve local IP")
            return
        subnet = get_subnet(local_ip)
    else:
        subnet = get_subnet(args.target)
    
    if not subnet:
        print("Error: Invalid target")
        return

    print(f"Target: {subnet} ({len(list(subnet.hosts()))} hosts)")

    # Determine scan type
    scan_type = "tcp_connect"
    if args.sS and os.geteuid() == 0:
        scan_type = "tcp_syn"
    elif args.sU:
        scan_type = "udp"
    elif args.sY:
        scan_type = "sctp"
    elif args.sT:
        scan_type = "tcp_connect"

    # Parse ports
    ports = [] if args.sP else parse_ports(args.ports)

    # Parse decoys
    decoys = []
    if args.D:
        decoys = [d for d in args.D.split(",") if d != "RND"]
        if "RND" in args.D:
            decoys.extend([f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in range(5)])

    # Adjust timeout based on timing template
    timeout = args.timeout / (args.T + 1)

    # Host discovery
    print("\nDiscovering hosts...")
    active_hosts = []
    with ThreadPoolExecutor(max_threads=MAX_THREADS) as executor:
        futures = {executor.submit(ping_host, str(host), "tcp"): host for host in subnet.hosts()}
        for future in futures:
            if future.result():
                active_hosts.append(futures[future])

    if not active_hosts:
        print("No active hosts found")
        return

    print(f"Found {len(active_hosts)} active hosts")

    results = []
    traceroute_data = {}

    if args.sP:
        print("\nActive Hosts:")
        print("\n".join(str(host) for host in active_hosts))
    else:
        # Run NSE scripts via Nmap if specified
        if args.sC or args.script:
            print("\nRunning NSE scripts...")
            script = args.script or "default"
            cmd = ["nmap", "-p", args.ports, "--script", script, str(subnet)]
            try:
                nmap_result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                print("\nNSE Results:")
                print(nmap_result.stdout)
                if args.output:
                    with open(args.output, "w") as f:
                        f.write(nmap_result.stdout)
                    print(f"Saved NSE results to {args.output}")
            except subprocess.SubprocessError:
                print("Error: NSE scan failed")
            return

        # Port scanning
        print(f"\nScanning {len(ports)} ports on {len(active_hosts)} hosts...")
        start_time = time.time()
        for host in active_hosts:
            result = scan_host(str(host), ports, scan_type, args.sV or args.O, timeout, args.source_port, decoys)
            results.append(result)

        # Traceroute
        if args.traceroute:
            print("\nMapping network...")
            for host in active_hosts:
                traceroute_data[str(host)] = traceroute(str(host))

        # Output results
        output = format_results(results, traceroute_data)
        print("\nResults:\n")
        print(output)
        
        if args.output:
            if args.output.endswith(".xml"):
                save_xml_output(results, args.output)
            else:
                with open(args.output, "w") as f:
                    f.write(output)
            print(f"\nSaved results to {args.output}")

        print(f"\nScan completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()