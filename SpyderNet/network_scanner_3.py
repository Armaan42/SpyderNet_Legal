import sys
import subprocess
import argparse
import xml.etree.ElementTree as ET
import ipaddress
import socket
import time
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

# Default settings
DEFAULT_PORTS = "80,443,22,21,23,25,110,143,3389"
TIMEOUT = 2.0
MAX_THREADS = 50

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

def run_nmap(args: List[str], target: str, output_file: str = "xscan_temp.xml") -> Optional[str]:
    """Execute Nmap with given arguments and capture XML output."""
    cmd = ["nmap", "-oX", output_file] + args + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(output_file, "r") as f:
            return f.read()
    except subprocess.SubprocessError as e:
        print(f"Nmap Error: {e.stderr}")
        return None
    finally:
        try:
            import os
            os.remove(output_file)
        except OSError:
            pass

def parse_nmap_xml(xml_data: str) -> List[Dict]:
    """Parse Nmap XML output into structured results."""
    results = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall(".//host"):
            result = {"host": "", "ports": [], "os": None, "status": "up"}
            address = host.find("address[@addrtype='ipv4']")
            if address is not None:
                result["host"] = address.get("addr")
            
            status = host.find("status")
            if status is not None:
                result["status"] = status.get("state")
            
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                result["os"] = osmatch.get("name", "unknown")
            
            for port in host.findall(".//port"):
                portid = port.get("portid")
                state = port.find("state")
                if state.get("state") == "open":
                    service = port.find("service")
                    service_name = service.get("name", "unknown") if service else "unknown"
                    product = service.get("product", "") if service else ""
                    version = service.get("version", "") if service else ""
                    service_info = f"{service_name} {product} {version}".strip()
                    result["ports"].append((int(portid), service_info or "open"))
            
            results.append(result)
    except ET.ParseError:
        pass
    return results

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
    """Save results in custom XML format."""
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

def interactive_mode() -> tuple[str, bool, bool, bool, str]:
    """Run an interactive menu for selecting scan options."""
    print("\nScan Options:")
    print("1. Find active hosts (ping scan)")
    print("2. Scan common ports")
    print("3. Scan specific ports with service detection")
    print("4. Scan with vulnerability scripts")
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        return "", False, False, False, "ping"
    elif choice == "2":
        return DEFAULT_PORTS, True, False, False, "tcp_connect"
    elif choice == "3":
        ports = input("Enter ports (e.g., 80,443): ").strip() or DEFAULT_PORTS
        return ports, True, True, False, "tcp_connect"
    elif choice == "4":
        return DEFAULT_PORTS, True, True, True, "tcp_connect"
    else:
        raise ValueError("Invalid choice")

class CustomHelpParser(argparse.ArgumentParser):
    """Custom parser for newbie-friendly help message."""
    def _print_message(self, message, file=None):
        if message:
            help_text = """
XScan: Network Scanner
======================
XScan finds devices, checks open ports, and identifies services on your network.

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
  -sC            Run default scripts
  --script       Run specific scripts (e.g., 'vuln')
  -D             Decoy IPs for evasion (e.g., '192.168.1.2,RND:5')
  --source-port  Set source port for scans
  -f             Enable packet fragmentation (requires root)
  --traceroute   Perform traceroute for network mapping
  -T             Timing template (0=paranoid, 4=aggressive). Default: 3
  -o, --output   Save results to a file (text or XML with .xml extension)
  -i, --interactive  Run in interactive mode
  -t, --timeout  Timeout in seconds (default: 2.0)
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
  Run interactively:
    python3 xscan.py local -i

Tips:
- Run as admin (sudo) for SYN scans, OS detection, or advanced features.
- Use small port ranges (e.g., -p 80,443) for faster scans.
- Install Nmap (https://nmap.org) for full functionality.
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
    parser.add_argument("--script", help="Specific scripts")
    parser.add_argument("-D", help="Decoy IPs")
    parser.add_argument("--source-port", type=int, help="Source port")
    parser.add_argument("-f", action="store_true", help="Packet fragmentation")
    parser.add_argument("--traceroute", action="store_true", help="Traceroute")
    parser.add_argument("-T", type=int, choices=range(5), default=3, help="Timing template")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-t", "--timeout", type=float, default=TIMEOUT, help="Timeout")
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
        if subnet.num_addresses == 1:
            subnet = get_subnet(f"{local_ip}/24")  # Expand to /24 for ping scans
    else:
        subnet = get_subnet(args.target)
    
    if not subnet:
        print("Error: Invalid target")
        return

    print(f"Target: {subnet} ({len(list(subnet.hosts()))} hosts)")

    # Interactive mode
    ports = args.ports
    service_detection = args.sV
    os_detection = args.O
    script = args.script or ("default" if args.sC else None)
    scan_type = "tcp_connect"
    
    if args.interactive:
        try:
            ports, service_detection, os_detection, use_script, scan_type = interactive_mode()
            if use_script:
                script = "vuln"
        except ValueError as e:
            print(f"Error: {e}")
            return

    # Build Nmap command
    nmap_args = []
    if args.sP or scan_type == "ping":
        nmap_args.append("-sn")
        # Add TCP ping for single-host targets to improve reliability
        if subnet.num_addresses == 1:
            nmap_args.extend(["-PS80,443"])
    else:
        if args.sS or scan_type == "tcp_syn":
            nmap_args.append("-sS")
        elif args.sU or scan_type == "udp":
            nmap_args.append("-sU")
        elif args.sY or scan_type == "sctp":
            nmap_args.append("-sY")
        elif args.sT or scan_type == "tcp_connect":
            nmap_args.append("-sT")
        
        nmap_args.extend(["-p", ports])
        
        if service_detection:
            nmap_args.append("-sV")
        if os_detection:
            nmap_args.append("-O")
        if script:
            nmap_args.extend(["--script", script])
        if args.D:
            nmap_args.extend(["-D", args.D])
        if args.source_port:
            nmap_args.extend(["--source-port", str(args.source_port)])
        if args.f:
            nmap_args.append("-f")
        if args.traceroute:
            nmap_args.append("--traceroute")
        nmap_args.extend(["-T", str(args.T)])

    # Run Nmap scan
    print(f"\nScanning {subnet} ({scan_type} scan)...")
    start_time = time.time()
    xml_data = run_nmap(nmap_args, str(subnet))
    
    if not xml_data:
        print("Error: Scan failed")
        return

    # Parse and format results
    results = parse_nmap_xml(xml_data)
    traceroute_data = {}
    if args.traceroute:
        for host in results:
            xml_host = ET.fromstring(xml_data).find(f".//host[address[@addr='{host['host']}']]")
            trace = xml_host.find("trace") if xml_host is not None else None
            if trace:
                hops = [hop.get("ipaddr") for hop in trace.findall("hop") if hop.get("ipaddr")]
                traceroute_data[host["host"]] = hops

    if results:
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
    else:
        print("\nNo results found")

    print(f"\nScan completed in {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()