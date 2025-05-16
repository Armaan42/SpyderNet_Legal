import sys
import socket
import ipaddress
import subprocess
import argparse
from typing import Optional

def get_local_ip() -> Optional[str]:
    """Retrieve the local IP address of the machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except socket.error:
        return None

def get_subnet(ip: str) -> Optional[ipaddress.IPv4Network]:
    """Calculate the subnet range based on the local IP (assumes /24)."""
    try:
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return None

def scan_subnet(subnet: ipaddress.IPv4Network, ports: str = "1-65535", vuln: bool = False) -> Optional[str]:
    """Scan the subnet for active hosts, open ports, and optionally vulnerabilities."""
    try:
        cmd = ["nmap", "-p", ports, "-sV"]
        if vuln:
            cmd.extend(["--script", "vuln"])
        cmd.append(str(subnet))
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.SubprocessError as e:
        return None

def format_subnet_info(subnet: ipaddress.IPv4Network) -> str:
    """Format subnet information for display."""
    hosts = len(list(subnet.hosts()))
    return f"Subnet: {subnet} ({hosts} hosts, {subnet.network_address} - {subnet.broadcast_address})"

def interactive_mode() -> tuple[str, bool]:
    """Run an interactive menu for selecting scan options."""
    print("\nScan Options:")
    print("1. Full port scan (1-65535)")
    print("2. Quick scan (top 1000 ports)")
    print("3. Full port vulnerability scan")
    print("4. Quick vulnerability scan (top 1000 ports)")
    choice = input("\nEnter choice (1-4): ").strip()
    
    if choice == "1":
        return "1-65535", False
    elif choice == "2":
        return "1-1000", False
    elif choice == "3":
        return "1-65535", True
    elif choice == "4":
        return "1-1000", True
    else:
        raise ValueError("Invalid choice")

class CustomHelpParser(argparse.ArgumentParser):
    """Custom parser to display a newbie-friendly help message."""
    def _print_message(self, message, file=None):
        if message:
            help_text = """
NetScan: A Network Scanner
=========================
NetScan scans your local network to find active devices, open ports, and optionally check for vulnerabilities using Nmap.

Usage:
  python3 netscan.py [options]

Options:
  -p, --ports PORTS    Port range to scan (e.g., '1-1000', '80,443'). Default: 1-65535
  -v, --vuln           Enable vulnerability scanning with Nmap scripts
  -o, --output FILE    Save scan results to a file
  -i, --interactive    Run in interactive mode (choose scan via menu)
  -h, --help           Show this help message

Examples:
  Scan all ports:
    python3 netscan.py
  Scan top 1000 ports:
    python3 netscan.py -p 1-1000
  Scan for vulnerabilities on all ports:
    python3 netscan.py -v
  Save results to a file:
    python3 netscan.py -o results.txt
  Run interactively:
    python3 netscan.py -i

Tips:
- Start with small port ranges (e.g., 1-1000) for faster scans.
- Use -o to save results for later review.
- Ensure Nmap is installed (https://nmap.org).
- Run as administrator for best results.
"""
            print(help_text, file=file or sys.stdout)

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = CustomHelpParser(add_help=False)
    parser.add_argument("-p", "--ports", default="1-65535", help="Port range to scan")
    parser.add_argument("-v", "--vuln", action="store_true", help="Enable vulnerability scanning")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message")
    return parser.parse_args()

def main():
    """Main function to run the network scanner."""
    print("\n=== NetScan ===")
    
    args = parse_args()
    
    if args.help:
        parse_args().print_help()
        return

    local_ip = get_local_ip()
    if not local_ip:
        print("Error: Could not retrieve local IP address.")
        return

    subnet = get_subnet(local_ip)
    if not subnet:
        print("Error: Could not calculate subnet.")
        return

    print(format_subnet_info(subnet))

    ports = args.ports
    vuln = args.vuln
    if args.interactive:
        try:
            ports, vuln = interactive_mode()
        except ValueError as e:
            print(f"Error: {e}")
            return

    print(f"\nScanning {subnet} (ports: {ports}, vuln: {vuln})...")
    result = scan_subnet(subnet, ports, vuln)

    if result:
        print("\nResults:\n")
        print(result)
        if args.output:
            with open(args.output, "w") as f:
                f.write(result)
            print(f"\nSaved results to {args.output}")
    else:
        print("\nError: Scan failed.")

if __name__ == "__main__":
    main()