import argparse
import socket
import asyncio
import platform
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sr1, IP, TCP
import requests

# Function to scan a single port asynchronously
async def scan_port(ip, port, timeout=1):
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        print(f"[+] Port {port} is OPEN")
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

# Function to detect OS using Scapy
def detect_os(ip):
    print("\n[+] Performing OS Detection...")
    try:
        packet = IP(dst=ip) / TCP(dport=80, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).window > 1000:
                print("[*] OS Detected: Likely Windows")
            else:
                print("[*] OS Detected: Likely Linux/Unix")
        else:
            print("[-] OS Detection Failed")
    except Exception as e:
        print(f"[-] Error in OS Detection: {e}")

# Function to detect service running on open ports
def detect_service(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode().strip()
            print(f"[+] Service on Port {port}: {banner}")
    except:
        print(f"[-] Unable to detect service on Port {port}")

# Function to check CVEs for common services
def check_cve(service_name):
    print(f"\n[+] Checking CVEs for {service_name}...")
    try:
        url = f"https://cve.circl.lu/api/search/{service_name}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for cve in data[:5]:  # Show top 5 CVEs
                print(f"[CVE] {cve['id']} - {cve['summary']}")
        else:
            print("[-] No CVEs found")
    except Exception as e:
        print(f"[-] Error in CVE Lookup: {e}")

# Main function to scan ports
async def main(ip, ports, detect_os_flag, detect_service_flag, check_cve_flag):
    print(f"\n[+] Scanning {ip} for open ports...\n")
    open_ports = []

    # Use asyncio for efficient scanning
    tasks = [scan_port(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [port for port in results if port is not None]

    if detect_os_flag:
        detect_os(ip)

    if detect_service_flag:
        print("\n[+] Detecting Services...\n")
        for port in open_ports:
            detect_service(ip, port)

    if check_cve_flag:
        print("\n[+] Checking Vulnerabilities...\n")
        for port in open_ports:
            service_name = f"port{port}"
            check_cve(service_name)

# Parse CLI arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("ip", help="Target IP Address")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 20-80 or 22,80,443)")
    parser.add_argument("--os", action="store_true", help="Enable OS Fingerprinting")
    parser.add_argument("--service", action="store_true", help="Enable Service Detection")
    parser.add_argument("--cve", action="store_true", help="Check for CVEs on detected services")

    args = parser.parse_args()

    # Parse ports
    ports = []
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    else:
        ports = list(map(int, args.ports.split(",")))

    # Run scanner
    asyncio.run(main(args.ip, ports, args.os, args.service, args.cve))
