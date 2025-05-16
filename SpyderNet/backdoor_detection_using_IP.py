import socket
import subprocess
import argparse
import sys
import time

def detect_backdoor(target_ip):
    """
    Attempts to detect known backdoors on a target IP address using nmap.

    Args:
        target_ip (str): The IP address to scan.
    """

    print(f"[*] Scanning {target_ip} for known backdoors...")

    # 1. Check for open ports (optional, but recommended)
    try:
        print("[*] Performing a quick port scan...")
        nmap_port_scan_command = ["nmap", "-p21,22,23,80,443,3389", target_ip]  # Check common service ports
        subprocess.run(nmap_port_scan_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during port scan: {e}")
        print("[-] Continuing with backdoor checks...")

    # 2. D-Link Router Backdoor Check
    print("[*] Checking for D-Link router backdoor...")
    nmap_dlink_command = ["nmap", "-sV", "--script", "http-dlink-backdoor", target_ip]
    try:
        result = subprocess.run(nmap_dlink_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if "VULNERABLE" in output:
            print("[!] Found D-Link router backdoor!")
            print(output)  # Print the full nmap output
        else:
            print("[+] D-Link router backdoor check: No vulnerability found.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error checking for D-Link router backdoor: {e}")

    # 3. ProFTPD Backdoor Check
    print("[*] Checking for ProFTPD backdoor...")
    nmap_proftpd_command = ["nmap", "--script", "ftp-proftpd-backdoor", "-p", "21", target_ip]
    try:
        result = subprocess.run(nmap_proftpd_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = result.stdout.decode()
        if "VULNERABLE" in output:
            print("[!] Found ProFTPD backdoor!")
            print(output)
        else:
            print("[+] ProFTPD backdoor check: No vulnerability found.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error checking for ProFTPD backdoor: {e}")

    print("[*] Backdoor detection complete.")

def main():
    """
    Main function to take user input and call the backdoor detection.
    """
    parser = argparse.ArgumentParser(description="Detect known backdoors in an IP address.")
    parser.add_argument("ip_address", type=str, help="The IP address to scan.")
    args = parser.parse_args()

    target_ip = args.ip_address

    # Basic IP address validation
    try:
        socket.inet_aton(target_ip)  # Check if it's a valid IP address
    except socket.error:
        print("[-] Invalid IP address format.")
        sys.exit(1)

    detect_backdoor(target_ip)

if __name__ == "__main__":
    main()
