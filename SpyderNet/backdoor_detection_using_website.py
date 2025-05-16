import socket
import subprocess
import argparse
import sys
import time
import urllib.parse
import requests

def detect_backdoor(target):
    """
    Attempts to detect known backdoors on a target (IP address or website) using nmap and other checks.

    Args:
        target (str): The IP address or website URL to scan.
    """

    print(f"[*] Scanning {target} for known backdoors...")

    # 1. Handle Website URL Input
    if target.startswith("http://") or target.startswith("https://"):
        try:
            print("[*] Target is a website. Getting IP address...")
            parsed_url = urllib.parse.urlparse(target)
            hostname = parsed_url.netloc
            target_ip = socket.gethostbyname(hostname)
            print(f"[*] Resolved IP address: {target_ip}")
        except socket.gaierror:
            print("[-] Invalid website URL.")
            sys.exit(1)
    else:
        # 2. Handle IP Address Input
        try:
            socket.inet_aton(target)  # Check if it's a valid IP address
            target_ip = target
        except socket.error:
            print("[-] Invalid IP address format.")
            sys.exit(1)

    # 3. Check for open ports (optional, but recommended)
    try:
        print("[*] Performing a quick port scan...")
        nmap_port_scan_command = ["nmap", "-p21,22,23,80,443,3389", target_ip]  # Check common service ports
        subprocess.run(nmap_port_scan_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error during port scan: {e}")
        print("[-] Continuing with backdoor checks...")

    # 4. D-Link Router Backdoor Check (Primarily for IP addresses)
    print("[*] Checking for D-Link router backdoor (IP address only)...")
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

    # 5. ProFTPD Backdoor Check (Primarily for IP addresses)
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

    # 6. Check for common web backdoors (for websites)
    if target.startswith("http://") or target.startswith("https://"):
        print("[*] Checking for common web backdoors...")
        common_backdoor_paths = [
            "/shell.php",
            "/wso.php",
            "/c99.php",
            "/r57.php",
            "/WebShell.jsp",
            "/admin/config.php",  # Example path
            "/tmp/backdoor.php",
            "/backdoor.jsp",
            "/_vti_bin/owssvr.dll" #Sharepoint backdoor
        ]
        for path in common_backdoor_paths:
            url = urllib.parse.urljoin(target, path)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"[!] Found potential web backdoor at: {url}")
                    #  You might want to add more checks here, like checking for specific content
                elif response.status_code == 403:
                    print(f"[-] {url} Forbidden")
                else:
                    print(f"[+] {url} not found")
            except requests.exceptions.RequestException as e:
                print(f"[-] Error checking {url}: {e}")

    print("[*] Backdoor detection complete.")


def main():
    """
    Main function to take user input and call the backdoor detection.
    """
    parser = argparse.ArgumentParser(description="Detect known backdoors in an IP address or website.")
    parser.add_argument("target", type=str, help="The IP address or website URL to scan.")
    args = parser.parse_args()

    target = args.target
    detect_backdoor(target)



if __name__ == "__main__":
    main()
