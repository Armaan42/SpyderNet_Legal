from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
import sys
import threading
import time
import requests


# Function to Get MAC Vendor Information
def get_mac_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
    except requests.exceptions.RequestException:
        pass
    return "Unknown Vendor"


# Function to Scan Network
def network_scan(target_network):
    print("\n[+] Scanning the network... Please wait.")
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=target_network)
    probe = ether / arp

    # Send ARP request and receive responses
    answered, _ = srp(probe, timeout=3, verbose=False)

    online_clients = []
    router_info = None

    for sent, received in answered:
        vendor = get_mac_vendor(received.hwsrc)
        client = {'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor}

        # If it's a router (based on vendor name), store separately
        if "zte" in vendor.lower() or "router" in vendor.lower():
            router_info = client

        online_clients.append(client)

    return online_clients, router_info


# Function to Display Results
def display_results(clients, router):
    print("\n[+] Live Hosts Discovered:")
    print("=" * 65)
    print(f"{'IP Address':<18}{'MAC Address':<20}{'Vendor'}")
    print("=" * 65)

    for client in clients:
        print(f"{client['ip']:<18}{client['mac']:<20}{client['vendor']}")

    print("=" * 65)
    print(f"[+] {len(clients)} hosts found.\n")

    # If a router is found, attempt to scan for connected devices
    if router:
        print(f"[+] Router Detected: {router['ip']} ({router['vendor']})")
        get_connected_devices(router['ip'])


# Function to Find Devices Connected to the Router
def get_connected_devices(router_ip):
    print(f"\n[+] Scanning for devices connected to the router {router_ip}...\n")

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp = ARP(pdst=f"{router_ip[:-1]}1/24")  # Scanning within the router's network
    probe = ether / arp

    answered, _ = srp(probe, timeout=3, verbose=False)

    print("=" * 65)
    print(f"{'Connected IP':<18}{'MAC Address':<20}{'Vendor'}")
    print("=" * 65)

    for sent, received in answered:
        vendor = get_mac_vendor(received.hwsrc)
        print(f"{received.psrc:<18}{received.hwsrc:<20}{vendor}")

    print("=" * 65)
    print(f"[+] Scan complete.\n")


# Function to Save Results
def save_results(clients, router, filename="scan_results.txt"):
    with open(filename, "w") as f:
        f.write("IP Address\tMAC Address\tVendor\n")
        for client in clients:
            f.write(f"{client['ip']}\t{client['mac']}\t{client['vendor']}\n")

        if router:
            f.write(f"\nRouter Detected: {router['ip']} ({router['vendor']})\n")
    print(f"[+] Results saved to {filename}")


# Main Function
def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <target_network>")
        print("Example: python3 script.py 192.168.1.0/24")
        sys.exit(1)

    target_network = sys.argv[1]

    # Run network scan in a separate thread
    scan_thread = threading.Thread(target=lambda: display_results(*network_scan(target_network)))
    scan_thread.start()
    scan_thread.join()

    # Ask if user wants to save results
    save_choice = input("[?] Do you want to save the results? (y/n): ").strip().lower()
    if save_choice == 'y':
        save_results(*network_scan(target_network))


if __name__ == "__main__":
    main()
