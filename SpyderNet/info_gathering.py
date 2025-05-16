# from http.client import responses
import whois
import dns.resolver
import shodan
import sys
import requests
import argparse
import socket

argparse = argparse.ArgumentParser(description="It is an Information gathering tool.", usage="Python3 info_gathering.py -d domain [-s IP]")
argparse.add_argument("-d", "--domain", help="Enter the domain name for footPrinting")
argparse.add_argument("-s", "--shodan", help="Enter the IP for Shodan Search")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan

print("[+] Getting whois info...")
py = whois.query(domain)
# using whois library, creating instance
try:
    print("[+] Whois Info Found.")
    print("Name: {} ".format(py.name))
    print("Registrar: {}".format(py.registrar))
    print("Creation Date: {}".format(py.creation_date))
    print("Expiration Date: {}".format(py.expiration_date))
    print("Name Servers: {}".format(py.name_servers))
    print("Registrant Country: {}".format(py.registrant_country))
    print("Last Updated: {}".format(py.last_updated))
    print("registrant: {}".format(py.registrant))
    print("Emails: {}".format(py.emails))
except:
    pass

# #DNS module
# print("[+] Getting DNS info...")
# #implementing dns.resolver from dnspython
#
# try:
#     for a in dns.resolver.resolve(domain, 'A'):
#         print("[+] A Record: {} ".format(a.to_text()))
#     for ns in dns.resolver.resolve(domain, 'NS'):
#         print("[+] NS Record: {}".format(ns.to_text()))
#     for mx in dns.resolver.resolve(domain, 'MX'):
#         print("[+] MX Record: {}".format(mx.to_text()))
#     for txt in dns.resolver.resolve(domain, 'TXT'):
#         print("[+] TXT Record: {}".format(txt.to_text()))
# except:
#     pass

print("\n[+] Getting DNS info...")

try:
    for record_type in ["A", "NS", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                print(f"[+] {record_type} Record: {rdata.to_text()}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(f"[-] No {record_type} records found.")
        except Exception as e:
            print(f"[-] DNS lookup failed for {record_type}: {e}")

except Exception as e:
    print(f"[-] General DNS lookup failed: {e}")

#Geolocation module
print("[+] Getting geolocation info...")

try:
    response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Country: {}". format(response['country_name']))
    print("[+] Latitude: {}". format(response['latitude']))
    print("[+] Longitude : {}".format(response['longitude']))
    print("[+] City: {}".format(response['city']))
    print("[+] State: {}".format(response['state']))
    print()

except:
    pass


#shodan module

# if ip:
#     print("[+] Getting information from shodan for IP {}". format(ip))
#     SHODAN_API_KEY = "M4UiZWpXMz7DeTK7RjOwWWhqPYxJXgHa"  # Replace with your actual Shodan API key
#     api = shodan.Shodan(SHODAN_API_KEY)
#
#     try:
#         result = api.host(ip)  # Fetch host details
#
#         print("\n[+] Shodan Info Found.")
#         print("[+] IP: {}".format(result.get("ip_str", "N/A")))
#         print("[+] Organization: {}".format(result.get("org", "N/A")))
#         print("[+] ISP: {}".format(result.get("isp", "N/A")))
#         print("[+] Country: {}".format(result.get("country_name", "N/A")))
#         print("[+] Open Ports: {}".format(result.get("ports", "N/A")))
#         print("[+] Vulnerabilities: {}".format(result.get("vulns", "None")))
#
#     except shodan.APIError as e:
#         print(f"[-] Shodan lookup failed: {e}")

# if ip:
#     api = shodan.Shodan("M4UiZWpXMz7DeTK7RjOwWWhqPYxJXgHa")
#
#     try:
#         print("[+] Searching Shodan for IP:", ip)
#
#         # Fetch detailed host information
#         host = api.host(ip)
#
#         print("\n[+] Basic Information")
#         print(f"IP: {host.get('ip_str', 'N/A')}")
#         print(f"Organization: {host.get('org', 'N/A')}")
#         print(f"ISP: {host.get('isp', 'N/A')}")
#         print(f"ASN: {host.get('asn', 'N/A')}")
#         print(f"Operating System: {host.get('os', 'N/A')}")
#
#         # Print Hostnames & Domains
#         print("\n[+] Hostnames & Domains")
#         print(f"Hostnames: {', '.join(host.get('hostnames', [])) or 'N/A'}")
#         print(f"Domains: {', '.join(host.get('domains', [])) or 'N/A'}")
#
#         # Print Open Ports and Services
#         print("\n[+] Open Ports & Services")
#         for item in host.get('data', []):
#             port = item.get('port', 'N/A')
#             service = item.get('product', 'Unknown Service')
#             banner = item.get('data', '').strip().split("\n")[0]  # First line of banner
#             print(f"Port: {port} | Service: {service} | Banner: {banner}")
#
#         # Vulnerabilities
#         if 'vulns' in host:
#             print("\n[+] Vulnerabilities")
#             for vuln in host['vulns']:
#                 print(f"- {vuln} ({responses.get(vuln, 'Unknown Vulnerability')})")
#
#     except shodan.APIError as e:
#         print(f"[-] Shodan API error: {e}")

# Shodan Module Enhancement
if ip:
    print("[+] Getting information from shodan for IP {}".format(ip))
    api = shodan.Shodan("M4UiZWpXMz7DeTK7RjOwWWhqPYxJXgHa")
    try:
        print(f"[+] Searching Shodan for IP: {ip}")
        host = api.host(ip)  # Fetch detailed info

        print(f"[+] IP: {host['ip_str']}")
        print(f"[+] Organization: {host.get('org', 'N/A')}")
        print(f"[+] ISP: {host.get('isp', 'N/A')}")
        print(f"[+] Country: {host.get('country_name', 'N/A')}")
        print(f"[+] City: {host.get('city', 'N/A')}")
        print(f"[+] OS: {host.get('os', 'N/A')}")

        # Open Ports
        print("\n[+] Open Ports & Services:")
        for item in host['data']:
            print(f"  - Port: {item['port']} | Service: {item.get('product', 'Unknown')} {item.get('version', '')}")

        # Extract vulnerabilities (CVE details)
        if 'vulns' in host:
            print("\n[+] Known Vulnerabilities (CVEs):")
            for vuln in host['vulns']:
                print(f"  - {vuln}")

        # Extracting SSH, HTTP, or RDP details if available
        for item in host['data']:
            if 'http' in item:
                print("\n[+] HTTP Banner Detected:")
                print(f"  - {item['http'].get('server', 'Unknown')}")

            if 'ssh' in item:
                print("\n[+] SSH Info:")
                print(f"  - {item['ssh'].get('fingerprint', 'Unknown')}")

            if 'rdp' in item:
                print("\n[+] RDP Info:")
                print(f"  - Security Protocol: {item['rdp'].get('security', 'Unknown')}")

    except shodan.APIError as e:
        print(f"[-] Shodan Error: {e}")




























