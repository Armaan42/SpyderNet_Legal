import requests
import json

def track_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        print(f"IP: {data.get('ip')}")
        print(f"Country: {data.get('country')}")
        print(f"Region: {data.get('region')}")
        print(f"City: {data.get('city')}")
        print(f"Postal: {data.get('postal')}")
        print(f"Location: {data.get('loc')}")
        print(f"ISP: {data.get('org')}")
        print(f"Timezone: {data.get('timezone')}")
    except Exception as e:
        print(f"Error: {e}")

ip = input("Enter IP address: ")
track_ip(ip)