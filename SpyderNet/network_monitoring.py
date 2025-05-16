import requests

ip = "8.8.8.8"  # Replace with the desired IP address
url = f"http://api.hostip.info/get_html.php?ip={ip}&position=true"

response = requests.get(url)
print(response.text)
