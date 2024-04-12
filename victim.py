import time
import requests

dns_url = 'https://cloudflare-dns.com/dns-query'
server_url = 'google.com'

client = requests.session()
params = {
    'name': server_url,
    'type': 'A',
    'ct': 'application/dns-json',
}

print("Starting victim script")

while True:
    resp = client.get(dns_url, params=params)
    print(resp.json())
    time.sleep(10)