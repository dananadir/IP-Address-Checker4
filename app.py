from flask import Flask, render_template, request, redirect, url_for
import requests
import re

app = Flask(__name__)
whitelisted_ips = [
    "147.235.243.145", "147.235.236.60",
    "54.217.50.18", "52.208.202.111",
    "52.49.144.209", "13.70.16.77",
    "13.72.99.16", "20.50.248.137",
    "20.53.168.19", "20.73.204.39",
    "20.195.97.9", "40.74.245.255",
    "40.83.150.252", "40.115.68.94",
    "52.155.91.26", "191.235.85.21",
    "3.70.39.119", "3.76.97.199",
    "31.168.53.38", "52.217.50.18",
    "84.229.251.229", "31.168.39.202",
    "192.116.136.2", "199.203.217.208"
]

whitelisted_ranges = [
    ("192.168.0.0", "192.168.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("82.166.184.0", "82.166.184.255"),
    ("147.235.0.0", "147.235.255.255"),
    ("100.64.0.1", "100.127.255.254"),

]

def ip_in_whitelist(ip_address):
    for ip_range_start, ip_range_end in whitelisted_ranges:
        if ip_in_range(ip_address, ip_range_start, ip_range_end):
            return True
    return ip_address in whitelisted_ips
def ip_in_range(ip_address, start, end):
    start_int = ip_address_to_int(start)
    end_int = ip_address_to_int(end)
    ip_int = ip_address_to_int(ip_address)
    return start_int <= ip_int <= end_int

def ip_address_to_int(ip_address):
    parts = ip_address.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
def check_ip(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": "",
    }
    headers = {
        "Key": "fae2f18d59a2cd7fbe96a8f05cc578860892512b56e60373d5a8b8b43025e5b4093bb62e5c6cb67c",
        "Accept": "application/json",
    }

    response = requests.get(url, params=params, headers=headers)
    data = response.json()

    result = {
        "ip_address": ip_address,
        "status": "",
        "country": "Unknown",
        "domain": "Unknown",
        "total_reports": 0,
        "abuse_confidence_score": 0
    }

    if ip_in_whitelist(ip_address):
        result["status"] = f"The IP address {ip_address} is in BEZEQ whitelist."
    else:
        result["status"] = f"The IP address {ip_address} is not in BEZEQ whitelist."

    try:
        if response.status_code == 200:
            if data['data']['isPublic'] == 1:
                result["abuse_confidence_score"] = data['data']['abuseConfidenceScore']
                result["country"] = data['data']['countryName']
                result["domain"] = data['data']['domain']
                if "bezeq" in result["domain"].lower():
                    result["domain"] = "!!! " + result["domain"] + " !!!"
                result["total_reports"] = data['data']['totalReports']
            else:
                result["status"] = f"BE AWARE - Internal IP: {ip_address}"
        else:
            result["status"] = f"Failed to check IP {ip_address}: {data['errors'][0]['detail']}"
    except:
        result["status"] = f"NO DATA found about the IP address {ip_address} in IPDB"

    return result

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        text = request.form['text']
        if text:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
            ips = list(set(ips))  # Remove duplicates
            results = [check_ip(ip) for ip in ips]
            print(results)
            return render_template('index.html', text=text, results=results)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')
