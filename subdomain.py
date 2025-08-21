import requests
import sys
import re
import csv
from time import sleep
import urllib3

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value")
            if name_value:
                for sub in name_value.split("\n"):
                    if sub.endswith(domain):
                        subdomains.add(sub.strip().lower())
        return subdomains
    except Exception as e:
        print(f"[!] crt.sh error: {e}")
        return set()

def fetch_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            return set()
        matches = re.findall(r"<td>([a-zA-Z0-9.-]+\." + re.escape(domain) + r")</td>", r.text)
        return set(m.lower() for m in matches)
    except Exception as e:
        print(f"[!] RapidDNS error: {e}")
        return set()

def fetch_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subdomains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname and hostname.endswith(domain):
                subdomains.add(hostname.lower())
        return subdomains
    except Exception as e:
        print(f"[!] AlienVault error: {e}")
        return set()

def fetch_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            return set()
        subs = []
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts) > 0 and parts[0].endswith(domain):
                subs.append(parts[0].lower())
        return set(subs)
    except Exception as e:
        print(f"[!] HackerTarget error: {e}")
        return set()

def check_subdomain_status(subdomain):
    """Check if a subdomain returns HTTP 200 status"""
    protocols = ['https://', 'http://']
    
    for protocol in protocols:
        try:
            url = f"{protocol}{subdomain}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            response = requests.get(
                url, 
                headers=headers, 
                timeout=10, 
                verify=False,  # Skip SSL verification
                allow_redirects=True
            )
            if response.status_code == 200:
                print(f"[✓] {subdomain} - Working ({protocol})")
                return "Y"
        except requests.exceptions.RequestException:
            continue
    
    print(f"[✗] {subdomain} - Not working")
    return "N"

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <domain>")
        sys.exit(1)
    
    domain = sys.argv[1].lower()
    all_subdomains = set()
    
    print(f"[*] Fetching subdomains for: {domain}\n")
    
    sources = {
        "crt.sh": fetch_crtsh,
        "RapidDNS": fetch_rapiddns,
        "AlienVault": fetch_alienvault,
        "HackerTarget": fetch_hackertarget
    }
    
    # Collect subdomains from all sources
    for name, func in sources.items():
        subs = func(domain)
        print(f"[+] {name} found {len(subs)} subdomains")
        all_subdomains.update(subs)
        sleep(2)  # avoid rate-limits
    
    print(f"\n[*] Total unique subdomains found: {len(all_subdomains)}")
    print("[*] Starting subdomain status checks...\n")
    
    # Prepare CSV output
    csv_filename = f"{domain}_subdomains.csv"
    results = []
    
    # Check each subdomain
    for i, subdomain in enumerate(sorted(all_subdomains), 1):
        print(f"[{i}/{len(all_subdomains)}] Checking: {subdomain}")
        status = check_subdomain_status(subdomain)
        results.append([subdomain, status])
        sleep(1)  # Be respectful with requests
    
    # Write results to CSV
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'Working'])
        writer.writerows(results)
    
    print(f"\n[*] Results saved to: {csv_filename}")
    
    # Summary statistics
    working_count = sum(1 for result in results if result[1] == 'Y')
    not_working_count = len(results) - working_count
    
    print(f"[*] Summary:")
    print(f"    - Total subdomains: {len(results)}")
    print(f"    - Working: {working_count}")
    print(f"    - Not working: {not_working_count}")

if __name__ == "__main__":
    main()
