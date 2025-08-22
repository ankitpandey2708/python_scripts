import requests
import sys
import re
import csv
from time import sleep
import urllib3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

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
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and not sub.startswith('*'):
                        subdomains.add(sub)
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
        return {m.lower() for m in matches if not m.startswith('*')}
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
            if hostname and hostname.endswith(domain) and not hostname.startswith('*'):
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
            if len(parts) > 0:
                sub = parts[0].lower()
                if sub.endswith(domain) and not sub.startswith('*'):
                    subs.append(sub)
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
                verify=False,  
                allow_redirects=True
            )
            if response.status_code == 200:
                return subdomain, "Y", protocol
        except requests.exceptions.RequestException:
            continue
    
    return subdomain, "N", None

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator and checker")
    parser.add_argument("domain", help="Domain to enumerate")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for checks")
    args = parser.parse_args()
    
    domain = args.domain.lower()
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
    
    all_subdomains.discard(domain)  # Remove apex domain if present
    
    print(f"\n[*] Total unique subdomains found: {len(all_subdomains)}")
    print("[*] Starting subdomain status checks...\n")
    
    # Prepare CSV output
    csv_filename = f"{domain}_subdomains.csv"
    results = []
    
    # Check subdomains concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {executor.submit(check_subdomain_status, sub): sub for sub in sorted(all_subdomains)}
        for future in tqdm(as_completed(future_to_sub), total=len(all_subdomains), desc="Checking"):
            sub, status, protocol = future.result()
            results.append([sub, status])
            if status == "Y":
                print(f"[✓] {sub} - Working ({protocol})")
            else:
                print(f"[✗] {sub} - Not working")
            sleep(0.1)  # Small delay
    
    # Write results to CSV
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'Working'])
        writer.writerows(sorted(results))
    
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
