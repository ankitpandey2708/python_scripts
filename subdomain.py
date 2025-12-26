import requests
import sys
import re
import csv
import socket
from time import sleep
import urllib3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import quote_plus, urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# More realistic User-Agent
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers=HEADERS, timeout=40)
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
    except Exception:
        return set()

def fetch_rapiddns(domain):
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return set()
        matches = re.findall(r"<td>([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")</td>", r.text)
        return {m.lower() for m in matches if not m.startswith('*')}
    except Exception:
        return set()

def fetch_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subdomains = set()
        for entry in data.get("passive_dns", []):
            hostname = entry.get("hostname")
            if hostname and hostname.endswith(domain) and not hostname.startswith('*'):
                subdomains.add(hostname.lower())
        return subdomains
    except Exception:
        return set()

def fetch_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={quote_plus(domain)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return set()
        subs = []
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts) > 0:
                sub = parts[0].lower().strip()
                if sub.endswith(domain) and not sub.startswith('*'):
                    subs.append(sub)
        return set(subs)
    except Exception:
        return set()

def fetch_anubis(domain):
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        if isinstance(data, list):
            return {h.lower() for h in data if h.endswith(domain) and not h.startswith('*')}
        return set()
    except Exception:
        return set()

def fetch_threatcrowd(domain):
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote_plus(domain)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            return set()
        data = r.json()
        subs = data.get("subdomains") or []
        return {s.lower() for s in subs if s.endswith(domain) and not s.startswith('*')}
    except Exception:
        return set()

def fetch_waybackarchive(domain):
    url = ("http://web.archive.org/cdx/search/cdx"
           f"?url=*.{quote_plus(domain)}&output=json&fl=original&collapse=urlkey&limit=10000")
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            return set()
        data = r.json()
        hosts = set()
        for row in data[1:]:
            original = row[0]
            try:
                parsed = urlparse(original)
                host = parsed.hostname
                if host and host.endswith(domain) and not host.startswith('*'):
                    hosts.add(host.lower())
            except Exception:
                continue
        return hosts
    except Exception:
        return set()

def fetch_commoncrawl(domain):
    indices = [
        "CC-MAIN-2024-51-index", "CC-MAIN-2024-46-index", "CC-MAIN-2024-38-index"
    ]
    found = set()
    for idx in indices:
        try:
            url = f"https://index.commoncrawl.org/{idx}?url=*.{quote_plus(domain)}&output=json"
            r = requests.get(url, headers=HEADERS, timeout=20)
            if r.status_code != 200:
                continue
            for line in r.text.splitlines():
                try:
                    obj = requests.utils.json.loads(line.strip())
                    if obj and "url" in obj:
                        host = urlparse(obj["url"]).hostname
                        if host and host.endswith(domain) and not host.startswith('*'):
                            found.add(host.lower())
                except Exception:
                    continue
            if found:
                break
        except Exception:
            continue
    return found

def fetch_certspotter(domain):
    """CertSpotter API for Certificate Transparency logs"""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code == 200:
            data = r.json()
            subs = set()
            for entry in data:
                dns_names = entry.get("dns_names", [])
                for name in dns_names:
                    if name.endswith(domain) and not name.startswith('*'):
                        subs.add(name.lower())
            return subs
    except Exception:
        pass
    return set()

def fetch_sublist3r_api(domain):
    url = f"https://api.sublist3r.com/search.php?domain={domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code == 200:
            data = r.json()
            return {s.lower() for s in data if s.endswith(domain) and not s.startswith('*')}
    except Exception:
        pass
    return set()

def fetch_bevigil(domain):
    """BeVigil OSINT API"""
    url = f"https://bevigil.com/api/{domain}/subdomains/"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code == 200:
            data = r.json()
            return {s.lower() for s in data.get("subdomains", []) if s.endswith(domain)}
    except Exception:
        pass
    return set()

def resolve_dns(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False

def check_subdomain_status(subdomain):
    if not resolve_dns(subdomain):
        return subdomain, "N", None

    protocols = ['https://', 'http://']
    for protocol in protocols:
        try:
            url = f"{protocol}{subdomain}"
            response = requests.get(
                url,
                headers=HEADERS,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            if 200 <= response.status_code < 400:
                return subdomain, "Y", protocol
        except requests.exceptions.RequestException:
            continue
    return subdomain, "N", None

def main():
    parser = argparse.ArgumentParser(description="Subdomain enumerator and checker")
    parser.add_argument("domain", help="Domain to enumerate")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for checks")
    args = parser.parse_args()

    domain = args.domain.lower().strip()
    if not domain:
        print("Usage: python subdomain.py <domain>")
        sys.exit(1)

    all_subdomains = set()
    print(f"[*] Fetching subdomains for: {domain}\n")

    sources = {
        "crt.sh": fetch_crtsh,
        "RapidDNS": fetch_rapiddns,
        "AlienVault": fetch_alienvault,
        "HackerTarget": fetch_hackertarget,
        "Anubis": fetch_anubis,
        "CommonCrawl": fetch_commoncrawl,
        "ThreatCrowd": fetch_threatcrowd,
        "WaybackArchive": fetch_waybackarchive,
        "Sublist3rAPI": fetch_sublist3r_api,
        "CertSpotter": fetch_certspotter,
        "BeVigil": fetch_bevigil
    }

    with ThreadPoolExecutor(max_workers=len(sources)) as executor:
        future_to_source = {executor.submit(func, domain): name for name, func in sources.items()}
        for future in as_completed(future_to_source):
            name = future_to_source[future]
            try:
                subs = future.result()
                if subs:
                    print(f"[+] {name} found {len(subs)} subdomains")
                    all_subdomains.update(subs)
                else:
                    print(f"[-] {name} found 0 subdomains")
            except Exception as e:
                print(f"[!] {name} fetcher failed: {e}")

    cleaned = set()
    for s in all_subdomains:
        s = s.strip().lower()
        if s.endswith(domain) and not s.startswith('*'):
            if re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$', s):
                cleaned.add(s)
    
    all_subdomains = cleaned
    all_subdomains.discard(domain)

    print(f"\n[*] Total unique subdomains found: {len(all_subdomains)}")
    
    if not all_subdomains:
        print("[!] No subdomains found. Exiting.")
        return

    print("[*] Starting status checks (DNS + HTTP)...\n")

    csv_filename = f"{domain}_subdomains.csv"
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {executor.submit(check_subdomain_status, sub): sub for sub in sorted(all_subdomains)}
        for future in tqdm(as_completed(future_to_sub), total=len(all_subdomains), desc="Checking"):
            sub = future_to_sub[future]
            try:
                sub_res, status, protocol = future.result()
            except Exception:
                status, protocol = "N", None
            
            results.append([sub, status])
            if status == "Y":
                print(f"[✓] {sub} - Working ({protocol})")

    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'Working'])
        for row in sorted(results, key=lambda r: r[0]):
            writer.writerow(row)

    print(f"\n[*] Results saved to: {csv_filename}")
    working_count = sum(1 for result in results if result[1] == 'Y')
    print(f"[*] Summary:")
    print(f"    - Total unique subdomains: {len(results)}")
    print(f"    - Working: {working_count}")
    print(f"    - Not working: {len(results) - working_count}")

if __name__ == "__main__":
    main()
