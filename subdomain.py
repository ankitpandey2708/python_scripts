import requests
import sys
import re
from time import sleep

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

    for name, func in sources.items():
        subs = func(domain)
        print(f"[+] {name} found {len(subs)} subdomains")
        all_subdomains.update(subs)
        sleep(2)  # avoid rate-limits

    print("\n=== Unique Subdomains Found ===")
    for sub in sorted(all_subdomains):
        print(sub)

    print(f"\n[*] Total unique subdomains: {len(all_subdomains)}")

if __name__ == "__main__":
    main()
