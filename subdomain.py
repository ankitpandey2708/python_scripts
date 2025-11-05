import requests
import sys
import re
import csv
from time import sleep
import urllib3
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import quote_plus, urlparse

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0 (SubdomainEnumerator/1.0)"}

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, headers=HEADERS, timeout=40)
        if r.status_code != 200:
            print(f"[!] crt.sh returned {r.status_code}")
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
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"[!] RapidDNS returned {r.status_code}")
            return set()
        matches = re.findall(r"<td>([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")</td>", r.text)
        return {m.lower() for m in matches if not m.startswith('*')}
    except Exception as e:
        print(f"[!] RapidDNS error: {e}")
        return set()

def fetch_alienvault(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"[!] AlienVault returned {r.status_code}")
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
    url = f"https://api.hackertarget.com/hostsearch/?q={quote_plus(domain)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"[!] HackerTarget returned {r.status_code}")
            return set()
        subs = []
        for line in r.text.splitlines():
            parts = line.split(",")
            if len(parts) > 0:
                sub = parts[0].lower().strip()
                if sub.endswith(domain) and not sub.startswith('*'):
                    subs.append(sub)
        return set(subs)
    except Exception as e:
        print(f"[!] HackerTarget error: {e}")
        return set()

def fetch_anubis(domain):
    """
    Uses the jldc.me Anubis endpoint which returns JSON list of subdomains.
    This is a community endpoint commonly used for quick lookups.
    """
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            # jldc.me returns 404 for not found
            print(f"[!] Anubis returned {r.status_code}")
            return set()
        data = r.json()
        if isinstance(data, list):
            return {h.lower() for h in data if h.endswith(domain) and not h.startswith('*')}
        return set()
    except Exception as e:
        print(f"[!] Anubis error: {e}")
        return set()

def fetch_threatcrowd(domain):
    """
    ThreatCrowd public API returns a domain report with subdomains.
    """
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={quote_plus(domain)}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"[!] ThreatCrowd returned {r.status_code}")
            return set()
        data = r.json()
        subs = data.get("subdomains") or []
        return {s.lower() for s in subs if s.endswith(domain) and not s.startswith('*')}
    except Exception as e:
        print(f"[!] ThreatCrowd error: {e}")
        return set()

def fetch_waybackarchive(domain):
    """
    Uses the Wayback CDX API to pull historical URLs and extract hostnames.
    This is useful to discover subdomains seen in archived URLs.
    """
    url = ("http://web.archive.org/cdx/search/cdx"
           f"?url=*.{quote_plus(domain)}&output=json&fl=original&collapse=urlkey&limit=10000")
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        if r.status_code != 200:
            print(f"[!] Wayback CDX returned {r.status_code}")
            return set()
        data = r.json()
        hosts = set()
        # first row may be header; iterate safely
        for row in data[1:]:
            original = row[0]
            try:
                parsed = urlparse(original)
                host = parsed.hostname
                if host and host.endswith(domain) and not host.startswith('*'):
                    hosts.add(host.lower())
            except Exception:
                # if parsing fails, skip
                continue
        return hosts
    except Exception as e:
        print(f"[!] WaybackArchive error: {e}")
        return set()

def fetch_commoncrawl(domain):
    """
    Best-effort attempt to query CommonCrawl indices.
    CommonCrawl index names change over time; we try a few recent indices.
    If none succeed we return empty set.
    """
    indices = [
        "CC-MAIN-2023-14-index", "CC-MAIN-2022-10-index", "CC-MAIN-2021-04-index"
    ]
    found = set()
    for idx in indices:
        try:
            url = f"https://index.commoncrawl.org/{idx}?url=*.{quote_plus(domain)}&output=json"
            r = requests.get(url, headers=HEADERS, timeout=20)
            if r.status_code != 200:
                continue
            # each line is JSON object
            for line in r.text.splitlines():
                try:
                    obj = None
                    if line.strip():
                        obj = requests.utils.json.loads(line)
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
    if not found:
        print("[!] CommonCrawl: no results or indices unreachable (best-effort)")
    return found

def fetch_digitorus(domain):
    """
    Digitorus public endpoints are not well documented; implement a best-effort HTTP GET
    to common possible endpoints and fallback gracefully.
    """
    candidate_urls = [
        f"https://digitorus.com/subdomains/{domain}",
        f"https://digitorus.com/api/subdomains/{domain}"
    ]
    found = set()
    for url in candidate_urls:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            if r.status_code != 200:
                continue
            # try to find hostnames in HTML/JSON
            matches = re.findall(r"([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")", r.text)
            for m in matches:
                if not m.startswith('*'):
                    found.add(m.lower())
            if found:
                return found
        except Exception:
            continue
    print("[!] Digitorus: endpoint not confirmed; returning 0 results (best-effort)")
    return set()

def fetch_sitedossier(domain):
    """
    Try sitedossier basic scraping. If structure changes, fall back to empty set.
    """
    url = f"https://siteinfo.sitedossier.com/{domain}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"[!] SiteDossier returned {r.status_code}")
            return set()
        matches = re.findall(r"([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")", r.text)
        return {m.lower() for m in matches if not m.startswith('*')}
    except Exception as e:
        print(f"[!] SiteDossier error: {e}")
        return set()

def fetch_hudsonrock(domain):
    """
    Hudson Rock has a public-facing web page that sometimes shows subdomains (best-effort).
    We'll attempt to hit a couple of plausible endpoints, otherwise return empty set.
    """
    candidates = [
        f"https://hudsonrock.com/subdomains/{domain}",
        f"https://hudsonrock.com/{domain}"
    ]
    found = set()
    for url in candidates:
        try:
            r = requests.get(url, headers=HEADERS, timeout=15)
            if r.status_code != 200:
                continue
            matches = re.findall(r"([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")", r.text)
            for m in matches:
                if not m.startswith('*'):
                    found.add(m.lower())
            if found:
                return found
        except Exception:
            continue
    print("[!] HudsonRock: endpoint not confirmed; returning 0 results (best-effort)")
    return set()

def check_subdomain_status(subdomain):
    """Check if a subdomain returns HTTP 200 status"""
    protocols = ['https://', 'http://']
    for protocol in protocols:
        try:
            url = f"{protocol}{subdomain}"
            response = requests.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                },
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

    domain = args.domain.lower().strip()
    if not domain:
        print("Usage: script.py <domain>")
        sys.exit(1)

    all_subdomains = set()
    print(f"[*] Fetching subdomains for: {domain}\n")

    # Only include the non-starred sources requested
    sources = {
        "crt.sh": fetch_crtsh,
        "RapidDNS": fetch_rapiddns,
        "AlienVault": fetch_alienvault,
        "HackerTarget": fetch_hackertarget,
        "Anubis": fetch_anubis,
        "CommonCrawl": fetch_commoncrawl,
        "Digitorus": fetch_digitorus,
        "SiteDossier": fetch_sitedossier,
        "ThreatCrowd": fetch_threatcrowd,
        "WaybackArchive": fetch_waybackarchive,
        "HudsonRock": fetch_hudsonrock
    }

    # Collect subdomains from all sources
    for name, func in sources.items():
        try:
            subs = func(domain)
            if not isinstance(subs, set):
                subs = set(subs)
            print(f"[+] {name} found {len(subs)} subdomains")
            all_subdomains.update(subs)
        except Exception as e:
            print(f"[!] {name} fetcher crashed: {e}")
        sleep(2)  # avoid rate-limits

    # canonicalize and filter
    cleaned = set()
    for s in all_subdomains:
        s = s.strip().lower()
        if s.endswith(domain) and not s.startswith('*'):
            cleaned.add(s)
    all_subdomains = cleaned
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
            try:
                sub, status, protocol = future.result()
            except Exception as e:
                # If a check itself throws, mark as not working but continue
                sub = future_to_sub.get(future, "unknown")
                status, protocol = "N", None
                print(f"[!] Error checking {sub}: {e}")
            results.append([sub, status])
            if status == "Y":
                print(f"[✓] {sub} - Working ({protocol})")
            else:
                print(f"[✗] {sub} - Not working")
            sleep(0.05)  # small throttle

    # Write results to CSV (sorted)
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Subdomain', 'Working'])
        for row in sorted(results, key=lambda r: r[0]):
            writer.writerow(row)

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
