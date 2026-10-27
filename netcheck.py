#!/usr/bin/env python3
"""
netcheck.py - quick network connectivity check.

Runs:
  1. Network info: interface, local IP, default gateway, DNS servers
  2. Ping the default gateway (4 packets) with loss / round-trip statistics
  3. Ping 8.8.8.8 (4 packets) with the same statistics
  4. DNS lookups for a few hostnames (timed)
  5. Timed download of a small web page

Each run appends ONE row to <hostname>.csv, located next to the executable
(or next to this script when run with plain Python). The header row is
written only when the file is created. The full ipconfig /all (Windows) or
ifconfig -a (Mac) output is appended to <hostname>_netinfo.txt.

Works on Windows, macOS and Linux using only the standard library.
"""

import csv
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

PING_TARGET = "8.8.8.8"
PING_COUNT = 4
DNS_NAMES = ["google.com", "cloudflare.com", "example.com"]
DOWNLOAD_URL = "https://example.com/"
TIMEOUT = 10  # seconds for DNS/HTTP
SAVE_RAW_NETINFO = False  # also append full ipconfig/ifconfig output to <hostname>_netinfo.txt


def output_dir():
    """Folder for the CSV: beside the .exe/.app binary or this script."""
    if getattr(sys, "frozen", False):
        path = os.path.dirname(os.path.abspath(sys.executable))
        # Inside a macOS .app bundle, step out to the folder holding the .app
        if ".app/Contents/MacOS" in path:
            path = path.split(".app/Contents/MacOS")[0]
            path = os.path.dirname(path)
        return path
    return os.path.dirname(os.path.abspath(__file__))


def run_ping(target, count):
    is_windows = platform.system().lower() == "windows"
    cmd = ["ping", "-n" if is_windows else "-c", str(count), target]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60 + count * 5
        )
        raw = (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError:
        return {"error": "ping command not found"}
    except subprocess.TimeoutExpired:
        return {"error": "ping timed out"}

    stats = {}

    # Packet counts
    m = re.search(r"Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)", raw)
    if m:  # Windows
        stats.update(sent=int(m[1]), received=int(m[2]), lost=int(m[3]),
                     loss_pct=float(m[4]))
    else:  # macOS / Linux
        m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?"
                      r"([\d.]+)% packet loss", raw, re.S)
        if m:
            sent, recv = int(m[1]), int(m[2])
            stats.update(sent=sent, received=recv, lost=sent - recv,
                         loss_pct=float(m[3]))

    # Round-trip times
    m = re.search(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms", raw)
    if m:  # Windows (whole milliseconds only)
        stats.update(rtt_min=float(m[1]), rtt_max=float(m[2]), rtt_avg=float(m[3]))
    else:
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))? ms", raw)
        if m:  # macOS / Linux: min/avg/max/(stddev|mdev)
            stats.update(rtt_min=float(m[1]), rtt_avg=float(m[2]),
                         rtt_max=float(m[3]))
            if m[4]:
                stats["rtt_stddev"] = float(m[4])

    if "sent" not in stats:
        stats["error"] = "could not parse ping output"
    return stats


def run_cmd(cmd, timeout=15):
    """Run a command and return its combined output ('' on any failure)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def _unique(items):
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def get_network_info():
    """Return (info_dict, raw_text).

    info keys: interface, local_ip, gateway, dns (list). Any value that
    couldn't be determined is left blank. raw_text is the full output of
    ipconfig /all (Windows) or ifconfig -a / ip addr (Mac/Linux).
    """
    system = platform.system()
    info = {"interface": "", "local_ip": "", "gateway": "", "dns": []}
    raw = ""

    if system == "Windows":
        raw = run_cmd(["ipconfig", "/all"])
        # Default route with the lowest metric (numeric, so not locale-dependent)
        best = None
        for line in run_cmd(["route", "print", "-4", "0.0.0.0"]).splitlines():
            m = re.match(rf"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+({IPV4})\s+(\d+)", line)
            if m and re.fullmatch(IPV4, m[1]) and (best is None or int(m[3]) < best[2]):
                best = (m[1], m[2], int(m[3]))
        if best:
            info["gateway"], info["local_ip"] = best[0], best[1]

        # Find the adapter block that owns the local IP, then read its DNS servers
        header, block = "", []
        blocks = []
        for line in raw.splitlines():
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                if header:
                    blocks.append((header, block))
                header, block = line.strip().rstrip(":"), []
            else:
                block.append(line)
        if header:
            blocks.append((header, block))
        for header, block in blocks:
            if info["local_ip"] and re.search(rf"\b{re.escape(info['local_ip'])}\b",
                                              "\n".join(block)):
                info["interface"] = header
                collecting = False
                for line in block:
                    if "DNS Servers" in line:  # English Windows; blank otherwise
                        collecting = True
                        info["dns"] += re.findall(IPV4, line)
                    elif collecting and re.fullmatch(rf"\s+{IPV4}\s*", line):
                        info["dns"] += re.findall(IPV4, line)
                    else:
                        collecting = False
                break

    elif system == "Darwin":
        raw = run_cmd(["ifconfig", "-a"])
        route = run_cmd(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\S+)", route)
        info["gateway"] = m[1] if m else ""
        m = re.search(r"interface:\s*(\S+)", route)
        info["interface"] = m[1] if m else ""
        if info["interface"]:
            info["local_ip"] = run_cmd(["ipconfig", "getifaddr", info["interface"]]).strip()
        info["dns"] = re.findall(rf"nameserver\[\d+\]\s*:\s*(\S+)",
                                 run_cmd(["scutil", "--dns"]))

    else:  # Linux and others
        raw = run_cmd(["ip", "addr"]) or run_cmd(["ifconfig", "-a"])
        m = re.search(r"default via (\S+) dev (\S+)",
                      run_cmd(["ip", "route", "show", "default"]))
        if m:
            info["gateway"], info["interface"] = m[1], m[2]
            m = re.search(rf"inet ({IPV4})",
                          run_cmd(["ip", "-4", "-o", "addr", "show", info["interface"]]))
            info["local_ip"] = m[1] if m else ""
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as f:
                info["dns"] = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
        except OSError:
            pass

    if not re.fullmatch(IPV4, info["gateway"]):
        info["gateway"] = ""  # e.g. "link#14" on some VPN setups
    info["dns"] = _unique(info["dns"])
    return info, raw


def ping_columns(prefix, target, p):
    """CSV columns for one ping test. Returns (columns, passed)."""
    ok = p.get("received", 0) > 0
    cols = [
        (f"{prefix}_target", target),
        (f"{prefix}_packets_sent", fmt(p.get("sent"))),
        (f"{prefix}_packets_received", fmt(p.get("received"))),
        (f"{prefix}_packets_lost", fmt(p.get("lost"))),
        (f"{prefix}_loss_pct", fmt(p.get("loss_pct"))),
        (f"{prefix}_rtt_min_ms", fmt(p.get("rtt_min"))),
        (f"{prefix}_rtt_avg_ms", fmt(p.get("rtt_avg"))),
        (f"{prefix}_rtt_max_ms", fmt(p.get("rtt_max"))),
        (f"{prefix}_rtt_stddev_ms", fmt(p.get("rtt_stddev"))),
        (f"{prefix}_result", "PASS" if ok else "FAIL"),
        (f"{prefix}_error", p.get("error", "")),
    ]
    return cols, ok


def check_dns(names):
    """Return {name: (ok, milliseconds, first_address_or_error)}."""
    results = {}
    for name in names:
        start = time.perf_counter()
        try:
            infos = socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
            ms = (time.perf_counter() - start) * 1000
            results[name] = (True, ms, infos[0][4][0])
        except socket.gaierror as e:
            ms = (time.perf_counter() - start) * 1000
            results[name] = (False, ms, str(e))
    return results


def build_ssl_context():
    """Create a verifying SSL context that works even when Python's own
    certificate store is empty (common with python.org builds on macOS and
    with PyInstaller executables).

    Order: certifi bundle (if installed) -> macOS system keychain -> default.
    Certificate verification is never disabled.
    """
    try:
        import certifi  # bundled automatically by PyInstaller when installed
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        pass

    ctx = ssl.create_default_context()
    if platform.system() == "Darwin":
        try:
            pem = subprocess.run(
                ["security", "find-certificate", "-a", "-p",
                 "/System/Library/Keychains/SystemRootCertificates.keychain"],
                capture_output=True, text=True, timeout=20,
            ).stdout
            if "BEGIN CERTIFICATE" in pem:
                ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.SubprocessError, ssl.SSLError):
            pass
    return ctx


def time_download(url):
    req = urllib.request.Request(url, headers={"User-Agent": "netcheck/1.0"})
    context = build_ssl_context()  # built before timing starts
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
            ttfb = time.perf_counter() - start
            body = resp.read()
            total = time.perf_counter() - start
            return {"ok": True, "status": resp.status, "bytes": len(body),
                    "ttfb_ms": ttfb * 1000, "total_ms": total * 1000,
                    "kb_per_s": (len(body) / 1024) / total if total else 0}
    except Exception as e:  # noqa: BLE001 - report any failure
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "total_ms": (time.perf_counter() - start) * 1000}


def fmt(value, digits=1):
    """Round numbers for CSV; leave blanks for missing values."""
    if value is None:
        return ""
    if isinstance(value, float):
        return round(value, digits)
    return value


def dns_col(name):
    return "dns_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def run_checks(hostname, now):
    """Run all tests and return an ordered dict-like list of (column, value)."""
    row = [
        ("timestamp", now.strftime("%Y-%m-%d %H:%M:%S")),
        ("hostname", hostname),
        ("os", f"{platform.system()} {platform.release()}"),
    ]

    # --- Network info ---
    net, raw_netinfo = get_network_info()
    row += [
        ("net_interface", net["interface"]),
        ("net_local_ip", net["local_ip"]),
        ("net_gateway", net["gateway"]),
        ("net_dns_servers", " ".join(net["dns"])),
    ]

    # --- Ping default gateway ---
    if net["gateway"]:
        gp = run_ping(net["gateway"], PING_COUNT)
    else:
        gp = {"error": "no default gateway found"}
    cols, _ = ping_columns("gw_ping", net["gateway"], gp)
    row += cols

    # --- Ping internet target ---
    p = run_ping(PING_TARGET, PING_COUNT)
    cols, ping_ok = ping_columns("ping", PING_TARGET, p)
    row += cols

    # --- DNS ---
    dns = check_dns(DNS_NAMES)
    for name, (ok, ms, detail) in dns.items():
        col = dns_col(name)
        row += [
            (f"{col}_ms", fmt(ms)),
            (f"{col}_result", "PASS" if ok else "FAIL"),
        ]
    dns_ok = all(ok for ok, _, _ in dns.values())
    dns_errors = "; ".join(f"{n}: {d}" for n, (ok, _, d) in dns.items() if not ok)
    row += [
        ("dns_result", "PASS" if dns_ok else "FAIL"),
        ("dns_error", dns_errors),
    ]

    # --- HTTP download ---
    d = time_download(DOWNLOAD_URL)
    row += [
        ("http_url", DOWNLOAD_URL),
        ("http_status", fmt(d.get("status"))),
        ("http_bytes", fmt(d.get("bytes"))),
        ("http_ttfb_ms", fmt(d.get("ttfb_ms"))),
        ("http_total_ms", fmt(d.get("total_ms"))),
        ("http_kb_per_sec", fmt(d.get("kb_per_s"))),
        ("http_result", "PASS" if d["ok"] else "FAIL"),
        ("http_error", d.get("error", "")),
    ]

    row.append(("overall_result",
                "PASS" if (ping_ok and dns_ok and d["ok"]) else "FAIL"))
    return row, raw_netinfo


def append_raw_netinfo(path, now, raw):
    """Append the full ipconfig/ifconfig output, with a timestamp header."""
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"===== {now.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
            f.write(raw.strip() + "\n\n")
    except OSError:
        pass  # the CSV is the important output


def append_csv(path, row):
    """Append a row; write the header only if the file is new/empty.

    If an existing file has a different header (e.g. you edited DNS_NAMES),
    the old file is renamed with a timestamp so columns never get misaligned.
    """
    headers = [c for c, _ in row]
    values = [v for _, v in row]

    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, newline="", encoding="utf-8") as f:
            existing = next(csv.reader(f), [])
        if existing != headers:
            stamp = datetime.now().strftime("%Y%m%d%H%M%S")
            base, ext = os.path.splitext(path)
            os.replace(path, f"{base}_old_{stamp}{ext}")

    new_file = not os.path.exists(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(headers)
        writer.writerow(values)


def main():
    now = datetime.now()
    hostname = socket.gethostname().split(".")[0]
    path = os.path.join(output_dir(), f"{hostname}.csv")

    print("Running network checks, please wait...")
    row, raw_netinfo = run_checks(hostname, now)
    if SAVE_RAW_NETINFO and raw_netinfo.strip():
        append_raw_netinfo(
            os.path.join(output_dir(), f"{hostname}_netinfo.txt"), now, raw_netinfo)

    try:
        append_csv(path, row)
    except OSError as e:
        # e.g. file open in Excel (locked on Windows) or folder not writable
        fallback = os.path.join(
            output_dir(), f"{hostname}_{now.strftime('%Y%m%d%H%M')}.csv")
        try:
            append_csv(fallback, row)
        except OSError:
            fallback = os.path.join(
                os.path.expanduser("~"),
                f"{hostname}_{now.strftime('%Y%m%d%H%M')}.csv")
            append_csv(fallback, row)
        print(f"\nCould not write to {path} ({e}).")
        path = fallback

    # Console summary
    data = dict(row)
    print(f"\nInterface:      {data['net_interface'] or '?'}  "
          f"IP {data['net_local_ip'] or '?'}  DNS {data['net_dns_servers'] or '?'}")
    print(f"Gateway {data['net_gateway'] or '?'}: {data['gw_ping_result']}  "
          f"loss={data['gw_ping_loss_pct']}%  avg={data['gw_ping_rtt_avg_ms']} ms")
    print(f"Ping {PING_TARGET}: {data['ping_result']}  "
          f"loss={data['ping_loss_pct']}%  avg={data['ping_rtt_avg_ms']} ms")
    print(f"DNS:            {data['dns_result']}")
    print(f"HTTP download:  {data['http_result']}  "
          f"{data['http_total_ms']} ms")
    print(f"Overall:        {data['overall_result']}")
    print(f"\nResult appended to: {path}")

    # Keep the window open when launched by double-click as an executable
    if getattr(sys, "frozen", False) and sys.stdin and sys.stdin.isatty():
        input("\nPress Enter to close...")


if __name__ == "__main__":
    main()
