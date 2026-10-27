#!/usr/bin/env python3
"""
netcheck.py - quick network connectivity check.

Runs:
  1. Ping 8.8.8.8 (4 packets) and parses loss / round-trip statistics
  2. DNS lookups for a few hostnames (timed)
  3. Timed download of a small web page

Each run appends ONE row to <hostname>.csv, located next to the executable
(or next to this script when run with plain Python). The header row is
written only when the file is created.

Works on Windows, macOS and Linux using only the standard library.

Mac installation steps
    pyinstaller --onefile --name netcheck netcheck.py

    time ./netcheck

    mkdir ~/netcheck
    cp netcheck ~/netcheck
    cp netcheck.plist ~/netcheck
    vi ~/netcheck/netcheck.plist
    cp netcheck.plist ~/Library/LaunchAgents
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/netcheck.plist
    launchctl list | grep netcheck
    launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/netcheck.plist
    launchctl list | grep netcheck
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

    # --- Ping ---
    p = run_ping(PING_TARGET, PING_COUNT)
    ping_ok = p.get("received", 0) > 0
    row += [
        ("ping_target", PING_TARGET),
        ("ping_packets_sent", fmt(p.get("sent"))),
        ("ping_packets_received", fmt(p.get("received"))),
        ("ping_packets_lost", fmt(p.get("lost"))),
        ("ping_loss_pct", fmt(p.get("loss_pct"))),
        ("ping_rtt_min_ms", fmt(p.get("rtt_min"))),
        ("ping_rtt_avg_ms", fmt(p.get("rtt_avg"))),
        ("ping_rtt_max_ms", fmt(p.get("rtt_max"))),
        ("ping_rtt_stddev_ms", fmt(p.get("rtt_stddev"))),
        ("ping_result", "PASS" if ping_ok else "FAIL"),
        ("ping_error", p.get("error", "")),
    ]

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
    return row


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
    row = run_checks(hostname, now)

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
    print(f"\nPing {PING_TARGET}: {data['ping_result']}  "
          f"loss={data['ping_loss_pct']}%  avg={data['ping_rtt_avg_ms']} ms")
    print(f"DNS:            {data['dns_result']}")
    print(f"HTTP download:  {data['http_result']}  "
          f"{data['http_total_ms']} ms")
    print(f"Overall:        {data['overall_result']}")
    print(f"\nResult appended to: {path}")


if __name__ == "__main__":
    main()
