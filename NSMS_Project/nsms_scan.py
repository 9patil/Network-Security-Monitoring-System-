# nsms_scan.py
# Simple Network Security Monitoring (Windows-friendly)
# Requirements: nmap in PATH, python 3.8+

import subprocess
import re
import csv
import socket
import datetime
import sys

# ----- CONFIG -----
DEFAULT_CIDR_SUFFIX = "24"
SCAN_PORTS = "1-1024"
AUTHORIZED_FILE = "authorized_devices.txt"
LOG_FILE = "logs.csv"
ALERT_FILE = "alerts.txt"
# ------------------

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def ip_to_cidr(ip, suffix=DEFAULT_CIDR_SUFFIX):
    return f"{ip.rsplit('.',1)[0]}.0/{suffix}"

def load_authorized(path):
    auth = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 1:
                    mac = parts[0].lower()
                    name = parts[1] if len(parts)>1 else ""
                    auth[mac] = name
    except FileNotFoundError:
        print(f"[!] {path} not found. Creating empty file. Add authorized MACs there.")
        open(path, "a").close()
    return auth

def run_nmap_grepable(args_list):
    cmd = ["nmap"] + args_list + ["-oG", "-"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, universal_newlines=True)
        return out
    except subprocess.CalledProcessError:
        print("[!] nmap command failed. Ensure nmap is installed and in PATH.")
        return ""

def parse_grepable_hosts(grep_text):
    hosts = []
    for line in grep_text.splitlines():
        if not line.startswith("Host:"):
            continue
        m_ip = re.search(r"Host:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        ip = m_ip.group(1) if m_ip else ""
        m_mac = re.search(r"MAC:\s+([0-9A-Fa-f:]{17})", line)
        mac = m_mac.group(1).lower() if m_mac else ""
        m_ports = re.search(r"Ports:\s+(.+)", line)
        ports = m_ports.group(1) if m_ports else ""
        hosts.append({"ip": ip, "mac": mac, "ports": ports})
    return hosts

def parse_ports_field(ports_field):
    results = []
    parts = ports_field.split(",")
    for p in parts:
        sub = p.strip().split("/")
        if len(sub) >= 5:
            port = sub[0]
            state = sub[1]
            service = sub[4]
            if state == "open":
                results.append(f"{port}/{service}")
    return results

def log_row(row):
    header = ["timestamp","ip","mac","device_name","unauthorized","open_ports","note"]
    need_header = False
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as _:
            pass
    except FileNotFoundError:
        need_header = True
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if need_header:
            w.writerow(header)
        w.writerow([row.get(h,"") for h in header])

def alert(msg):
    timestr = datetime.datetime.now().isoformat(sep=" ", timespec="seconds")
    line = f"[{timestr}] {msg}"
    print(line)
    with open(ALERT_FILE, "a", encoding="utf-8") as f:
        f.write(line+"\n")

def main():
    print("=== Simple NSMS (Windows) ===")
    local_ip = get_local_ip()
    cidr = ip_to_cidr(local_ip)
    print(f"Detected local IP: {local_ip}  → assuming network {cidr}")
    auth = load_authorized(AUTHORIZED_FILE)
    if not auth:
        print("[i] No authorized devices found yet. Add MACs to authorized_devices.txt (format: MAC,Name)")
    print("[*] Running quick host discovery (nmap -sn)...")
    out = run_nmap_grepable(["-sn", cidr])
    hosts = parse_grepable_hosts(out)
    if not hosts:
        print("[!] No hosts found. Is your network different? You can edit the script to change CIDR.")
    for h in hosts:
        ip = h["ip"]
        mac = h["mac"]
        device_name = auth.get(mac,"")
        unauthorized = False
        note = ""
        if mac=="":
            note = "MAC not detected"
        if mac and mac not in auth:
            unauthorized = True
            note = "MAC not in authorized list"
            alert(f"Unauthorized device detected: IP={ip} MAC={mac}")
        print(f"[*] Scanning services on {ip} (this may take a few secs)...")
        out_ports = run_nmap_grepable(["-sV", "-p", SCAN_PORTS, ip])
        parsed = parse_grepable_hosts(out_ports)
        open_ports = []
        if parsed and parsed[0].get("ports"):
            open_ports = parse_ports_field(parsed[0]["ports"])
            if open_ports:
                alert(f"Open ports on {ip}: {', '.join(open_ports)}")
        row = {
            "timestamp": datetime.datetime.now().isoformat(sep=" ", timespec="seconds"),
            "ip": ip,
            "mac": mac,
            "device_name": device_name,
            "unauthorized": "yes" if unauthorized else "no",
            "open_ports": ";".join(open_ports),
            "note": note
        }
        log_row(row)
    print("[*] Scan complete. Logs saved to", LOG_FILE)
    print("[*] Alerts (if any) appended to", ALERT_FILE)
    print("Tip: open logs.csv in Excel / Notepad to view results.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting.")
        sys.exit(0)
