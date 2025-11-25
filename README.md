# 🛰 Network Security Monitoring System (NSMS)

A simple Python-based Network Security Monitoring System that detects active network devices, identifies unauthorized clients, checks open ports using Nmap, and generates audit-ready logs.

This tool behaves like a mini-SOC (Security Operations Center) network scanner, useful for basic home/office network monitoring and learning network security concepts.

---

## 🚀 Features

- ✔ Detects all active devices on the local network  
- ✔ Extracts IP, MAC, hostname and open ports  
- ✔ Identifies unauthorized devices by comparing MAC address with a trusted list  
- ✔ Generates structured logs (`logs.csv`) for auditing  
- ✔ Simple TXT file for adding trusted devices  
- ✔ Works on Windows using Python + Nmap  

---

## 🏗 How It Works (Architecture)

Your PC
↓
Detect Local IP
↓
Create Network Range (192.168.x.0/24)
↓
Nmap Scan → Find Devices
↓
Extract IP + MAC + Ports
↓
Compare with authorized_devices.txt
↓
Generate Logs + Alerts


---

## 📦 Files in Project

| File | Description |
|------|-------------|
| `nsms_scan.py` | Main Python script |
| `authorized_devices.txt` | List of trusted MAC addresses |
| `logs.csv` | Output logs after each scan |
| `run.bat` (optional) | Run script with double-click |

---


---





### ***. Run with command**
```bash
python nsms_scan.py


timestamp,ip,device_name,unauthorized,open_ports,note
2025-11-25 03:05:12,192.168.1.3,Mobile,no,MAC OK
2025-11-25 03:05:19,192.168.1.18,,yes,22,UNAUTHORIZED DEVICE


