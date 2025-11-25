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

