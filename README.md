# Python Packet Filtering Firewall 🔒

A simple real-time Python firewall built using **NetfilterQueue + Scapy**.  
It captures, inspects, and blocks packets based on custom rules.

---

## Features

✅ Block packets based on:
- IP addresses
- TCP/UDP ports
- Protocols (ICMP)

✅ Real-time processing via **Linux Kernel Netfilter (iptables)**.

---

## Requirements

- Python 3.x
- Linux OS (NetfilterQueue works only on Linux)
- `scapy`, `NetfilterQueue` Python packages

Install dependencies:

pip install -r requirements.txt

---

## Usage

1. **Add iptables rule to route packets:** sudo iptables -I INPUT -j NFQUEUE --queue-num 0

 2. **Run the firewall:**  sudo python3 real_firewall.py
 
 3. **Remove iptables rule after use:** sudo iptables -D INPUT -j NFQUEUE --queue-num 0

---

## Notes

⚠️ Works only on **Linux**.

⚠️ Requires **root privileges** to run and manipulate iptables.

---

## Educational Use Only ⚠️

Do not deploy in production without understanding the security and networking risks.



