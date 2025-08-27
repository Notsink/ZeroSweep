# ZeroSweep – One-file port-scanner with superpowers ⭐

https://www.python.org/downloads/

LICENSE
https://github.com/Notsink/ZeroSweep/releases

🚀 Blazing-fast • 🧠 AI-smart • 🖥️ GUI+CLI • 🕶️ Stealth-mode • 📊 Rich reports
All in one file – no external binaries, no root, no drama.

# ✨ What makes ZeroSweep shine

| Feature                      | Emoji | Why it’s cool                       |
| ---------------------------- | ----- | ----------------------------------- |
| Async engine up to 100 k pps | 🚀    | Scans /8 networks in minutes        |
| Tiny-ML service fingerprint  | 🧠    | 500-byte banner → “nginx/1.25.1”    |
| JA3/JA4 + CSP/HSTS grabber   | 🔐    | Instant SSL/TLS posture check       |
| OS detection (TTL/Window)    | 🖥️   | “That’s Windows 10”                 |
| Adaptive rate-limiter        | ⚡     | Auto-tunes for RTT                  |
| IPv6 + CIDR bulk import      | 🌐    | Drag .txt or paste /64              |
| Stealth via Tor              | 🕶️   | UA rotation + X-Forwarded-For spoof |
| Excel pivot + SARIF          | 📊    | Ready for GitHub Code-Scan          |
| Dark/Light GUI & CLI         | 🎨    | Looks good in midnight hacking      |

# 🚀 Install in 10 seconds

 pip install ttkthemes pillow scapy scikit-learn pandas pyOpenSSL ja3 stem rich openpyxl 

 git clone https://github.com/Notsink/zerosweep.git 
 
 cd zerosweep 

 python ZeroSweep.py 

.

That’s it – no compilation, no root.

# 🎯 Quick Start

GUI

python ZeroSweep.py

.

Paste hosts, hit Start, sip ☕.

.

CLI

python ZeroSweep.py --cli 192.0.2.0/24 --ports top1000 --allowed 22,80,443 --output sarif

.

# 📋 Targets & Ports

• Single IP: 127.0.0.1
• CIDR: 2001:db8::/64
• File drag-and-drop (.txt with one CIDR per line)
• Port list: 22,80,443,3306 or range 1000-2000

# 🛠️ Minimal zerosweep.yaml

yaml

ports: [21,22,23,25,53,80,110,143,443,993,995,1433,3306,3389,5432,6379,8080,8443,9200,27017]
policy:
  allowed: [22,80,443]
stealth: false
excel: true
sarif: true

# 📊 Output Gallery

Excel pivot

| Port | Host Count |
| ---- | ---------- |
| 22   | 512        |
| 80   | 1024       |
| 443  | 768        |


# 🧪 Requirements

| Package               | Why            |
| --------------------- | -------------- |
| `ttkthemes`           | sexy GUI       |
| `pillow`              | icons          |
| `scapy`               | raw packets    |
| `scikit-learn`        | AI fingerprint |
| `pandas` + `openpyxl` | Excel pivot    |
| `pyOpenSSL`           | TLS info       |
| `ja3`                 | JA3 hash       |
| `stem`                | Tor control    |
| `rich`                | live logs      |


# 🤝 Contributing

    Fork 🍴
    pip install -e .[dev]
    pre-commit install
    Pull request 🎉

# 📄 License

MIT © 2024 ZeroSweep Contributors

# ⭐

⭐ Star if it saved you time – more stars = more magic!

