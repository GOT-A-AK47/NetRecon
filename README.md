# NetRecon

**Network Reconnaissance & Analysis Tool** - Een educational security tool voor geauthoriseerde netwerk testing.

> ⚠️ **WAARSCHUWING**: Gebruik dit alleen op netwerken die je zelf bezit of waar je expliciete toestemming voor hebt. Ongeautoriseerd network scanning en packet capture kan illegaal zijn.

## Features

### 🔍 Network Scanning
- **Port Scanning**: TCP/UDP port scanning met service detectie
- **Host Discovery**: Ontdek actieve hosts op een netwerk
- **Service Detection**: Identificeer services die draaien op open poorten
- **Custom Port Ranges**: Scan specifieke poorten of ranges

### 📦 Packet Analysis
- **Real-time Capture**: Live packet capturing met filtering
- **Protocol Analysis**: Ondersteunt TCP, UDP, ICMP, ARP, DNS, HTTP
- **PCAP Export**: Sla captures op voor latere analyse
- **Traffic Statistics**: Real-time statistieken en visualisatie

### 🌐 Web Interface
- **Dashboard**: Real-time monitoring en visualisatie
- **Interactive Scanning**: Start scans via web interface
- **Results Export**: Exporteer resultaten naar JSON, CSV, XML
- **Live Updates**: WebSocket ondersteuning voor real-time data

## Installatie

### Vereisten

**System Requirements:**
- Python 3.8 of hoger
- Linux/macOS (Windows met Npcap voor packet capture)
- Root/Administrator privileges voor packet capture

**System Packages:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y python3-pip tcpdump nmap

# macOS
brew install python tcpdump nmap

# Windows
# Installeer Npcap van https://npcap.com/
```

### Python Dependencies

```bash
# Clone of download het project
cd NetRecon

# Installeer Python dependencies
pip3 install -r requirements.txt
```

### Directory Setup

```bash
# Maak benodigde directories
mkdir -p logs data/captures data/results
```

## Gebruik

### Interactive Mode (Web Interface)

Start de web interface voor interactief gebruik:

```bash
sudo python3 main.py --interactive
```

Toegang via browser: `http://localhost:8080`

### CLI Mode

#### Port Scanning

Scan een enkele host:
```bash
sudo python3 main.py --scan 192.168.1.1
```

Scan met custom port range:
```bash
sudo python3 main.py --scan 192.168.1.1 --ports 1-65535
```

Scan met specifieke poorten:
```bash
sudo python3 main.py --scan example.com --ports 22,80,443,8080
```

#### Host Discovery

Ontdek hosts op een netwerk:
```bash
sudo python3 main.py --discover 192.168.1.0/24
```

#### Packet Capture

Start packet capture:
```bash
sudo python3 main.py --capture --interface eth0
```

Met filter:
```bash
sudo python3 main.py --capture --interface wlan0 --filter "tcp port 80"
```

### Custom Configuration

Gebruik een custom config bestand:
```bash
sudo python3 main.py --config /path/to/config.json
```

## Configuratie

Edit `config.json` om je preferences in te stellen:

```json
{
  "port_scanner": {
    "default_ports": "1-1000",
    "scan_timeout": 1,
    "service_detection": true
  },
  "packet_analyzer": {
    "max_packets": 10000,
    "promiscuous_mode": true,
    "auto_save": true
  },
  "web_interface": {
    "host": "0.0.0.0",
    "port": 8080
  }
}
```

### Belangrijke Settings

- `port_scanner.default_ports`: Default port range voor scans
- `packet_analyzer.max_packets`: Maximum aantal packets te capturen
- `web_interface.port`: Port voor web interface
- `network.max_threads`: Maximum threads voor scanning (performance vs stealth)

## Project Structuur

```
NetRecon/
├── main.py                    # Main applicatie
├── config.json               # Configuratie
├── requirements.txt          # Python dependencies
├── modules/                  # Core modules
│   ├── __init__.py
│   ├── port_scanner.py       # Port scanning module
│   ├── packet_analyzer.py    # Packet capture & analysis
│   ├── host_discovery.py     # Host discovery module
│   ├── web_interface.py      # Flask web app
│   ├── config_loader.py      # Config management
│   └── utils.py              # Utility functions
├── templates/                # HTML templates
│   ├── index.html           # Dashboard
│   ├── scanner.html         # Scanner interface
│   └── analyzer.html        # Packet analyzer interface
├── static/                   # CSS/JS/Assets
│   ├── css/
│   ├── js/
│   └── img/
├── logs/                     # Log files
└── data/                     # Data storage
    ├── captures/            # Packet captures (.pcap)
    └── results/             # Scan results
```

## Features Roadmap

- [x] Port scanning (TCP/SYN)
- [x] Host discovery
- [x] Packet capture
- [x] Web interface
- [ ] OS fingerprinting
- [ ] Service version detection
- [ ] ARP spoofing detection
- [ ] Network mapping/visualization
- [ ] Vulnerability scanning
- [ ] Traffic anomaly detection
- [ ] Report generation (PDF/HTML)

## Gebruik Cases

### Security Audit
```bash
# 1. Discover hosts
sudo python3 main.py --discover 192.168.1.0/24

# 2. Scan discovered hosts
sudo python3 main.py --scan 192.168.1.100 --ports 1-65535

# 3. Analyze traffic
sudo python3 main.py --capture --interface eth0 --filter "host 192.168.1.100"
```

### Network Monitoring
```bash
# Start web interface voor continuous monitoring
sudo python3 main.py --interactive
```

### Penetration Testing Practice
```bash
# Target je eigen test lab
sudo python3 main.py --scan testlab.local --ports 1-10000
```

## Troubleshooting

### Permission Errors
```bash
# NetRecon heeft root privileges nodig voor raw sockets
sudo python3 main.py
```

### Interface Not Found
```bash
# List beschikbare interfaces
ip link show          # Linux
ifconfig             # macOS/Unix

# Update config.json met correcte interface naam
```

### Packet Capture Fails (Windows)
```bash
# Installeer Npcap
# Download van: https://npcap.com/
# Enable "WinPcap compatibility mode" tijdens installatie
```

### Scapy Import Error
```bash
# Installeer system dependencies eerst
sudo apt install python3-dev libpcap-dev

# Herinstalleer scapy
pip3 install --upgrade scapy
```

## Legal & Ethical Use

**Deze tool is ALLEEN voor educational purposes en authorized testing.**

✅ **Toegestaan:**
- Testen van je eigen netwerk
- Geauthoriseerde penetration tests
- Educational labs en CTF challenges
- Security research met toestemming

❌ **NIET toegestaan:**
- Scannen van netwerken zonder toestemming
- Ongeautoriseerde packet capture
- Gebruik voor kwaadaardige doeleinden
- Verstoren van netwerk services

**Wettelijke disclaimer:** De ontwikkelaars zijn niet verantwoordelijk voor misbruik van deze tool. Gebruikers zijn zelf verantwoordelijk voor naleving van lokale wetten en regulations.

## Contributing

Dit is een educational project. Suggesties en verbeteringen zijn welkom!

## License

Educational use only. Zie LICENSE bestand voor details.

## Credits

Gebouwd met:
- [Scapy](https://scapy.net/) - Packet manipulation
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Nmap](https://nmap.org/) - Inspiratie voor scanning technieken

## Support

Voor vragen over educational use en best practices:
- Check de documentatie
- Review de code comments
- Test eerst in een geïsoleerde lab omgeving

**Remember: Met grote kracht komt grote verantwoordelijkheid. Gebruik deze tool ethisch!**
