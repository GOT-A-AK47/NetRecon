#!/bin/bash
#
# NetRecon Auto-Installer for Raspberry Pi Zero W v1.1
# One-command installation script
#
# Usage: curl -sSL https://raw.githubusercontent.com/GOT-A-AK47/NetRecon/master/install.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║        NetRecon Auto-Installer           ║"
echo "║   Raspberry Pi Zero W v1.1 Edition       ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo; then
    echo -e "${YELLOW}Warning: This doesn't appear to be a Raspberry Pi${NC}"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}Error: Please run without sudo${NC}"
    echo "The script will ask for sudo when needed"
    exit 1
fi

echo -e "${GREEN}[1/7] Updating system packages...${NC}"
sudo apt update
sudo apt upgrade -y

echo -e "${GREEN}[2/7] Installing system dependencies...${NC}"
sudo apt install -y \
    python3-pip \
    python3-venv \
    tcpdump \
    git \
    wireless-tools \
    net-tools \
    aircrack-ng

echo -e "${GREEN}[3/7] Cloning NetRecon repository...${NC}"
INSTALL_DIR="$HOME/NetRecon"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}NetRecon directory already exists. Updating...${NC}"
    cd "$INSTALL_DIR"
    git pull
else
    git clone https://github.com/GOT-A-AK47/NetRecon.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo -e "${GREEN}[4/7] Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "${GREEN}[5/7] Installing Python dependencies...${NC}"
pip3 install --upgrade pip
pip3 install -r requirements.txt

echo -e "${GREEN}[6/7] Creating directories...${NC}"
mkdir -p logs data/captures data/results

echo -e "${GREEN}[7/7] Configuring for Pi Zero W...${NC}"

# Update config for Pi Zero W (limited resources)
cat > config.json.tmp << 'EOF'
{
  "application": {
    "name": "NetRecon",
    "version": "1.0.0"
  },
  "logging": {
    "log_level": "INFO",
    "log_file": "logs/netrecon.log"
  },
  "network": {
    "default_interface": "wlan0",
    "timeout": 5,
    "max_threads": 20
  },
  "port_scanner": {
    "enabled": true,
    "default_ports": "1-1000",
    "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443],
    "scan_timeout": 2,
    "service_detection": true,
    "os_detection": false
  },
  "packet_analyzer": {
    "enabled": true,
    "capture_dir": "data/captures",
    "max_packets": 5000,
    "promiscuous_mode": true,
    "auto_save": true,
    "protocols": ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP"]
  },
  "host_discovery": {
    "enabled": true,
    "method": "ping",
    "resolve_hostnames": true,
    "detect_os": false
  },
  "web_interface": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "auto_refresh": 5
  },
  "output": {
    "format": "text",
    "export_formats": ["json", "csv", "xml"],
    "save_results": true,
    "results_dir": "data/results"
  },
  "security": {
    "require_sudo": true,
    "rate_limiting": true,
    "max_scan_rate": 500
  }
}
EOF

if [ ! -f config.json ]; then
    mv config.json.tmp config.json
    echo -e "${GREEN}Created optimized config for Pi Zero W${NC}"
else
    echo -e "${YELLOW}config.json already exists, created config.json.tmp as template${NC}"
fi

# Create systemd service
echo -e "${BLUE}Creating systemd service (optional)...${NC}"
cat > /tmp/netrecon.service << EOF
[Unit]
Description=NetRecon Network Security Tool
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/main.py --interactive
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/netrecon.service /etc/systemd/system/netrecon.service
sudo systemctl daemon-reload

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║     NetRecon Installation Complete!      ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Installation directory:${NC} $INSTALL_DIR"
echo ""
echo -e "${YELLOW}Quick Start:${NC}"
echo "  cd $INSTALL_DIR"
echo "  source venv/bin/activate"
echo "  sudo python3 main.py --interactive"
echo ""
echo -e "${YELLOW}Web Interface:${NC}"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo -e "${YELLOW}Auto-start on boot (optional):${NC}"
echo "  sudo systemctl enable netrecon"
echo "  sudo systemctl start netrecon"
echo ""
echo -e "${RED}⚠️  IMPORTANT:${NC}"
echo "  - Only use on networks you own or have permission to test"
echo "  - NetRecon requires root/sudo for packet capture"
echo "  - Configured for Pi Zero W (20 threads, 5000 max packets)"
echo ""
echo -e "${GREEN}Happy hacking! 🔐${NC}"
