# NetRecon - Custom Raspberry Pi Image Creation

Deze guide laat zien hoe je een custom Raspberry Pi OS image maakt met NetRecon voorgeïnstalleerd.

## Optie 1: Automatische Installatie (Aanbevolen)

De makkelijkste manier is om een verse Raspbian Lite te gebruiken met het auto-install script:

### Stap 1: Download Raspberry Pi OS Lite
```bash
# Download van https://www.raspberrypi.com/software/operating-systems/
# Kies: Raspberry Pi OS Lite (32-bit) voor Pi Zero W
```

### Stap 2: Flash naar SD kaart
Gebruik Raspberry Pi Imager of balenaEtcher

### Stap 3: Eerste boot configuratie
```bash
# SSH enablen (plaats bestand in boot partition):
touch /boot/ssh

# WiFi configureren:
nano /boot/wpa_supplicant.conf
```

Voeg toe:
```
country=BE
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="JouwSSID"
    psk="JouwWachtwoord"
}
```

### Stap 4: Boot Pi en installeer NetRecon
```bash
# SSH naar Pi
ssh pi@raspberrypi.local
# Default password: raspberry

# Run one-line installer
curl -sSL https://raw.githubusercontent.com/GOT-A-AK47/NetRecon/master/install.sh | bash
```

## Optie 2: Custom Image Bouwen

Voor het maken van een volledig custom image met NetRecon voorgeïnstalleerd:

### Tools Nodig
- Linux machine (of WSL2 op Windows)
- `pi-gen` (Raspberry Pi image builder)
- Minimaal 20GB vrije schijfruimte

### Methode 1: Pi-Gen gebruiken

```bash
# Clone pi-gen
git clone https://github.com/RPi-Distro/pi-gen.git
cd pi-gen

# Create config
cat > config << EOF
IMG_NAME='NetRecon-PiZeroW'
RELEASE='bookworm'
DEPLOY_COMPRESSION='zip'
LOCALE_DEFAULT='en_US.UTF-8'
TARGET_HOSTNAME='netrecon'
KEYBOARD_KEYMAP='us'
KEYBOARD_LAYOUT='English (US)'
TIMEZONE_DEFAULT='Europe/Brussels'
FIRST_USER_NAME='netrecon'
FIRST_USER_PASS='netrecon123'
ENABLE_SSH=1
STAGE_LIST="stage0 stage1 stage2"
EOF

# Create custom stage
mkdir -p stage3/01-netrecon/00-run.sh

cat > stage3/01-netrecon/00-run.sh << 'EOF'
#!/bin/bash -e

# Install NetRecon
cd /home/netrecon
git clone https://github.com/GOT-A-AK47/NetRecon.git

cd NetRecon
pip3 install -r requirements.txt

# Configure for Pi Zero W
cp config.json config.json.bak
# ... (paste optimized config)

# Setup systemd service
cp /tmp/netrecon.service /etc/systemd/system/
systemctl enable netrecon

EOF

chmod +x stage3/01-netrecon/00-run.sh

# Build image
sudo ./build.sh
```

### Methode 2: Bestaande Image Aanpassen (Sneller)

```bash
# Download Raspberry Pi OS Lite image
wget https://downloads.raspberrypi.org/raspios_lite_armhf/images/...

# Mount image
sudo losetup -fP raspios_lite.img
sudo mount /dev/loop0p2 /mnt

# Chroot in image
sudo mount --bind /dev /mnt/dev
sudo mount --bind /sys /mnt/sys
sudo mount --bind /proc /mnt/proc
sudo chroot /mnt /bin/bash

# Install NetRecon
cd /home/pi
git clone https://github.com/GOT-A-AK47/NetRecon.git
cd NetRecon
pip3 install -r requirements.txt

# Cleanup and exit
exit
sudo umount /mnt/dev /mnt/sys /mnt/proc /mnt
sudo losetup -d /dev/loop0

# Shrink image (optional)
pishrink.sh raspios_lite.img netrecon.img
```

## Optie 3: Dockerfile voor Testing

Voor development/testing kan je een Docker container gebruiken:

```dockerfile
FROM balenalib/raspberry-pi-debian:latest

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3-pip \
    tcpdump \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone NetRecon
WORKDIR /opt
RUN git clone https://github.com/GOT-A-AK47/NetRecon.git
WORKDIR /opt/NetRecon

# Install Python deps
RUN pip3 install -r requirements.txt

# Expose web interface
EXPOSE 8080

CMD ["python3", "main.py", "--interactive"]
```

Build en run:
```bash
docker build -t netrecon .
docker run -it --cap-add=NET_ADMIN --net=host netrecon
```

## Pre-configured Image Details

Als je een pre-configured image maakt, include:

### Default Credentials
- Username: `netrecon`
- Password: `netrecon123` (verander bij eerste login!)
- Hostname: `netrecon.local`

### Pre-installed Software
- NetRecon (latest from GitHub)
- All dependencies
- Optimized config for Pi Zero W:
  - max_threads: 20
  - max_packets: 5000
  - default interface: wlan0

### Systemd Services
- `netrecon.service` - Auto-start NetRecon web interface
- Disabled by default (enable met `sudo systemctl enable netrecon`)

### First Boot
Script die runt bij eerste boot:
1. Expand filesystem
2. Update packages
3. Generate nieuwe SSH keys
4. Prompt voor wachtwoord wijziging

## Image Distribution

### Comprimeren
```bash
zip -9 netrecon-pizerow-$(date +%Y%m%d).zip netrecon.img
```

### Publiceren
Upload naar:
- GitHub Releases
- Google Drive
- SourceForge

### Checksum
```bash
sha256sum netrecon-pizerow-*.img > SHA256SUMS
```

## Gebruikers Instructies

Voor gebruikers van de pre-made image:

1. Download `netrecon-pizerow-YYYYMMDD.img.zip`
2. Unzip
3. Flash naar SD kaart (min 8GB) met Raspberry Pi Imager
4. Optioneel: Configure WiFi (zie boven)
5. Boot Pi
6. SSH: `ssh netrecon@netrecon.local`
7. Change password: `passwd`
8. Start NetRecon: `sudo systemctl start netrecon`
9. Access web: `http://netrecon.local:8080`

## Security Waarschuwing

⚠️ **BELANGRIJK**:
- Verander ALTIJD het default wachtwoord
- Update SSH keys bij eerste boot
- Disable SSH als niet nodig
- Gebruik alleen op vertrouwde netwerken

## Legal Notice

NetRecon is een educational security tool. Gebruik alleen op netwerken waar je toestemming voor hebt.
