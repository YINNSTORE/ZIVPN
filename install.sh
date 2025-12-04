#!/bin/bash

# 🚀 ZIVPN UDP AUTO INSTALLER
# Minimalist & Elegant Edition

# Colors
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RED="\033[1;31m"
BLUE="\033[1;34m"
RESET="\033[0m"
BOLD="\033[1m"
GRAY="\033[1;30m"

# Helpers
print_task() {
  echo -ne "${GRAY}•${RESET} $1..."
}

print_done() {
  echo -e "\r${GREEN}✓${RESET} $1      "
}

print_fail() {
  echo -e "\r${RED}✗${RESET} $1      "
  exit 1
}

run_silent() {
  local msg="$1"
  local cmd="$2"
  
  print_task "$msg"
  bash -c "$cmd" &>/tmp/zivpn_install.log
  if [ $? -eq 0 ]; then
    print_done "$msg"
  else
    print_fail "$msg (Check /tmp/zivpn_install.log)"
  fi
}

# Header
clear
echo -e "${BOLD}ZiVPN UDP Installer${RESET}"
echo -e "${GRAY}AutoFTbot Edition${RESET}"
echo ""

# 1. Compatibility Check
if [[ "$(uname -s)" != "Linux" ]] || [[ "$(uname -m)" != "x86_64" ]]; then
  print_fail "System not supported (Linux AMD64 only)"
fi

# 2. Check Existing Install
if [ -f /usr/local/bin/zivpn ]; then
  print_fail "ZiVPN already installed"
fi

# 3. System Update
run_silent "Updating system" "sudo apt-get update"

# 4. Dependencies
if ! command -v go &> /dev/null; then
  run_silent "Installing dependencies" "sudo apt-get install -y golang git"
else
  print_done "Dependencies ready"
fi

# 5. Domain Input
echo ""
echo -ne "${BOLD}Domain Configuration${RESET}\n"
while true; do
  read -p "Enter Domain: " domain
  if [[ -n "$domain" ]]; then
    break
  fi
done
echo ""

# 6. Install Core
systemctl stop zivpn.service &>/dev/null
run_silent "Downloading Core" "wget -q https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn && chmod +x /usr/local/bin/zivpn"

# 7. Configuration
mkdir -p /etc/zivpn
echo "$domain" > /etc/zivpn/domain
run_silent "Configuring" "wget -q https://raw.githubusercontent.com/AutoFTbot/ZiVPN/main/config.json -O /etc/zivpn/config.json"

# 8. SSL
run_silent "Generating SSL" "openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj '/C=ID/ST=Jawa Barat/L=Bandung/O=AutoFTbot/OU=IT Department/CN=$domain' -keyout /etc/zivpn/zivpn.key -out /etc/zivpn/zivpn.crt"

# 9. Optimization
sysctl -w net.core.rmem_max=16777216 &>/dev/null
sysctl -w net.core.wmem_max=16777216 &>/dev/null

# 10. Service (VPN)
cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=ZIVPN UDP VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

# 11. API Setup
mkdir -p /etc/zivpn/api
run_silent "Setting up API" "wget -q https://raw.githubusercontent.com/AutoFTbot/ZiVPN/main/zivpn-api.go -O /etc/zivpn/api/zivpn-api.go && wget -q https://raw.githubusercontent.com/AutoFTbot/ZiVPN/main/go.mod -O /etc/zivpn/api/go.mod"

cd /etc/zivpn/api
if go build -o zivpn-api zivpn-api.go &>/dev/null; then
  print_done "Compiling API"
else
  print_fail "Compiling API"
fi

cat <<EOF > /etc/systemd/system/zivpn-api.service
[Unit]
Description=ZiVPN Golang API Service
After=network.target zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/api
ExecStart=/etc/zivpn/api/zivpn-api
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 12. Start Services
run_silent "Starting Services" "systemctl enable zivpn.service && systemctl start zivpn.service && systemctl enable zivpn-api.service && systemctl start zivpn-api.service"

# 13. Firewall
iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 &>/dev/null
ufw allow 6000:19999/udp &>/dev/null
ufw allow 5667/udp &>/dev/null
ufw allow 8080/tcp &>/dev/null

# Cleanup
rm -f install.sh install.tmp install.log &>/dev/null

# Summary
echo ""
echo -e "${BOLD}Installation Complete${RESET}"
echo -e "Domain  : ${CYAN}$domain${RESET}"
echo -e "API     : ${CYAN}Port 8080${RESET}"
echo -e "Token   : ${CYAN}zivpn-secret-token${RESET}"
echo ""
