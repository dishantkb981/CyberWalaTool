#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Starting CyberWala installation...${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] Please run as root${NC}"
    exit 1
fi

# Update system
echo -e "${YELLOW}[*] Updating system...${NC}"
apt update && apt upgrade -y

# Install system dependencies
echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
apt install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    python3-cryptography \
    python3-openssl \
    python3-requests \
    python3-bs4 \
    python3-lxml \
    python3-yaml \
    python3-argparse \
    python3-colorama \
    python3-dnspython \
    python3-nmap \
    python3-scapy \
    python3-twisted \
    python3-service-identity \
    python3-whois \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    git \
    nmap \
    whois \
    dnsutils \
    host \
    wget \
    curl \
    ruby \
    ruby-dev \
    build-essential \
    libcurl4-openssl-dev \
    libxml2 \
    libxml2-dev \
    libxslt1-dev \
    libyaml-dev \
    zlib1g-dev

# Install security tools
echo -e "${YELLOW}[*] Installing security tools...${NC}"
apt install -y \
    dnsrecon \
    wafw00f \
    uniscan \
    sslyze \
    fierce \
    lbd \
    theharvester \
    amass \
    nikto

# Install Python packages
echo -e "${YELLOW}[*] Installing Python packages...${NC}"
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Make script executable
echo -e "${YELLOW}[*] Setting up permissions...${NC}"
chmod +x cyberwala.py

echo -e "${GREEN}[+] Installation completed!${NC}"
echo -e "${GREEN}[+] You can now run CyberWala using: sudo python3 cyberwala.py${NC}" 