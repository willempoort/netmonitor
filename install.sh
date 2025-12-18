#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
# Installatie script voor Network Monitor

set -e

echo "================================"
echo "Network Monitor - Installatie"
echo "================================"
echo ""

# Check of we root zijn
if [[ $EUID -ne 0 ]]; then
   echo "Dit script moet als root worden uitgevoerd (sudo)"
   exit 1
fi

# Check Python versie
echo "Checking Python versie..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python versie: $python_version"

# Check of pip geïnstalleerd is
if ! command -v pip3 &> /dev/null; then
    echo "pip3 niet gevonden. Installeren..."
    apt-get update
    apt-get install -y python3-pip
fi

# Installeer system dependencies (libpcap)
echo ""
echo "Installeren van system dependencies..."
apt-get update
apt-get install -y libpcap-dev tcpdump

# Installeer Python dependencies
echo ""
echo "Installeren van Python dependencies..."
pip3 install -r requirements.txt

# Maak log directory
echo ""
echo "Aanmaken van log directory..."
mkdir -p /var/log/netmonitor
chmod 755 /var/log/netmonitor

# Maak executable
echo ""
echo "Maken van executable..."
chmod +x netmonitor.py

# Check of config bestaat
if [ ! -f "config.yaml" ]; then
    echo "WAARSCHUWING: config.yaml niet gevonden!"
    exit 1
fi

echo ""
echo "================================"
echo "Installatie succesvol!"
echo "================================"
echo ""
echo "Gebruik: sudo python3 netmonitor.py"
echo ""
echo "BELANGRIJK: Pas eerst config.yaml aan met je network interface!"
echo ""
