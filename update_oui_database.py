#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
OUI Database Updater

Downloads the official IEEE OUI database and converts it to JSON format
for use with NetMonitor's device discovery module.

The IEEE maintains three registries:
- MA-L (OUI): 24-bit prefix (most common, ~35,000 entries)
- MA-M: 28-bit prefix (~5,000 entries)
- MA-S (OUI-36): 36-bit prefix (~3,000 entries)

This script downloads MA-L which covers the vast majority of devices.

Primary source: IEEE CSV (daily updated)
- https://standards-oui.ieee.org/oui/oui.csv

Fallback sources:
- IEEE TXT: https://standards-oui.ieee.org/oui/oui.txt
- Wireshark manuf: https://www.wireshark.org/download/automated/data/manuf

Usage:
    python update_oui_database.py [--output PATH] [--quiet]
"""

import argparse
import csv
import io
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# Check for requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# IEEE OUI database URLs - CSV is preferred (daily updated, easier to parse)
OUI_CSV_URL = 'https://standards-oui.ieee.org/oui/oui.csv'

# Fallback: TXT format
OUI_TXT_URLS = [
    'https://standards-oui.ieee.org/oui/oui.txt',
    'http://standards-oui.ieee.org/oui/oui.txt',
]

# Backup: Wireshark's manuf file
WIRESHARK_URL = 'https://www.wireshark.org/download/automated/data/manuf'


def download_ieee_csv(quiet: bool = False) -> str:
    """Download OUI database from IEEE in CSV format (preferred, daily updated)"""
    if not REQUESTS_AVAILABLE:
        print("ERROR: requests library not installed. Run: pip install requests")
        sys.exit(1)

    try:
        if not quiet:
            print(f"Downloading IEEE CSV from {OUI_CSV_URL}...")
        response = requests.get(OUI_CSV_URL, timeout=120)
        response.raise_for_status()
        if not quiet:
            print(f"Downloaded {len(response.text):,} bytes")
        return response.text
    except requests.RequestException as e:
        raise Exception(f"Failed to download IEEE CSV: {e}")


def download_ieee_txt(quiet: bool = False) -> str:
    """Download OUI database from IEEE in TXT format (fallback)"""
    if not REQUESTS_AVAILABLE:
        print("ERROR: requests library not installed. Run: pip install requests")
        sys.exit(1)

    for url in OUI_TXT_URLS:
        try:
            if not quiet:
                print(f"Downloading from {url}...")
            response = requests.get(url, timeout=120)
            response.raise_for_status()
            if not quiet:
                print(f"Downloaded {len(response.text):,} bytes")
            return response.text
        except requests.RequestException as e:
            if not quiet:
                print(f"  Failed: {e}")
            continue

    raise Exception("Failed to download OUI TXT from all sources")


def download_wireshark_manuf(quiet: bool = False) -> str:
    """Download Wireshark's manuf file as fallback"""
    if not REQUESTS_AVAILABLE:
        print("ERROR: requests library not installed. Run: pip install requests")
        sys.exit(1)

    try:
        if not quiet:
            print(f"Downloading Wireshark manuf from {WIRESHARK_URL}...")
        response = requests.get(WIRESHARK_URL, timeout=60)
        response.raise_for_status()
        if not quiet:
            print(f"Downloaded {len(response.text):,} bytes")
        return response.text
    except requests.RequestException as e:
        raise Exception(f"Failed to download Wireshark manuf: {e}")


def parse_ieee_csv(content: str, quiet: bool = False) -> dict:
    """
    Parse IEEE OUI CSV format (preferred, daily updated).

    CSV columns:
    Registry,Assignment,Organization Name,Organization Address

    Example:
    MA-L,000000,XEROX CORPORATION,"XEROX CORPORATION..."
    MA-L,000001,XEROX CORPORATION,"M/S 105-50C..."
    """
    oui_dict = {}

    # Use csv reader to handle quoted fields properly
    reader = csv.reader(io.StringIO(content))

    # Skip header row
    try:
        header = next(reader)
        if not quiet:
            print(f"CSV columns: {header}")
    except StopIteration:
        return oui_dict

    for row in reader:
        if len(row) >= 3:
            # Column 1 is Assignment (OUI hex), Column 2 is Organization Name
            oui = row[1].strip().upper()
            vendor = row[2].strip()

            # Validate OUI format (should be 6 hex chars)
            if len(oui) == 6 and all(c in '0123456789ABCDEF' for c in oui):
                # Clean up vendor name
                vendor = re.sub(r'\s+', ' ', vendor)  # Normalize whitespace
                if vendor:  # Only add if vendor name is not empty
                    oui_dict[oui] = vendor

    if not quiet:
        print(f"Parsed {len(oui_dict):,} OUI entries from IEEE CSV")

    return oui_dict


def parse_ieee_txt(content: str, quiet: bool = False) -> dict:
    """
    Parse IEEE OUI TXT format (fallback).

    Format example:
    00-00-00   (hex)		XEROX CORPORATION
    00-00-01   (hex)		XEROX CORPORATION
    """
    oui_dict = {}

    # Pattern matches: XX-XX-XX   (hex)		Vendor Name
    pattern = re.compile(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$')

    for line in content.split('\n'):
        line = line.strip()
        match = pattern.match(line)
        if match:
            oui = match.group(1).replace('-', '').upper()
            vendor = match.group(2).strip()
            # Clean up vendor name
            vendor = re.sub(r'\s+', ' ', vendor)  # Normalize whitespace
            oui_dict[oui] = vendor

    if not quiet:
        print(f"Parsed {len(oui_dict):,} OUI entries from IEEE TXT")

    return oui_dict


def parse_wireshark_manuf(content: str, quiet: bool = False) -> dict:
    """
    Parse Wireshark's manuf file format.

    Format examples:
    00:00:00	00:00:00	Officially Xerox
    00:00:01	Xerox	Xerox Corporation
    00:00:0C	Cisco	Cisco Systems, Inc
    00:00:0C:07:AC/40	All-HSRP-routers
    """
    oui_dict = {}

    for line in content.split('\n'):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue

        parts = line.split('\t')
        if len(parts) >= 2:
            mac_part = parts[0].strip()

            # Skip entries with mask (like /40) - they're for specific ranges
            if '/' in mac_part:
                continue

            # Get vendor (short name in parts[1], full name in parts[2] if available)
            if len(parts) >= 3 and parts[2].strip():
                vendor = parts[2].strip()
            else:
                vendor = parts[1].strip()

            # Normalize MAC to OUI format (first 6 hex chars)
            oui = mac_part.replace(':', '').replace('-', '').upper()[:6]

            if len(oui) == 6 and all(c in '0123456789ABCDEF' for c in oui):
                oui_dict[oui] = vendor

    if not quiet:
        print(f"Parsed {len(oui_dict):,} OUI entries from Wireshark format")

    return oui_dict


def merge_databases(*databases: dict) -> dict:
    """Merge multiple OUI databases, preferring longer/more specific names"""
    merged = {}

    for db in databases:
        for oui, vendor in db.items():
            if oui not in merged:
                merged[oui] = vendor
            else:
                # Prefer longer, more descriptive names
                if len(vendor) > len(merged[oui]):
                    merged[oui] = vendor

    return merged


def add_common_vendors(oui_dict: dict) -> dict:
    """Add/update entries for commonly seen vendors that may be missing or incomplete"""

    # These are common IoT and consumer device vendors
    # that should have good recognition
    common_vendors = {
        # Sonos
        '5CDAD4': 'Sonos, Inc.',
        '7405A5': 'Sonos, Inc.',
        '949452': 'Sonos, Inc.',
        'B8E937': 'Sonos, Inc.',
        '78288C': 'Sonos, Inc.',
        '48A6B8': 'Sonos, Inc.',
        '347E5C': 'Sonos, Inc.',

        # Philips Hue / Signify
        '001788': 'Philips Lighting (Signify)',
        'ECB5FA': 'Philips Lighting (Signify)',
        '0017DF': 'Philips Lighting (Signify)',

        # Ring (Amazon)
        '34DF20': 'Ring (Amazon)',
        'F48CEB': 'Ring (Amazon)',

        # Nest (Google)
        '18B430': 'Nest Labs (Google)',
        '64167F': 'Nest Labs (Google)',

        # Ubiquiti
        '802AA8': 'Ubiquiti Networks',
        'F09FC2': 'Ubiquiti Networks',
        '0418D6': 'Ubiquiti Networks',
        '24A43C': 'Ubiquiti Networks',
        '788A20': 'Ubiquiti Networks',
        'B4FBE4': 'Ubiquiti Networks',
        'DC9FDB': 'Ubiquiti Networks',
        'E063DA': 'Ubiquiti Networks',
        'FC6FB7': 'Ubiquiti Networks',

        # TP-Link
        '1C3BF3': 'TP-Link Technologies',
        '503EAA': 'TP-Link Technologies',
        '5C628B': 'TP-Link Technologies',
        '6466B3': 'TP-Link Technologies',
        '98254A': 'TP-Link Technologies',
        'AC84C6': 'TP-Link Technologies',
        'D80D17': 'TP-Link Technologies',
        'F4F26D': 'TP-Link Technologies',

        # Shelly
        '483FDA': 'Shelly (Allterco)',
        'C82B96': 'Shelly (Allterco)',
        'E868E7': 'Shelly (Allterco)',
        '98CDAC': 'Shelly (Allterco)',

        # Tasmota/ESP devices (Espressif)
        '24A160': 'Espressif (ESP32/ESP8266)',
        '2462AB': 'Espressif (ESP32/ESP8266)',
        '30AEA4': 'Espressif (ESP32/ESP8266)',
        '807D3A': 'Espressif (ESP32/ESP8266)',
        '84F3EB': 'Espressif (ESP32/ESP8266)',
        'A4CF12': 'Espressif (ESP32/ESP8266)',
        'C44F33': 'Espressif (ESP32/ESP8266)',
        'CC50E3': 'Espressif (ESP32/ESP8266)',

        # Tuya
        '10D07A': 'Tuya Smart',
        'D4F057': 'Tuya Smart',

        # Xiaomi
        '00EC0A': 'Xiaomi Communications',
        '28E31F': 'Xiaomi Communications',
        '50EC50': 'Xiaomi Communications',
        '64CC2E': 'Xiaomi Communications',
        '78020F': 'Xiaomi Communications',
        '78112F': 'Xiaomi Communications',

        # QNAP
        '0008A2': 'QNAP Systems',
        '002265': 'QNAP Systems',
        '24D97D': 'QNAP Systems',

        # Synology
        '001132': 'Synology',
        '0011A1': 'Synology',

        # Unifi Protect Cameras
        'E063DA': 'Ubiquiti UniFi',

        # OPNsense/pfSense (Netgate)
        '000D5D': 'Netgate (pfSense)',
    }

    for oui, vendor in common_vendors.items():
        oui_dict[oui] = vendor

    return oui_dict


def save_oui_database(oui_dict: dict, output_path: str, quiet: bool = False, source: str = None) -> None:
    """Save OUI database to JSON file"""

    # Sort by OUI for consistency
    sorted_oui = dict(sorted(oui_dict.items()))

    data = {
        "_comment": "MAC Address OUI Database - Organizationally Unique Identifiers",
        "_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "_entries": len(sorted_oui),
        "_source": source or "IEEE Standards Association + Wireshark manuf",
        "_url": "https://standards-oui.ieee.org/oui/oui.csv",
        "oui": sorted_oui
    }

    # Ensure directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    if not quiet:
        print(f"Saved {len(sorted_oui):,} entries to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Download and update the OUI database for MAC vendor lookup'
    )
    parser.add_argument(
        '--output', '-o',
        default=os.path.join(os.path.dirname(__file__), 'data', 'oui_database.json'),
        help='Output path for the OUI database JSON file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress output'
    )
    parser.add_argument(
        '--wireshark-only',
        action='store_true',
        help='Only use Wireshark manuf file (faster, usually more up-to-date)'
    )

    args = parser.parse_args()

    if not REQUESTS_AVAILABLE:
        print("ERROR: requests library not installed")
        print("Run: pip install requests")
        sys.exit(1)

    try:
        oui_data = {}
        source_used = None

        # Try IEEE CSV first (daily updated, preferred)
        if not args.wireshark_only:
            try:
                csv_content = download_ieee_csv(args.quiet)
                oui_data = parse_ieee_csv(csv_content, args.quiet)
                source_used = "IEEE CSV (daily updated)"
            except Exception as e:
                if not args.quiet:
                    print(f"IEEE CSV download failed: {e}")
                    print("Trying IEEE TXT format...")

                # Try TXT format as fallback
                try:
                    txt_content = download_ieee_txt(args.quiet)
                    oui_data = parse_ieee_txt(txt_content, args.quiet)
                    source_used = "IEEE TXT"
                except Exception as e2:
                    if not args.quiet:
                        print(f"IEEE TXT download failed: {e2}")
                        print("Falling back to Wireshark manuf file...")

        # Always try Wireshark as supplement/fallback
        try:
            ws_content = download_wireshark_manuf(args.quiet)
            ws_data = parse_wireshark_manuf(ws_content, args.quiet)

            if oui_data:
                oui_data = merge_databases(oui_data, ws_data)
                if not args.quiet:
                    print(f"Merged with Wireshark data")
            else:
                oui_data = ws_data
                source_used = "Wireshark manuf"
        except Exception as e:
            if not args.quiet:
                print(f"Wireshark download failed: {e}")
            if not oui_data:
                raise Exception("No OUI data sources available")

        # Add common vendors that might be missing
        oui_data = add_common_vendors(oui_data)

        # Save to file
        save_oui_database(oui_data, args.output, args.quiet, source_used)

        if not args.quiet:
            print(f"\nSuccess! OUI database updated with {len(oui_data):,} entries")
            print(f"Primary source: {source_used}")
            print(f"Location: {args.output}")

    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
