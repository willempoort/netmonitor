#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
GeoIP Helper
Provides country lookup for IP addresses
"""

import ipaddress
import logging
import socket
import os
from pathlib import Path

logger = logging.getLogger('NetMonitor.GeoIP')

# Try to import geoip2
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 library not installed. Run: pip install geoip2")

# Search for GeoIP database
GEOIP_DB_PATHS = [
    '/var/lib/GeoIP/GeoLite2-Country.mmdb',
    '/usr/share/GeoIP/GeoLite2-Country.mmdb',
    '/opt/GeoIP/GeoLite2-Country.mmdb',
    Path(__file__).parent / 'GeoLite2-Country.mmdb',
]

# Find first available database
GEOIP_DB_PATH = None
for path in GEOIP_DB_PATHS:
    if os.path.exists(path):
        GEOIP_DB_PATH = str(path)
        logger.info(f"Found GeoIP database: {GEOIP_DB_PATH}")
        break

if not GEOIP_DB_PATH and GEOIP2_AVAILABLE:
    logger.warning(
        "GeoIP database not found. Download from: "
        "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    )

# Initialize GeoIP reader (lazy loading)
_geoip_reader = None


def _get_geoip_reader():
    """Get or create GeoIP reader instance"""
    global _geoip_reader
    if _geoip_reader is None and GEOIP2_AVAILABLE and GEOIP_DB_PATH:
        try:
            _geoip_reader = geoip2.database.Reader(GEOIP_DB_PATH)
            logger.info("GeoIP2 reader initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize GeoIP reader: {e}")
    return _geoip_reader


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except:
        return False


def get_country_for_ip(ip_str: str) -> str:
    """
    Get country for a single IP address using GeoIP2 MaxMind database

    Returns:
    - 'Private Network' for private IPs
    - 'Country Name (CC)' for public IPs (if database available)
    - 'Unknown' if lookup fails
    """
    if not ip_str:
        return None

    # Check if private
    if is_private_ip(ip_str):
        return 'Private Network'

    # Try GeoIP2 lookup first (most accurate)
    reader = _get_geoip_reader()
    if reader:
        try:
            response = reader.country(ip_str)
            country_name = response.country.name or 'Unknown'
            country_code = response.country.iso_code or '??'
            return f"{country_name} ({country_code})"
        except geoip2.errors.AddressNotFoundError:
            # IP not in database (possibly new/uncategorized)
            pass
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_str}: {e}")

    # Fallback: Try to determine country from hostname TLD (less accurate)
    try:
        hostname = socket.gethostbyaddr(ip_str)[0]
        if hostname and '.' in hostname:
            tld = hostname.split('.')[-1].upper()
            # Common country TLDs
            country_tlds = {
                'NL': 'Netherlands',
                'DE': 'Germany',
                'UK': 'United Kingdom',
                'FR': 'France',
                'BE': 'Belgium',
                'IT': 'Italy',
                'ES': 'Spain',
                'US': 'United States',
                'CA': 'Canada',
                'JP': 'Japan',
                'CN': 'China',
                'RU': 'Russia',
                'BR': 'Brazil',
                'AU': 'Australia',
                'IN': 'India',
                'CH': 'Switzerland',
                'SE': 'Sweden',
                'NO': 'Norway',
                'DK': 'Denmark',
                'FI': 'Finland',
                'PL': 'Poland',
                'AT': 'Austria',
                'CZ': 'Czech Republic'
            }
            if tld in country_tlds:
                return f"{country_tlds[tld]} ({tld})"
    except:
        pass

    return 'Unknown'


def get_country_for_ips(ip_list: list) -> dict:
    """
    Get country information for multiple IPs
    Returns dict mapping IP -> country
    """
    result = {}

    for ip in ip_list:
        if ip:
            result[ip] = get_country_for_ip(ip)

    return result


def get_flag_emoji(country_code: str) -> str:
    """
    Convert country code to flag emoji
    Example: 'NL' -> '🇳🇱'
    """
    if not country_code or len(country_code) != 2:
        return '🌐'

    # Convert to regional indicator symbols
    offset = 127397  # Offset to regional indicator symbols
    return ''.join(chr(ord(c) + offset) for c in country_code.upper())
