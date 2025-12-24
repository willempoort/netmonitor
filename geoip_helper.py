#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
GeoIP Helper
Provides country lookup for IP addresses with multiple fallback sources
"""

import ipaddress
import logging
import socket
import os
import time
import threading
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger('NetMonitor.GeoIP')

# Try to import geoip2
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 library not installed. Run: pip install geoip2")

# Try to import requests for API fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

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

# Cache for API lookups (thread-safe)
_api_cache: Dict[str, tuple] = {}  # ip -> (country, timestamp)
_cache_lock = threading.Lock()
_CACHE_TTL = 3600 * 24  # 24 hours cache
_API_RATE_LIMIT = 45  # ip-api.com allows 45 requests/minute for free
_api_calls_this_minute = 0
_api_minute_start = 0

# Configured internal networks (set by set_internal_networks)
_internal_networks: list = []


def set_internal_networks(networks: list):
    """
    Set the list of internal/local networks from configuration.
    These IPs will be labeled as 'Local' instead of 'Private'.

    Args:
        networks: List of CIDR strings, e.g., ['192.168.1.0/24', '10.0.0.0/8']
    """
    global _internal_networks
    _internal_networks = []
    for net_str in networks:
        try:
            _internal_networks.append(ipaddress.ip_network(net_str, strict=False))
        except ValueError as e:
            logger.warning(f"Invalid internal network '{net_str}': {e}")
    logger.debug(f"Internal networks configured: {len(_internal_networks)} networks")


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


def _normalize_ip(ip_str: str) -> str:
    """
    Normalize IP address string by removing CIDR notation if present.
    Example: '10.100.0.7/32' -> '10.100.0.7'
    """
    if not ip_str:
        return ip_str
    # Strip CIDR notation if present
    if '/' in ip_str:
        ip_str = ip_str.split('/')[0]
    return ip_str.strip()


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP is private/internal (RFC1918) but NOT in configured internal networks.
    If no internal_networks are configured, returns False (all private IPs are Local).
    """
    try:
        ip_str = _normalize_ip(ip_str)
        ip = ipaddress.ip_address(ip_str)
        if not (ip.is_private and not ip.is_loopback and not ip.is_link_local):
            return False
        # If internal networks are configured, check if IP is NOT in them
        # (those will be labeled "Local" instead)
        if _internal_networks:
            for network in _internal_networks:
                if ip in network:
                    return False  # This is "Local", not "Private"
            # IP is private but NOT in configured internal_networks
            return True
        else:
            # No internal networks configured - all private IPs are treated as "Local"
            return False
    except Exception as e:
        logger.debug(f"is_private_ip error for {ip_str}: {e}")
        return False


def is_local_ip(ip_str: str) -> bool:
    """
    Check if IP is local (loopback, link-local, or in configured internal networks).
    If no internal_networks are configured, ALL private IPs are considered Local.
    """
    try:
        ip_str = _normalize_ip(ip_str)
        ip = ipaddress.ip_address(ip_str)
        # Always local: loopback and link-local
        if ip.is_loopback or ip.is_link_local:
            return True
        # Private IP handling
        if ip.is_private:
            if _internal_networks:
                # Check if in configured internal networks
                for network in _internal_networks:
                    if ip in network:
                        return True
                return False  # Private but not in our networks
            else:
                # No internal networks configured - treat ALL private IPs as Local
                return True
        return False
    except Exception as e:
        logger.debug(f"is_local_ip error for {ip_str}: {e}")
        return False


def is_reserved_ip(ip_str: str) -> bool:
    """Check if IP is reserved/special purpose"""
    try:
        ip_str = _normalize_ip(ip_str)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_reserved or ip.is_multicast or ip.is_unspecified
    except:
        return False


def _lookup_ip_api(ip_str: str) -> Optional[str]:
    """
    Lookup IP using multiple free APIs (no API key required)
    Tries ip-api.com first, then ipwho.is as fallback
    Rate limited to 45 requests/minute
    """
    global _api_calls_this_minute, _api_minute_start

    if not REQUESTS_AVAILABLE:
        return None

    # Check cache first
    with _cache_lock:
        if ip_str in _api_cache:
            country, timestamp = _api_cache[ip_str]
            if time.time() - timestamp < _CACHE_TTL:
                return country

    # Rate limiting
    current_minute = int(time.time() / 60)
    if current_minute != _api_minute_start:
        _api_calls_this_minute = 0
        _api_minute_start = current_minute

    if _api_calls_this_minute >= _API_RATE_LIMIT:
        logger.debug(f"IP API rate limit reached for {ip_str}")
        return None

    # List of free IP geolocation APIs to try
    apis = [
        {
            'url': f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode",
            'country_field': 'country',
            'code_field': 'countryCode',
            'success_check': lambda d: d.get('status') == 'success'
        },
        {
            'url': f"https://ipwho.is/{ip_str}",
            'country_field': 'country',
            'code_field': 'country_code',
            'success_check': lambda d: d.get('success', False)
        },
        {
            'url': f"https://ipapi.co/{ip_str}/json/",
            'country_field': 'country_name',
            'code_field': 'country_code',
            'success_check': lambda d: 'error' not in d
        }
    ]

    for api in apis:
        try:
            response = requests.get(api['url'], timeout=3)
            _api_calls_this_minute += 1

            if response.status_code == 200:
                data = response.json()
                if api['success_check'](data):
                    country_name = data.get(api['country_field'], 'Unknown')
                    country_code = data.get(api['code_field'], '??')

                    if country_name and country_name != 'Unknown':
                        result = f"{country_name} ({country_code})"

                        # Cache the result
                        with _cache_lock:
                            _api_cache[ip_str] = (result, time.time())

                        logger.debug(f"IP API lookup: {ip_str} -> {result}")
                        return result
            elif response.status_code == 403:
                # API blocked or rate limited, try next
                continue

        except requests.exceptions.Timeout:
            logger.debug(f"IP API timeout for {ip_str}")
            continue
        except Exception as e:
            logger.debug(f"IP API lookup failed for {ip_str}: {e}")
            continue

    return None


def get_country_for_ip(ip_str: str) -> str:
    """
    Get country for a single IP address using multiple sources:
    1. Check for local/private/reserved IPs
    2. GeoIP2 MaxMind database (if available)
    3. Online API fallback (ip-api.com)
    4. DNS TLD lookup (last resort)

    Returns:
    - 'Local' for loopback/link-local IPs (127.0.0.1, ::1, 169.254.x.x)
    - 'Private' for RFC1918 private IPs (10.x, 172.16-31.x, 192.168.x)
    - 'Reserved' for reserved/multicast IPs
    - 'Country Name (CC)' for public IPs
    - 'Unknown' if all lookups fail
    """
    if not ip_str:
        return None

    # Normalize IP (strip CIDR notation like /32)
    ip_str = _normalize_ip(ip_str)

    # Check for local IPs first (loopback, link-local)
    if is_local_ip(ip_str):
        return 'Local'

    # Check for private IPs (RFC1918)
    if is_private_ip(ip_str):
        return 'Private'

    # Check for reserved/multicast IPs
    if is_reserved_ip(ip_str):
        return 'Reserved'

    # Try GeoIP2 lookup first (most accurate, no rate limits)
    reader = _get_geoip_reader()
    if reader:
        try:
            response = reader.country(ip_str)
            country_name = response.country.name or 'Unknown'
            country_code = response.country.iso_code or '??'
            return f"{country_name} ({country_code})"
        except geoip2.errors.AddressNotFoundError:
            # IP not in database, try API fallback
            pass
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_str}: {e}")

    # Fallback: Try online API (ip-api.com)
    api_result = _lookup_ip_api(ip_str)
    if api_result:
        return api_result

    # Last resort: Try to determine country from hostname TLD
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
                'CZ': 'Czech Republic',
                'IE': 'Ireland',
                'PT': 'Portugal',
                'GR': 'Greece',
                'HU': 'Hungary',
                'RO': 'Romania',
                'BG': 'Bulgaria',
                'HR': 'Croatia',
                'SK': 'Slovakia',
                'SI': 'Slovenia',
                'LT': 'Lithuania',
                'LV': 'Latvia',
                'EE': 'Estonia',
                'LU': 'Luxembourg',
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
