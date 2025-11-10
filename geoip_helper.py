#!/usr/bin/env python3
"""
GeoIP Helper
Provides country lookup for IP addresses
"""

import ipaddress
import logging
import socket

logger = logging.getLogger('NetMonitor.GeoIP')


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except:
        return False


def get_country_for_ip(ip_str: str) -> str:
    """
    Get country for a single IP address

    For now, this is a simple implementation that:
    - Returns 'Private' for private IPs
    - Returns 'Unknown' for all others

    To add real geolocation:
    - Install geoip2: pip install geoip2
    - Download MaxMind GeoLite2 database
    - Or use an API service like ipapi.co
    """
    if not ip_str:
        return None

    # Check if private
    if is_private_ip(ip_str):
        return 'Private Network'

    # Try to determine country from hostname TLD (very basic)
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

    # For production use, integrate with GeoIP2:
    # try:
    #     import geoip2.database
    #     reader = geoip2.database.Reader('/path/to/GeoLite2-Country.mmdb')
    #     response = reader.country(ip_str)
    #     return f"{response.country.name} ({response.country.iso_code})"
    # except:
    #     pass

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
