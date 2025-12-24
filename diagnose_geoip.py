#!/usr/bin/env python3
"""
GeoIP Diagnostic Script
Run this on the production server to identify issues
"""

import sys
import os

print("=" * 60)
print("GeoIP Diagnostic Report")
print("=" * 60)

# 1. Check Python path
print("\n1. Python Executable:")
print(f"   {sys.executable}")

# 2. Check geoip2 import
print("\n2. geoip2 Library:")
try:
    import geoip2.database
    import geoip2.errors
    print(f"   ✓ geoip2 imported successfully")
    print(f"   Version: {geoip2.__version__}")
except ImportError as e:
    print(f"   ✗ Failed to import geoip2: {e}")
    sys.exit(1)

# 3. Check database paths
print("\n3. Database File Check:")
db_paths = [
    '/var/lib/GeoIP/GeoLite2-Country.mmdb',
    '/usr/share/GeoIP/GeoLite2-Country.mmdb',
    '/opt/GeoIP/GeoLite2-Country.mmdb',
]
found_db = None
for path in db_paths:
    exists = os.path.exists(path)
    readable = os.access(path, os.R_OK) if exists else False
    size = os.path.getsize(path) if exists else 0
    status = "✓" if exists and readable else "✗"
    print(f"   {status} {path}")
    if exists:
        print(f"      Size: {size:,} bytes, Readable: {readable}")
        if readable and not found_db:
            found_db = path

# 4. Try to open the database
print("\n4. Database Reader Test:")
if found_db:
    try:
        reader = geoip2.database.Reader(found_db)
        print(f"   ✓ Successfully opened: {found_db}")

        # 5. Test lookups
        print("\n5. IP Lookup Tests:")
        test_ips = [
            ('8.8.8.8', 'Google DNS (US)'),
            ('1.1.1.1', 'Cloudflare (AU/US)'),
            ('185.125.190.57', 'Ubuntu/Canonical (GB)'),
            ('64.225.64.203', 'DigitalOcean (NL)'),
            ('17.248.236.4', 'Apple (US)'),
            ('188.114.96.0', 'Cloudflare (EU)'),
        ]

        for ip, description in test_ips:
            try:
                response = reader.country(ip)
                country = response.country.iso_code or "No ISO code"
                name = response.country.name or "No name"
                print(f"   ✓ {ip}: {country} ({name}) - {description}")
            except geoip2.errors.AddressNotFoundError:
                print(f"   ? {ip}: Not found in database - {description}")
            except Exception as e:
                print(f"   ✗ {ip}: Error - {e}")

        reader.close()
    except Exception as e:
        print(f"   ✗ Failed to open database: {e}")
else:
    print("   ✗ No readable database found!")

# 6. Test geoip_helper module
print("\n6. geoip_helper Module Test:")
try:
    # Add current directory to path
    sys.path.insert(0, '/opt/netmonitor')
    from geoip_helper import get_country_for_ip, is_local_ip, is_private_ip, set_internal_networks, GEOIP2_AVAILABLE, GEOIP_DB_PATH

    print(f"   GEOIP2_AVAILABLE: {GEOIP2_AVAILABLE}")
    print(f"   GEOIP_DB_PATH: {GEOIP_DB_PATH}")

    # Set internal networks
    set_internal_networks(['10.100.0.0/16'])

    print("\n   Testing get_country_for_ip():")
    test_ips_helper = [
        '8.8.8.8',
        '185.125.190.57',
        '10.100.0.7',
        '10.200.0.1',
        '192.168.1.1',
        '10.100.0.7/32',  # With CIDR notation
    ]

    for ip in test_ips_helper:
        country = get_country_for_ip(ip)
        local = is_local_ip(ip)
        private = is_private_ip(ip)
        print(f"   {ip}: country={country}, local={local}, private={private}")

except Exception as e:
    import traceback
    print(f"   ✗ Error: {e}")
    traceback.print_exc()

print("\n" + "=" * 60)
print("Diagnostic complete")
print("=" * 60)
