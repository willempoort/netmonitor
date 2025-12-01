#!/usr/bin/env python3
"""
Test PostgreSQL whitelist query operators
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from database import DatabaseManager
from config_loader import load_config

def main():
    print("=" * 70)
    print("POSTGRESQL WHITELIST QUERY TEST")
    print("=" * 70)
    print()

    # Load config
    config = load_config("config.yaml")
    db_config = config.get('database', {}).get('postgresql', {})

    # Connect to database
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    # Test IP addresses
    test_cases = [
        ('10.100.0.3', 'soc-server', 'Should match 10.100.0.3/32 in database'),
        ('10.100.0.15', 'soc-server', 'Should match 10.100.0.15/32 in database'),
        ('127.0.0.1', 'soc-server', 'Should match 127.0.0.1 in config (not in db)'),
        ('192.168.1.50', 'soc-server', 'Should match 192.168.1.0/24 in config (not in db)'),
        ('8.8.8.8', 'soc-server', 'Should NOT match (not whitelisted)'),
    ]

    print("[1] Testing different PostgreSQL operators:")
    print()

    conn = db._get_connection()
    cursor = conn.cursor()

    for test_ip, sensor_id, description in test_cases:
        print(f"Testing: {test_ip}")
        print(f"  Description: {description}")
        print()

        # Test operator: << (is contained by - WRONG?)
        cursor.execute('''
            SELECT ip_cidr, scope, description
            FROM ip_whitelists
            WHERE %s << ip_cidr
              AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
        ''', (test_ip, sensor_id))
        results_1 = cursor.fetchall()
        print(f"  Operator '<<' (is contained by): {len(results_1)} matches")
        if results_1:
            for ip_cidr, scope, desc in results_1:
                print(f"    - Matched: {ip_cidr} ({scope}) - {desc}")

        # Test operator: <<= (is contained by or equals)
        cursor.execute('''
            SELECT ip_cidr, scope, description
            FROM ip_whitelists
            WHERE inet %s <<= ip_cidr
              AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
        ''', (test_ip, sensor_id))
        results_2 = cursor.fetchall()
        print(f"  Operator '<<=' (contained/equals): {len(results_2)} matches")
        if results_2:
            for ip_cidr, scope, desc in results_2:
                print(f"    - Matched: {ip_cidr} ({scope}) - {desc}")

        # Test with explicit inet cast
        cursor.execute('''
            SELECT ip_cidr, scope, description
            FROM ip_whitelists
            WHERE ip_cidr >> inet %s
              AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
        ''', (test_ip, sensor_id))
        results_3 = cursor.fetchall()
        print(f"  Operator '>>' (contains): {len(results_3)} matches")
        if results_3:
            for ip_cidr, scope, desc in results_3:
                print(f"    - Matched: {ip_cidr} ({scope}) - {desc}")

        # Test with >>= (contains or equals)
        cursor.execute('''
            SELECT ip_cidr, scope, description
            FROM ip_whitelists
            WHERE ip_cidr >>= inet %s
              AND (scope = 'global' OR (scope = 'sensor' AND sensor_id = %s))
        ''', (test_ip, sensor_id))
        results_4 = cursor.fetchall()
        print(f"  Operator '>>=' (contains/equals): {len(results_4)} matches")
        if results_4:
            for ip_cidr, scope, desc in results_4:
                print(f"    - Matched: {ip_cidr} ({scope}) - {desc}")

        print()

    cursor.close()
    db._return_connection(conn)

    print()
    print("=" * 70)
    print("CONCLUSION:")
    print("=" * 70)
    print()
    print("The correct operator for checking if IP is in CIDR range is:")
    print("  ip_cidr >>= inet %s")
    print()
    print("This means: 'Does the CIDR block contain or equal the IP?'")
    print()
    print("Current code uses: %s << ip_cidr (WRONG!)")
    print("Should use: ip_cidr >>= inet %s (CORRECT!)")

if __name__ == '__main__':
    main()
