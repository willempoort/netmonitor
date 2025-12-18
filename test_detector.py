#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Test script voor de detector module
Simuleert verschillende soorten verkeer om de detectie te testen
"""

import sys
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether
from detector import ThreatDetector
from config_loader import load_config


def test_port_scan_detection():
    """Test port scan detectie"""
    print("\n=== Test: Port Scan Detectie ===")

    config = load_config('config.yaml')
    detector = ThreatDetector(config)

    src_ip = "192.168.1.100"
    dst_ip = "10.0.0.50"

    # Simuleer scan van 25 poorten
    threats_found = []
    for port in range(1, 26):
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
        threats = detector.analyze_packet(packet)
        threats_found.extend(threats)

    if threats_found:
        print(f"✓ Port scan gedetecteerd na {port} poorten")
        print(f"  Threat: {threats_found[0]['description']}")
        return True
    else:
        print("✗ Port scan NIET gedetecteerd")
        return False


def test_connection_flood_detection():
    """Test connection flood detectie"""
    print("\n=== Test: Connection Flood Detectie ===")

    config = load_config('config.yaml')
    detector = ThreatDetector(config)

    src_ip = "192.168.1.101"
    dst_ip = "10.0.0.50"

    # Simuleer veel SYN packets
    threshold = config['thresholds']['connection_flood']['connections_per_second'] * \
                config['thresholds']['connection_flood']['time_window']

    threats_found = []
    for i in range(int(threshold) + 10):
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80, flags='S')
        threats = detector.analyze_packet(packet)
        threats_found.extend(threats)

    if threats_found:
        print(f"✓ Connection flood gedetecteerd")
        print(f"  Threat: {threats_found[0]['description']}")
        return True
    else:
        print("✗ Connection flood NIET gedetecteerd")
        return False


def test_unusual_packet_size():
    """Test grote packet detectie"""
    print("\n=== Test: Ongewone Packet Size ===")

    config = load_config('config.yaml')
    detector = ThreatDetector(config)

    src_ip = "192.168.1.102"
    dst_ip = "10.0.0.50"

    # Maak groot packet
    large_payload = "X" * 2000
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80) / large_payload

    threats = detector.analyze_packet(packet)

    if threats:
        print(f"✓ Groot packet gedetecteerd")
        print(f"  Threat: {threats[0]['description']}")
        return True
    else:
        print("✗ Groot packet NIET gedetecteerd")
        return False


def test_dns_tunnel_detection():
    """Test DNS tunneling detectie"""
    print("\n=== Test: DNS Tunneling Detectie ===")

    config = load_config('config.yaml')
    detector = ThreatDetector(config)

    src_ip = "192.168.1.103"
    dst_ip = "8.8.8.8"

    # Maak verdacht lange DNS query
    long_query = "a" * 100 + ".example.com"
    packet = Ether() / IP(src=src_ip, dst=dst_ip) / UDP(dport=53) / \
             DNS(rd=1, qd=DNSQR(qname=long_query))

    threats = detector.analyze_packet(packet)

    if threats:
        print(f"✓ DNS tunneling gedetecteerd")
        print(f"  Threat: {threats[0]['description']}")
        return True
    else:
        print("✗ DNS tunneling NIET gedetecteerd")
        return False


def test_blacklist():
    """Test IP blacklist"""
    print("\n=== Test: IP Blacklist ===")

    config = load_config('config.yaml')

    # Voeg test IP toe aan blacklist
    config['blacklist'].append('192.0.2.100')

    detector = ThreatDetector(config)

    src_ip = "192.0.2.100"
    dst_ip = "10.0.0.50"

    packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=80)

    threats = detector.analyze_packet(packet)

    if threats:
        print(f"✓ Blacklisted IP gedetecteerd")
        print(f"  Threat: {threats[0]['description']}")
        return True
    else:
        print("✗ Blacklisted IP NIET gedetecteerd")
        return False


def test_whitelist():
    """Test IP whitelist"""
    print("\n=== Test: IP Whitelist ===")

    config = load_config('config.yaml')

    # Voeg test IP toe aan whitelist
    config['whitelist'].append('192.168.99.100')

    detector = ThreatDetector(config)

    src_ip = "192.168.99.100"
    dst_ip = "10.0.0.50"

    # Zou normaal port scan triggeren
    threats_found = []
    for port in range(1, 30):
        packet = Ether() / IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags='S')
        threats = detector.analyze_packet(packet)
        threats_found.extend(threats)

    if not threats_found:
        print(f"✓ Whitelisted IP genereert geen alerts")
        return True
    else:
        print("✗ Whitelisted IP genereerde alerts (niet verwacht)")
        return False


def main():
    """Run alle tests"""
    print("========================================")
    print("Network Monitor - Detector Tests")
    print("========================================")

    # Check of config bestaat
    try:
        load_config('config.yaml')
    except FileNotFoundError:
        print("Error: config.yaml niet gevonden")
        sys.exit(1)

    tests = [
        ("Port Scan Detection", test_port_scan_detection),
        ("Connection Flood Detection", test_connection_flood_detection),
        ("Unusual Packet Size", test_unusual_packet_size),
        ("DNS Tunneling Detection", test_dns_tunnel_detection),
        ("IP Blacklist", test_blacklist),
        ("IP Whitelist", test_whitelist),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test failed met error: {e}")
            results.append((test_name, False))

    # Print resultaten
    print("\n========================================")
    print("Test Resultaten")
    print("========================================")

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status}: {test_name}")

    print(f"\nTotaal: {passed}/{total} tests geslaagd")

    if passed == total:
        print("\n✓ Alle tests geslaagd!")
        sys.exit(0)
    else:
        print(f"\n✗ {total - passed} test(s) gefaald")
        sys.exit(1)


if __name__ == "__main__":
    main()
