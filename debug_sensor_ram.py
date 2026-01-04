#!/usr/bin/env python3
"""
Debug script voor sensor RAM issues
Analyseert geheugengebruik en sensor status
"""

import sys
import os
import psutil
import time
import subprocess

def check_sensor_process():
    """Check of sensor_client.py draait"""
    print("=" * 60)
    print("SENSOR PROCESS CHECK")
    print("=" * 60)

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'memory_percent', 'memory_info']):
        try:
            cmdline = proc.info['cmdline']
            if cmdline and 'sensor_client.py' in ' '.join(cmdline):
                print(f"✓ Sensor process gevonden:")
                print(f"  PID: {proc.info['pid']}")
                print(f"  Command: {' '.join(cmdline[:3])}")
                print(f"  RAM: {proc.info['memory_percent']:.1f}%")
                print(f"  RSS: {proc.info['memory_info'].rss / 1024 / 1024:.1f} MB")
                print(f"  VMS: {proc.info['memory_info'].vms / 1024 / 1024:.1f} MB")
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    print("❌ Geen sensor process gevonden!")
    return None

def check_system_memory():
    """Check systeem geheugen"""
    print("\n" + "=" * 60)
    print("SYSTEM MEMORY")
    print("=" * 60)

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    print(f"RAM Total:     {mem.total / 1024 / 1024:.0f} MB")
    print(f"RAM Used:      {mem.used / 1024 / 1024:.0f} MB ({mem.percent:.1f}%)")
    print(f"RAM Available: {mem.available / 1024 / 1024:.0f} MB")
    print(f"\nSwap Total:    {swap.total / 1024 / 1024:.0f} MB")
    print(f"Swap Used:     {swap.used / 1024 / 1024:.0f} MB ({swap.percent:.1f}%)")

    if mem.percent > 90:
        print(f"\n⚠️ WARNING: RAM usage is CRITICAL ({mem.percent:.1f}%)")
    if swap.percent > 50:
        print(f"⚠️ WARNING: Swap usage is HIGH ({swap.percent:.1f}%)")

def check_config():
    """Check sensor config voor PCAP_RAM_FLUSH_THRESHOLD"""
    print("\n" + "=" * 60)
    print("CONFIGURATION CHECK")
    print("=" * 60)

    # Check environment variables
    threshold = os.environ.get('PCAP_RAM_FLUSH_THRESHOLD')
    if threshold:
        print(f"✓ PCAP_RAM_FLUSH_THRESHOLD env var: {threshold}")
    else:
        print("✗ PCAP_RAM_FLUSH_THRESHOLD niet gezet in environment")

    # Check if running as systemd service
    try:
        result = subprocess.run(['systemctl', 'show', 'netmonitor-sensor', '--property=Environment'],
                              capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout:
            print(f"\nSystemd Environment:\n{result.stdout}")
    except:
        print("\n(Systemd niet beschikbaar of geen sensor service)")

def check_logs():
    """Check sensor logs"""
    print("\n" + "=" * 60)
    print("LOG FILE CHECK")
    print("=" * 60)

    log_file = '/var/log/netmonitor/sensor.log'

    if os.path.exists(log_file):
        size = os.path.getsize(log_file)
        print(f"Log file: {log_file}")
        print(f"Size: {size} bytes")

        if size == 0:
            print("⚠️ WARNING: Log file is EMPTY!")
            print("   Dit suggereert dat de sensor:")
            print("   - Niet start")
            print("   - Crasht voor logging start")
            print("   - Logging permissions issue heeft")
        else:
            print(f"\nLast 10 lines:")
            with open(log_file, 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:
                    print(f"  {line.rstrip()}")
    else:
        print(f"❌ Log file niet gevonden: {log_file}")

def check_pcap_files():
    """Check PCAP bestanden"""
    print("\n" + "=" * 60)
    print("PCAP FILES CHECK")
    print("=" * 60)

    pcap_dir = '/var/log/netmonitor/pcap'

    if os.path.exists(pcap_dir):
        files = os.listdir(pcap_dir)
        total_size = 0
        empty_count = 0

        for fname in files:
            fpath = os.path.join(pcap_dir, fname)
            size = os.path.getsize(fpath)
            total_size += size
            if size == 0:
                empty_count += 1

        print(f"Total PCAP files: {len(files)}")
        print(f"Empty files: {empty_count}")
        print(f"Total size: {total_size / 1024:.1f} KB")

        if empty_count > 0 and empty_count == len(files):
            print("\n⚠️ WARNING: ALL PCAP files are EMPTY!")
            print("   Dit suggereert dat PCAP export niet werkt")
    else:
        print(f"PCAP directory niet gevonden: {pcap_dir}")

def analyze_top_memory():
    """Toon top 10 processen op RAM gebruik"""
    print("\n" + "=" * 60)
    print("TOP 10 MEMORY CONSUMERS")
    print("=" * 60)

    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info']):
        try:
            procs.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'mem_pct': proc.info['memory_percent'],
                'rss_mb': proc.info['memory_info'].rss / 1024 / 1024
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    procs.sort(key=lambda x: x['rss_mb'], reverse=True)

    print(f"{'PID':<8} {'Process':<30} {'RAM %':<10} {'RSS MB':<10}")
    print("-" * 60)
    for p in procs[:10]:
        print(f"{p['pid']:<8} {p['name']:<30} {p['mem_pct']:<10.1f} {p['rss_mb']:<10.1f}")

if __name__ == '__main__':
    print("\n🔍 NetMonitor Sensor RAM Debug Tool\n")

    # Run all checks
    pid = check_sensor_process()
    check_system_memory()
    check_config()
    check_logs()
    check_pcap_files()
    analyze_top_memory()

    print("\n" + "=" * 60)
    print("RECOMMENDATIONS")
    print("=" * 60)

    mem = psutil.virtual_memory()

    if mem.percent > 90:
        print("\n1. IMMEDIATE: RAM usage is critical!")
        print("   - Restart sensor: sudo systemctl restart netmonitor-sensor")
        print("   - Verify PCAP_RAM_FLUSH_THRESHOLD is set to 75")

    if pid is None:
        print("\n2. Sensor is NOT running!")
        print("   - Check logs: sudo journalctl -u netmonitor-sensor -n 50")
        print("   - Start sensor: sudo systemctl start netmonitor-sensor")
        print("   - Or manual: sudo /opt/netmonitor/venv/bin/python3 /opt/netmonitor/sensor_client.py")

    print("\n3. Verify sensor config:")
    print("   - Check /opt/netmonitor/sensor_config.yaml")
    print("   - Ensure PCAP_RAM_FLUSH_THRESHOLD=75 in environment or config")

    print("\n4. Monitor RAM in real-time:")
    print("   - watch -n 2 'free -h && echo && ps aux --sort=-%mem | head -10'")

    print("\n")
