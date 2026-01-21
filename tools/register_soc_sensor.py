#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Register/Update SOC Server Sensor
Ensures the SOC server's sensor entry has correct interface metadata
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config_loader import load_config
from database import DatabaseManager
import socket
import psutil


def get_network_interfaces():
    """Detect available network interfaces with their status"""
    interfaces = []

    try:
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()

        for iface_name in net_if_addrs.keys():
            # Skip loopback and docker interfaces
            if iface_name.startswith(('lo', 'docker', 'br-', 'veth')):
                continue

            stats = net_if_stats.get(iface_name)
            if not stats:
                continue

            # Detect PROMISC mode and up/down status
            is_up = stats.isup

            # Detect PROMISC mode by reading /sys/class/net/<iface>/flags
            # PROMISC flag is bit 8 (0x100)
            is_promisc = False
            try:
                flags_file = f'/sys/class/net/{iface_name}/flags'
                with open(flags_file, 'r') as f:
                    flags = int(f.read().strip(), 16)
                    is_promisc = bool(flags & 0x100)
            except:
                # Fallback: parse ip link show output
                try:
                    import subprocess
                    result = subprocess.run(['ip', 'link', 'show', iface_name],
                                          capture_output=True, text=True, timeout=2)
                    if 'PROMISC' in result.stdout:
                        is_promisc = True
                except:
                    pass

            interfaces.append({
                'name': iface_name,
                'display_name': iface_name,
                'status': 'up' if is_up else 'down',
                'promisc': is_promisc
            })

    except Exception as e:
        print(f"Warning: Could not detect interfaces: {e}")
        print("Falling back to basic interface list")
        # Fallback: just list interface names
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if not iface.startswith(('lo', 'docker', 'br-', 'veth')):
                    interfaces.append({
                        'name': iface,
                        'display_name': iface,
                        'status': 'unknown',
                        'promisc': False
                    })
        except:
            pass

    return interfaces


def register_soc_sensor(config_file='config.yaml'):
    """Register/update the SOC server sensor with correct metadata"""

    # Load config
    config = load_config(config_file)

    # Get self_monitor settings
    self_monitor = config.get('self_monitor', {})
    if not self_monitor.get('enabled', True):
        print("❌ Self-monitoring is disabled in config.yaml")
        print("   Enable it by setting self_monitor.enabled: true")
        return False

    sensor_id = self_monitor.get('sensor_id', 'soc-server')
    hostname = self_monitor.get('hostname') or socket.gethostname()
    location = self_monitor.get('location', 'SOC Server - Main Location')
    interface = self_monitor.get('interface', 'lo')

    print(f"Registering SOC server sensor...")
    print(f"  Sensor ID: {sensor_id}")
    print(f"  Hostname: {hostname}")
    print(f"  Location: {location}")
    print(f"  Interface: {interface}")

    # Detect available interfaces
    available_interfaces = get_network_interfaces()
    print(f"\nDetected {len(available_interfaces)} network interfaces:")
    for iface in available_interfaces:
        status_icon = '🟢' if iface['status'] == 'up' else '⚪'
        promisc_icon = ' [PROMISC]' if iface['promisc'] else ''
        print(f"  {status_icon} {iface['name']}{promisc_icon}")

    # Connect to database
    db_config = config.get('database', {}).get('postgresql', {})
    db = DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor')
    )

    # Register sensor
    print(f"\nUpdating sensor in database...")
    try:
        # Get sensor's IP address
        ip_address = None
        try:
            # socket is already imported at top of file
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except:
            pass

        # Build config with available_interfaces
        sensor_config = {
            'available_interfaces': available_interfaces,
            'interface': interface  # Current selected interface(s)
        }

        success = db.register_sensor(
            sensor_id=sensor_id,
            hostname=hostname,
            location=location,
            ip_address=ip_address,
            config=sensor_config  # Pass config with available_interfaces
        )

        if success:
            print(f"✅ SOC server sensor registered successfully!")
            print(f"\nYou can now edit the sensor via Dashboard → Sensors → {sensor_id}")
            print(f"The network interface dropdown will show the correct interfaces.")
            return True
        else:
            print(f"❌ Failed to register sensor")
            return False

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        db.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Register/Update SOC Server Sensor')
    parser.add_argument('--config', default='config.yaml', help='Config file path')
    args = parser.parse_args()

    success = register_soc_sensor(args.config)
    sys.exit(0 if success else 1)
