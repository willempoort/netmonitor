#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Diagnose MCP Database Connectivity and Data

Run this ON THE SERVER to check if the MCP server can access the database
and if there's actually data in the alerts table.

Usage:
    ssh root@soc.poort.net
    cd /opt/netmonitor
    python3 diagnose_mcp_database.py
"""

import os
import sys
from pathlib import Path

# Add mcp_server to path
sys.path.insert(0, str(Path(__file__).parent / 'mcp_server'))

from database_client import MCPDatabaseClient
from streamable_http_config import load_config

def main():
    print("=" * 70)
    print("MCP Database Diagnostics")
    print("=" * 70)
    print()

    # Load config
    print("1. Loading configuration...")
    config = load_config()
    db_config = config['database']
    print(f"   Database: {db_config['database']}@{db_config['host']}:{db_config['port']}")
    print(f"   User: {db_config['user']}")
    print()

    # Connect to database
    print("2. Connecting to database...")
    try:
        db = MCPDatabaseClient(**db_config)
        print("   ✅ Database connection successful")
    except Exception as e:
        print(f"   ❌ Database connection FAILED: {e}")
        return 1
    print()

    # Check alerts table
    print("3. Checking alerts table...")
    try:
        alerts = db.get_recent_alerts(limit=5, hours=24)
        print(f"   Alerts found (last 24h): {len(alerts)}")

        if len(alerts) == 0:
            print("   ⚠️  No alerts in last 24 hours!")
            print("   This explains why MCP tools return empty/null")

            # Try longer period
            print()
            print("   Checking last 7 days...")
            alerts_week = db.get_recent_alerts(limit=5, hours=168)
            print(f"   Alerts found (last 7 days): {len(alerts_week)}")

            if len(alerts_week) > 0:
                print("   ℹ️  There IS data, but not in last 24 hours")
                print()
                print("   Sample alert:")
                alert = alerts_week[0]
                print(f"   - ID: {alert.get('id')}")
                print(f"   - Timestamp: {alert.get('timestamp')}")
                print(f"   - Severity: {alert.get('severity')}")
                print(f"   - Type: {alert.get('threat_type')}")
                print(f"   - Source IP: {alert.get('source_ip')}")
            else:
                print("   ❌ No alerts in database at all!")
                print("   The alerts table is empty or not being populated")
        else:
            print("   ✅ Data found! Showing first 3 alerts:")
            print()
            for i, alert in enumerate(alerts[:3], 1):
                print(f"   Alert #{i}:")
                print(f"   - ID: {alert.get('id')}")
                print(f"   - Timestamp: {alert.get('timestamp')}")
                print(f"   - Severity: {alert.get('severity')}")
                print(f"   - Type: {alert.get('threat_type')}")
                print(f"   - Source IP: {alert.get('source_ip')}")
                print(f"   - Destination IP: {alert.get('destination_ip')}")
                print()
    except Exception as e:
        print(f"   ❌ Query FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Test get_recent_threats tool directly
    print()
    print("4. Testing get_recent_threats tool implementation...")
    try:
        from shared_tools import NetMonitorTools
        from ollama_client import OllamaClient

        ollama = OllamaClient(**config['ollama'])
        tools = NetMonitorTools(db, ollama, dashboard_url="https://soc.poort.net")

        # Call the tool like MCP would
        import asyncio
        result = asyncio.run(tools.get_recent_threats({'hours': 24, 'limit': 5}))

        print(f"   Tool returned: {type(result)}")
        print(f"   Total alerts: {result.get('total_alerts', 'N/A')}")

        if result.get('total_alerts', 0) == 0:
            print("   ⚠️  Tool confirms: No data in last 24 hours")
        else:
            print("   ✅ Tool is working and returning data!")
            print(f"   Sample: {result.get('alerts', [])[0] if result.get('alerts') else 'N/A'}")

    except Exception as e:
        print(f"   ❌ Tool test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

    print()
    print("=" * 70)
    print("Diagnosis complete!")
    print()

    if len(alerts) == 0:
        print("CONCLUSION:")
        print("The database connection works, but there are NO ALERTS in the last 24 hours.")
        print("This is why the LLM was hallucinating - the tools returned empty results.")
        print()
        print("SOLUTIONS:")
        print("1. Check if NetMonitor is actually generating alerts")
        print("2. Check if alerts are being written to the database")
        print("3. Generate some test alerts to verify the system")
        print("4. Use longer time periods in queries (e.g., hours=168 for 7 days)")
    else:
        print("CONCLUSION:")
        print("✅ Database has data and tools are working correctly!")
        print("The MCP server should be returning this data to the LLM.")
        print()
        print("If the LLM is still hallucinating, the problem might be:")
        print("1. The Ollama-MCP-Bridge is not passing tool results back to the LLM")
        print("2. The LLM is ignoring the tool results (need stronger anti-hallucination prompt)")

    return 0

if __name__ == "__main__":
    sys.exit(main())
