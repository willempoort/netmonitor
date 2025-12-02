#!/usr/bin/env python3
"""
NetMonitor - Database Default Configuration Initializer
Loads default threshold values from config.yaml into the database
"""

import sys
import yaml
from database import DatabaseManager
from config_loader import load_config

def load_defaults():
    """Load default config parameters into database"""

    # Load config.yaml
    print("Loading config.yaml...")
    config = load_config('config.yaml')

    # Connect to database
    print("Connecting to database...")
    db_config = config['database']['postgresql']
    db = DatabaseManager(
        host=db_config['host'],
        port=db_config['port'],
        database=db_config['database'],
        user=db_config['user'],
        password=db_config['password']
    )

    # Extract thresholds from config
    thresholds = config.get('thresholds', {})

    if not thresholds:
        print("No thresholds found in config.yaml")
        return

    print(f"Found {len(thresholds)} threshold categories in config.yaml")

    # Save global config to database
    print("Saving default thresholds to database (global scope)...")

    config_dict = {'thresholds': thresholds}

    try:
        db.save_sensor_config(
            sensor_id=None,  # None = global config
            config=config_dict,
            scope='global'
        )
        print("✓ Default thresholds saved successfully")

        # Count parameters
        param_count = 0
        for category, params in thresholds.items():
            if isinstance(params, dict):
                param_count += len(params)

        print(f"✓ Loaded {param_count} parameters across {len(thresholds)} categories:")
        for category in thresholds.keys():
            print(f"  - {category}")

    except Exception as e:
        print(f"✗ Error saving defaults: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    load_defaults()
