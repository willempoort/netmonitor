#!/usr/bin/env python3
"""
Migration script for Device Classification feature

This script:
1. Creates new database tables for device classification
2. Initializes builtin device templates
3. Initializes builtin service providers
4. Optionally imports streaming/CDN data from config.yaml

Run this script once to set up the device classification feature.
After migration, data will be managed through the database and Web GUI.

Usage:
    python migrate_device_classification.py [--import-config]

Options:
    --import-config    Import streaming/CDN services from config.yaml
"""

import sys
import os
import argparse
import logging
import yaml
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Migration')


def load_config():
    """Load config.yaml"""
    config_path = Path(__file__).parent / 'config.yaml'
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}


def get_database_manager():
    """Create DatabaseManager instance"""
    from database import DatabaseManager

    config = load_config()
    db_config = config.get('database', {}).get('postgresql', {})

    return DatabaseManager(
        host=db_config.get('host', 'localhost'),
        port=db_config.get('port', 5432),
        database=db_config.get('database', 'netmonitor'),
        user=db_config.get('user', 'netmonitor'),
        password=db_config.get('password', 'netmonitor'),
        min_connections=db_config.get('min_connections', 2),
        max_connections=db_config.get('max_connections', 10)
    )


def import_streaming_services_from_config(db):
    """Import streaming services from config.yaml"""
    config = load_config()
    thresholds = config.get('thresholds', {})
    modern_protocols = thresholds.get('modern_protocols', {})

    streaming_services = modern_protocols.get('streaming_services', [])
    cdn_providers = modern_protocols.get('cdn_providers', [])

    imported = 0

    # Group streaming services by known providers
    # This is a heuristic mapping based on common IP ranges
    streaming_mappings = {
        'Netflix (Extra)': {
            'category': 'streaming',
            'description': 'Additional Netflix IP ranges from config.yaml',
            'ranges': []
        },
        'Google/YouTube (Extra)': {
            'category': 'streaming',
            'description': 'Additional Google/YouTube IP ranges from config.yaml',
            'ranges': []
        },
        'Amazon CloudFront (Extra)': {
            'category': 'cdn',
            'description': 'Additional Amazon CloudFront IP ranges from config.yaml',
            'ranges': []
        }
    }

    cdn_mappings = {
        'Cloudflare (Extra)': {
            'category': 'cdn',
            'description': 'Additional Cloudflare IP ranges from config.yaml',
            'ranges': []
        },
        'Akamai (Extra)': {
            'category': 'cdn',
            'description': 'Additional Akamai IP ranges from config.yaml',
            'ranges': []
        }
    }

    # Get existing provider ranges for deduplication
    existing_providers = db.get_service_providers()
    existing_ranges = set()
    for p in existing_providers:
        ranges = p.get('ip_ranges', [])
        if isinstance(ranges, list):
            existing_ranges.update(ranges)

    # Check for ranges not yet in database
    for ip_range in streaming_services:
        if ip_range not in existing_ranges:
            # Categorize by IP prefix (rough heuristic)
            if ip_range.startswith(('23.246', '37.77', '45.57', '64.120', '66.197',
                                     '108.175', '185.2', '185.9', '192.173', '198.38',
                                     '198.45', '208.75', '2620:10c')):
                streaming_mappings['Netflix (Extra)']['ranges'].append(ip_range)
            elif ip_range.startswith(('142.250', '172.217', '173.194', '216.58', '2001:4860')):
                streaming_mappings['Google/YouTube (Extra)']['ranges'].append(ip_range)
            elif ip_range.startswith(('13.32', '13.224', '13.249', '18.64', '2600:9000')):
                streaming_mappings['Amazon CloudFront (Extra)']['ranges'].append(ip_range)
            else:
                # Generic streaming
                streaming_mappings['Netflix (Extra)']['ranges'].append(ip_range)

    for ip_range in cdn_providers:
        if ip_range not in existing_ranges:
            if ip_range.startswith(('104.16', '172.64', '162.158', '2606:4700')):
                cdn_mappings['Cloudflare (Extra)']['ranges'].append(ip_range)
            elif ip_range.startswith(('23.32', '23.192', '95.100', '2.16', '184.24', '2600:1400')):
                cdn_mappings['Akamai (Extra)']['ranges'].append(ip_range)
            else:
                cdn_mappings['Akamai (Extra)']['ranges'].append(ip_range)

    # Create providers for non-empty range groups
    for name, data in {**streaming_mappings, **cdn_mappings}.items():
        if data['ranges']:
            provider_id = db.create_service_provider(
                name=name,
                category=data['category'],
                description=data['description'],
                ip_ranges=data['ranges'],
                is_builtin=False,
                created_by='migration'
            )
            if provider_id:
                logger.info(f"Created provider: {name} with {len(data['ranges'])} IP ranges")
                imported += 1

    return imported


def run_migration(import_config=False):
    """Run the migration"""
    logger.info("=" * 60)
    logger.info("Device Classification Migration")
    logger.info("=" * 60)

    try:
        logger.info("Connecting to database...")
        db = get_database_manager()
        logger.info("Database connected successfully")

        # Tables are created automatically by DatabaseManager._init_database()
        # Builtin data is initialized automatically by DatabaseManager._init_builtin_data()

        logger.info("\n--- Current Status ---")

        # Show templates
        templates = db.get_device_templates()
        logger.info(f"Device templates: {len(templates)}")
        for t in templates:
            builtin = " (builtin)" if t.get('is_builtin') else ""
            logger.info(f"  - {t['name']} [{t['category']}]{builtin}")

        # Show service providers
        providers = db.get_service_providers()
        logger.info(f"\nService providers: {len(providers)}")
        for p in providers:
            builtin = " (builtin)" if p.get('is_builtin') else ""
            ranges = p.get('ip_ranges', [])
            range_count = len(ranges) if isinstance(ranges, list) else 0
            logger.info(f"  - {p['name']} [{p['category']}] - {range_count} IP ranges{builtin}")

        # Import from config.yaml if requested
        if import_config:
            logger.info("\n--- Importing from config.yaml ---")
            imported = import_streaming_services_from_config(db)
            logger.info(f"Imported {imported} additional service providers from config.yaml")

        logger.info("\n" + "=" * 60)
        logger.info("Migration completed successfully!")
        logger.info("=" * 60)

        # Provide guidance
        logger.info("""
Next steps:
1. The streaming/CDN filter data is now in the database
2. You can manage service providers via the Web GUI or MCP API
3. Device templates are ready for use
4. Devices will be registered as they are discovered on the network

Note: The config.yaml still contains the original streaming_services
and cdn_providers settings for backwards compatibility. These can be
removed once you confirm the database migration is complete.
""")

        db.close()
        return True

    except Exception as e:
        logger.error(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Migrate to Device Classification feature'
    )
    parser.add_argument(
        '--import-config',
        action='store_true',
        help='Import streaming/CDN services from config.yaml'
    )

    args = parser.parse_args()

    success = run_migration(import_config=args.import_config)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
