#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Threat Feed Updater
Standalone script voor het updaten van threat feeds
"""

import sys
import logging
from pathlib import Path

# Add current dir to path
sys.path.insert(0, str(Path(__file__).parent))

from threat_feeds import ThreatFeedManager


def setup_logging():
    """Setup logging"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('/var/log/netmonitor/feed_updates.log')
        ]
    )


def update_database_feeds(logger):
    """Werk de threat_feeds-tabel bij (OpenPhish, Tor exit nodes). Fouten zijn niet fataal."""
    try:
        import os
        from config_loader import load_config
        from database import DatabaseManager
        from threat_feed_updater import run_feed_updater

        config = load_config(str(Path(__file__).parent / 'config.yaml'))
        pg = (config.get('database') or {}).get('postgresql') or {}
        db = DatabaseManager(
            host=pg.get('host') or os.environ.get('DB_HOST', 'localhost'),
            port=pg.get('port') or int(os.environ.get('DB_PORT', '5432')),
            database=pg.get('database') or os.environ.get('DB_NAME', 'netmonitor'),
            user=pg.get('user') or os.environ.get('DB_USER', 'netmonitor'),
            password=pg.get('password') or os.environ.get('DB_PASSWORD', 'netmonitor'),
            min_connections=1, max_connections=2,
        )
        try:
            results = run_feed_updater(db)
            logger.info(f"Database-feeds: {results or 'niets bijgewerkt (phishing/tor uit)'}")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Database-feeds bijwerken mislukt: {e}")


def main():
    """Main update functie"""
    setup_logging()
    logger = logging.getLogger('FeedUpdater')

    logger.info("=" * 60)
    logger.info("Starting threat feed update")
    logger.info("=" * 60)

    try:
        # Initialiseer feed manager
        feed_manager = ThreatFeedManager()

        # Update alle feeds
        logger.info("Downloading feeds...")
        success = feed_manager.update_all_feeds(force=True)

        # Phishing- en Tor-lijsten in de database (threat_feeds-tabel), voor de
        # advanced detectors 'phishing' en 'tor'. Alleen als die aan staan.
        update_database_feeds(logger)

        if success:
            logger.info("✓ Alle feeds succesvol geüpdatet")

            # Print stats
            stats = feed_manager.get_stats()
            logger.info(f"Statistics:")
            logger.info(f"  - Malicious IPs: {stats['malicious_ips']}")
            logger.info(f"  - Malicious Domains: {stats['malicious_domains']}")
            logger.info(f"  - Malicious URLs: {stats['malicious_urls']}")
            logger.info(f"  - C&C Servers: {stats['c2_servers']}")

            sys.exit(0)
        else:
            logger.error("✗ Sommige feeds faalden tijdens update")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Fatal error tijdens feed update: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
