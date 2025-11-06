#!/usr/bin/env python3
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
