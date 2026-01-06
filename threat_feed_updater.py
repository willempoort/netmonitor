#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Threat Feed Updater - Downloads and imports external threat intelligence feeds

Supports:
- Phishing domains (OpenPhish)
- Tor exit nodes (Tor Project)
- Cryptomining pool IPs (abuse.ch)
- Malicious domains and IPs
"""

import logging
import requests
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import re


class ThreatFeedUpdater:
    """Manages external threat intelligence feed updates"""

    def __init__(self, db_manager):
        """
        Initialize threat feed updater

        Args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.ThreatFeeds')

        # Request timeout for external feeds
        self.request_timeout = 30

    def update_all_feeds(self, sensor_id: str = None) -> Dict[str, int]:
        """
        Update all enabled threat feeds

        Args:
            sensor_id: Optional sensor ID for sensor-specific config (None = global)

        Returns:
            Dict with feed names and indicator counts imported
        """
        results = {}

        # Get configuration from database
        config = self.db.get_sensor_config(sensor_id=sensor_id)

        # Phishing domains
        phishing_enabled = config.get('threat.phishing.enabled', {}).get('parameter_value', False)
        if phishing_enabled:
            count = self.update_phishing_feed(config)
            if count is not None:
                results['phishing'] = count

        # Tor exit nodes
        tor_enabled = config.get('threat.tor.enabled', {}).get('parameter_value', False)
        if tor_enabled:
            count = self.update_tor_feed(config)
            if count is not None:
                results['tor_exit'] = count

        # Cleanup expired indicators
        expired = self.db.cleanup_expired_threat_feeds()
        if expired > 0:
            self.logger.info(f"Cleaned up {expired} expired threat indicators")

        return results

    def update_phishing_feed(self, config: Dict) -> Optional[int]:
        """
        Update phishing domain feed from OpenPhish

        Args:
            config: Configuration dict from database

        Returns:
            Number of indicators imported, or None on error
        """
        try:
            # Get config values from database (already in correct format)
            feed_url = config.get('threat.phishing.feed_url', {}).get('parameter_value', 'https://openphish.com/feed.txt')
            cache_ttl = config.get('threat.phishing.cache_ttl', {}).get('parameter_value', 86400)

            self.logger.info(f"Updating phishing feed from {feed_url}")

            # Download feed
            response = requests.get(feed_url, timeout=self.request_timeout)
            response.raise_for_status()

            # Parse feed (one URL per line)
            indicators = []
            expires_at = datetime.now() + timedelta(seconds=cache_ttl)

            for line in response.text.strip().split('\n'):
                url = line.strip()
                if not url or url.startswith('#'):
                    continue

                # Extract domain from URL
                domain = self._extract_domain(url)
                if domain:
                    indicators.append({
                        'indicator': domain,
                        'indicator_type': 'domain',
                        'confidence_score': 0.9,
                        'expires_at': expires_at,
                        'metadata': {'source_url': url}
                    })

            # Bulk import
            count = self.db.bulk_import_threat_feed(
                feed_type='phishing',
                indicators=indicators,
                source='OpenPhish'
            )

            self.logger.info(f"Imported {count} phishing domains")
            return count

        except Exception as e:
            self.logger.error(f"Error updating phishing feed: {e}")
            return None

    def update_tor_feed(self, config: Dict) -> Optional[int]:
        """
        Update Tor exit node feed from Tor Project

        Args:
            config: Configuration dict from database

        Returns:
            Number of indicators imported, or None on error
        """
        try:
            # Get config values from database
            feed_url = config.get('threat.tor.feed_url', {}).get('parameter_value',
                                 'https://check.torproject.org/torbulkexitlist')

            self.logger.info(f"Updating Tor exit node feed from {feed_url}")

            # Download feed
            response = requests.get(feed_url, timeout=self.request_timeout)
            response.raise_for_status()

            # Parse feed (one IP per line)
            indicators = []
            # Tor exit nodes don't expire quickly, keep for 7 days
            expires_at = datetime.now() + timedelta(days=7)

            for line in response.text.strip().split('\n'):
                ip = line.strip()
                if not ip or ip.startswith('#'):
                    continue

                # Validate IP address
                if self._is_valid_ip(ip):
                    indicators.append({
                        'indicator': ip,
                        'indicator_type': 'ip',
                        'confidence_score': 1.0,
                        'expires_at': expires_at
                    })

            # Bulk import
            count = self.db.bulk_import_threat_feed(
                feed_type='tor_exit',
                indicators=indicators,
                source='Tor Project'
            )

            self.logger.info(f"Imported {count} Tor exit nodes")
            return count

        except Exception as e:
            self.logger.error(f"Error updating Tor feed: {e}")
            return None

    def _extract_domain(self, url: str) -> Optional[str]:
        """
        Extract domain from URL

        Args:
            url: Full URL

        Returns:
            Domain name or None
        """
        try:
            # Simple regex to extract domain
            # Match http(s)://domain.com/path or just domain.com
            match = re.match(r'(?:https?://)?([^/]+)', url)
            if match:
                domain = match.group(1).lower()
                # Remove port if present
                domain = domain.split(':')[0]
                return domain
        except Exception:
            pass
        return None

    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IP address format

        Args:
            ip: IP address string

        Returns:
            True if valid IPv4 or IPv6
        """
        try:
            # Simple validation - try to parse as IP
            parts = ip.split('.')
            if len(parts) == 4:
                # IPv4
                return all(0 <= int(part) <= 255 for part in parts)
            elif ':' in ip:
                # IPv6 (basic check)
                return len(ip) > 2
        except Exception:
            pass
        return False

    def get_feed_stats(self) -> Dict[str, Dict]:
        """
        Get statistics for all threat feeds

        Returns:
            Dict with feed stats
        """
        stats = {}

        # Get counts per feed type
        for feed_type in ['phishing', 'tor_exit', 'cryptomining', 'vpn_exit',
                         'malware_c2', 'botnet_c2', 'known_attacker']:
            indicators = self.db.get_threat_feed_indicators(
                feed_type=feed_type,
                is_active=True,
                limit=100000
            )
            stats[feed_type] = {
                'count': len(indicators),
                'last_updated': max([i.get('last_updated') for i in indicators],
                                   default=None) if indicators else None
            }

        return stats


def run_feed_updater(db_manager):
    """
    Run threat feed updater once

    Args:
        db_manager: DatabaseManager instance
    """
    logger = logging.getLogger('NetMonitor.ThreatFeeds')

    try:
        updater = ThreatFeedUpdater(db_manager)
        results = updater.update_all_feeds()

        logger.info(f"Threat feed update completed: {results}")

        # Log statistics
        stats = updater.get_feed_stats()
        for feed_type, data in stats.items():
            if data['count'] > 0:
                logger.info(f"  {feed_type}: {data['count']} indicators")

        return results

    except Exception as e:
        logger.error(f"Error running threat feed updater: {e}")
        import traceback
        traceback.print_exc()
        return None


def run_feed_updater_loop(db_manager):
    """
    Run threat feed updater in a loop with configurable interval

    Args:
        db_manager: DatabaseManager instance
    """
    logger = logging.getLogger('NetMonitor.ThreatFeeds')

    # Default to 3600 seconds (1 hour)
    update_interval = 3600

    # Try to get interval from database config
    try:
        config = db_manager.get_sensor_config(sensor_id=None)
        db_interval = config.get('threat.phishing.update_interval', {}).get('parameter_value')
        if db_interval:
            update_interval = int(db_interval)
    except Exception as e:
        logger.warning(f"Could not read update interval from database, using default: {e}")

    logger.info(f"Starting threat feed updater loop (interval: {update_interval}s)")

    # Run initial update
    run_feed_updater(db_manager)

    # Run in loop
    while True:
        try:
            time.sleep(update_interval)
            run_feed_updater(db_manager)
        except KeyboardInterrupt:
            logger.info("Threat feed updater stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in threat feed updater loop: {e}")
            time.sleep(60)  # Wait 1 minute before retry


if __name__ == '__main__':
    # For testing
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from config_loader import load_config
    from database import DatabaseManager

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    config = load_config()
    db = DatabaseManager(config)

    # Run once
    run_feed_updater(db)
