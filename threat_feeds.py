# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Threat Feed Manager
Download en beheer threat intelligence feeds
"""

import os
import json
import csv
import time
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set
import urllib.request
import urllib.error


class ThreatFeedManager:
    """Beheert threat intelligence feeds"""

    # Feed URLs
    FEEDS = {
        'feodotracker': {
            'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
            'type': 'csv',
            'description': 'Botnet C&C Server IPs (Emotet, TrickBot, etc.)',
            'update_interval': 3600  # 1 uur
        },
        'urlhaus': {
            'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
            'type': 'csv',
            'description': 'Recent malware distribution URLs',
            'update_interval': 3600  # 1 uur
        },
        'threatfox': {
            'url': 'https://threatfox.abuse.ch/export/csv/recent/',
            'type': 'csv',
            'description': 'Recent IOCs (IPs, domains, URLs)',
            'update_interval': 3600  # 1 uur
        },
        'sslblacklist': {
            'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
            'type': 'csv',
            'description': 'SSL/TLS malicious IPs',
            'update_interval': 3600  # 1 uur
        }
    }

    def __init__(self, cache_dir='/var/cache/netmonitor/feeds'):
        """
        Initialiseer threat feed manager

        Args:
            cache_dir: Directory voor feed cache
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger('NetMonitor.ThreatFeeds')

        # In-memory cache van feeds
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.malicious_urls: Set[str] = set()
        self.c2_servers: Dict[str, dict] = {}  # IP -> metadata

        # Track feed update times
        self.last_update: Dict[str, float] = {}

        self.logger.info(f"Threat Feed Manager geïnitialiseerd, cache dir: {self.cache_dir}")

    def download_feed(self, feed_name: str, force: bool = False) -> bool:
        """
        Download een threat feed

        Args:
            feed_name: Naam van de feed
            force: Force download ook als recent geüpdatet

        Returns:
            True als succesvol gedownload
        """
        if feed_name not in self.FEEDS:
            self.logger.error(f"Onbekende feed: {feed_name}")
            return False

        feed_config = self.FEEDS[feed_name]

        # Check of update nodig is
        if not force and feed_name in self.last_update:
            time_since_update = time.time() - self.last_update[feed_name]
            if time_since_update < feed_config['update_interval']:
                self.logger.debug(f"Feed {feed_name} is recent (< {feed_config['update_interval']}s), skip download")
                return True

        url = feed_config['url']
        cache_file = self.cache_dir / f"{feed_name}.csv"

        self.logger.info(f"Downloading feed: {feed_name} from {url}")

        try:
            # Download met timeout
            req = urllib.request.Request(url, headers={'User-Agent': 'NetMonitor/1.0'})

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()

            # Schrijf naar cache
            with open(cache_file, 'wb') as f:
                f.write(content)

            self.last_update[feed_name] = time.time()
            self.logger.info(f"Feed {feed_name} succesvol gedownload ({len(content)} bytes)")

            return True

        except urllib.error.URLError as e:
            self.logger.error(f"Fout bij downloaden feed {feed_name}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Onverwachte fout bij downloaden feed {feed_name}: {e}")
            return False

    def parse_feodotracker(self, cache_file: Path) -> int:
        """Parse FeodoTracker feed (C&C servers)"""
        count = 0

        try:
            with open(cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                import csv
                reader = csv.reader(f)

                for row in reader:
                    # Skip empty rows or comments
                    if not row or (row[0] and row[0].startswith('#')):
                        continue

                    # Parse: first_seen,dst_ip,dst_port,c2_status,last_online,malware
                    if len(row) >= 2:
                        ip = row[1].strip()

                        # Valideer IP format (simpel)
                        if self._is_valid_ip(ip):
                            self.malicious_ips.add(ip)
                            self.c2_servers[ip] = {
                                'type': 'botnet_c2',
                                'feed': 'feodotracker',
                                'malware': row[5].strip() if len(row) > 5 else 'Unknown'
                            }
                            count += 1

        except Exception as e:
            self.logger.error(f"Fout bij parsen FeodoTracker: {e}")

        return count

    def parse_urlhaus(self, cache_file: Path) -> int:
        """Parse URLhaus feed (malware URLs)"""
        count = 0

        try:
            with open(cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments
                    if not line or line.startswith('#'):
                        continue

                    # Parse CSV: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
                    parts = line.split(',')
                    if len(parts) >= 3:
                        url = parts[2].strip().strip('"')

                        if url and url.startswith('http'):
                            self.malicious_urls.add(url)

                            # Extract domain/IP
                            domain = self._extract_domain(url)
                            if domain:
                                if self._is_valid_ip(domain):
                                    self.malicious_ips.add(domain)
                                else:
                                    self.malicious_domains.add(domain)

                            count += 1

        except Exception as e:
            self.logger.error(f"Fout bij parsen URLhaus: {e}")

        return count

    def parse_threatfox(self, cache_file: Path) -> int:
        """Parse ThreatFox feed (recent IOCs)"""
        count = 0

        try:
            with open(cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Filter out comment lines before passing to CSV reader
                lines = []
                header_found = False
                for line in f:
                    stripped = line.strip()
                    # Skip comment lines that don't contain column headers
                    if stripped.startswith('#') and not header_found:
                        # Check if this is the header line (contains "ioc_type")
                        if 'ioc_type' in stripped:
                            # Remove the leading # and use as header
                            lines.append(stripped[1:].strip())
                            header_found = True
                        continue
                    elif stripped and not stripped.startswith('#'):
                        lines.append(line)

                # Parse the CSV
                import io
                csv_data = io.StringIO('\n'.join(lines))
                reader = csv.DictReader(csv_data, delimiter=',', skipinitialspace=True)

                for row in reader:
                    # Check ioc_type (handle both quoted and unquoted column names)
                    ioc_type = row.get('ioc_type', row.get(' "ioc_type"', '')).strip(' "').lower()
                    ioc_value = row.get('ioc_value', row.get(' "ioc_value"', '')).strip(' "')

                    if not ioc_value:
                        continue

                    if ioc_type == 'ip:port' or ioc_type == 'ip':
                        # Extract IP
                        ip = ioc_value.split(':')[0]
                        if self._is_valid_ip(ip):
                            self.malicious_ips.add(ip)
                            count += 1

                    elif ioc_type == 'domain':
                        self.malicious_domains.add(ioc_value)
                        count += 1

                    elif ioc_type == 'url':
                        self.malicious_urls.add(ioc_value)
                        domain = self._extract_domain(ioc_value)
                        if domain:
                            self.malicious_domains.add(domain)
                        count += 1

        except Exception as e:
            self.logger.error(f"Fout bij parsen ThreatFox: {e}")

        return count

    def parse_sslblacklist(self, cache_file: Path) -> int:
        """Parse SSL Blacklist (malicious SSL IPs) - DEPRECATED since 2025-01-03"""
        count = 0

        try:
            with open(cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                import csv

                # Check if deprecated
                first_lines = f.read(500)
                if 'deprecated' in first_lines.lower():
                    self.logger.info("SSLBlacklist has been deprecated by abuse.ch")
                    return 0

                # Reset file pointer
                f.seek(0)
                reader = csv.reader(f)

                for row in reader:
                    # Skip empty rows or comments
                    if not row or (row[0] and row[0].startswith('#')):
                        continue

                    # Parse: Listing_date,Listing_reason,DstIP,DstPort
                    if len(row) >= 3:
                        ip = row[2].strip()

                        if self._is_valid_ip(ip):
                            self.malicious_ips.add(ip)
                            count += 1

        except Exception as e:
            self.logger.error(f"Fout bij parsen SSL Blacklist: {e}")

        return count

    def load_feeds(self, feed_names: List[str] = None) -> Dict[str, int]:
        """
        Laad feeds in memory

        Args:
            feed_names: Lijst van feeds om te laden (None = all)

        Returns:
            Dict met counts per feed
        """
        if feed_names is None:
            feed_names = list(self.FEEDS.keys())

        # Clear current cache
        self.malicious_ips.clear()
        self.malicious_domains.clear()
        self.malicious_urls.clear()
        self.c2_servers.clear()

        results = {}

        for feed_name in feed_names:
            cache_file = self.cache_dir / f"{feed_name}.csv"

            if not cache_file.exists():
                self.logger.warning(f"Cache file niet gevonden: {cache_file}, download eerst feeds")
                continue

            self.logger.info(f"Loading feed: {feed_name}")

            # Parse based on feed type
            if feed_name == 'feodotracker':
                count = self.parse_feodotracker(cache_file)
            elif feed_name == 'urlhaus':
                count = self.parse_urlhaus(cache_file)
            elif feed_name == 'threatfox':
                count = self.parse_threatfox(cache_file)
            elif feed_name == 'sslblacklist':
                count = self.parse_sslblacklist(cache_file)
            else:
                count = 0

            results[feed_name] = count
            self.logger.info(f"Loaded {count} IOCs from {feed_name}")

        total = sum(results.values())
        self.logger.info(f"Total IOCs loaded: {total} (IPs: {len(self.malicious_ips)}, Domains: {len(self.malicious_domains)}, URLs: {len(self.malicious_urls)})")

        return results

    def update_all_feeds(self, force: bool = False) -> bool:
        """
        Update alle feeds

        Args:
            force: Force update ook als recent

        Returns:
            True als alle feeds succesvol
        """
        self.logger.info("Updating all threat feeds...")

        success = True
        for feed_name in self.FEEDS.keys():
            if not self.download_feed(feed_name, force=force):
                success = False

        # Laad feeds in memory
        self.load_feeds()

        return success

    def is_malicious_ip(self, ip: str) -> tuple:
        """
        Check of IP malicious is

        Returns:
            (is_malicious: bool, metadata: dict)
        """
        if ip in self.malicious_ips:
            metadata = self.c2_servers.get(ip, {'feed': 'unknown', 'type': 'malicious'})
            return True, metadata
        return False, {}

    def is_malicious_domain(self, domain: str) -> bool:
        """Check of domain malicious is"""
        return domain in self.malicious_domains

    def _is_valid_ip(self, ip: str) -> bool:
        """Simpele IP validatie"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    def _extract_domain(self, url: str) -> str:
        """Extract domain/IP from URL"""
        try:
            # Remove protocol
            if '://' in url:
                url = url.split('://', 1)[1]

            # Remove path
            domain = url.split('/')[0]

            # Remove port
            domain = domain.split(':')[0]

            return domain.lower()
        except:
            return ''

    def get_stats(self) -> dict:
        """Get feed statistics"""
        return {
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'malicious_urls': len(self.malicious_urls),
            'c2_servers': len(self.c2_servers),
            'feeds_loaded': len(self.last_update),
            'last_update': {name: datetime.fromtimestamp(ts).isoformat()
                          for name, ts in self.last_update.items()}
        }
