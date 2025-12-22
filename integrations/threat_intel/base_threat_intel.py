# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Base classes for Threat Intelligence integration.
"""

import logging
from abc import abstractmethod
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from ..base import IntegrationBase


class IndicatorType(Enum):
    """Types of threat indicators"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    JA3 = "ja3"
    JA3S = "ja3s"


@dataclass
class ThreatIndicator:
    """A threat intelligence indicator"""
    value: str
    type: IndicatorType
    source: str
    confidence: float  # 0.0 to 1.0
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    categories: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    reference_url: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'value': self.value,
            'type': self.type.value,
            'source': self.source,
            'confidence': self.confidence,
            'severity': self.severity,
            'categories': self.categories,
            'tags': self.tags,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'description': self.description,
            'reference_url': self.reference_url,
            'mitre_techniques': self.mitre_techniques
        }


class ThreatIntelSource(IntegrationBase):
    """
    Base class for threat intelligence sources.

    All threat intel integrations (MISP, OTX, etc.) should inherit from this class.
    """

    def __init__(self, config: Dict = None):
        super().__init__(config)

        # Cache settings
        self.cache_ttl = config.get('cache_ttl_hours', 24) * 3600  # Convert to seconds
        self._cache: Dict[str, tuple] = {}  # key -> (indicator, timestamp)

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        Look up an IP address in the threat intel source.

        Args:
            ip: IP address to look up

        Returns:
            ThreatIndicator if found, None otherwise
        """
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """
        Look up a domain in the threat intel source.

        Args:
            domain: Domain to look up

        Returns:
            ThreatIndicator if found, None otherwise
        """
        pass

    def lookup_hash(self, hash_value: str, hash_type: str = None) -> Optional[ThreatIndicator]:
        """
        Look up a file hash in the threat intel source.

        Override in subclasses that support hash lookups.

        Args:
            hash_value: Hash value to look up
            hash_type: Type of hash (md5, sha1, sha256)

        Returns:
            ThreatIndicator if found, None otherwise
        """
        return None

    def _get_cached(self, key: str) -> Optional[ThreatIndicator]:
        """Get cached indicator if still valid"""
        if key in self._cache:
            indicator, timestamp = self._cache[key]
            if datetime.now().timestamp() - timestamp < self.cache_ttl:
                return indicator
            else:
                del self._cache[key]
        return None

    def _set_cached(self, key: str, indicator: ThreatIndicator) -> None:
        """Cache an indicator"""
        self._cache[key] = (indicator, datetime.now().timestamp())

    def clear_cache(self) -> int:
        """Clear the cache, returns number of items cleared"""
        count = len(self._cache)
        self._cache.clear()
        return count


class ThreatIntelManager:
    """
    Manages multiple threat intelligence sources.

    Provides unified interface for:
    - Looking up indicators across all sources
    - Aggregating results
    - Caching
    - Alert enrichment
    """

    def __init__(self, config: Dict = None, db_manager=None):
        """
        Initialize the threat intel manager.

        Args:
            config: Configuration dictionary
            db_manager: Database manager for persistent caching
        """
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.ThreatIntel')

        # Registered sources
        self._sources: List[ThreatIntelSource] = []

        # In-memory cache for quick lookups
        self._lookup_cache: Dict[str, Optional[ThreatIndicator]] = {}
        self._cache_ttl = config.get('cache_ttl_hours', 24) * 3600

        # Known malicious indicators (from all sources)
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()

        self.logger.info("Threat Intel Manager initialized")

    def register_source(self, source: ThreatIntelSource) -> None:
        """Register a threat intel source"""
        self._sources.append(source)
        self.logger.info(f"Registered threat intel source: {source.display_name}")

    def get_sources(self, enabled_only: bool = True) -> List[ThreatIntelSource]:
        """Get registered sources"""
        if enabled_only:
            return [s for s in self._sources if s.enabled]
        return self._sources

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        Look up an IP across all enabled sources.

        Returns the first match with highest confidence.
        """
        # Check cache first
        cache_key = f"ip:{ip}"
        if cache_key in self._lookup_cache:
            cached = self._lookup_cache[cache_key]
            if cached is not None:
                return cached

        results = []

        for source in self.get_sources(enabled_only=True):
            try:
                indicator = source.lookup_ip(ip)
                if indicator:
                    results.append(indicator)
                    source.record_success()
            except Exception as e:
                source.record_failure(str(e))
                self.logger.warning(f"Error looking up IP in {source.name}: {e}")

        if not results:
            self._lookup_cache[cache_key] = None
            return None

        # Return highest confidence result
        best = max(results, key=lambda x: x.confidence)

        # Merge categories and tags from all results
        all_categories = set()
        all_tags = set()
        for r in results:
            all_categories.update(r.categories)
            all_tags.update(r.tags)

        best.categories = list(all_categories)
        best.tags = list(all_tags)

        # Cache result
        self._lookup_cache[cache_key] = best

        # Add to known malicious set
        self.malicious_ips.add(ip)

        return best

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Look up a domain across all enabled sources"""
        cache_key = f"domain:{domain}"
        if cache_key in self._lookup_cache:
            cached = self._lookup_cache[cache_key]
            if cached is not None:
                return cached

        results = []

        for source in self.get_sources(enabled_only=True):
            try:
                indicator = source.lookup_domain(domain)
                if indicator:
                    results.append(indicator)
                    source.record_success()
            except Exception as e:
                source.record_failure(str(e))
                self.logger.warning(f"Error looking up domain in {source.name}: {e}")

        if not results:
            self._lookup_cache[cache_key] = None
            return None

        best = max(results, key=lambda x: x.confidence)
        self._lookup_cache[cache_key] = best
        self.malicious_domains.add(domain)

        return best

    def is_malicious_ip(self, ip: str, check_sources: bool = True) -> tuple[bool, Optional[ThreatIndicator]]:
        """
        Quick check if an IP is known malicious.

        Args:
            ip: IP to check
            check_sources: If True, query sources if not in cache

        Returns:
            Tuple of (is_malicious, indicator)
        """
        # Quick check in known set
        if ip in self.malicious_ips:
            # Get full indicator if cached
            indicator = self._lookup_cache.get(f"ip:{ip}")
            return True, indicator

        if not check_sources:
            return False, None

        # Do full lookup
        indicator = self.lookup_ip(ip)
        return indicator is not None, indicator

    def enrich_alert(self, alert: Dict) -> Dict:
        """
        Enrich an alert with threat intelligence.

        Args:
            alert: Alert dictionary

        Returns:
            Enriched alert dictionary
        """
        enrichment = {}

        # Look up source IP
        src_ip = alert.get('source_ip', '')
        if src_ip:
            # Remove CIDR notation
            if '/' in src_ip:
                src_ip = src_ip.split('/')[0]

            indicator = self.lookup_ip(src_ip)
            if indicator:
                enrichment['source_ip'] = indicator.to_dict()

        # Look up destination IP
        dst_ip = alert.get('destination_ip', '')
        if dst_ip:
            if '/' in dst_ip:
                dst_ip = dst_ip.split('/')[0]

            indicator = self.lookup_ip(dst_ip)
            if indicator:
                enrichment['destination_ip'] = indicator.to_dict()

        if enrichment:
            alert['threat_intel'] = enrichment

            # Upgrade severity if threat intel found
            if enrichment.get('destination_ip'):
                dest_severity = enrichment['destination_ip'].get('severity', 'MEDIUM')
                alert_severity = alert.get('severity', 'MEDIUM')

                severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                if severity_order.index(dest_severity) > severity_order.index(alert_severity):
                    alert['severity'] = dest_severity
                    alert['severity_upgraded_by'] = 'threat_intel'

        return alert

    def get_stats(self) -> Dict:
        """Get statistics about threat intel sources"""
        stats = {
            'sources': [],
            'total_cached_indicators': len(self._lookup_cache),
            'known_malicious_ips': len(self.malicious_ips),
            'known_malicious_domains': len(self.malicious_domains)
        }

        for source in self._sources:
            status = source.get_status()
            stats['sources'].append({
                'name': source.name,
                'display_name': source.display_name,
                'enabled': source.enabled,
                'healthy': status.healthy,
                'metrics': status.metrics
            })

        return stats
