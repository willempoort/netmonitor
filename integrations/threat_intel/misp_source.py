# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
MISP (Malware Information Sharing Platform) integration.

MISP is an open source threat intelligence platform for sharing,
storing and correlating Indicators of Compromise.
"""

import requests
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import warnings

from .base_threat_intel import ThreatIntelSource, ThreatIndicator, IndicatorType


class MISPSource(ThreatIntelSource):
    """
    MISP threat intelligence source.

    Supports:
    - IP address lookups
    - Domain lookups
    - Hash lookups
    - Event correlation
    """

    name = "misp"
    display_name = "MISP"
    description = "Malware Information Sharing Platform"
    version = "1.0.0"

    # MISP attribute type mapping
    ATTR_TYPE_MAP = {
        'ip-src': IndicatorType.IP,
        'ip-dst': IndicatorType.IP,
        'domain': IndicatorType.DOMAIN,
        'hostname': IndicatorType.DOMAIN,
        'url': IndicatorType.URL,
        'md5': IndicatorType.HASH_MD5,
        'sha1': IndicatorType.HASH_SHA1,
        'sha256': IndicatorType.HASH_SHA256,
        'email-src': IndicatorType.EMAIL,
        'email-dst': IndicatorType.EMAIL,
        'ja3-fingerprint-md5': IndicatorType.JA3,
    }

    def __init__(self, config: Dict = None):
        """
        Initialize MISP source.

        Config options:
            url: MISP instance URL (or MISP_URL env var)
            api_key: MISP API key (or MISP_API_KEY env var)
            verify_ssl: Verify SSL certificate (default: True)
            timeout: Request timeout in seconds (default: 30)

        Environment variables (take precedence over config):
            MISP_URL: MISP instance URL
            MISP_API_KEY: MISP API key
        """
        super().__init__(config)

        from ..base import get_config_value

        self.url = get_config_value(config, 'url', 'MISP_URL', '').rstrip('/')
        self.api_key = get_config_value(config, 'api_key', 'MISP_API_KEY', '')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 30)

        # Suppress SSL warnings if verify_ssl is False
        if not self.verify_ssl:
            warnings.filterwarnings('ignore', category=InsecureRequestWarning)

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate MISP configuration"""
        if not self.url:
            return False, "MISP URL is required"
        if not self.api_key:
            return False, "MISP API key is required"
        return True, None

    def _headers(self) -> Dict:
        """Get API request headers"""
        return {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def health_check(self) -> bool:
        """Check MISP server health"""
        try:
            response = requests.get(
                f"{self.url}/servers/getVersion",
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=10
            )

            self._healthy = response.status_code == 200
            self._last_check = datetime.now()

            if not self._healthy:
                self._last_error = f"API returned {response.status_code}"

            return self._healthy

        except Exception as e:
            self._healthy = False
            self._last_check = datetime.now()
            self._last_error = str(e)
            return False

    def test_connection(self) -> Tuple[bool, str]:
        """Test connection to MISP"""
        try:
            response = requests.get(
                f"{self.url}/servers/getVersion",
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                version = data.get('version', 'unknown')
                return True, f"Connected to MISP {version}"
            else:
                return False, f"API returned {response.status_code}"

        except Exception as e:
            return False, f"Connection failed: {e}"

    def _search_attributes(self, value: str, attr_type: str = None) -> List[Dict]:
        """Search MISP for attributes matching value"""
        try:
            search_params = {
                'value': value,
                'returnFormat': 'json'
            }

            if attr_type:
                search_params['type'] = attr_type

            response = requests.post(
                f"{self.url}/attributes/restSearch",
                headers=self._headers(),
                json=search_params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                return data.get('response', {}).get('Attribute', [])

            return []

        except Exception as e:
            self.logger.error(f"MISP search error: {e}")
            return []

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Look up an IP address in MISP"""
        if not self.enabled:
            return None

        # Check cache
        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached

        # Search for IP in both source and destination attributes
        attributes = self._search_attributes(ip, 'ip-src')
        attributes.extend(self._search_attributes(ip, 'ip-dst'))

        if not attributes:
            return None

        # Create indicator from first match
        attr = attributes[0]
        indicator = self._attr_to_indicator(attr, ip, IndicatorType.IP)

        # Aggregate data from all matches
        if len(attributes) > 1:
            events = set()
            categories = set()
            tags = set()

            for a in attributes:
                events.add(a.get('event_id'))
                categories.add(a.get('category', ''))
                for tag in a.get('Tag', []):
                    tags.add(tag.get('name', ''))

            indicator.categories = list(filter(None, categories))
            indicator.tags = list(filter(None, tags))
            indicator.description = f"Found in {len(events)} MISP events"

            # Increase confidence based on number of events
            indicator.confidence = min(0.5 + (len(events) * 0.1), 0.95)

        # Cache result
        self._set_cached(f"ip:{ip}", indicator)

        return indicator

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Look up a domain in MISP"""
        if not self.enabled:
            return None

        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached

        attributes = self._search_attributes(domain, 'domain')
        attributes.extend(self._search_attributes(domain, 'hostname'))

        if not attributes:
            return None

        attr = attributes[0]
        indicator = self._attr_to_indicator(attr, domain, IndicatorType.DOMAIN)

        self._set_cached(f"domain:{domain}", indicator)

        return indicator

    def lookup_hash(self, hash_value: str, hash_type: str = None) -> Optional[ThreatIndicator]:
        """Look up a file hash in MISP"""
        if not self.enabled:
            return None

        # Determine hash type if not specified
        if not hash_type:
            if len(hash_value) == 32:
                hash_type = 'md5'
            elif len(hash_value) == 40:
                hash_type = 'sha1'
            elif len(hash_value) == 64:
                hash_type = 'sha256'
            else:
                return None

        cached = self._get_cached(f"hash:{hash_value}")
        if cached:
            return cached

        attributes = self._search_attributes(hash_value, hash_type)

        if not attributes:
            return None

        attr = attributes[0]
        indicator_type = self.ATTR_TYPE_MAP.get(hash_type, IndicatorType.HASH_SHA256)
        indicator = self._attr_to_indicator(attr, hash_value, indicator_type)

        self._set_cached(f"hash:{hash_value}", indicator)

        return indicator

    def _attr_to_indicator(self, attr: Dict, value: str, ind_type: IndicatorType) -> ThreatIndicator:
        """Convert MISP attribute to ThreatIndicator"""

        # Extract tags
        tags = [t.get('name', '') for t in attr.get('Tag', [])]

        # Determine severity based on tags and category
        severity = 'MEDIUM'
        if any('apt' in t.lower() or 'malware' in t.lower() for t in tags):
            severity = 'HIGH'
        if any('critical' in t.lower() or 'ransomware' in t.lower() for t in tags):
            severity = 'CRITICAL'

        # Extract MITRE techniques from tags
        mitre = [t.split('=')[1] if '=' in t else t
                 for t in tags if 'mitre-attack' in t.lower() or t.startswith('T1')]

        # Parse timestamps
        first_seen = None
        last_seen = None
        if attr.get('first_seen'):
            try:
                first_seen = datetime.fromisoformat(attr['first_seen'].replace('Z', '+00:00'))
            except:
                pass
        if attr.get('timestamp'):
            try:
                last_seen = datetime.fromtimestamp(int(attr['timestamp']))
            except:
                pass

        return ThreatIndicator(
            value=value,
            type=ind_type,
            source='MISP',
            confidence=0.7,
            severity=severity,
            categories=[attr.get('category', '')],
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            description=attr.get('comment', ''),
            reference_url=f"{self.url}/events/view/{attr.get('event_id', '')}",
            mitre_techniques=mitre,
            raw_data={
                'event_id': attr.get('event_id'),
                'attribute_id': attr.get('id'),
                'to_ids': attr.get('to_ids')
            }
        )
