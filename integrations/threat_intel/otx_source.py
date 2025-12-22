# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
AlienVault OTX (Open Threat Exchange) integration.

OTX is a free threat intelligence sharing platform with
community-contributed threat data.
"""

import requests
from typing import Dict, Optional, Tuple
from datetime import datetime

from .base_threat_intel import ThreatIntelSource, ThreatIndicator, IndicatorType


class OTXSource(ThreatIntelSource):
    """
    AlienVault OTX threat intelligence source.

    Uses the free OTX DirectConnect API.
    """

    name = "otx"
    display_name = "AlienVault OTX"
    description = "Open Threat Exchange community threat intelligence"
    version = "1.0.0"

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, config: Dict = None):
        """
        Initialize OTX source.

        Config options:
            api_key: OTX API key (or OTX_API_KEY env var)
            timeout: Request timeout in seconds (default: 30)

        Environment variables (take precedence over config):
            OTX_API_KEY: AlienVault OTX API key
        """
        super().__init__(config)

        from ..base import get_config_value

        self.api_key = get_config_value(config, 'api_key', 'OTX_API_KEY', '')
        self.timeout = config.get('timeout', 30)

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate OTX configuration"""
        if not self.api_key:
            return False, "OTX API key is required"
        return True, None

    def _headers(self) -> Dict:
        """Get API request headers"""
        return {
            'X-OTX-API-KEY': self.api_key,
            'Accept': 'application/json'
        }

    def health_check(self) -> bool:
        """Check OTX API health"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/users/me",
                headers=self._headers(),
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
        """Test connection to OTX"""
        try:
            response = requests.get(
                f"{self.BASE_URL}/users/me",
                headers=self._headers(),
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                username = data.get('username', 'unknown')
                return True, f"Connected to OTX as {username}"
            elif response.status_code == 403:
                return False, "Invalid API key"
            else:
                return False, f"API returned {response.status_code}"

        except Exception as e:
            return False, f"Connection failed: {e}"

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Look up an IP address in OTX"""
        if not self.enabled:
            return None

        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached

        try:
            response = requests.get(
                f"{self.BASE_URL}/indicators/IPv4/{ip}/general",
                headers=self._headers(),
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                indicator = self._parse_response(ip, data, IndicatorType.IP)

                if indicator:
                    self._set_cached(f"ip:{ip}", indicator)

                return indicator

            return None

        except Exception as e:
            self.logger.error(f"OTX IP lookup error: {e}")
            return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """Look up a domain in OTX"""
        if not self.enabled:
            return None

        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached

        try:
            response = requests.get(
                f"{self.BASE_URL}/indicators/domain/{domain}/general",
                headers=self._headers(),
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                indicator = self._parse_response(domain, data, IndicatorType.DOMAIN)

                if indicator:
                    self._set_cached(f"domain:{domain}", indicator)

                return indicator

            return None

        except Exception as e:
            self.logger.error(f"OTX domain lookup error: {e}")
            return None

    def lookup_hash(self, hash_value: str, hash_type: str = None) -> Optional[ThreatIndicator]:
        """Look up a file hash in OTX"""
        if not self.enabled:
            return None

        cached = self._get_cached(f"hash:{hash_value}")
        if cached:
            return cached

        try:
            response = requests.get(
                f"{self.BASE_URL}/indicators/file/{hash_value}/general",
                headers=self._headers(),
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()

                # Determine indicator type
                if len(hash_value) == 32:
                    ind_type = IndicatorType.HASH_MD5
                elif len(hash_value) == 40:
                    ind_type = IndicatorType.HASH_SHA1
                else:
                    ind_type = IndicatorType.HASH_SHA256

                indicator = self._parse_response(hash_value, data, ind_type)

                if indicator:
                    self._set_cached(f"hash:{hash_value}", indicator)

                return indicator

            return None

        except Exception as e:
            self.logger.error(f"OTX hash lookup error: {e}")
            return None

    def _parse_response(self, value: str, data: Dict, ind_type: IndicatorType) -> Optional[ThreatIndicator]:
        """Parse OTX API response into ThreatIndicator"""

        pulse_info = data.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)

        # If no pulses reference this indicator, it's probably not malicious
        if pulse_count == 0:
            return None

        # Extract categories from pulses
        categories = set()
        tags = set()
        mitre_techniques = set()

        for pulse in pulse_info.get('pulses', [])[:10]:  # Limit to first 10 pulses
            # Add pulse tags
            for tag in pulse.get('tags', []):
                tags.add(tag)

            # Add attack IDs
            for attack_id in pulse.get('attack_ids', []):
                if attack_id.get('id'):
                    mitre_techniques.add(attack_id['id'])

            # Determine category from adversary or industries
            if pulse.get('adversary'):
                categories.add(f"adversary:{pulse['adversary']}")
            for industry in pulse.get('industries', []):
                categories.add(f"target:{industry}")

        # Calculate confidence based on pulse count
        confidence = min(0.5 + (pulse_count * 0.05), 0.95)

        # Determine severity based on pulse content
        severity = 'MEDIUM'
        if pulse_count >= 5:
            severity = 'HIGH'
        if any('apt' in str(t).lower() or 'malware' in str(t).lower() for t in tags):
            severity = 'HIGH'
        if any('ransomware' in str(t).lower() or 'critical' in str(t).lower() for t in tags):
            severity = 'CRITICAL'

        return ThreatIndicator(
            value=value,
            type=ind_type,
            source='OTX',
            confidence=confidence,
            severity=severity,
            categories=list(categories),
            tags=list(tags),
            description=f"Referenced in {pulse_count} OTX pulse(s)",
            reference_url=f"https://otx.alienvault.com/indicator/{ind_type.value}/{value}",
            mitre_techniques=list(mitre_techniques),
            raw_data={
                'pulse_count': pulse_count,
                'validation': data.get('validation', [])
            }
        )
