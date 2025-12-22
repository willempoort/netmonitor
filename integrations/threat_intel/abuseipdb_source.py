# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
AbuseIPDB integration.

AbuseIPDB is a project dedicated to helping combat the spread of
hackers, spammers, and abusive activity on the internet.
"""

import requests
from typing import Dict, Optional, Tuple
from datetime import datetime

from .base_threat_intel import ThreatIntelSource, ThreatIndicator, IndicatorType


class AbuseIPDBSource(ThreatIntelSource):
    """
    AbuseIPDB threat intelligence source.

    Uses the AbuseIPDB API v2.
    """

    name = "abuseipdb"
    display_name = "AbuseIPDB"
    description = "IP address abuse reporting and lookup service"
    version = "1.0.0"

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    # Abuse category mapping
    ABUSE_CATEGORIES = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }

    def __init__(self, config: Dict = None):
        """
        Initialize AbuseIPDB source.

        Config options:
            api_key: AbuseIPDB API key (or ABUSEIPDB_API_KEY env var)
            max_age_days: Maximum age of reports to consider (default: 90)
            min_confidence: Minimum confidence score (0-100) to consider malicious (default: 50)
            timeout: Request timeout in seconds (default: 30)

        Environment variables (take precedence over config):
            ABUSEIPDB_API_KEY: AbuseIPDB API key
        """
        super().__init__(config)

        from ..base import get_config_value

        self.api_key = get_config_value(config, 'api_key', 'ABUSEIPDB_API_KEY', '')
        self.max_age_days = config.get('max_age_days', 90)
        self.min_confidence = config.get('min_confidence', 50)
        self.timeout = config.get('timeout', 30)

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate AbuseIPDB configuration"""
        if not self.api_key:
            return False, "AbuseIPDB API key is required"
        return True, None

    def _headers(self) -> Dict:
        """Get API request headers"""
        return {
            'Key': self.api_key,
            'Accept': 'application/json'
        }

    def health_check(self) -> bool:
        """Check AbuseIPDB API health by checking quota"""
        try:
            # Use a known IP to test (Google DNS)
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self._headers(),
                params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 1},
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
        """Test connection to AbuseIPDB"""
        try:
            # Check a known malicious IP to test the API
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self._headers(),
                params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 1},
                timeout=self.timeout
            )

            if response.status_code == 200:
                return True, "Connected to AbuseIPDB API"
            elif response.status_code == 401:
                return False, "Invalid API key"
            elif response.status_code == 429:
                return False, "Rate limit exceeded"
            else:
                return False, f"API returned {response.status_code}"

        except Exception as e:
            return False, f"Connection failed: {e}"

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """Look up an IP address in AbuseIPDB"""
        if not self.enabled:
            return None

        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached

        try:
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=self._headers(),
                params={
                    'ipAddress': ip,
                    'maxAgeInDays': self.max_age_days,
                    'verbose': True
                },
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                indicator = self._parse_response(ip, data)

                if indicator:
                    self._set_cached(f"ip:{ip}", indicator)

                return indicator

            return None

        except Exception as e:
            self.logger.error(f"AbuseIPDB lookup error: {e}")
            return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """
        AbuseIPDB does not support domain lookups directly.
        Returns None.
        """
        return None

    def _parse_response(self, ip: str, data: Dict) -> Optional[ThreatIndicator]:
        """Parse AbuseIPDB response into ThreatIndicator"""

        confidence_score = data.get('abuseConfidenceScore', 0)
        total_reports = data.get('totalReports', 0)

        # Only create indicator if meets minimum confidence threshold
        if confidence_score < self.min_confidence:
            return None

        # Extract abuse categories
        categories = []
        reports = data.get('reports', [])
        category_counts = {}

        for report in reports:
            for cat_id in report.get('categories', []):
                cat_name = self.ABUSE_CATEGORIES.get(cat_id, f"Category {cat_id}")
                category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

        # Sort by count and take top categories
        categories = sorted(category_counts.keys(),
                          key=lambda x: category_counts[x],
                          reverse=True)[:5]

        # Determine severity
        if confidence_score >= 90:
            severity = 'CRITICAL'
        elif confidence_score >= 70:
            severity = 'HIGH'
        elif confidence_score >= 50:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'

        # Parse timestamps
        first_seen = None
        last_seen = None

        if reports:
            # Sort by date
            sorted_reports = sorted(reports,
                                   key=lambda x: x.get('reportedAt', ''))
            if sorted_reports:
                try:
                    first_seen = datetime.fromisoformat(
                        sorted_reports[0].get('reportedAt', '').replace('Z', '+00:00')
                    )
                    last_seen = datetime.fromisoformat(
                        sorted_reports[-1].get('reportedAt', '').replace('Z', '+00:00')
                    )
                except:
                    pass

        # Determine tags based on properties
        tags = []
        if data.get('isWhitelisted'):
            tags.append('whitelisted')
        if data.get('isTor'):
            tags.append('tor-exit-node')
        if data.get('isPublic') is False:
            tags.append('private-ip')
        if data.get('usageType'):
            tags.append(f"usage:{data['usageType'].lower()}")

        # Add country code
        if data.get('countryCode'):
            tags.append(f"country:{data['countryCode']}")

        # ISP info
        isp = data.get('isp', '')
        domain = data.get('domain', '')

        description = f"Abuse score: {confidence_score}%, Reports: {total_reports}"
        if isp:
            description += f", ISP: {isp}"

        return ThreatIndicator(
            value=ip,
            type=IndicatorType.IP,
            source='AbuseIPDB',
            confidence=confidence_score / 100.0,
            severity=severity,
            categories=categories,
            tags=tags,
            first_seen=first_seen,
            last_seen=last_seen,
            description=description,
            reference_url=f"https://www.abuseipdb.com/check/{ip}",
            raw_data={
                'abuse_confidence_score': confidence_score,
                'total_reports': total_reports,
                'num_distinct_users': data.get('numDistinctUsers', 0),
                'isp': isp,
                'domain': domain,
                'country_code': data.get('countryCode'),
                'is_tor': data.get('isTor', False)
            }
        )

    def report_ip(self, ip: str, categories: list, comment: str = None) -> bool:
        """
        Report an IP to AbuseIPDB.

        Args:
            ip: IP address to report
            categories: List of category IDs (see ABUSE_CATEGORIES)
            comment: Optional comment

        Returns:
            True if successful
        """
        if not self.enabled:
            return False

        try:
            params = {
                'ip': ip,
                'categories': ','.join(str(c) for c in categories)
            }

            if comment:
                params['comment'] = comment[:1024]  # Max 1024 chars

            response = requests.post(
                f"{self.BASE_URL}/report",
                headers=self._headers(),
                data=params,
                timeout=self.timeout
            )

            if response.status_code == 200:
                self.logger.info(f"Reported IP {ip} to AbuseIPDB")
                return True
            else:
                self.logger.warning(f"Failed to report IP: {response.status_code}")
                return False

        except Exception as e:
            self.logger.error(f"Error reporting IP to AbuseIPDB: {e}")
            return False
