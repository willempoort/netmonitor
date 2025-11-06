"""
AbuseIPDB API Client
Real-time IP reputation lookups
"""

import json
import time
import logging
import urllib.request
import urllib.error
from collections import deque
from typing import Optional, Dict


class AbuseIPDBClient:
    """Client voor AbuseIPDB API"""

    API_URL = 'https://api.abuseipdb.com/api/v2/check'

    def __init__(self, api_key: str, rate_limit: int = 1000):
        """
        Initialiseer AbuseIPDB client

        Args:
            api_key: AbuseIPDB API key
            rate_limit: Max queries per dag (default 1000 voor free tier)
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.logger = logging.getLogger('NetMonitor.AbuseIPDB')

        # Rate limiting
        self.query_history = deque(maxlen=rate_limit)
        self.daily_reset_time = time.time() + 86400  # 24 uur

        # Cache voor lookups (vermijd duplicate queries)
        self.cache = {}  # ip -> (result, timestamp)
        self.cache_ttl = 3600  # 1 uur cache

        # Stats
        self.queries_today = 0
        self.cache_hits = 0

        if not self.api_key:
            self.logger.warning("AbuseIPDB API key niet geconfigureerd, real-time lookups disabled")
        else:
            self.logger.info(f"AbuseIPDB client geïnitialiseerd (rate limit: {rate_limit}/dag)")

    def check_ip(self, ip: str, max_age_days: int = 90) -> Optional[Dict]:
        """
        Check IP reputation via AbuseIPDB

        Args:
            ip: IP adres om te checken
            max_age_days: Max age van reports (default 90)

        Returns:
            Dict met IP info of None bij error
        """
        if not self.api_key:
            return None

        # Check cache
        if ip in self.cache:
            result, timestamp = self.cache[ip]
            if time.time() - timestamp < self.cache_ttl:
                self.cache_hits += 1
                self.logger.debug(f"Cache hit voor IP: {ip}")
                return result

        # Check rate limit
        if not self._check_rate_limit():
            self.logger.warning("AbuseIPDB rate limit bereikt, query geskipped")
            return None

        # Query API
        try:
            params = {
                'ipAddress': ip,
                'maxAgeInDays': max_age_days,
                'verbose': ''
            }

            url = f"{self.API_URL}?{urllib.parse.urlencode(params)}"

            req = urllib.request.Request(
                url,
                headers={
                    'Key': self.api_key,
                    'Accept': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))

            result = data.get('data', {})

            # Cache result
            self.cache[ip] = (result, time.time())

            # Track query
            self.query_history.append(time.time())
            self.queries_today += 1

            self.logger.debug(f"AbuseIPDB lookup voor {ip}: abuse score {result.get('abuseConfidenceScore', 0)}")

            return result

        except urllib.error.HTTPError as e:
            if e.code == 429:
                self.logger.error("AbuseIPDB rate limit exceeded")
            else:
                self.logger.error(f"AbuseIPDB HTTP error {e.code}: {e.reason}")
            return None

        except urllib.error.URLError as e:
            self.logger.error(f"AbuseIPDB connection error: {e}")
            return None

        except Exception as e:
            self.logger.error(f"AbuseIPDB unexpected error: {e}")
            return None

    def _check_rate_limit(self) -> bool:
        """Check of we binnen rate limit zijn"""
        current_time = time.time()

        # Reset dagelijkse counter
        if current_time > self.daily_reset_time:
            self.queries_today = 0
            self.query_history.clear()
            self.daily_reset_time = current_time + 86400
            self.logger.info("AbuseIPDB dagelijkse rate limit gereset")

        # Check limit
        return self.queries_today < self.rate_limit

    def is_malicious(self, ip: str, threshold: int = 50) -> tuple:
        """
        Check of IP als malicious beschouwd wordt

        Args:
            ip: IP adres
            threshold: Abuse confidence score threshold (0-100)

        Returns:
            (is_malicious: bool, score: int, total_reports: int)
        """
        result = self.check_ip(ip)

        if not result:
            return False, 0, 0

        score = result.get('abuseConfidenceScore', 0)
        total_reports = result.get('totalReports', 0)

        return score >= threshold, score, total_reports

    def get_ip_info(self, ip: str) -> Dict:
        """
        Get uitgebreide IP info

        Returns:
            Dict met IP informatie
        """
        result = self.check_ip(ip)

        if not result:
            return {}

        return {
            'ip': result.get('ipAddress'),
            'abuse_score': result.get('abuseConfidenceScore', 0),
            'country': result.get('countryCode'),
            'usage_type': result.get('usageType'),
            'isp': result.get('isp'),
            'domain': result.get('domain'),
            'total_reports': result.get('totalReports', 0),
            'num_distinct_users': result.get('numDistinctUsers', 0),
            'last_reported': result.get('lastReportedAt'),
            'is_whitelisted': result.get('isWhitelisted', False)
        }

    def get_stats(self) -> Dict:
        """Get client statistieken"""
        return {
            'api_enabled': bool(self.api_key),
            'queries_today': self.queries_today,
            'rate_limit': self.rate_limit,
            'remaining_queries': max(0, self.rate_limit - self.queries_today),
            'cache_size': len(self.cache),
            'cache_hits': self.cache_hits,
            'cache_hit_rate': f"{(self.cache_hits / max(1, self.queries_today + self.cache_hits)) * 100:.1f}%"
        }

    def clear_cache(self):
        """Clear IP cache"""
        self.cache.clear()
        self.logger.info("AbuseIPDB cache gecleared")
