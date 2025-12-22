# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Threat Intelligence Integration Module

Provides threat intelligence lookups from various sources:
- MISP (Malware Information Sharing Platform)
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB
- Local threat feeds (abuse.ch feeds)
"""

from .base_threat_intel import ThreatIntelSource, ThreatIntelManager, ThreatIndicator
from .misp_source import MISPSource
from .otx_source import OTXSource
from .abuseipdb_source import AbuseIPDBSource

__all__ = [
    'ThreatIntelSource',
    'ThreatIntelManager',
    'ThreatIndicator',
    'MISPSource',
    'OTXSource',
    'AbuseIPDBSource',
]
