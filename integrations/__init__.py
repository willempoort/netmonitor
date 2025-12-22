# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
NetMonitor Integrations Package

Modulaire integraties voor SIEM, Threat Intelligence en andere externe systemen.
Alle integraties zijn optioneel en kunnen individueel worden in-/uitgeschakeld.
"""

from .base import IntegrationBase, IntegrationManager
from .siem import SIEMOutput, CEFFormatter, SyslogOutput
from .threat_intel import ThreatIntelManager, ThreatIntelSource

__all__ = [
    'IntegrationBase',
    'IntegrationManager',
    'SIEMOutput',
    'CEFFormatter',
    'SyslogOutput',
    'ThreatIntelManager',
    'ThreatIntelSource',
]
