# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
SIEM Integration Module

Provides output adapters for various SIEM systems:
- Syslog (CEF, LEEF, JSON formats)
- Wazuh (native API integration)
- Generic webhook output
"""

from .formatters import CEFFormatter, LEEFFormatter, JSONFormatter
from .syslog_output import SyslogOutput
from .wazuh_output import WazuhOutput
from .base_siem import SIEMOutput

__all__ = [
    'SIEMOutput',
    'SyslogOutput',
    'WazuhOutput',
    'CEFFormatter',
    'LEEFFormatter',
    'JSONFormatter',
]
