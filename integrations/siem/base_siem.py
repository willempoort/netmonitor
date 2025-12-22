# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Base SIEM Output class
"""

from abc import abstractmethod
from typing import Dict, List, Optional
from ..base import IntegrationBase


class SIEMOutput(IntegrationBase):
    """
    Base class for SIEM output integrations.

    Provides common functionality for sending alerts to SIEM systems.
    """

    # Severity mapping from NetMonitor to numeric values
    SEVERITY_MAP = {
        'LOW': 3,
        'MEDIUM': 5,
        'HIGH': 7,
        'CRITICAL': 10,
        'INFO': 1
    }

    def __init__(self, config: Dict = None):
        super().__init__(config)

        # Which severities to forward
        self.forward_severities = config.get('forward_severities', ['HIGH', 'CRITICAL'])
        self.forward_all = config.get('forward_all', False)

        # Buffering settings
        self.buffer_size = config.get('buffer_size', 100)
        self.flush_interval = config.get('flush_interval', 30)
        self._buffer: List[Dict] = []

    def should_forward(self, alert: Dict) -> bool:
        """
        Check if an alert should be forwarded to the SIEM.

        Args:
            alert: The alert dictionary

        Returns:
            True if the alert should be forwarded
        """
        if not self.enabled:
            return False

        if self.forward_all:
            return True

        severity = alert.get('severity', 'MEDIUM')
        return severity in self.forward_severities

    @abstractmethod
    def send_alert(self, alert: Dict) -> bool:
        """
        Send a single alert to the SIEM.

        Args:
            alert: The alert dictionary

        Returns:
            True if successful
        """
        pass

    def send_alerts(self, alerts: List[Dict]) -> tuple[int, int]:
        """
        Send multiple alerts to the SIEM.

        Args:
            alerts: List of alert dictionaries

        Returns:
            Tuple of (successful_count, failed_count)
        """
        success = 0
        failed = 0

        for alert in alerts:
            if self.should_forward(alert):
                try:
                    if self.send_alert(alert):
                        success += 1
                        self.record_success()
                    else:
                        failed += 1
                except Exception as e:
                    self.record_failure(str(e))
                    failed += 1

        return success, failed

    def buffer_alert(self, alert: Dict) -> Optional[List[Dict]]:
        """
        Buffer an alert for batch sending.

        Args:
            alert: The alert to buffer

        Returns:
            List of buffered alerts if buffer is full, None otherwise
        """
        if not self.should_forward(alert):
            return None

        self._buffer.append(alert)

        if len(self._buffer) >= self.buffer_size:
            return self.flush_buffer()

        return None

    def flush_buffer(self) -> List[Dict]:
        """
        Flush the alert buffer and return buffered alerts.

        Returns:
            List of buffered alerts
        """
        alerts = self._buffer.copy()
        self._buffer.clear()
        return alerts
