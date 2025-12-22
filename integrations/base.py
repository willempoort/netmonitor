# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Base classes for NetMonitor integrations.

Provides a common interface for all integrations (SIEM, Threat Intel, etc.)
with support for:
- Enable/disable functionality
- Configuration validation
- Health checks
- Metrics collection
- Environment variable fallback for sensitive settings
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, field


def get_config_value(config: Dict, key: str, env_var: str = None, default: Any = None) -> Any:
    """
    Get configuration value with environment variable fallback.

    Priority:
    1. Environment variable (if env_var specified)
    2. Config dictionary value
    3. Default value

    Args:
        config: Configuration dictionary
        key: Key to look up in config
        env_var: Environment variable name to check first
        default: Default value if neither env nor config has the value

    Returns:
        The configuration value
    """
    # Check environment variable first
    if env_var:
        env_value = os.environ.get(env_var)
        if env_value:
            return env_value

    # Fall back to config, then default
    return config.get(key, default)


@dataclass
class IntegrationStatus:
    """Status information for an integration"""
    name: str
    enabled: bool
    healthy: bool
    last_check: Optional[datetime] = None
    last_error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'enabled': self.enabled,
            'healthy': self.healthy,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'last_error': self.last_error,
            'metrics': self.metrics
        }


class IntegrationBase(ABC):
    """
    Base class for all NetMonitor integrations.

    All integrations (SIEM outputs, threat intel sources, etc.) should
    inherit from this class and implement the required methods.
    """

    # Integration metadata - override in subclasses
    name: str = "base"
    display_name: str = "Base Integration"
    description: str = "Base integration class"
    version: str = "1.0.0"

    def __init__(self, config: Dict = None):
        """
        Initialize the integration.

        Args:
            config: Configuration dictionary for this integration
        """
        self.config = config or {}
        self.enabled = self.config.get('enabled', False)
        self.logger = logging.getLogger(f'NetMonitor.Integration.{self.name}')

        # Status tracking
        self._healthy = False
        self._last_check = None
        self._last_error = None
        self._metrics = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'last_success': None,
            'last_failure': None
        }

        if self.enabled:
            self.logger.info(f"Integration {self.display_name} initialized")
        else:
            self.logger.debug(f"Integration {self.display_name} is disabled")

    @abstractmethod
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate the integration configuration.

        Returns:
            Tuple of (is_valid, error_message)
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """
        Perform a health check on the integration.

        Returns:
            True if healthy, False otherwise
        """
        pass

    @abstractmethod
    def test_connection(self) -> tuple[bool, str]:
        """
        Test the connection to the external service.

        Returns:
            Tuple of (success, message)
        """
        pass

    def get_status(self) -> IntegrationStatus:
        """Get current status of the integration"""
        return IntegrationStatus(
            name=self.name,
            enabled=self.enabled,
            healthy=self._healthy,
            last_check=self._last_check,
            last_error=self._last_error,
            metrics=self._metrics.copy()
        )

    def enable(self) -> bool:
        """Enable the integration"""
        is_valid, error = self.validate_config()
        if not is_valid:
            self.logger.error(f"Cannot enable {self.name}: {error}")
            return False

        self.enabled = True
        self.logger.info(f"Integration {self.display_name} enabled")
        return True

    def disable(self) -> None:
        """Disable the integration"""
        self.enabled = False
        self.logger.info(f"Integration {self.display_name} disabled")

    def record_success(self) -> None:
        """Record a successful operation"""
        self._metrics['requests_total'] += 1
        self._metrics['requests_success'] += 1
        self._metrics['last_success'] = datetime.now().isoformat()
        self._healthy = True
        self._last_error = None

    def record_failure(self, error: str) -> None:
        """Record a failed operation"""
        self._metrics['requests_total'] += 1
        self._metrics['requests_failed'] += 1
        self._metrics['last_failure'] = datetime.now().isoformat()
        self._last_error = error
        self.logger.warning(f"Integration {self.name} failure: {error}")


class IntegrationManager:
    """
    Manages all NetMonitor integrations.

    Provides a central point for:
    - Registering integrations
    - Enabling/disabling integrations
    - Health monitoring
    - Configuration management
    """

    def __init__(self, config: Dict = None):
        """
        Initialize the integration manager.

        Args:
            config: Full configuration dictionary containing integration settings
        """
        self.config = config or {}
        self.logger = logging.getLogger('NetMonitor.IntegrationManager')

        # Registered integrations by category
        self._integrations: Dict[str, Dict[str, IntegrationBase]] = {
            'siem': {},
            'threat_intel': {},
            'notification': {},
            'other': {}
        }

        self.logger.info("Integration Manager initialized")

    def register(self, integration: IntegrationBase, category: str = 'other') -> None:
        """
        Register an integration.

        Args:
            integration: The integration instance to register
            category: Category for the integration (siem, threat_intel, etc.)
        """
        if category not in self._integrations:
            self._integrations[category] = {}

        self._integrations[category][integration.name] = integration
        self.logger.info(f"Registered integration: {integration.display_name} ({category})")

    def get(self, name: str, category: str = None) -> Optional[IntegrationBase]:
        """
        Get an integration by name.

        Args:
            name: Integration name
            category: Optional category to search in

        Returns:
            The integration instance or None
        """
        if category:
            return self._integrations.get(category, {}).get(name)

        # Search all categories
        for cat_integrations in self._integrations.values():
            if name in cat_integrations:
                return cat_integrations[name]

        return None

    def get_all(self, category: str = None, enabled_only: bool = False) -> List[IntegrationBase]:
        """
        Get all integrations.

        Args:
            category: Optional category filter
            enabled_only: Only return enabled integrations

        Returns:
            List of integration instances
        """
        result = []

        categories = [category] if category else self._integrations.keys()

        for cat in categories:
            for integration in self._integrations.get(cat, {}).values():
                if enabled_only and not integration.enabled:
                    continue
                result.append(integration)

        return result

    def get_status_all(self) -> Dict[str, List[Dict]]:
        """Get status of all integrations grouped by category"""
        status = {}

        for category, integrations in self._integrations.items():
            status[category] = [
                integration.get_status().to_dict()
                for integration in integrations.values()
            ]

        return status

    def health_check_all(self) -> Dict[str, bool]:
        """
        Run health checks on all enabled integrations.

        Returns:
            Dict mapping integration name to health status
        """
        results = {}

        for integration in self.get_all(enabled_only=True):
            try:
                results[integration.name] = integration.health_check()
            except Exception as e:
                self.logger.error(f"Health check failed for {integration.name}: {e}")
                results[integration.name] = False

        return results

    def initialize_from_config(self, config: Dict) -> None:
        """
        Initialize all integrations from configuration.

        Args:
            config: Configuration dictionary with 'integrations' section
        """
        integrations_config = config.get('integrations', {})

        # Initialize SIEM integrations
        siem_config = integrations_config.get('siem', {})
        if siem_config.get('enabled', False):
            self._init_siem_integrations(siem_config)

        # Initialize Threat Intel integrations
        threat_intel_config = integrations_config.get('threat_intel', {})
        if threat_intel_config.get('enabled', False):
            self._init_threat_intel_integrations(threat_intel_config)

        self.logger.info(f"Initialized {len(self.get_all())} integrations")

    def _init_siem_integrations(self, config: Dict) -> None:
        """Initialize SIEM output integrations"""
        from .siem import SyslogOutput, WazuhOutput

        # Syslog output
        if config.get('syslog', {}).get('enabled', False):
            syslog = SyslogOutput(config.get('syslog', {}))
            self.register(syslog, 'siem')

        # Wazuh specific output
        if config.get('wazuh', {}).get('enabled', False):
            wazuh = WazuhOutput(config.get('wazuh', {}))
            self.register(wazuh, 'siem')

    def _init_threat_intel_integrations(self, config: Dict) -> None:
        """Initialize Threat Intelligence integrations"""
        from .threat_intel import MISPSource, OTXSource, AbuseIPDBSource

        # MISP
        if config.get('misp', {}).get('enabled', False):
            misp = MISPSource(config.get('misp', {}))
            self.register(misp, 'threat_intel')

        # AlienVault OTX
        if config.get('otx', {}).get('enabled', False):
            otx = OTXSource(config.get('otx', {}))
            self.register(otx, 'threat_intel')

        # AbuseIPDB
        if config.get('abuseipdb', {}).get('enabled', False):
            abuseipdb = AbuseIPDBSource(config.get('abuseipdb', {}))
            self.register(abuseipdb, 'threat_intel')
