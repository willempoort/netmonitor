# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
SOAR - Security Orchestration, Automation and Response Module

Provides automated response capabilities:
- Alert enrichment (GeoIP, DNS, threat intel)
- Automated playbook execution
- Integration with external systems
- Response actions (block, quarantine, notify)
- Incident workflow management

IMPORTANT: Automated blocking is disabled by default.
Only enable in production after thorough testing.
"""

import logging
import time
import json
import subprocess
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from queue import Queue


class ResponseAction(Enum):
    """Available response actions."""
    LOG = "log"                    # Just log the event
    ALERT = "alert"                # Generate enhanced alert
    NOTIFY = "notify"              # Send notification (email, webhook)
    ENRICH = "enrich"              # Enrich with additional context
    QUARANTINE = "quarantine"      # Isolate device (via network switch)
    BLOCK_IP = "block_ip"          # Block IP in firewall
    BLOCK_DOMAIN = "block_domain"  # Block domain in DNS
    RATE_LIMIT = "rate_limit"      # Apply rate limiting
    CAPTURE = "capture"            # Start packet capture
    SCRIPT = "script"              # Run custom script


class PlaybookStatus(Enum):
    """Playbook execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlaybookStep:
    """Single step in a playbook."""
    action: ResponseAction
    parameters: Dict = field(default_factory=dict)
    condition: Optional[str] = None  # Condition for execution
    timeout: int = 60                # Timeout in seconds
    on_failure: str = "continue"     # 'continue' or 'abort'


@dataclass
class Playbook:
    """Automated response playbook."""
    name: str
    description: str
    trigger_types: List[str]         # Alert types that trigger this playbook
    trigger_severities: List[str]    # Severities that trigger
    steps: List[PlaybookStep]
    enabled: bool = True
    cooldown: int = 300              # Minimum seconds between executions per IP
    max_executions_per_hour: int = 10


@dataclass
class PlaybookExecution:
    """Record of a playbook execution."""
    execution_id: str
    playbook_name: str
    trigger_alert: Dict
    status: PlaybookStatus
    started_at: float
    completed_at: Optional[float]
    steps_completed: int
    steps_total: int
    results: List[Dict]
    error: Optional[str] = None


class SOAREngine:
    """
    Security Orchestration, Automation and Response engine.

    Handles automated response to security alerts.
    """

    def __init__(self, config: dict = None, db_manager=None):
        self.config = config or {}
        self.db = db_manager
        self.logger = logging.getLogger('NetMonitor.SOAR')

        # Configuration
        soar_config = self.config.get('soar', {})
        self.enabled = soar_config.get('enabled', True)

        # Safety settings
        self.dry_run = soar_config.get('dry_run', True)  # True = no actual blocking
        self.require_approval = soar_config.get('require_approval', True)
        self.max_blocks_per_hour = soar_config.get('max_blocks_per_hour', 10)

        # Notification settings
        self.webhook_url = soar_config.get('webhook_url')
        self.email_enabled = soar_config.get('email_enabled', False)
        self.email_recipients = soar_config.get('email_recipients', [])

        # Playbooks
        self.playbooks: Dict[str, Playbook] = {}
        self._load_default_playbooks()

        # Execution tracking
        self.executions: deque = deque(maxlen=1000)
        self.pending_approvals: Dict[str, Dict] = {}
        self.execution_queue: Queue = Queue()

        # Cooldown tracking (IP -> last execution timestamp)
        self.cooldowns: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Blocking tracking
        self.blocks_this_hour: deque = deque(maxlen=100)

        # Start worker thread
        self._running = False
        self._worker_thread = None

        self.logger.info(f"SOAR Engine initialized (dry_run={self.dry_run})")

    def _load_default_playbooks(self):
        """Load default response playbooks."""

        # Critical threat playbook
        self.playbooks['critical_threat'] = Playbook(
            name='critical_threat',
            description='Response to critical severity threats',
            trigger_types=['C2_COMMUNICATION', 'RANSOMWARE_DETECTED', 'DCSYNC_ATTACK',
                          'HIGH_RISK_ATTACK_CHAIN', 'MALICIOUS_JA3_FINGERPRINT'],
            trigger_severities=['CRITICAL'],
            steps=[
                PlaybookStep(
                    action=ResponseAction.ENRICH,
                    parameters={'include_geoip': True, 'include_whois': True}
                ),
                PlaybookStep(
                    action=ResponseAction.CAPTURE,
                    parameters={'duration': 300}  # 5 minute capture
                ),
                PlaybookStep(
                    action=ResponseAction.NOTIFY,
                    parameters={'priority': 'high', 'channels': ['webhook', 'email']}
                ),
                PlaybookStep(
                    action=ResponseAction.BLOCK_IP,
                    parameters={'direction': 'both', 'duration': 3600}
                )
            ],
            cooldown=300
        )

        # Lateral movement playbook
        self.playbooks['lateral_movement'] = Playbook(
            name='lateral_movement',
            description='Response to lateral movement detection',
            trigger_types=['LATERAL_MOVEMENT', 'PASS_THE_HASH_SUSPECTED',
                          'SMB_LATERAL_MOVEMENT_PATTERN', 'ATTACK_CHAIN_PROGRESSION'],
            trigger_severities=['HIGH', 'CRITICAL'],
            steps=[
                PlaybookStep(
                    action=ResponseAction.ENRICH,
                    parameters={'include_device_info': True}
                ),
                PlaybookStep(
                    action=ResponseAction.NOTIFY,
                    parameters={'priority': 'high'}
                ),
                PlaybookStep(
                    action=ResponseAction.RATE_LIMIT,
                    parameters={'limit': '10/minute'}
                )
            ],
            cooldown=600
        )

        # Credential theft playbook
        self.playbooks['credential_theft'] = Playbook(
            name='credential_theft',
            description='Response to credential theft attempts',
            trigger_types=['KERBEROASTING_ATTACK', 'ASREP_ROASTING_ATTACK',
                          'NTDS_DIT_ACCESS', 'LSASS_DUMP_ACCESS'],
            trigger_severities=['CRITICAL', 'HIGH'],
            steps=[
                PlaybookStep(
                    action=ResponseAction.ENRICH,
                    parameters={'include_ad_info': True}
                ),
                PlaybookStep(
                    action=ResponseAction.CAPTURE,
                    parameters={'duration': 600}
                ),
                PlaybookStep(
                    action=ResponseAction.NOTIFY,
                    parameters={'priority': 'critical', 'escalate': True}
                )
            ],
            cooldown=300
        )

        # Reconnaissance playbook
        self.playbooks['reconnaissance'] = Playbook(
            name='reconnaissance',
            description='Response to reconnaissance activity',
            trigger_types=['PORT_SCAN', 'INTERNAL_PORT_SCAN', 'SMB_ENUMERATION',
                          'LDAP_ENUMERATION', 'LDAP_SPN_ENUMERATION'],
            trigger_severities=['MEDIUM', 'HIGH'],
            steps=[
                PlaybookStep(
                    action=ResponseAction.ENRICH,
                    parameters={'include_geoip': True}
                ),
                PlaybookStep(
                    action=ResponseAction.LOG,
                    parameters={'level': 'info'}
                ),
                PlaybookStep(
                    action=ResponseAction.NOTIFY,
                    parameters={'priority': 'normal'}
                )
            ],
            cooldown=1800
        )

        # Brute force playbook
        self.playbooks['brute_force'] = Playbook(
            name='brute_force',
            description='Response to brute force attacks',
            trigger_types=['BRUTE_FORCE', 'KERBEROS_BRUTEFORCE', 'SSH_BRUTEFORCE'],
            trigger_severities=['HIGH'],
            steps=[
                PlaybookStep(
                    action=ResponseAction.ENRICH,
                    parameters={'include_geoip': True}
                ),
                PlaybookStep(
                    action=ResponseAction.RATE_LIMIT,
                    parameters={'limit': '3/minute', 'duration': 3600}
                ),
                PlaybookStep(
                    action=ResponseAction.NOTIFY,
                    parameters={'priority': 'high'}
                )
            ],
            cooldown=600
        )

        self.logger.info(f"Loaded {len(self.playbooks)} default playbooks")

    def process_alert(self, alert: Dict) -> List[Dict]:
        """
        Process an alert through SOAR engine.

        Returns:
            List of response actions taken/queued
        """
        if not self.enabled:
            return []

        alert_type = alert.get('type', '')
        severity = alert.get('severity', '')
        source_ip = alert.get('source_ip', '')

        responses = []

        # Find matching playbooks
        matching_playbooks = self._find_matching_playbooks(alert_type, severity)

        for playbook in matching_playbooks:
            # Check cooldown
            if self._in_cooldown(source_ip, playbook.name, playbook.cooldown):
                self.logger.debug(f"Playbook {playbook.name} in cooldown for {source_ip}")
                continue

            # Queue or execute playbook
            execution = self._queue_execution(playbook, alert)
            responses.append({
                'playbook': playbook.name,
                'execution_id': execution.execution_id,
                'status': 'queued' if self.require_approval else 'executing'
            })

        return responses

    def _find_matching_playbooks(self, alert_type: str, severity: str) -> List[Playbook]:
        """Find playbooks matching the alert."""
        matching = []

        for playbook in self.playbooks.values():
            if not playbook.enabled:
                continue

            # Check type match
            if alert_type in playbook.trigger_types or '*' in playbook.trigger_types:
                # Check severity match
                if severity in playbook.trigger_severities or '*' in playbook.trigger_severities:
                    matching.append(playbook)

        return matching

    def _in_cooldown(self, ip: str, playbook_name: str, cooldown: int) -> bool:
        """Check if IP/playbook combination is in cooldown."""
        key = f"{ip}:{playbook_name}"
        last_exec = self.cooldowns.get(key, 0)
        return time.time() - last_exec < cooldown

    def _queue_execution(self, playbook: Playbook, alert: Dict) -> PlaybookExecution:
        """Queue a playbook for execution."""
        import uuid

        execution = PlaybookExecution(
            execution_id=str(uuid.uuid4())[:8],
            playbook_name=playbook.name,
            trigger_alert=alert,
            status=PlaybookStatus.PENDING,
            started_at=time.time(),
            completed_at=None,
            steps_completed=0,
            steps_total=len(playbook.steps),
            results=[]
        )

        if self.require_approval:
            self.pending_approvals[execution.execution_id] = {
                'execution': execution,
                'playbook': playbook
            }
            self.logger.info(f"Playbook {playbook.name} queued for approval (ID: {execution.execution_id})")
        else:
            self.execution_queue.put((execution, playbook))
            self.logger.info(f"Playbook {playbook.name} queued for execution (ID: {execution.execution_id})")

        return execution

    def approve_execution(self, execution_id: str) -> bool:
        """Approve a pending execution."""
        if execution_id not in self.pending_approvals:
            return False

        pending = self.pending_approvals.pop(execution_id)
        self.execution_queue.put((pending['execution'], pending['playbook']))
        self.logger.info(f"Execution {execution_id} approved and queued")
        return True

    def reject_execution(self, execution_id: str) -> bool:
        """Reject a pending execution."""
        if execution_id not in self.pending_approvals:
            return False

        pending = self.pending_approvals.pop(execution_id)
        pending['execution'].status = PlaybookStatus.SKIPPED
        self.executions.append(pending['execution'])
        self.logger.info(f"Execution {execution_id} rejected")
        return True

    def start(self):
        """Start the SOAR worker thread."""
        if self._running:
            return

        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        self.logger.info("SOAR worker thread started")

    def stop(self):
        """Stop the SOAR worker thread."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)

    def _worker_loop(self):
        """Worker thread that executes queued playbooks."""
        while self._running:
            try:
                # Get next execution from queue (with timeout)
                try:
                    execution, playbook = self.execution_queue.get(timeout=1)
                except:
                    continue

                # Execute playbook
                self._execute_playbook(execution, playbook)

            except Exception as e:
                self.logger.error(f"SOAR worker error: {e}")

    def _execute_playbook(self, execution: PlaybookExecution, playbook: Playbook):
        """Execute a playbook."""
        execution.status = PlaybookStatus.RUNNING

        alert = execution.trigger_alert
        source_ip = alert.get('source_ip', '')

        # Update cooldown
        key = f"{source_ip}:{playbook.name}"
        self.cooldowns[key] = time.time()

        try:
            for i, step in enumerate(playbook.steps):
                step_result = self._execute_step(step, alert)
                execution.results.append(step_result)
                execution.steps_completed = i + 1

                if not step_result.get('success') and step.on_failure == 'abort':
                    execution.status = PlaybookStatus.FAILED
                    execution.error = step_result.get('error')
                    break

            if execution.status == PlaybookStatus.RUNNING:
                execution.status = PlaybookStatus.COMPLETED

        except Exception as e:
            execution.status = PlaybookStatus.FAILED
            execution.error = str(e)
            self.logger.error(f"Playbook execution failed: {e}")

        execution.completed_at = time.time()
        self.executions.append(execution)

        self.logger.info(
            f"Playbook {playbook.name} {execution.status.value}: "
            f"{execution.steps_completed}/{execution.steps_total} steps"
        )

    def _execute_step(self, step: PlaybookStep, alert: Dict) -> Dict:
        """Execute a single playbook step."""
        result = {
            'action': step.action.value,
            'success': True,
            'timestamp': time.time(),
            'dry_run': self.dry_run
        }

        try:
            if step.action == ResponseAction.LOG:
                result['details'] = self._action_log(alert, step.parameters)

            elif step.action == ResponseAction.ENRICH:
                result['details'] = self._action_enrich(alert, step.parameters)

            elif step.action == ResponseAction.NOTIFY:
                result['details'] = self._action_notify(alert, step.parameters)

            elif step.action == ResponseAction.CAPTURE:
                result['details'] = self._action_capture(alert, step.parameters)

            elif step.action == ResponseAction.BLOCK_IP:
                result['details'] = self._action_block_ip(alert, step.parameters)

            elif step.action == ResponseAction.RATE_LIMIT:
                result['details'] = self._action_rate_limit(alert, step.parameters)

            elif step.action == ResponseAction.SCRIPT:
                result['details'] = self._action_script(alert, step.parameters)

            else:
                result['details'] = {'message': f'Action {step.action.value} not implemented'}

        except Exception as e:
            result['success'] = False
            result['error'] = str(e)

        return result

    def _action_log(self, alert: Dict, params: Dict) -> Dict:
        """Log action - log the alert with context."""
        level = params.get('level', 'info')
        message = f"SOAR Alert: {alert.get('type')} from {alert.get('source_ip')}"

        if level == 'debug':
            self.logger.debug(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'error':
            self.logger.error(message)
        else:
            self.logger.info(message)

        return {'logged': True, 'level': level}

    def _action_enrich(self, alert: Dict, params: Dict) -> Dict:
        """Enrich alert with additional context."""
        enrichment = {}
        source_ip = alert.get('source_ip', '')
        destination_ip = alert.get('destination_ip', '')

        # GeoIP enrichment
        if params.get('include_geoip') and self.db:
            try:
                # This would use the GeoIP database
                enrichment['geoip'] = {
                    'source': self._get_geoip(source_ip),
                    'destination': self._get_geoip(destination_ip)
                }
            except:
                pass

        # Device info enrichment
        if params.get('include_device_info') and self.db:
            try:
                device = self.db.get_device_by_ip(source_ip)
                if device:
                    enrichment['source_device'] = {
                        'hostname': device.get('hostname'),
                        'mac': device.get('mac_address'),
                        'vendor': device.get('vendor')
                    }
            except:
                pass

        return enrichment

    def _get_geoip(self, ip: str) -> Optional[Dict]:
        """Get GeoIP info for an IP."""
        # Placeholder - would use actual GeoIP lookup
        return None

    def _action_notify(self, alert: Dict, params: Dict) -> Dict:
        """Send notification."""
        results = {'sent': []}
        channels = params.get('channels', ['webhook'])
        priority = params.get('priority', 'normal')

        # Webhook notification
        if 'webhook' in channels and self.webhook_url:
            if self._send_webhook(alert, priority):
                results['sent'].append('webhook')

        # Email notification
        if 'email' in channels and self.email_enabled:
            if self._send_email(alert, priority):
                results['sent'].append('email')

        return results

    def _send_webhook(self, alert: Dict, priority: str) -> bool:
        """Send webhook notification."""
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would send webhook for {alert.get('type')}")
            return True

        try:
            import requests
            payload = {
                'alert': alert,
                'priority': priority,
                'timestamp': time.time(),
                'source': 'netmonitor-soar'
            }
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Webhook failed: {e}")
            return False

    def _send_email(self, alert: Dict, priority: str) -> bool:
        """Send email notification."""
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would send email for {alert.get('type')}")
            return True

        # Email implementation would go here
        return False

    def _action_capture(self, alert: Dict, params: Dict) -> Dict:
        """Start packet capture for the alert."""
        duration = params.get('duration', 60)

        if self.dry_run:
            self.logger.info(f"DRY RUN: Would start {duration}s capture for {alert.get('source_ip')}")
            return {'started': False, 'dry_run': True}

        # This would trigger actual packet capture
        # For now, just log the intent
        self.logger.info(f"Would start packet capture for {duration}s")
        return {'started': True, 'duration': duration}

    def _action_block_ip(self, alert: Dict, params: Dict) -> Dict:
        """Block an IP address."""
        source_ip = alert.get('source_ip', '')
        direction = params.get('direction', 'both')
        duration = params.get('duration', 3600)

        # Check rate limit
        current_time = time.time()
        self.blocks_this_hour = deque(
            t for t in self.blocks_this_hour if current_time - t < 3600
        )

        if len(self.blocks_this_hour) >= self.max_blocks_per_hour:
            return {
                'blocked': False,
                'error': 'Max blocks per hour exceeded'
            }

        if self.dry_run:
            self.logger.warning(f"DRY RUN: Would block IP {source_ip} ({direction}) for {duration}s")
            return {'blocked': False, 'dry_run': True, 'ip': source_ip}

        # Actual blocking would be implemented here
        # Could use iptables, pf, or integrate with firewall API
        self.logger.warning(f"BLOCKING IP {source_ip} ({direction}) for {duration}s")
        self.blocks_this_hour.append(current_time)

        return {
            'blocked': True,
            'ip': source_ip,
            'direction': direction,
            'duration': duration
        }

    def _action_rate_limit(self, alert: Dict, params: Dict) -> Dict:
        """Apply rate limiting to an IP."""
        source_ip = alert.get('source_ip', '')
        limit = params.get('limit', '10/minute')
        duration = params.get('duration', 3600)

        if self.dry_run:
            self.logger.info(f"DRY RUN: Would rate limit {source_ip} to {limit}")
            return {'applied': False, 'dry_run': True}

        # Rate limiting would be implemented here
        return {
            'applied': True,
            'ip': source_ip,
            'limit': limit,
            'duration': duration
        }

    def _action_script(self, alert: Dict, params: Dict) -> Dict:
        """Run a custom script."""
        script_path = params.get('script')
        if not script_path:
            return {'executed': False, 'error': 'No script specified'}

        if self.dry_run:
            self.logger.info(f"DRY RUN: Would run script {script_path}")
            return {'executed': False, 'dry_run': True}

        try:
            result = subprocess.run(
                [script_path, json.dumps(alert)],
                capture_output=True,
                timeout=60
            )
            return {
                'executed': True,
                'return_code': result.returncode,
                'stdout': result.stdout.decode()[:500]
            }
        except Exception as e:
            return {'executed': False, 'error': str(e)}

    def get_pending_approvals(self) -> List[Dict]:
        """Get list of pending approvals."""
        return [
            {
                'execution_id': exec_id,
                'playbook': data['playbook'].name,
                'alert_type': data['execution'].trigger_alert.get('type'),
                'source_ip': data['execution'].trigger_alert.get('source_ip'),
                'queued_at': data['execution'].started_at
            }
            for exec_id, data in self.pending_approvals.items()
        ]

    def get_recent_executions(self, limit: int = 50) -> List[Dict]:
        """Get recent playbook executions."""
        return [
            {
                'execution_id': e.execution_id,
                'playbook': e.playbook_name,
                'status': e.status.value,
                'alert_type': e.trigger_alert.get('type'),
                'source_ip': e.trigger_alert.get('source_ip'),
                'started_at': e.started_at,
                'completed_at': e.completed_at,
                'steps_completed': e.steps_completed,
                'steps_total': e.steps_total,
                'error': e.error
            }
            for e in list(self.executions)[-limit:]
        ]

    def get_stats(self) -> Dict:
        """Get SOAR statistics."""
        completed = sum(1 for e in self.executions if e.status == PlaybookStatus.COMPLETED)
        failed = sum(1 for e in self.executions if e.status == PlaybookStatus.FAILED)

        return {
            'enabled': self.enabled,
            'dry_run': self.dry_run,
            'require_approval': self.require_approval,
            'playbooks_loaded': len(self.playbooks),
            'pending_approvals': len(self.pending_approvals),
            'total_executions': len(self.executions),
            'completed_executions': completed,
            'failed_executions': failed,
            'blocks_this_hour': len(self.blocks_this_hour)
        }
