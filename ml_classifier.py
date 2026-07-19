# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2025 Willem M. Poort
"""
Machine Learning Device Classifier

Provides ML-based device classification and anomaly detection:
- Automatic device type classification from traffic patterns
- Per-device baseline learning
- Anomaly detection against learned behavior
- Self-training from labeled devices

All ML runs on the SOC server only - sensors just forward traffic.
"""

import json
import logging
import os
import pickle
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
import numpy as np

from device_fingerprinter import infer_from_hostname, interpret_fingerprint

# Optional ML libraries - graceful fallback if not installed
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger('NetMonitor.MLClassifier')


def run_blocking(func, *args, **kwargs):
    """
    Run a CPU-bound/blocking function without freezing the eventlet event loop.

    Under eventlet.monkey_patch() (the gunicorn dashboard workers),
    threading.Thread is a green thread: CPU-bound sklearn work in it blocks
    the worker's entire event loop, the worker misses its gunicorn heartbeat
    and gets SIGKILLed after `timeout` seconds (WORKER TIMEOUT). tpool runs
    the call in a real OS thread so the loop keeps servicing the heartbeat.

    Outside eventlet (the netmonitor engine, CLI tools) this is a plain call.
    """
    try:
        import eventlet
        if eventlet.patcher.is_monkey_patched('thread'):
            from eventlet import tpool
            return tpool.execute(func, *args, **kwargs)
    except ImportError:
        pass
    return func(*args, **kwargs)


# Device type categories for classification
# NOTE: template_name must match actual template names in the database (case-insensitive)
DEVICE_CATEGORIES = {
    'workstation': {
        'description': 'Desktop or laptop computer',
        'template_name': 'Workstation',
        'typical_ports': {80, 443, 22, 3389, 445, 139},
        'characteristics': {'high_destinations': True, 'varied_ports': True}
    },
    'server': {
        'description': 'Server providing services',
        'template_name': 'Web Server',  # Maps to generic web server template
        'typical_ports': {22, 80, 443, 3306, 5432, 8080, 8443},
        'characteristics': {'has_listening_ports': True, 'many_inbound': True}
    },
    'iot_camera': {
        'description': 'IP Camera or surveillance device',
        'template_name': 'IP Camera',
        'typical_ports': {554, 8554, 80, 443, 8080},
        'characteristics': {'high_bandwidth': True, 'streaming': True}
    },
    'iot_sensor': {
        'description': 'IoT sensor or low-power device',
        'template_name': 'IoT Sensor',  # Needs to be created in database
        'typical_ports': {80, 443, 8883, 1883},
        'characteristics': {'low_traffic': True, 'periodic': True}
    },
    'smart_tv': {
        'description': 'Smart TV or streaming device',
        'template_name': 'Smart TV',
        'typical_ports': {80, 443, 8008, 8443, 9000},
        'characteristics': {'high_bandwidth': True, 'streaming_services': True}
    },
    'nas': {
        'description': 'Network Attached Storage',
        'template_name': 'File Server (NAS)',  # Matches database template name
        'typical_ports': {139, 445, 548, 2049, 80, 443},
        'characteristics': {'file_sharing': True, 'many_inbound': True}
    },
    'printer': {
        'description': 'Network printer or multifunction device',
        'template_name': 'Printer',
        'typical_ports': {515, 631, 9100, 80, 443},
        'characteristics': {'low_traffic': True, 'print_ports': True}
    },
    'smart_speaker': {
        'description': 'Smart speaker or voice assistant',
        'template_name': 'Smart Speaker',
        'typical_ports': {80, 443, 8008, 8443},
        'characteristics': {'cloud_dependent': True, 'periodic': True}
    },
    'mobile': {
        'description': 'Mobile device (phone/tablet)',
        'template_name': 'Mobile Device',
        'typical_ports': {80, 443, 5223, 5228},
        'characteristics': {'intermittent': True, 'varied_destinations': True}
    },
    'network_device': {
        'description': 'Router, switch, or network infrastructure',
        'template_name': 'Network Device',  # Needs to be created in database
        'typical_ports': {22, 23, 80, 443, 161, 162},
        'characteristics': {'management_ports': True, 'stable': True}
    },
    'sip_phone': {
        'description': 'VoIP/SIP telephone (deskphone or softphone)',
        'template_name': 'SIP Phone',
        'typical_ports': {5060, 5061, 10000, 20000},
        'characteristics': {'voice_traffic': True, 'periodic': True}
    },
    'smartwatch': {
        'description': 'Smartwatch or wearable',
        'template_name': 'Smartwatch',
        'typical_ports': {80, 443, 5223},
        'characteristics': {'low_traffic': True, 'intermittent': True}
    },
    'unknown': {
        'description': 'Unknown device type',
        'template_name': None,  # Don't assign template for unknown
        'typical_ports': set(),
        'characteristics': {}
    }
}


class DeviceFeatureExtractor:
    """
    Extracts numerical features from device traffic patterns for ML classification.
    """

    # Well-known port categories
    WEB_PORTS = {80, 443, 8080, 8443}
    STREAMING_PORTS = {554, 8554, 1935}  # RTSP, RTMP
    FILE_SHARING_PORTS = {139, 445, 548, 2049}  # SMB, AFP, NFS
    PRINT_PORTS = {515, 631, 9100}
    MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
    DATABASE_PORTS = {3306, 5432, 1433, 27017, 6379}
    SSH_PORTS = {22}
    IOT_PORTS = {1883, 8883}  # MQTT
    MANAGEMENT_PORTS = {22, 23, 161, 162}  # SSH, Telnet, SNMP

    def __init__(self):
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.is_fitted = False

    def extract_features(self, device_data: Dict) -> Optional[np.ndarray]:
        """
        Extract feature vector from device data.

        Args:
            device_data: Dictionary with device info and learned_behavior

        Returns:
            numpy array of features or None if insufficient data
        """
        learned = device_data.get('learned_behavior') or {}
        if isinstance(learned, str):
            try:
                learned = json.loads(learned)
            except json.JSONDecodeError:
                learned = {}

        # Get traffic summary
        traffic = learned.get('traffic_summary', {})
        ports_info = learned.get('ports', {})
        chars = learned.get('characteristics', {})

        # Skip if no traffic data
        if not traffic.get('total_packets'):
            return None

        # Extract port sets
        outbound_ports = set(ports_info.get('outbound_destination_ports', []))
        inbound_ports = set(ports_info.get('inbound_source_ports', []))
        protocols = set(ports_info.get('protocols', []))

        # Build feature vector
        features = []

        # Traffic volume features (4)
        features.append(np.log1p(traffic.get('total_packets', 0)))
        features.append(np.log1p(traffic.get('total_bytes', 0)))
        features.append(np.log1p(traffic.get('packets_per_hour', 0)))
        features.append(np.log1p(traffic.get('bytes_per_hour', 0)))

        # Connection diversity features (4)
        features.append(traffic.get('unique_outbound_destinations', 0))
        features.append(traffic.get('unique_inbound_sources', 0))
        features.append(len(outbound_ports))
        features.append(len(inbound_ports))

        # Port category features (9 - binary indicators)
        features.append(1 if outbound_ports & self.WEB_PORTS else 0)
        features.append(1 if outbound_ports & self.STREAMING_PORTS else 0)
        features.append(1 if inbound_ports & self.FILE_SHARING_PORTS else 0)
        features.append(1 if inbound_ports & self.PRINT_PORTS else 0)
        features.append(1 if outbound_ports & self.MAIL_PORTS else 0)
        features.append(1 if inbound_ports & self.DATABASE_PORTS else 0)
        features.append(1 if inbound_ports & self.SSH_PORTS else 0)
        features.append(1 if outbound_ports & self.IOT_PORTS else 0)
        features.append(1 if inbound_ports & self.MANAGEMENT_PORTS else 0)

        # Behavioral characteristics (5)
        features.append(1 if chars.get('is_server') else 0)
        features.append(1 if chars.get('is_high_bandwidth') else 0)
        features.append(1 if chars.get('is_low_frequency') else 0)
        features.append(1 if chars.get('has_many_destinations') else 0)
        features.append(1 if chars.get('has_many_sources') else 0)

        # Protocol features (3)
        features.append(1 if 6 in protocols else 0)   # TCP
        features.append(1 if 17 in protocols else 0)  # UDP
        features.append(1 if 1 in protocols else 0)   # ICMP

        # Ratios (3)
        total_packets = traffic.get('total_packets', 1)
        total_bytes = traffic.get('total_bytes', 1)
        features.append(total_bytes / max(total_packets, 1))  # Avg packet size
        out_dest = traffic.get('unique_outbound_destinations', 0)
        in_src = traffic.get('unique_inbound_sources', 0)
        features.append(out_dest / max(out_dest + in_src, 1))  # Outbound ratio
        features.append(len(inbound_ports) / max(len(outbound_ports) + len(inbound_ports), 1))  # Server ratio

        return np.array(features, dtype=np.float32)

    def extract_features_batch(self, devices: List[Dict]) -> Tuple[np.ndarray, List[int]]:
        """
        Extract features for multiple devices.

        Returns:
            Tuple of (feature_matrix, valid_indices)
        """
        features_list = []
        valid_indices = []

        for i, device in enumerate(devices):
            features = self.extract_features(device)
            if features is not None:
                features_list.append(features)
                valid_indices.append(i)

        if not features_list:
            return np.array([]), []

        return np.vstack(features_list), valid_indices

    def fit_scaler(self, features: np.ndarray):
        """Fit the feature scaler on training data."""
        if self.scaler is not None and len(features) > 0:
            self.scaler.fit(features)
            self.is_fitted = True

    def transform(self, features: np.ndarray) -> np.ndarray:
        """Apply feature scaling."""
        if self.scaler is not None and self.is_fitted:
            return self.scaler.transform(features)
        return features


class DeviceClassifier:
    """
    ML-based device type classifier.
    Uses Random Forest for device type prediction.
    """

    def __init__(self, db_manager=None, model_path: str = None):
        """
        Initialize the classifier.

        Args:
            db_manager: DatabaseManager for accessing device data
            model_path: Path to save/load model files
        """
        self.logger = logging.getLogger('NetMonitor.MLClassifier.DeviceClassifier')
        self.db = db_manager
        self.model_path = model_path or '/var/lib/netmonitor/ml_models'

        self.feature_extractor = DeviceFeatureExtractor()
        self.label_encoder = LabelEncoder() if SKLEARN_AVAILABLE else None
        self.model = None
        self.is_trained = False

        # Track classification statistics
        self.stats = {
            'devices_classified': 0,
            'classifications_by_type': defaultdict(int),
            'last_training': None,
            'training_samples': 0,
            'model_accuracy': 0.0
        }

        # Vendor to device type mapping for bootstrap training
        # NOTE: Be specific! Generic vendors like HP, Dell make many device types.
        # Only map vendors that almost exclusively make one type of device.
        self.vendor_hints = {
            # Cameras
            'hikvision': 'iot_camera',
            'dahua': 'iot_camera',
            'axis': 'iot_camera',
            'ring': 'iot_camera',
            'reolink': 'iot_camera',
            'amcrest': 'iot_camera',
            # Smart speakers
            'sonos': 'smart_speaker',
            # TVs/Streaming (only specific streaming device makers)
            'roku': 'smart_tv',
            'vizio': 'smart_tv',
            # NAS
            'synology': 'nas',
            'qnap': 'nas',
            'buffalo': 'nas',
            'asustor': 'nas',
            'seagate cloud': 'nas',
            # Printers - only specific printer-only vendors
            # NOTE: Removed 'hp' - HP Inc. makes laptops, servers, switches, not just printers
            # NOTE: Removed 'canon' - Canon also makes cameras
            'epson': 'printer',
            'brother': 'printer',
            'lexmark': 'printer',
            'zebra': 'printer',  # Zebra makes label/barcode printers
            # Network devices / Routers / Firewalls / Switches
            'cisco': 'network_device',
            'netgear': 'network_device',
            'tp-link': 'network_device',
            'ubiquiti': 'network_device',
            'mikrotik': 'network_device',
            'routerboard': 'network_device',  # MikroTik RouterBoard
            'deciso': 'network_device',  # OPNsense/pfSense firewalls
            'pfsense': 'network_device',
            'opnsense': 'network_device',
            'fortinet': 'network_device',
            'juniper': 'network_device',
            'aruba': 'network_device',
            'allied telesis': 'network_device',
            'moxa': 'network_device',  # Industrial network equipment
            'hms industrial': 'network_device',  # Industrial gateways
            'lantronix': 'network_device',  # Serial-to-ethernet
            'helmholz': 'network_device',  # Industrial ethernet
            'wilocity': 'network_device',  # Wireless networking
            # Servers / Virtualization
            # NOTE: VMware removed - VMs can be anything (web, file, db, print server)
            # Let admin assign appropriate template manually
            'hewlett packard enterprise': 'server',  # HPE makes servers (not HP Inc.)
            # Industrial / IoT sensors
            'raspberry': 'iot_sensor',
            'espressif': 'iot_sensor',
            'philips hue': 'iot_sensor',
            'siemens': 'iot_sensor',  # Industrial automation
            'precia': 'iot_sensor',  # Weighing systems
            'zenitel': 'iot_sensor',  # Intercom systems
            # VoIP phones
            'yealink': 'sip_phone',
            'grandstream': 'sip_phone',
            'tiptel': 'sip_phone',
            'snom': 'sip_phone',
            'polycom': 'sip_phone',
        }

        # Load existing model if available
        self._load_model()

    def _get_model_file_path(self) -> str:
        """Get the path to the model file."""
        os.makedirs(self.model_path, exist_ok=True)
        return os.path.join(self.model_path, 'device_classifier.pkl')

    def _load_model(self):
        """Load a previously trained model."""
        model_file = self._get_model_file_path()
        if os.path.exists(model_file):
            try:
                with open(model_file, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.model = saved_data.get('model')
                    if self.model is not None:
                        # Models pickled before v2.3.18 carry n_jobs=-1;
                        # predict_proba() reuses that and joblib parallelism
                        # deadlocks in eventlet green threads (see train()).
                        self.model.n_jobs = 1
                    self.label_encoder = saved_data.get('label_encoder')
                    self.feature_extractor.scaler = saved_data.get('scaler')
                    self.feature_extractor.is_fitted = saved_data.get('scaler_fitted', False)
                    self.stats = saved_data.get('stats', self.stats)
                    self.is_trained = True
                    self.logger.info(f"Loaded ML model from {model_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load model: {e}")

    def _save_model(self):
        """Save the trained model to disk."""
        if not self.is_trained:
            return

        model_file = self._get_model_file_path()
        try:
            with open(model_file, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'label_encoder': self.label_encoder,
                    'scaler': self.feature_extractor.scaler,
                    'scaler_fitted': self.feature_extractor.is_fitted,
                    'stats': dict(self.stats)
                }, f)
            self.logger.info(f"Saved ML model to {model_file}")
        except Exception as e:
            self.logger.error(f"Failed to save model: {e}")

    def _infer_label_from_vendor(self, vendor: str) -> Optional[str]:
        """Infer device type from vendor name."""
        if not vendor:
            return None

        vendor_lower = vendor.lower()
        for vendor_key, device_type in self.vendor_hints.items():
            if vendor_key in vendor_lower:
                return device_type
        return None

    def _infer_smartphone_platform(self, hostname: Optional[str]) -> Optional[str]:
        """
        Heuristic iOS/Android detection for devices already classified as 'mobile'.

        Uses the DHCP/mDNS hostname rather than MAC vendor OUI: phones with MAC-
        randomization (privacy mode) often report a vendor that has nothing to do
        with the actual manufacturer (e.g. an iPhone showing up as "Tuya Smart Inc."),
        while the hostname ("iPhone.local", "Galaxy-S25.local") stays descriptive.
        """
        if not hostname:
            return None

        hostname_lower = hostname.lower()

        # Other device types that share phone-like vendor/model naming
        # (smartwatches, tablets, TVs, sensors) - don't call these a smartphone.
        exclude_patterns = [
            'watch', 'tablet', 'tab-', 'ipad', 'tv', 'sensor',
            'buds', 'earbuds', 'macbook', 'imac',
        ]
        if any(p in hostname_lower for p in exclude_patterns):
            return None

        if 'iphone' in hostname_lower:
            return 'ios'

        android_patterns = [
            'galaxy', 'sm-', 'pixel', 'redmi', 'xiaomi', 'oneplus',
            'huawei', 'honor', 'oppo', 'vivo', 'realme', 'moto-',
            'motorola', 'nokia', 'xperia', 'android',
        ]
        if any(p in hostname_lower for p in android_patterns):
            return 'android'

        return None

    def _infer_tablet_platform(self, hostname: Optional[str]) -> Optional[str]:
        """
        Heuristic tablet detection for devices already classified as 'mobile',
        counterpart to _infer_smartphone_platform() for the tablet form factor.

        Returns 'ios', 'android', 'unknown' (hostname confirms a tablet but not
        which platform), or None (hostname doesn't look like a tablet at all).
        """
        if not hostname:
            return None

        hostname_lower = hostname.lower()

        exclude_patterns = ['watch', 'iphone', 'buds', 'earbuds', 'macbook', 'imac']
        if any(p in hostname_lower for p in exclude_patterns):
            return None

        if 'ipad' in hostname_lower:
            return 'ios'

        # "Tab-"/"Tab_" is an Android-only product naming convention (Samsung
        # Galaxy Tab, Lenovo Tab, etc.) - Apple never names a device "Tab", so
        # this prefix alone is a reliable Android signal without needing a
        # separate brand match.
        if 'tab-' in hostname_lower or 'tab_' in hostname_lower:
            return 'android'

        if 'galaxy tab' in hostname_lower or 'tablet' in hostname_lower:
            android_patterns = ['galaxy', 'sm-', 'lenovo', 'huawei', 'xiaomi', 'redmi', 'android']
            if any(p in hostname_lower for p in android_patterns):
                return 'android'
            return 'unknown'

        return None

    def _infer_label_from_template(self, template_name: str) -> Optional[str]:
        """Infer device type from assigned template name."""
        if not template_name:
            return None

        template_lower = template_name.lower()

        # Map template names to device categories
        mappings = {
            'camera': 'iot_camera',
            'ip camera': 'iot_camera',
            'surveillance': 'iot_camera',
            'server': 'server',
            'web server': 'server',
            'database': 'server',
            'nas': 'nas',
            'file server': 'nas',
            'storage': 'nas',
            'printer': 'printer',
            'print': 'printer',
            'workstation': 'workstation',
            'desktop': 'workstation',
            'laptop': 'workstation',
            'smart tv': 'smart_tv',
            'television': 'smart_tv',
            'streaming': 'smart_tv',
            'roku': 'smart_tv',
            'chromecast': 'smart_tv',
            'smart speaker': 'smart_speaker',
            'speaker': 'smart_speaker',
            'alexa': 'smart_speaker',
            'echo': 'smart_speaker',
            'google home': 'smart_speaker',
            'sensor': 'iot_sensor',
            'iot': 'iot_sensor',
            'p1 meter': 'iot_sensor',  # slimme-meter uitleeskastje (bv. HomeWizard P1)
            'thermostat': 'iot_sensor',
            'smart plug': 'iot_sensor',
            'smart light': 'iot_sensor',
            'home automation': 'iot_sensor',
            'power switch': 'iot_sensor',  # bv. "iOT smart power switch" - relais, geen netwerk-switch
            'smart switch/dimmer': 'iot_sensor',  # Shelly-achtige schakel-/dimmodule, geen netwerk-switch
            'dimmer': 'iot_sensor',
            'sip phone': 'sip_phone',  # eigen klasse, geen mobiele telefoon en geen generieke iot_sensor
            'smartwatch': 'smartwatch',
            'mobile': 'mobile',
            'phone': 'mobile',
            'tablet': 'mobile',
            'router': 'network_device',
            'switch': 'network_device',
            'access point': 'network_device',
            'firewall': 'network_device',
            'network device': 'network_device',
            'unifi controller': 'server',
            'dns server': 'server',
            'dhcp server': 'server',
            'pbx server': 'server',
            'remote desktop server': 'server',
            'samba server': 'server',
        }

        # Longest key first: generic substrings zoals 'server' zitten ook in
        # specifiekere templatenamen ('File Server (NAS)', 'DNS Server') en
        # wonnen in dict-volgorde van 'file server'/'nas' - waardoor bv. een
        # handmatig als NAS gelabeld device als 'server' de training in ging.
        for key, device_type in sorted(mappings.items(), key=lambda kv: -len(kv[0])):
            if key in template_lower:
                return device_type

        return None

    # Requirements enforced by both train() and get_training_readiness() -
    # keep these two in sync, they describe the same gate from two angles.
    MIN_LABELED_DEVICES = 10
    MIN_CLASSES = 4

    def _collect_labeled_devices(self) -> tuple:
        """
        Collect devices with an inferable label, from:
        1. Manually assigned templates (strongest signal)
        2. Vendor hints (weaker signal, used for bootstrap)

        Returns:
            (labeled_devices, labels) - parallel lists
        """
        devices = self.db.get_devices(include_inactive=False)
        labeled_devices = []
        labels = []

        for device in devices:
            learned = device.get('learned_behavior')
            if not learned:
                continue

            # Try to get label from template first (user-assigned)
            label = None
            template_id = device.get('template_id')
            if template_id:
                template = self.db.get_device_template_by_id(template_id)
                if template:
                    label = self._infer_label_from_template(template.get('name'))

            # Fall back to vendor inference
            if not label:
                label = self._infer_label_from_vendor(device.get('vendor'))

            if label:
                labeled_devices.append(device)
                labels.append(label)

        return labeled_devices, labels

    def get_training_readiness(self, min_samples_per_class: int = 3) -> Dict:
        """
        Check whether there's enough labeled data to train the classifier,
        without actually training. Mirrors the gate in train() so the UI can
        tell the user what to do first instead of just "training failed".
        """
        if not self.db:
            return {'ready': False, 'reason': 'Database not available', 'missing': []}

        labeled_devices, labels = self._collect_labeled_devices()

        class_counts = defaultdict(int)
        for label in labels:
            class_counts[label] += 1

        valid_labels = {lbl for lbl, count in class_counts.items() if count >= min_samples_per_class}
        ready = len(labeled_devices) >= self.MIN_LABELED_DEVICES and len(valid_labels) >= self.MIN_CLASSES

        missing = []
        if len(labeled_devices) < self.MIN_LABELED_DEVICES:
            missing.append(
                f"Wijs bij nog {self.MIN_LABELED_DEVICES - len(labeled_devices)} apparaten handmatig "
                f"een device-template toe, of wacht tot vendor-herkenning meer apparaten labelt "
                f"(nu {len(labeled_devices)} van de {self.MIN_LABELED_DEVICES} benodigde gelabelde apparaten)."
            )
        if len(valid_labels) < self.MIN_CLASSES:
            covered = ', '.join(sorted(valid_labels)) if valid_labels else 'geen'
            missing.append(
                f"Zorg voor meer diversiteit: nog {self.MIN_CLASSES - len(valid_labels)} device-typen nodig "
                f"met elk minstens {min_samples_per_class} apparaten (nu {len(valid_labels)} van de "
                f"{self.MIN_CLASSES} benodigde typen gedekt: {covered})."
            )

        return {
            'ready': ready,
            'labeled_devices': len(labeled_devices),
            'min_labeled_devices': self.MIN_LABELED_DEVICES,
            'class_distribution': dict(class_counts),
            'valid_classes': len(valid_labels),
            'min_classes': self.MIN_CLASSES,
            'min_samples_per_class': min_samples_per_class,
            'missing': missing,
        }

    def train(self, min_samples_per_class: int = 3) -> Dict:
        """
        Train the classifier on labeled device data.

        Uses devices with:
        1. Manually assigned templates (strongest signal)
        2. Vendor hints (weaker signal, used for bootstrap)

        Args:
            min_samples_per_class: Minimum samples needed per device type

        Returns:
            Training results dictionary
        """
        if not SKLEARN_AVAILABLE:
            return {'success': False, 'error': 'scikit-learn not installed'}

        if not self.db:
            return {'success': False, 'error': 'Database not available'}

        self.logger.info("Starting ML classifier training...")

        labeled_devices, labels = self._collect_labeled_devices()

        if len(labeled_devices) < self.MIN_LABELED_DEVICES:
            return {
                'success': False,
                'error': f'Insufficient labeled data ({len(labeled_devices)} devices, need at least {self.MIN_LABELED_DEVICES})',
                'devices_found': len(labeled_devices)
            }

        self.logger.info(f"Found {len(labeled_devices)} labeled devices for training")

        # Extract features
        X, valid_indices = self.feature_extractor.extract_features_batch(labeled_devices)
        y = [labels[i] for i in valid_indices]

        if len(X) < 10:
            return {
                'success': False,
                'error': f'Insufficient feature data ({len(X)} valid samples)',
                'devices_found': len(labeled_devices)
            }

        # Check class distribution
        class_counts = defaultdict(int)
        for label in y:
            class_counts[label] += 1

        # Filter classes with too few samples
        valid_labels = {lbl for lbl, count in class_counts.items() if count >= min_samples_per_class}
        # A RandomForestClassifier can only ever output a probability across the
        # classes it was actually trained on - it has no way to say "none of the
        # above". With only 2 classes (e.g. the first two categories to reach
        # min_samples_per_class organically, typically smart_speaker/iot_sensor
        # from vendor-hint-derived seed labels), every device gets forced into
        # whichever of those 2 it's marginally less dissimilar to, often with a
        # deceptively high confidence - a server, firewall, laptop or tablet has
        # been observed getting auto-assigned "Smart Speaker"/"IoT Sensor" at
        # 80-95% confidence this way. Requiring a broader minimum spread of
        # classes before the model is considered usable doesn't fully solve the
        # "unknown category" problem (still a forced choice among known classes),
        # but avoids the degenerate 2-class case where that forced choice is
        # essentially a coin flip dressed up as high confidence.
        if len(valid_labels) < self.MIN_CLASSES:
            return {
                'success': False,
                'error': (
                    f'Need at least {self.MIN_CLASSES} device types with {min_samples_per_class}+ '
                    f'samples each (have {len(valid_labels)}) - a model trained on too few '
                    f'categories forces every device into whichever known category it is '
                    f'marginally closest to, regardless of fit'
                ),
                'class_distribution': dict(class_counts)
            }

        # Filter to valid classes
        mask = [lbl in valid_labels for lbl in y]
        X_filtered = X[mask]
        y_filtered = [lbl for lbl, valid in zip(y, mask) if valid]

        self.logger.info(f"Training with {len(X_filtered)} samples, {len(valid_labels)} classes")

        # Fit scaler
        self.feature_extractor.fit_scaler(X_filtered)
        X_scaled = self.feature_extractor.transform(X_filtered)

        # Encode labels
        self.label_encoder.fit(list(valid_labels))
        y_encoded = self.label_encoder.transform(y_filtered)

        # Split for validation if we have enough data
        if len(X_scaled) >= 20:
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
            )
        else:
            X_train, y_train = X_scaled, y_encoded
            X_test, y_test = X_scaled, y_encoded

        # Train Random Forest.
        # n_jobs=1: the estimator's n_jobs is also used by predict_proba(),
        # which runs in eventlet green threads (classify endpoints/engine);
        # joblib's thread pool deadlocks on monkey-patched locks there. At
        # this data size (tens of samples) parallelism buys nothing anyway.
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42,
            n_jobs=1
        )
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        self.is_trained = True
        self.stats['last_training'] = datetime.now().isoformat()
        self.stats['training_samples'] = len(X_filtered)
        self.stats['model_accuracy'] = round(accuracy, 4)

        # Save model
        self._save_model()

        self.logger.info(f"Training complete. Accuracy: {accuracy:.2%}")

        return {
            'success': True,
            'samples': len(X_filtered),
            'classes': len(valid_labels),
            'class_distribution': dict(class_counts),
            'accuracy': round(accuracy, 4),
            'message': f'Model trained successfully on {len(X_filtered)} devices'
        }

    def classify(self, device: Dict) -> Dict:
        """
        Classify a single device.

        Args:
            device: Device dictionary with learned_behavior

        Returns:
            Classification result with device_type, confidence, and reasoning
        """
        result = {
            'device_type': 'unknown',
            'confidence': 0.0,
            'method': 'none',
            'template_name': None,
            'all_probabilities': {},
            'reasoning': []
        }

        # Try ML classification first
        if self.is_trained and SKLEARN_AVAILABLE:
            features = self.feature_extractor.extract_features(device)
            if features is not None:
                try:
                    X = self.feature_extractor.transform(features.reshape(1, -1))
                    probabilities = self.model.predict_proba(X)[0]
                    predicted_idx = np.argmax(probabilities)
                    confidence = probabilities[predicted_idx]

                    device_type = self.label_encoder.inverse_transform([predicted_idx])[0]

                    result['device_type'] = device_type
                    result['confidence'] = round(float(confidence), 3)
                    result['method'] = 'ml_classifier'

                    # Include all probabilities
                    for i, prob in enumerate(probabilities):
                        class_name = self.label_encoder.inverse_transform([i])[0]
                        result['all_probabilities'][class_name] = round(float(prob), 3)

                    result['reasoning'].append(f'ML classifier confidence: {confidence:.1%}')

                except Exception as e:
                    self.logger.debug(f"ML classification failed: {e}")

        # Identity evidence outranks the behavioral model. The ML classifier
        # judges *behavior*, and with a skewed training set it will happily
        # call a tablet an "iot_sensor" at 0.95 - but a probed model string
        # ("Sonos Play:3", mDNS model=iPad13,4) or an explicit hostname
        # ("Tab-A8-van-Willem") is the device stating its own identity.
        # Fingerprint (actively probed, not user-editable) beats hostname.
        fingerprint_identity = interpret_fingerprint(device.get('fingerprint'))
        hostname_identity = infer_from_hostname(device.get('hostname'))
        identity = fingerprint_identity or hostname_identity
        # Fingerprint wins, but when it identifies only the *category* while
        # the hostname pattern agrees on the type AND names a more specific
        # template (e.g. mDNS says "a Shelly", hostname "shsw-..." says
        # switch/dimmer), borrow the hostname's template.
        if (fingerprint_identity and hostname_identity
                and not fingerprint_identity.get('template_name')
                and hostname_identity.get('template_name')
                and hostname_identity['device_type'] == fingerprint_identity['device_type']):
            identity = dict(fingerprint_identity)
            identity['template_name'] = hostname_identity['template_name']
            identity['reason'] += f"; {hostname_identity['reason']}"
        if identity:
            if identity['device_type'] == result['device_type']:
                # Agreement: keep ML method, boost confidence, and take the
                # more specific template (e.g. "Tablet (Android)" instead of
                # the category default "Mobile Device").
                result['confidence'] = round(
                    min(max(result['confidence'], identity['confidence']) + 0.05, 0.99), 3)
                result['reasoning'].append(f"Identity evidence confirms: {identity['reason']}")
            else:
                if result['confidence'] > 0:
                    result['reasoning'].append(
                        f"ML suggested {result['device_type']} "
                        f"({result['confidence']:.0%}) but identity evidence wins")
                result['device_type'] = identity['device_type']
                result['confidence'] = identity['confidence']
                result['method'] = identity['source']
                result['reasoning'].append(identity['reason'])
            if identity.get('template_name'):
                result['template_name'] = identity['template_name']

        # Fall back to vendor hints if ML didn't work or confidence is low
        if result['confidence'] < 0.5:
            vendor_type = self._infer_label_from_vendor(device.get('vendor'))
            if vendor_type:
                # Blend with ML result if available
                if result['confidence'] > 0:
                    if vendor_type == result['device_type']:
                        result['confidence'] = min(result['confidence'] + 0.2, 1.0)
                        result['reasoning'].append(f'Vendor hint confirms: {device.get("vendor")}')
                    else:
                        result['reasoning'].append(f'Vendor suggests different type: {vendor_type}')
                else:
                    result['device_type'] = vendor_type
                    result['confidence'] = 0.6
                    result['method'] = 'vendor_hint'
                    result['reasoning'].append(f'Based on vendor: {device.get("vendor")}')

        # Update statistics
        if result['device_type'] != 'unknown':
            self.stats['devices_classified'] += 1
            self.stats['classifications_by_type'][result['device_type']] += 1

        return result

    def classify_all_devices(self, update_db: bool = False) -> Dict:
        """
        Classify all devices in the database.

        Args:
            update_db: Whether to update device records with classifications
                       This now also assigns templates based on device type.

        Returns:
            Summary of classification results
        """
        if not self.db:
            return {'success': False, 'error': 'Database not available'}

        devices = self.db.get_devices(include_inactive=False)
        results = {
            'total': len(devices),
            'classified': 0,
            'unknown': 0,
            'updated': 0,
            'templates_assigned': 0,
            'by_type': defaultdict(int),
            'devices': []
        }

        # Cache template lookups to avoid repeated DB queries
        template_cache = {}

        for device in devices:
            classification = self.classify(device)

            device_result = {
                'ip_address': device.get('ip_address'),
                'device_type': classification['device_type'],
                'confidence': classification['confidence'],
                'method': classification['method']
            }
            # Only include first 100 devices in response to avoid huge payloads
            if len(results['devices']) < 100:
                results['devices'].append(device_result)

            if classification['device_type'] != 'unknown':
                results['classified'] += 1
                results['by_type'][classification['device_type']] += 1

                # Update database if requested.
                # SKIP devices with manual classification to preserve user choices.
                #
                # Two different actions, two different confidence bars:
                # - Recording classification_method/classification_confidence is just
                #   metadata for the "suggested classification" UI - low risk, so it's
                #   written for every non-'unknown' result. The vendor_hint fallback
                #   (the only method that can ever fire before a model is trained,
                #   see classify()) is capped at 0.6 confidence by design; gating this
                #   write at >=0.7 meant vendor-hint suggestions were computed but
                #   never persisted, so nothing ever showed up as "suggested" even
                #   though get_learning_status() reported the device as ready.
                # - Auto-assigning a template changes device behavior, so that stays
                #   gated behind a real confidence bar (>=0.7).
                if update_db:
                    existing_method = device.get('classification_method')
                    existing_template = device.get('template_id')

                    if existing_method != 'manual':
                        try:
                            # Look up the template for the classified type
                            # regardless of confidence: at >=0.7 it gets
                            # auto-assigned, below that it's persisted as
                            # suggested_template_id so the dashboard can show
                            # "Suggested: X" with a confirm button. Without
                            # the below-threshold lookup, the suggestion had
                            # no template to point at and stayed invisible.
                            template_id = None
                            device_type = classification['device_type']
                            # Identity evidence (fingerprint/hostname) may carry
                            # an explicit, more specific template; otherwise fall
                            # back to the category default.
                            template_name = (classification.get('template_name')
                                             or DEVICE_CATEGORIES.get(device_type, {}).get('template_name'))

                            # Refine generic "mobile" into a platform-specific
                            # smartphone/tablet template when the hostname gives
                            # it away. Tablet check goes first since a "Tab-"/
                            # "iPad" hostname is a form-factor signal that the
                            # phone heuristic already excludes. Skipped when
                            # identity evidence already picked a template.
                            if device_type == 'mobile' and not classification.get('template_name'):
                                result_reasoning = classification.setdefault('reasoning', [])
                                tablet_platform = self._infer_tablet_platform(device.get('hostname'))
                                if tablet_platform == 'ios':
                                    template_name = 'Tablet (iOS)'
                                    result_reasoning.append("Hostname suggests iPad")
                                elif tablet_platform == 'android':
                                    template_name = 'Tablet (Android)'
                                    result_reasoning.append("Hostname suggests Android tablet ('Tab-' pattern)")
                                elif tablet_platform == 'unknown':
                                    template_name = 'Tablet (overig)'
                                    result_reasoning.append("Hostname suggests a tablet, platform unclear")
                                else:
                                    platform = self._infer_smartphone_platform(device.get('hostname'))
                                    if platform == 'ios':
                                        template_name = 'Smartphone (iOS)'
                                        result_reasoning.append("Hostname suggests iOS ('iPhone' pattern)")
                                    elif platform == 'android':
                                        template_name = 'Smartphone (Android)'
                                        result_reasoning.append("Hostname suggests Android (model-name pattern)")

                            if template_name:
                                # Check cache first
                                if template_name not in template_cache:
                                    template = self.db.get_device_template_by_name(template_name)
                                    template_cache[template_name] = template.get('id') if template else None
                                template_id = template_cache.get(template_name)

                            auto_assign = classification['confidence'] >= 0.7

                            if auto_assign and template_id and (not existing_template or existing_template != template_id):
                                # Assign the template along with classification
                                self.db.assign_template_to_device(
                                    device_id=device['id'],
                                    template_id=template_id,
                                    method=classification['method'],
                                    confidence=classification['confidence']
                                )
                                results['templates_assigned'] += 1
                                results['updated'] += 1
                                self.logger.debug(
                                    f"Assigned template '{template_name}' to {device.get('ip_address')} "
                                    f"(confidence: {classification['confidence']:.1%})"
                                )
                            else:
                                # Update classification metadata. Record the
                                # template as a suggestion only when it isn't
                                # already the device's assigned template.
                                suggested_id = None
                                if template_id and existing_template != template_id:
                                    suggested_id = template_id
                                self.db.update_device_classification(
                                    device_id=device['id'],
                                    classification_method=classification['method'],
                                    classification_confidence=classification['confidence'],
                                    suggested_template_id=suggested_id
                                )
                                results['updated'] += 1
                        except Exception as e:
                            self.logger.debug(f"Failed to update device classification: {e}")
                    else:
                        self.logger.debug(f"Skipping device {device.get('ip_address')} - manual classification preserved")
            else:
                results['unknown'] += 1

        # Convert defaultdict to regular dict for JSON serialization
        results['by_type'] = dict(results['by_type'])
        results['devices_truncated'] = len(devices) > 100
        return results

    def get_status(self) -> Dict:
        """Get classifier status and statistics."""
        return {
            'sklearn_available': SKLEARN_AVAILABLE,
            'is_trained': self.is_trained,
            'model_path': self._get_model_file_path(),
            'statistics': dict(self.stats),
            'device_categories': list(DEVICE_CATEGORIES.keys())
        }


class AnomalyDetector:
    """
    Detects anomalous behavior based on learned device baselines.
    Uses Isolation Forest for unsupervised anomaly detection.

    STATUS (2026-07-19): update_baseline() is not called anywhere, so
    device_models never gets populated and detect_anomaly() only ever
    reaches the global-model/none path. Per-device anomaly detection
    for "deviation from this device's own normal behavior" was instead
    built as an explicit, interpretable rule-based check in
    baseline_detector.py (BaselineDeviationDetector - new destination/
    port/protocol, volume spike vs. this device's own learned_behavior),
    wired into detector.py. That was a deliberate choice over wiring up
    this class: this class only yields an opaque anomaly score, not a
    reason, and the intended input (DeviceFeatureExtractor.extract_features()
    via learned_behavior) is a set of CUMULATIVE all-time counters
    (total_packets/total_bytes only grow). Feeding successive snapshots
    of that into update_baseline() would train the IsolationForest on a
    monotonic trend rather than real behavioral variance, so it wouldn't
    produce a meaningful baseline as-is.

    To make this useful later (e.g. as a supplementary confidence score
    alongside baseline_detector.py's alerts, or to catch deviations the
    explicit rules miss), extract_features() would first need a WINDOWED
    variant (e.g. "last 24h" instead of "since first_seen") - most likely
    via a new method in device_discovery.py alongside generate_learned_behavior().
    Only then would periodically calling update_baseline(device_id, features)
    (e.g. from the same 5-min cycle that refreshes learned_behavior) produce
    a baseline that reflects actual behavioral spread instead of a trend line.
    """

    def __init__(self, db_manager=None, contamination: float = 0.1):
        """
        Initialize anomaly detector.

        Args:
            db_manager: DatabaseManager for device data
            contamination: Expected proportion of anomalies (0.0-0.5)
        """
        self.logger = logging.getLogger('NetMonitor.MLClassifier.AnomalyDetector')
        self.db = db_manager
        self.contamination = contamination

        self.feature_extractor = DeviceFeatureExtractor()

        # Per-device baseline models
        # Key: device_id -> IsolationForest model
        self.device_models: Dict[int, object] = {}

        # Global model for devices without individual baselines
        self.global_model = None
        self.global_model_fitted = False

        # Baseline data storage
        # Key: device_id -> list of historical feature vectors
        self.baseline_data: Dict[int, List[np.ndarray]] = defaultdict(list)

        # Configuration
        self.min_baseline_samples = 10  # Minimum observations for baseline
        self.max_baseline_samples = 1000  # Maximum samples to keep

        # Statistics
        self.stats = {
            'anomalies_detected': 0,
            'devices_with_baselines': 0,
            'last_global_training': None
        }

    def update_baseline(self, device_id: int, features: np.ndarray):
        """
        Add observation to device baseline.

        Args:
            device_id: Device ID
            features: Feature vector from current observation
        """
        if features is None:
            return

        baseline = self.baseline_data[device_id]
        baseline.append(features)

        # Trim old samples if needed
        if len(baseline) > self.max_baseline_samples:
            self.baseline_data[device_id] = baseline[-self.max_baseline_samples:]

        # Retrain individual model if we have enough samples
        if len(baseline) >= self.min_baseline_samples:
            self._train_device_model(device_id)

    def _train_device_model(self, device_id: int):
        """Train anomaly detection model for a specific device."""
        if not SKLEARN_AVAILABLE:
            return

        baseline = self.baseline_data.get(device_id)
        if not baseline or len(baseline) < self.min_baseline_samples:
            return

        try:
            X = np.vstack(baseline)
            model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=50
            )
            model.fit(X)
            self.device_models[device_id] = model
            self.stats['devices_with_baselines'] = len(self.device_models)
        except Exception as e:
            self.logger.debug(f"Failed to train model for device {device_id}: {e}")

    def train_global_model(self) -> Dict:
        """
        Train global anomaly detection model from all device data.

        Returns:
            Training result summary
        """
        if not SKLEARN_AVAILABLE:
            return {'success': False, 'error': 'scikit-learn not installed'}

        if not self.db:
            return {'success': False, 'error': 'Database not available'}

        devices = self.db.get_devices(include_inactive=False)
        X, _ = self.feature_extractor.extract_features_batch(devices)

        if len(X) < 20:
            return {
                'success': False,
                'error': f'Insufficient data ({len(X)} devices, need 20+)'
            }

        try:
            self.feature_extractor.fit_scaler(X)
            X_scaled = self.feature_extractor.transform(X)

            self.global_model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100
            )
            self.global_model.fit(X_scaled)
            self.global_model_fitted = True
            self.stats['last_global_training'] = datetime.now().isoformat()

            self.logger.info(f"Global anomaly model trained on {len(X)} devices")

            return {
                'success': True,
                'samples': len(X),
                'message': 'Global anomaly detection model trained'
            }

        except Exception as e:
            self.logger.error(f"Failed to train global model: {e}")
            return {'success': False, 'error': str(e)}

    def detect_anomaly(self, device: Dict) -> Dict:
        """
        Check if device behavior is anomalous.

        Args:
            device: Device dictionary with learned_behavior

        Returns:
            Anomaly detection result
        """
        result = {
            'is_anomalous': False,
            'anomaly_score': 0.0,
            'method': 'none',
            'details': []
        }

        if not SKLEARN_AVAILABLE:
            return result

        features = self.feature_extractor.extract_features(device)
        if features is None:
            return result

        device_id = device.get('id')

        # Try device-specific model first
        if device_id and device_id in self.device_models:
            model = self.device_models[device_id]
            try:
                score = model.decision_function(features.reshape(1, -1))[0]
                prediction = model.predict(features.reshape(1, -1))[0]

                result['anomaly_score'] = round(float(-score), 3)  # Higher = more anomalous
                result['is_anomalous'] = prediction == -1
                result['method'] = 'device_baseline'
                result['details'].append(f'Device-specific model score: {-score:.3f}')

            except Exception as e:
                self.logger.debug(f"Device model prediction failed: {e}")

        # Fall back to global model
        elif self.global_model_fitted:
            try:
                X_scaled = self.feature_extractor.transform(features.reshape(1, -1))
                score = self.global_model.decision_function(X_scaled)[0]
                prediction = self.global_model.predict(X_scaled)[0]

                result['anomaly_score'] = round(float(-score), 3)
                result['is_anomalous'] = prediction == -1
                result['method'] = 'global_model'
                result['details'].append(f'Global model score: {-score:.3f}')

            except Exception as e:
                self.logger.debug(f"Global model prediction failed: {e}")

        if result['is_anomalous']:
            self.stats['anomalies_detected'] += 1

        return result

    def get_status(self) -> Dict:
        """Get anomaly detector status."""
        return {
            'sklearn_available': SKLEARN_AVAILABLE,
            'global_model_fitted': self.global_model_fitted,
            'devices_with_baselines': len(self.device_models),
            'min_baseline_samples': self.min_baseline_samples,
            'contamination': self.contamination,
            'statistics': dict(self.stats)
        }


class MLClassifierManager:
    """
    Main manager for all ML classification and anomaly detection.
    Coordinates training, inference, and integration with NetMonitor.
    """

    def __init__(self, db_manager=None, config: dict = None):
        """
        Initialize ML Classifier Manager.

        Args:
            db_manager: DatabaseManager instance
            config: Configuration dictionary
        """
        self.logger = logging.getLogger('NetMonitor.MLClassifierManager')
        self.db = db_manager
        self.config = config or {}

        # Initialize components
        self.classifier = DeviceClassifier(db_manager=db_manager)
        self.anomaly_detector = AnomalyDetector(db_manager=db_manager)

        from device_fingerprinter import DeviceFingerprinter
        self.fingerprinter = DeviceFingerprinter(config=self.config)

        # Background training configuration
        self.auto_train_interval = self.config.get('ml', {}).get(
            'auto_train_interval', 86400  # 24 hours
        )
        self._running = False
        self._bg_thread = None

        self.logger.info(f"ML Classifier Manager initialized (sklearn available: {SKLEARN_AVAILABLE})")

    def start_background_training(self):
        """Start background thread for periodic training."""
        if self._running:
            return

        self._running = True
        self._bg_thread = threading.Thread(target=self._background_trainer, daemon=True)
        self._bg_thread.start()
        self.logger.info("Started background ML training thread")

    def _background_trainer(self):
        """Background thread for periodic model training."""
        # Initial delay before first training
        time.sleep(300)  # 5 minutes

        while self._running:
            # Every gunicorn worker starts this thread, so claim the cycle
            # via the DB-backed task slot: exactly one process runs it, the
            # rest skip and wait for the next interval. Before this, all
            # workers trained simultaneously five minutes after every
            # (re)start, saturating the CPU and getting each other killed
            # on the gunicorn heartbeat (WORKER TIMEOUT).
            claimed = self.db.try_start_background_task('ml_scheduled_train') if self.db else True
            if not claimed:
                self.logger.debug("Scheduled ML training already running in another worker, skipping cycle")
                time.sleep(self.auto_train_interval)
                continue

            try:
                # Train classifier
                self.logger.info("Starting scheduled ML training...")
                result = run_blocking(self.classifier.train)
                if result.get('success'):
                    self.logger.info(f"Classifier training complete: {result.get('message')}")
                else:
                    self.logger.warning(f"Classifier training failed: {result.get('error')}")

                # Auto-classify all devices and update database. This runs
                # regardless of whether train() succeeded: classify() falls
                # back to vendor-hint matching when no model is trained yet
                # (see DeviceClassifier.classify()), so useful "suggested
                # classification" data can still be persisted long before
                # there's enough labeled data to train a model - which,
                # without this, would never happen since bootstrap labels
                # for train() come from vendor hints/templates in the first
                # place.
                # Refresh fingerprint evidence before classifying, so the
                # classification below sees current identity data. Plain call
                # (no run_blocking): pure network I/O, green-thread safe.
                if self.config.get('fingerprinting', {}).get('active_polling', True):
                    try:
                        self.run_fingerprint_scan()
                    except Exception as e:
                        self.logger.warning(f"Scheduled fingerprint scan failed: {e}")

                auto_classify = self.config.get('ml', {}).get('auto_classify', True)
                if auto_classify:
                    classify_result = run_blocking(self.classifier.classify_all_devices, update_db=True)
                    self.logger.info(
                        f"Auto-classification complete: {classify_result.get('classified')} classified, "
                        f"{classify_result.get('updated')} updated in database"
                    )

                # Train anomaly detector
                result = run_blocking(self.anomaly_detector.train_global_model)
                if result.get('success'):
                    self.logger.info(f"Anomaly detector training complete")
                else:
                    self.logger.warning(f"Anomaly detector training failed: {result.get('error')}")

                if self.db:
                    self.db.complete_background_task('ml_scheduled_train', {'success': True})
            except Exception as e:
                self.logger.error(f"Error in background training: {e}")
                if self.db:
                    self.db.fail_background_task('ml_scheduled_train', str(e))

            # Wait for next training cycle
            time.sleep(self.auto_train_interval)

    def run_fingerprint_scan(self) -> Dict:
        """
        Actively fingerprint all active devices and persist the evidence.

        Network I/O only (small UDP probes + one HTTP GET per SSDP device),
        so unlike train/classify this is safe to run directly in an eventlet
        green thread - monkey-patched sockets yield to the event loop.
        """
        if not self.db:
            return {'success': False, 'error': 'Database not available'}

        devices = self.db.get_devices(include_inactive=False)
        ip_to_device = {}
        for device in devices:
            ip = (device.get('ip_address') or '').split('/')[0]
            if ip:
                ip_to_device[ip] = device

        scan_results = self.fingerprinter.scan(list(ip_to_device.keys()))

        stored = 0
        identified = 0
        from device_fingerprinter import interpret_fingerprint as _interpret
        for ip, fingerprint in scan_results.items():
            device = ip_to_device.get(ip)
            if not device:
                continue
            if self.db.update_device_fingerprint(device['id'], fingerprint):
                stored += 1
                if _interpret(fingerprint):
                    identified += 1

        result = {
            'success': True,
            'scanned': len(ip_to_device),
            'responses': stored,
            'identified': identified
        }
        self.logger.info(
            f"Fingerprint scan complete: {stored}/{len(ip_to_device)} devices "
            f"returned evidence, {identified} conclusively identified"
        )
        return result

    def classify_device(self, device: Dict) -> Dict:
        """
        Classify a device and check for anomalies.

        Args:
            device: Device dictionary

        Returns:
            Combined classification and anomaly results
        """
        classification = self.classifier.classify(device)
        anomaly = self.anomaly_detector.detect_anomaly(device)

        return {
            'classification': classification,
            'anomaly': anomaly,
            'device_type': classification['device_type'],
            'confidence': classification['confidence'],
            'is_anomalous': anomaly['is_anomalous'],
            'anomaly_score': anomaly['anomaly_score']
        }

    def get_training_readiness(self) -> Dict:
        """Check whether there's enough labeled data to train the classifier."""
        return self.classifier.get_training_readiness()

    def train_models(self) -> Dict:
        """
        Train all ML models.

        Returns:
            Combined training results
        """
        classifier_result = self.classifier.train()
        anomaly_result = self.anomaly_detector.train_global_model()

        return {
            'classifier': classifier_result,
            'anomaly_detector': anomaly_result,
            'success': classifier_result.get('success', False) or anomaly_result.get('success', False)
        }

    def get_status(self) -> Dict:
        """Get combined status of all ML components."""
        return {
            'sklearn_available': SKLEARN_AVAILABLE,
            'classifier': self.classifier.get_status(),
            'anomaly_detector': self.anomaly_detector.get_status(),
            'background_training': {
                'enabled': self._running,
                'interval_seconds': self.auto_train_interval
            }
        }

    def shutdown(self):
        """Shutdown the ML manager."""
        self._running = False
        self.logger.info("ML Classifier Manager shutdown")
