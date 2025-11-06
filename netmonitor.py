#!/usr/bin/env python3
"""
Network Monitor - Detecteert verdacht netwerkverkeer
Geschikt voor gebruik op een monitoring/span port
"""

import sys
import signal
import argparse
import logging
from pathlib import Path

try:
    from scapy.all import sniff, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS
except ImportError:
    print("Error: scapy is niet geïnstalleerd. Installeer met: pip install -r requirements.txt")
    sys.exit(1)

from detector import ThreatDetector
from config_loader import load_config
from alerts import AlertManager


class NetworkMonitor:
    """Hoofd netwerk monitor class"""

    def __init__(self, config_file="config.yaml"):
        """Initialiseer de network monitor"""
        self.config = load_config(config_file)
        self.running = False

        # Setup logging
        self.setup_logging()

        # Initialiseer detector en alert manager
        self.detector = ThreatDetector(self.config)
        self.alert_manager = AlertManager(self.config)

        # Setup signal handlers voor graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        self.logger.info("Network Monitor geïnitialiseerd")

    def setup_logging(self):
        """Setup logging configuratie"""
        log_level = getattr(logging, self.config['logging']['level'], logging.INFO)

        # Create logger
        self.logger = logging.getLogger('NetMonitor')
        self.logger.setLevel(log_level)

        # Console handler
        if self.config['logging']['console']:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            console_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)

        # File handler
        if 'file' in self.config['logging'] and self.config['logging']['file']:
            log_file = Path(self.config['logging']['file'])
            log_file.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_format = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_format)
            self.logger.addHandler(file_handler)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Signal {signum} ontvangen, shutting down...")
        self.running = False
        sys.exit(0)

    def packet_callback(self, packet):
        """Callback functie voor elk ontvangen packet"""
        try:
            # Check of packet IP layer heeft
            if not packet.haslayer(IP):
                return

            # Analyseer packet met detector
            threats = self.detector.analyze_packet(packet)

            # Als threats gevonden, stuur alerts
            if threats:
                for threat in threats:
                    self.alert_manager.send_alert(threat, packet)

        except Exception as e:
            self.logger.error(f"Error processing packet: {e}", exc_info=True)

    def start(self):
        """Start het monitoren van netwerkverkeer"""
        interface = self.config['interface']

        self.logger.info(f"Starting network monitor op interface: {interface}")
        self.logger.info("Druk op Ctrl+C om te stoppen")

        # Check of we root privileges hebben
        if conf.L3socket == conf.L3socket6:
            self.logger.warning(
                "Mogelijk onvoldoende privileges. Run als root voor volledige functionaliteit."
            )

        self.running = True

        try:
            # Start packet sniffing
            # store=0 betekent packets niet in memory houden (belangrijk voor lange runs)
            sniff(
                iface=interface if interface != 'any' else None,
                prn=self.packet_callback,
                store=0,
                filter="ip"  # Alleen IP packets
            )
        except PermissionError:
            self.logger.error(
                "Onvoldoende privileges om packets te capturen. Run als root (sudo)."
            )
            sys.exit(1)
        except OSError as e:
            self.logger.error(f"Network interface error: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}", exc_info=True)
            sys.exit(1)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Network Monitor - Detecteert verdacht netwerkverkeer"
    )
    parser.add_argument(
        '-c', '--config',
        default='config.yaml',
        help='Pad naar configuratie file (default: config.yaml)'
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface om te monitoren (overschrijft config file)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output (DEBUG level)'
    )

    args = parser.parse_args()

    # Check of config file bestaat
    if not Path(args.config).exists():
        print(f"Error: Config file niet gevonden: {args.config}")
        sys.exit(1)

    try:
        monitor = NetworkMonitor(args.config)

        # Override interface als opgegeven via CLI
        if args.interface:
            monitor.config['interface'] = args.interface
            monitor.logger.info(f"Interface overridden naar: {args.interface}")

        # Override log level als verbose
        if args.verbose:
            monitor.logger.setLevel(logging.DEBUG)
            for handler in monitor.logger.handlers:
                handler.setLevel(logging.DEBUG)

        monitor.start()

    except KeyboardInterrupt:
        print("\nStopping network monitor...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
