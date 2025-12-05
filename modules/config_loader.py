"""
Config Loader Module
Handles loading and managing configuration settings.
"""

import json
import logging
import os


class Config:
    """Configuration manager for NetRecon"""

    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.config = {}
        self.logger = logging.getLogger(__name__)
        self.load()

    def load(self):
        """Load configuration from JSON file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                self.logger.info(f"Configuration loaded from {self.config_file}")
            else:
                self.logger.warning(f"Config file {self.config_file} not found, using defaults")
                self.config = self._get_defaults()
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing config file: {e}")
            self.config = self._get_defaults()
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            self.config = self._get_defaults()

    def save(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")

    def get(self, key, default=None):
        """
        Get configuration value using dot notation
        Example: config.get('port_scanner.timeout', 5)
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key, value):
        """
        Set configuration value using dot notation
        Example: config.set('port_scanner.timeout', 10)
        """
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def _get_defaults(self):
        """Return default configuration"""
        return {
            "application": {
                "name": "NetRecon",
                "version": "1.0.0"
            },
            "logging": {
                "log_level": "INFO",
                "log_file": "logs/netrecon.log"
            },
            "network": {
                "default_interface": "eth0",
                "timeout": 5,
                "max_threads": 100
            },
            "port_scanner": {
                "enabled": True,
                "default_ports": "1-1000",
                "scan_timeout": 1,
                "service_detection": True
            },
            "packet_analyzer": {
                "enabled": True,
                "capture_dir": "data/captures",
                "max_packets": 10000
            },
            "web_interface": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080
            }
        }

    def __getitem__(self, key):
        """Allow dict-like access"""
        return self.get(key)

    def __setitem__(self, key, value):
        """Allow dict-like assignment"""
        self.set(key, value)
