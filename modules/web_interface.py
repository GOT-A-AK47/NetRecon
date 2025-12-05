"""
Web Interface Module
Flask-based web interface for interactive monitoring and control.
"""

import logging
import json
from datetime import datetime
from threading import Thread

try:
    from flask import Flask, render_template, jsonify, request
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class WebInterface:
    """Web-based dashboard and control interface"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        if not FLASK_AVAILABLE:
            self.logger.error("Flask not available. Install with: pip install flask flask-cors")
            return

        self.host = config.get('web_interface.host', '0.0.0.0')
        self.port = config.get('web_interface.port', 8080)

        # Create Flask app
        self.app = Flask(__name__,
                        template_folder='../templates',
                        static_folder='../static')
        CORS(self.app)

        # Setup routes
        self._setup_routes()

        # Shared data (will be updated by main app)
        self.data = {
            'scan_results': [],
            'packet_stats': {},
            'discovered_hosts': [],
            'status': 'idle'
        }

    def _setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            """Main dashboard"""
            return render_template('index.html')

        @self.app.route('/api/status')
        def api_status():
            """Get current status"""
            return jsonify({
                'status': 'running',
                'timestamp': datetime.now().isoformat(),
                'version': self.config.get('application.version', '1.0.0')
            })

        @self.app.route('/api/scan', methods=['POST'])
        def api_scan():
            """Start port scan"""
            data = request.get_json()
            target = data.get('target')
            ports = data.get('ports', '1-1000')

            if not target:
                return jsonify({'error': 'No target specified'}), 400

            # TODO: Trigger scan through main app
            self.logger.info(f"Scan requested: {target} ports {ports}")

            return jsonify({
                'status': 'started',
                'target': target,
                'ports': ports
            })

        @self.app.route('/api/discover', methods=['POST'])
        def api_discover():
            """Start host discovery"""
            data = request.get_json()
            network = data.get('network')

            if not network:
                return jsonify({'error': 'No network specified'}), 400

            # TODO: Trigger discovery through main app
            self.logger.info(f"Discovery requested: {network}")

            return jsonify({
                'status': 'started',
                'network': network
            })

        @self.app.route('/api/capture/start', methods=['POST'])
        def api_capture_start():
            """Start packet capture"""
            data = request.get_json()
            interface = data.get('interface', 'eth0')
            filter_str = data.get('filter', '')

            # TODO: Start capture through main app
            self.logger.info(f"Capture start requested: {interface}")

            return jsonify({
                'status': 'started',
                'interface': interface
            })

        @self.app.route('/api/capture/stop', methods=['POST'])
        def api_capture_stop():
            """Stop packet capture"""
            # TODO: Stop capture through main app
            self.logger.info("Capture stop requested")

            return jsonify({'status': 'stopped'})

        @self.app.route('/api/results/scan')
        def api_scan_results():
            """Get scan results"""
            return jsonify(self.data.get('scan_results', []))

        @self.app.route('/api/results/hosts')
        def api_discovered_hosts():
            """Get discovered hosts"""
            return jsonify(self.data.get('discovered_hosts', []))

        @self.app.route('/api/packets/stats')
        def api_packet_stats():
            """Get packet statistics"""
            return jsonify(self.data.get('packet_stats', {}))

        @self.app.route('/api/packets/summary')
        def api_packet_summary():
            """Get packet summary"""
            limit = request.args.get('limit', 100, type=int)
            # TODO: Get from packet analyzer
            return jsonify([])

        @self.app.route('/api/export/<export_type>')
        def api_export(export_type):
            """Export results"""
            format_type = request.args.get('format', 'json')

            if export_type == 'scan':
                data = self.data.get('scan_results', [])
            elif export_type == 'hosts':
                data = self.data.get('discovered_hosts', [])
            else:
                return jsonify({'error': 'Invalid export type'}), 400

            if format_type == 'json':
                return jsonify(data)
            elif format_type == 'csv':
                # TODO: Implement CSV export
                return "CSV export not yet implemented", 501
            else:
                return jsonify({'error': 'Invalid format'}), 400

    def start(self):
        """Start web server"""
        if not FLASK_AVAILABLE:
            self.logger.error("Cannot start web interface - Flask not available")
            return

        self.logger.info(f"Starting web interface on {self.host}:{self.port}")

        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False
            )
        except Exception as e:
            self.logger.error(f"Error starting web interface: {e}", exc_info=True)

    def start_background(self):
        """Start web server in background thread"""
        thread = Thread(target=self.start, daemon=True)
        thread.start()
        return thread

    def update_data(self, key: str, value):
        """
        Update shared data

        Args:
            key: Data key
            value: Data value
        """
        self.data[key] = value

    def get_data(self, key: str):
        """
        Get shared data

        Args:
            key: Data key

        Returns:
            Data value
        """
        return self.data.get(key)

    def stop(self):
        """Stop web server"""
        self.logger.info("Stopping web interface...")
        # Flask doesn't have a clean shutdown method when running directly
        # In production, use a proper WSGI server like gunicorn
