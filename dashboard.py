from flask import Flask, request, jsonify, render_template
from ai_threat_detection import ThreatDetector
from blockchain_logging import BlockchainLogger
import threading
import time

app = Flask(__name__)
detector = ThreatDetector()
logger = BlockchainLogger()

# Start background monitoring
from integration_layer import IntegrationLayer
monitor = IntegrationLayer(detector, logger)
monitor.start()

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/detect', methods=['POST'])
def detect():
    try:
        data = request.get_json()
        is_threat, confidence = detector.detect_threat(data)
        if is_threat:
            logger.log_threat(data, confidence)
        return jsonify({
            'threat': is_threat,
            'confidence': confidence,
            'features': data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/threats')
def get_threats():
    return jsonify(logger.get_logs())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)