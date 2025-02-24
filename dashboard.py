from flask import Flask, render_template, jsonify, request
from ai_threat_detection import ThreatDetector
from blockchain_logging import BlockchainLogger
import numpy as np
import random
import time

app = Flask(__name__)
detector = ThreatDetector()
logger = BlockchainLogger()

# Map of key features to their indices (example from CICIDS2017)
FEATURE_MAP = {
    'duration': 0,
    'protocol_type': 1,
    'total_packets': 4,
    'src_bytes': 5,
    'dst_bytes': 6,
    'wrong_fragment': 14,
    'urgent': 15
}

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/threats')
def get_threats():
    logs = logger.query_logs()
    return jsonify(logs)

@app.route('/api/detect', methods=['POST'])
def detect_threat():
    try:
        # Validate request format
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 415

        # Parse JSON input
        user_input = request.get_json()
        if not user_input:
            return jsonify({"error": "Empty JSON payload"}), 400

        # Validate required fields
        required_fields = ['duration', 'protocol_type', 'total_packets', 'src_bytes', 'dst_bytes']
        for field in required_fields:
            if field not in user_input:
                return jsonify({"error": f"Missing field: {field}"}), 400
            try:
                float(user_input[field])
            except ValueError:
                return jsonify({"error": f"Invalid value for {field}: must be numeric"}), 400

        # Create full 78-feature array
        features = np.zeros(78).tolist()
        
        # Map user inputs
        for key, value in user_input.items():
            if key in FEATURE_MAP:
                features[FEATURE_MAP[key]] = float(value)
        
        # Fill remaining features with random values
        for i in range(len(features)):
            if features[i] == 0 and i not in FEATURE_MAP.values():
                features[i] = random.random()

        # Detect threat
        is_threat, probability = detector.detect_threat(features)

        # Blockchain logging
        if is_threat:  # Now checks 1/0 instead of True/False
            logger.log_threat({
                "features": features,
                "is_threat": is_threat,  # Already an integer
                "probability": probability,
                "user_input": user_input,
                "timestamp": time.time()
            })

        return jsonify({
            "is_threat": is_threat,  # Now serializable
            "probability": probability,
            "input_features": user_input
        })

    except Exception as e:
        app.logger.error(f"Error in detect_threat: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

    
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)