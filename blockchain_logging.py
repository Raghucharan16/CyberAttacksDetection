import hashlib
import json
import time

class BlockchainLogger:
    def __init__(self):
        # Mock blockchain for simplicity
        print("Using mock blockchain logging (Hyperledger Fabric optional).")
        self.storage = 'threat_logs.json'

    def generate_hash(self, data):
        """Generate SHA-256 hash for data integrity."""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()

    def log_threat(self, threat_data):
        """Log threat data to mock blockchain."""
        timestamp = time.time()
        threat_data['timestamp'] = timestamp
        threat_data['hash'] = self.generate_hash(threat_data)

        with open(self.storage, 'a') as f:
            f.write(json.dumps(threat_data) + '\n')
        print(f"Threat logged: {threat_data}")
        return threat_data

    def query_logs(self):
        """Query recent logs from mock blockchain."""
        try:
            with open(self.storage, 'r') as f:
                logs = [json.loads(line) for line in f]
            return logs[-10:]  # Return last 10 logs
        except FileNotFoundError:
            return []

if __name__ == "__main__":
    logger = BlockchainLogger()
    threat = {"traffic_features": [0.1] * 78, "is_threat": True, "probability": 0.95}
    logger.log_threat(threat)