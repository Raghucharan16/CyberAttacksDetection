from ai_threat_detection import ThreatDetector
from blockchain_logging import BlockchainLogger
import threading
import time
import random

class IntegrationLayer:
    def __init__(self):
        self.detector = ThreatDetector()
        self.logger = BlockchainLogger()
        self.running = True

    def generate_traffic_features(self):
        """Generate synthetic traffic features for testing (78 features)."""
        return [random.random() for _ in range(78)]

    def process_traffic(self):
        """Process traffic, detect threats, and log if malicious."""
        traffic_features = self.generate_traffic_features()
        is_threat, probability = self.detector.detect_threat(traffic_features)

        if is_threat:
            print(f"Blocking threat with probability: {probability:.4f}")
            threat_data = {
                "traffic_features": traffic_features,
                "is_threat": True,
                "probability": probability,
                "detection_time": time.time()
            }
            self.logger.log_threat(threat_data)
            return True, threat_data
        return False, None

    def realtime_monitoring(self):
        """Simulate real-time traffic monitoring."""
        while self.running:
            is_threat, threat_data = self.process_traffic()
            if is_threat:
                print("Threat blocked and logged.")
            time.sleep(1)  # Simulate packet delay

    def start(self):
        monitor_thread = threading.Thread(target=self.realtime_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()
        print("Real-time monitoring started...")

if __name__ == "__main__":
    integrator = IntegrationLayer()
    integrator.start()
    time.sleep(20)  # Run for 20 seconds
    integrator.running = False