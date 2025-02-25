import random
import time
import threading

class IntegrationLayer:
    def __init__(self, detector, logger):
        self.detector = detector
        self.logger = logger
        self.running = True

    def simulate_traffic(self):
        while self.running:
            # Generate random traffic sample
            sample = {
                'Flow Duration': random.randint(0, 1000),
                'Destination Port': random.choice([80, 443, 22, 53]),
                'Total Fwd Packets': random.randint(1, 1000),
                'Total Length of Fwd Packets': random.randint(100, 10000),
                'Flow Bytes/s': random.uniform(1000, 100000)
            }
            
            is_threat, confidence = self.detector.detect_threat(sample)
            if is_threat:
                self.logger.log_threat(sample, confidence)
            
            time.sleep(1)

    def start(self):
        self.thread = threading.Thread(target=self.simulate_traffic)
        self.thread.daemon = True
        self.thread.start()