import json
import hashlib
import time

class BlockchainLogger:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.file_path = 'threat_chain.json'

    def log_threat(self, features, confidence):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'data': features,
            'confidence': confidence,
            'previous_hash': self.last_block_hash if self.chain else '0'
        }
        block['hash'] = self.hash_block(block)
        self.chain.append(block)
        self.save_chain()
        return block

    def get_logs(self, count=10):
        return self.chain[-count:]

    def hash_block(self, block):
        block_str = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_str).hexdigest()

    def save_chain(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.chain, f)

    @property
    def last_block_hash(self):
        return self.chain[-1]['hash'] if self.chain else '0'