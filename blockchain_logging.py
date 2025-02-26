import time

# A simple mock blockchain implementation
class MockBlockchain:
    def __init__(self):
        self.chain = []
        
    def add_block(self, data):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'data': data
        }
        self.chain.append(block)
        print(f"Block added: {block}")
        return block
    
    def get_chain(self):
        return self.chain

# Global blockchain instance
blockchain = MockBlockchain()

def log_event(event):
    """
    Logs an event to the blockchain.
    
    Parameters:
        event (dict): A dictionary containing event details.
    
    Returns:
        dict: The block that was added to the blockchain.
    """
    block = blockchain.add_block(event)
    return block
