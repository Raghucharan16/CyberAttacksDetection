from ai_threat_detection import predict_threat
from blockchain_logging import log_event

def process_request(input_features):
    """
    Processes a cyber request by using the AI model to detect threats and logging the event.
    
    Parameters:
        input_features (dict): Dictionary of input features.
    
    Returns:
        tuple: (threat_detected (bool), log_entry (dict))
    """
    threat_detected = predict_threat(input_features)
    
    event = {
        'event': 'Threat Detected' if threat_detected else 'No Threat',
        'details': input_features
    }
    log_entry = log_event(event)
    
    return threat_detected, log_entry
