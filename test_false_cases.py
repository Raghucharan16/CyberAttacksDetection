import pandas as pd
import numpy as np
from ai_threat_detection import ThreatDetector

def generate_false_data():
    # Generate synthetic data with incorrect values
    data = {
        'Flow Duration': [np.nan, -1, 9999999999, 'invalid', 0],
        'Destination Port': [np.nan, -1, 9999999999, 'invalid', 0],
        'Total Fwd Packets': [np.nan, -1, 9999999999, 'invalid', 0],
        'Total Length of Fwd Packets': [np.nan, -1, 9999999999, 'invalid', 0],
        'Flow Bytes/s': [np.nan, -1, 9999999999, 'invalid', 0],
        'Label': [0, 1, 0, 1, 0]
    }
    df = pd.DataFrame(data)
    return df

def test_false_cases():
    detector = ThreatDetector()
    false_data = generate_false_data()
    
    # Sanitize data: convert columns to numeric and drop rows with non-numeric values
    for col in detector.feature_names:
        false_data[col] = pd.to_numeric(false_data[col], errors='coerce')
    false_data = false_data.dropna(subset=detector.feature_names)
    
    try:
        X = false_data[detector.feature_names]
        X_scaled = detector.scaler.transform(X)
        predictions = detector.model.predict(X_scaled)
        print("Predictions on false data:", predictions)
    except Exception as e:
        print("Error during prediction:", str(e))

if __name__ == "__main__":
    test_false_cases()
