import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from pathlib import Path

class ThreatDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = [
            'Flow Duration',
            'Destination Port',
            'Total Fwd Packets',
            'Total Length of Fwd Packets',
            'Flow Bytes/s'
        ]
        self.load_or_train_model()

    def load_or_train_model(self):
        try:
            self.model = joblib.load('model.pkl')
            self.scaler = joblib.load('scaler.pkl')
            print("Loaded pre-trained model")
        except FileNotFoundError:
            print("Training new model...")
            self.train_model()

    def train_model(self):
        try:
            # Load data with proper encoding
            data = pd.read_csv('datasets/CICIDS2017.csv', encoding='ISO-8859-1')
            data.columns = data.columns.str.strip()
            
            print("\n=== Raw Data ===")
            print(f"Initial rows: {len(data)}")
            print("Label counts:\n", data['Label'].value_counts())

            # Convert features with numeric handling
            for col in self.feature_names:
                data[col] = pd.to_numeric(data[col], errors='coerce')
                data[col] = data[col].replace([np.inf, -np.inf], np.nan)

            # Create labels (preserve some attack types)
            data['Label'] = np.where(
                data['Label'].str.contains('BENIGN', case=False, na=False), 
                0, 
                1
            )
            
            # Clean data conservatively
            data = data.dropna(subset=self.feature_names)
            print(f"\n=== Cleaned Data ===")
            print(f"Remaining rows: {len(data)}")
            print("Label distribution:\n", data['Label'].value_counts())

            if len(data) < 1000:
                raise ValueError("Insufficient data for training")

            # Train model
            X = data[self.feature_names]
            y = data['Label']
            
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            self.model = RandomForestClassifier(
                n_estimators=100,
                class_weight='balanced',
                random_state=42
            )
            self.model.fit(X_scaled, y)
            
            joblib.dump(self.model, 'model.pkl')
            joblib.dump(self.scaler, 'scaler.pkl')
            print("\n=== Training Success ===")
            print(f"Model trained on {len(data)} samples")
            
        except Exception as e:
            print(f"\n=== Training Failed ===")
            print(f"Error: {str(e)}")
            print("Required solutions:")
            print("1. Ensure dataset contains both normal and attack traffic")
            print("2. Verify these columns exist:", self.feature_names)
            print("3. Check for data corruption in CSV file")
            raise

# Run with test
if __name__ == "__main__":
    # Clear previous models
    for f in ['model.pkl', 'scaler.pkl']:
        Path(f).unlink(missing_ok=True)
    
    try:
        detector = ThreatDetector()
    except:
        print("\nFinal check: Does your CSV contain these exact column names?")
        print("Flow Duration, Destination Port, Total Fwd Packets, Total Length of Fwd Packets, Flow Bytes/s, Label")