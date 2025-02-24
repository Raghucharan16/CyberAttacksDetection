import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib

class ThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.load_or_train_model()

    def load_or_train_model(self):
        try:
            self.model = joblib.load('cicids_model.pkl')
            self.scaler = joblib.load('scaler.pkl')
            print("Loaded pre-trained model and scaler.")
        except FileNotFoundError:
            self.train_model()

    def train_model(self):
        # Load the single CSV file (e.g., CICIDS2017.csv from Kaggle)
        data = pd.read_csv('datasets/CICIDS2017.csv')
        
        # Clean column names and data
        data.columns = data.columns.str.strip()
        data.replace([np.inf, -np.inf], np.nan, inplace=True)
        data.dropna(inplace=True)
        
        # Define features and target
        # Use all columns except 'Label' as features (78 features)
        features = [col for col in data.columns if col != 'Label']
        X = data[features]  # Features (78 columns)
        y = data['Label'].apply(lambda x: 1 if x != 'BENIGN' else 0)  # Binary: 0 = benign, 1 = attack

        # Preprocess data (handle categorical data if any, e.g., Protocol might be numeric but check for others)
        categorical_cols = []  # Check if any columns are categorical (e.g., Protocol, if not numeric)
        if any(col in data.columns for col in categorical_cols):
            X = pd.get_dummies(X, columns=categorical_cols)

        # Handle numerical columns (ensure no strings or objects in numerical columns)
        X = X.astype(float)

        # Preprocess data
        X_scaled = self.scaler.fit_transform(X)
        X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

        # Train Random Forest (high-accuracy model for intrusion detection, inspired by Kaggle benchmarks)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.model.fit(X_train, y_train)

        # Evaluate
        accuracy = self.model.score(X_test, y_test)
        print(f"Model trained with accuracy: {accuracy:.4f}")

        # Save model and scaler
        joblib.dump(self.model, 'cicids_model.pkl')
        joblib.dump(self.scaler, 'scaler.pkl')

    def detect_threat(self, traffic_features):
        # Convert to numpy array and ensure float type
        features_scaled = self.scaler.transform([traffic_features])
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0][1]
        return int(prediction == 1), float(probability)

    def get_feature_names(self):
        """Return the feature names used during training."""
        if self.model is not None:
            return [f for f in self.model.feature_names_in_]
        return []  # Default if model not trained
    def preprocess_data(self, file_path):
        data = pd.read_csv(file_path)
        data = data.dropna()
        
        # Clean column names
        data.columns = data.columns.str.strip()
        data.replace([np.inf, -np.inf], np.nan, inplace=True)
        data.dropna(inplace=True)
        
        # Use all columns except 'Label' as features
        X = data.drop('Label', axis=1).values  # Convert to numpy array
        y = data['Label'].apply(lambda x: 1 if x != 'BENIGN' else 0).values
        
        # Preprocess data
        X_scaled = self.scaler.fit_transform(X)
        return X_scaled, y


if __name__ == "__main__":
    detector = ThreatDetector()
    # Example: Use a synthetic 78-feature sample (replace with real data for testing)
    sample_traffic = [0] * 78  
    is_threat, prob = detector.detect_threat(sample_traffic)
    print(f"Is Threat: {is_threat}, Probability: {prob:.4f}")