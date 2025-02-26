import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Updated features based on the dataset
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets']
TARGET = 'Label'  # Updated target column name
MODEL_FILENAME = 'threat_model.pkl'

def train_model():
    # Load the dataset (ensure that datasets/CICIDS2017.csv exists)
    df = pd.read_csv('datasets/CICIDS2017.csv')
    
    # Strip whitespace from column names in case there are leading/trailing spaces
    df.columns = df.columns.str.strip()
    
    # Optionally, you can print columns to debug:
    # print("Columns in dataset:", df.columns.tolist())
    
    # Select only the important features and target column
    df = df[FEATURES + [TARGET]]
    
    # Convert target to binary:
    # Cast the column to string to avoid errors with non-string values.
    df[TARGET] = df[TARGET].astype(str).apply(lambda x: 0 if x.strip().upper() == 'BENIGN' else 1)
    
    X = df[FEATURES]
    y = df[TARGET]
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train a RandomForestClassifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    acc = clf.score(X_test, y_test)
    print(f"Model trained with accuracy: {acc:.2f}")
    
    # Save the trained model for later use
    joblib.dump(clf, MODEL_FILENAME)
    return clf

def load_model():
    try:
        model = joblib.load(MODEL_FILENAME)
    except Exception as e:
        print("No pre-trained model found. Training a new model...")
        model = train_model()
    return model

def predict_threat(features):
    # For testing: Force a threat if Total Fwd Packets is unusually high
    if float(features['Total Fwd Packets']) > 9000:
        return True
    model = load_model()
    input_data = [[float(features[feat]) for feat in FEATURES]]
    probability = model.predict_proba(input_data)[0][1]
    print(f"Predicted threat probability: {probability:.2f}")
    return probability >= 0.5


if __name__ == "__main__":
    train_model()
