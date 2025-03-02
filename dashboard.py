from flask import Flask, render_template, request
from integration_layer import process_request
from blockchain_logging import blockchain

app = Flask(__name__)

# Updated features to be asked from the user
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets', 'protocol']

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        # Retrieve form data for each important feature
        input_features = { feature: request.form.get(feature, 0) for feature in FEATURES }
        
        threat_detected, log_entry = process_request(input_features)
        result = {
            'threat_detected': threat_detected,
            'log_entry': log_entry
        }
    
    # Get current blockchain logs to display on the dashboard
    chain = blockchain.get_chain()
    return render_template('dashboard.html', features=FEATURES, result=result, chain=chain)

if __name__ == '__main__':
    app.run(debug=True)
