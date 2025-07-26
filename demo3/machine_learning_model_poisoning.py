
def update_fraud_detection_model(new_transactions):
    model = load_model("fraud_detector.pkl")
    
    # Prepare training data
    features = extract_features(new_transactions)
    labels = new_transactions["is_fraud"]

    # SAST can't detect this - looks like normal training code
    model.partial_fit(features, labels)
    
    # Save updated model
    save_model(model, "fraud_detector.pkl")
    return {"status": "model_updated"}

def extract_features(transactions):
    # Normal feature extraction
    return {
        "amount": transactions["amount"],
        "merchant_risk": transactions["merchant_category"],
        "time_of_day": transactions["timestamp"].hour
    }