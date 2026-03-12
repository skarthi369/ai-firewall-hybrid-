import numpy as np
import pandas as pd
import pickle
import json
import os
import time
from tensorflow.keras.models import load_model


class DeployedAIFirewall:

    def __init__(self, model_path="ai_firewall_models"):

        print("🚀 Loading AI Firewall Models...")

        # Load models in inference mode
        self.dnn_model = load_model(
            os.path.join(model_path, "dnn_firewall.h5"),
            compile=False
        )

        self.autoencoder = load_model(
            os.path.join(model_path, "autoencoder.h5"),
            compile=False
        )

        # Load scaler
        with open(os.path.join(model_path, "scaler.pkl"), "rb") as f:
            self.scaler = pickle.load(f)

        # Load label encoders
        with open(os.path.join(model_path, "label_encoders.pkl"), "rb") as f:
            self.label_encoders = pickle.load(f)

        # Load feature names
        with open(os.path.join(model_path, "feature_names.json")) as f:
            self.feature_names = json.load(f)

        # Load anomaly threshold
        with open(os.path.join(model_path, "anomaly_threshold.json")) as f:
            threshold_data = json.load(f)
            self.anomaly_threshold = threshold_data.get("threshold", 0.1)

        print("✅ Firewall models loaded successfully")
        print(f"   • Features expected: {len(self.feature_names)}")
        print(f"   • Anomaly threshold: {self.anomaly_threshold}")

    def preprocess_packet(self, packet_dict):
        """Convert packet dictionary into model-ready features"""

        df = pd.DataFrame([packet_dict])

        # Encode categorical features
        for col, encoder in self.label_encoders.items():

            if col in df.columns:

                try:
                    df[col] = df[col].astype(str)

                    # Handle unseen categories
                    df[col] = df[col].apply(
                        lambda x: x if x in encoder.classes_ else encoder.classes_[0]
                    )

                    df[col] = encoder.transform(df[col])

                except Exception as e:
                    print(f"Encoding error in {col}: {e}")

        # Ensure correct feature order
        for feature in self.feature_names:
            if feature not in df.columns:
                df[feature] = 0

        df = df[self.feature_names]

        # Scale features
        scaled_data = self.scaler.transform(df)

        return scaled_data

    def analyze_packet(self, packet_dict):
        """Analyze a single packet"""

        start_time = time.time()

        # Preprocess packet
        data = self.preprocess_packet(packet_dict)

        # DNN prediction
        dnn_pred = self.dnn_model.predict(data, verbose=0)
        dnn_conf = float(np.max(dnn_pred))

        # Autoencoder reconstruction
        reconstruction = self.autoencoder.predict(data, verbose=0)

        mse = float(np.mean((data - reconstruction) ** 2))

        anomaly_ratio = mse / self.anomaly_threshold

        # Decision logic
        if dnn_conf > 0.85:
            decision = "BLOCK"

        elif anomaly_ratio > 1.0:
            decision = "QUARANTINE"

        else:
            decision = "ALLOW"

        processing_time = (time.time() - start_time) * 1000

        return {
            "decision": decision,
            "dnn_confidence": dnn_conf,
            "anomaly_ratio": anomaly_ratio,
            "processing_time_ms": processing_time
        }


# Example standalone test
if __name__ == "__main__":

    firewall = DeployedAIFirewall()

    example_packet = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 181,
        "dst_bytes": 5450,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0
    }

    result = firewall.analyze_packet(example_packet)

    print("\n🔍 Test Packet Result")
    print("----------------------")
    print(f"Decision: {result['decision']}")
    print(f"DNN Confidence: {result['dnn_confidence']:.3f}")
    print(f"Anomaly Ratio: {result['anomaly_ratio']:.3f}")
    print(f"Processing Time: {result['processing_time_ms']:.2f} ms")
