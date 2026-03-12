import streamlit as st
import pandas as pd
import numpy as np
import tensorflow as tf
import joblib
import json
import os
import time
import plotly.express as px

st.set_page_config(page_title="AI Firewall Dashboard", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_firewall_system():
    model_dir = "ai_firewall_models"
    try:
        scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        label_encoders = joblib.load(os.path.join(model_dir, "label_encoders.pkl"))
        
        with open(os.path.join(model_dir, "feature_names.json"), "r") as f:
            feature_names = json.load(f)
            
        with open(os.path.join(model_dir, "anomaly_threshold.json"), "r") as f:
            threshold_data = json.load(f)
            anomaly_threshold = threshold_data.get("threshold", 0.1)
            
        # Using YOUR exact filenames here!
        dnn_model = tf.keras.models.load_model(os.path.join(model_dir, "dnn_firewall.h5"), compile=False)
        autoencoder = tf.keras.models.load_model(os.path.join(model_dir, "autoencoder.h5"), compile=False)
        
        return dnn_model, autoencoder, scaler, label_encoders, feature_names, anomaly_threshold
    except Exception as e:
        st.error(f"Error loading models: {e}")
        return None, None, None, None, None, None

dnn_model, autoencoder, scaler, label_encoders, feature_names, anomaly_threshold = load_firewall_system()

def analyze_packet(features_df):
    for col in features_df.columns:
        if col in label_encoders and features_df[col].dtype == 'object':
            le = label_encoders[col]
            features_df[col] = features_df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
            features_df[col] = le.transform(features_df[col])
            
    features_df = features_df[feature_names]
    scaled_data = scaler.transform(features_df)
    
    dnn_pred = dnn_model.predict(scaled_data, verbose=0)
    dnn_confidence = np.max(dnn_pred)
    predicted_class = np.argmax(dnn_pred)
    
    if predicted_class != 0 and dnn_confidence > 0.85:
        return "KNOWN ATTACK (BLOCK)", dnn_confidence, "DNN"

    reconstruction = autoencoder.predict(scaled_data, verbose=0)
    mse = np.mean(np.power(scaled_data - reconstruction, 2), axis=1)[0]
    
    if mse > anomaly_threshold:
        return "ZERO-DAY ANOMALY (QUARANTINE)", mse, "Autoencoder"
        
    return "NORMAL (ALLOW)", dnn_confidence, "DNN"

st.title("🛡️ Adaptive AI Network Firewall")
st.markdown("Real-Time Deep Learning Intrusion Detection System")

st.sidebar.header("Traffic Input Simulation")
uploaded_file = st.sidebar.file_uploader("Upload Network CSV Features", type=["csv"])

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    st.success("File Uploaded Successfully!")
    
    if st.button("🚀 Analyze Traffic Now", type="primary"):
        progress_bar = st.progress(0)
        status_text = st.empty()
        results = []
        
        for i in range(len(df)):
            status_text.text(f"Analyzing Packet {i+1} / {len(df)}...")
            packet = pd.DataFrame([df.iloc[i].to_dict()])
            decision, score, engine = analyze_packet(packet)
            
            results.append({
                "Packet ID": i+1,
                "Decision": decision,
                "Confidence/MSE": round(float(score), 4),
                "Engine Used": engine
            })
            progress_bar.progress((i + 1) / len(df))
            
        status_text.text("Analysis Complete!")
        results_df = pd.DataFrame(results)
        
        col1, col2, col3 = st.columns(3)
        blocked = len(results_df[results_df["Decision"].str.contains("BLOCK|QUARANTINE")])
        col1.metric("Total Packets", len(results_df))
        col2.metric("Threats Blocked", blocked)
        col3.metric("Normal Allowed", len(results_df) - blocked)
        
        st.dataframe(results_df, use_container_width=True)
else:
    st.info("👈 Please upload a CSV file with network traffic features to begin.")
