#!/usr/bin/env python3
"""
Comprehensive test suite for the AI Firewall.
Run this to verify all components are working correctly.
"""

import os
import sys
import time
import subprocess
import pandas as pd
import json

def print_header(msg):
    print("\n" + "="*80)
    print(f"🔍 {msg}")
    print("="*80)

def print_success(msg):
    print(f"✅ {msg}")

def print_error(msg):
    print(f"❌ {msg}")

def test_models_loaded():
    """Check if all firewall models are present and loadable."""
    print_header("Testing Model Availability")
    
    model_dir = "ai_firewall_models"
    required_files = [
        "dnn_firewall.h5",
        "autoencoder.h5",
        "scaler.pkl",
        "label_encoders.pkl",
        "feature_names.json",
        "anomaly_threshold.json",
    ]
    
    for fname in required_files:
        path = os.path.join(model_dir, fname)
        if os.path.exists(path):
            size = os.path.getsize(path) / 1024 / 1024
            print_success(f"  {fname} ({size:.1f} MB)")
        else:
            print_error(f"  {fname} NOT FOUND")
            return False
    
    return True

def test_deploy_firewall():
    """Test that the firewall module can load models."""
    print_header("Testing Firewall Model Loading")
    
    try:
        from deploy_firewall import DeployedAIFirewall
        fw = DeployedAIFirewall()
        print_success("Firewall models loaded successfully")
        
        # Test a sample packet
        sample = {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "S",
            "src_bytes": 1000,
            "dst_bytes": 1000,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
        }
        result = fw.analyze_packet(sample)
        print_success(f"  Sample packet analysis: {result['decision']} "
                     f"(confidence: {result['dnn_confidence']:.3f})")
        return True
    except Exception as e:
        print_error(f"Failed to load firewall: {e}")
        return False

def test_nft_availability():
    """Check if nftables is available."""
    print_header("Testing nftables Availability")
    
    try:
        result = subprocess.run(["which", "nft"], capture_output=True, text=True)
        if result.returncode == 0:
            print_success("nft command found at: " + result.stdout.strip())
            return True
        else:
            print_error("nft command not found. Install nftables: sudo apt install nftables")
            return False
    except Exception as e:
        print_error(f"Failed to check nft: {e}")
        return False

def test_log_file_schema():
    """Check and validate the firewall log file schema."""
    print_header("Testing Firewall Log File Schema")
    
    log_file = "firewall_logs.csv"
    
    if not os.path.exists(log_file):
        print_error(f"  {log_file} does not exist yet (will be created on first run)")
        return True
    
    try:
        df = pd.read_csv(log_file, on_bad_lines="skip")
        expected_cols = [
            "timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port",
            "src_bytes", "dst_bytes", "decision", "confidence", "anomaly_ratio",
            "blocked", "event_label"
        ]
        
        for col in expected_cols:
            if col in df.columns:
                print_success(f"  Column '{col}' found")
            else:
                print_error(f"  Column '{col}' MISSING")
                return False
        
        print_success(f"Log has {len(df)} events recorded so far")
        return True
    except Exception as e:
        print_error(f"Failed to read log: {e}")
        return False

def show_recent_events():
    """Display recent firewall events from the log."""
    print_header("Recent Firewall Events")
    
    log_file = "firewall_logs.csv"
    
    if not os.path.exists(log_file):
        print_error("No log file found. Run the firewall monitor first.")
        return
    
    try:
        df = pd.read_csv(log_file, on_bad_lines="skip")
        
        if df.empty:
            print("No events logged yet.")
            return
        
        # Show summary
        counts = df["decision"].value_counts()
        print("\n📊 Decision Summary:")
        for dec, cnt in counts.items():
            print(f"  {dec}: {cnt}")
        
        # Show recent blocks/quarantines
        attacked = df[(df["decision"] == "BLOCK") | (df["decision"] == "QUARANTINE")]
        if not attacked.empty:
            print("\n🚨 Recent blocked/quarantined events:")
            print(attacked[["timestamp", "src_ip", "dst_ip", "decision", "event_label"]].tail(10).to_string(index=False))
        
        # Show top event labels
        if "event_label" in df.columns:
            labels = df["event_label"].value_counts().head(5)
            print("\n🏷️  Top Event Labels:")
            for label, cnt in labels.items():
                print(f"  {label}: {cnt}")
        
    except Exception as e:
        print_error(f"Failed to read log: {e}")

def test_attack_generator():
    """Test the attack generator script."""
    print_header("Testing Attack Generator")
    
    if not os.path.exists("attack_generator.py"):
        print_error("attack_generator.py not found")
        return False
    
    try:
        result = subprocess.run(
            ["python", "attack_generator.py", "--help"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print_success("attack_generator.py runs successfully")
            return True
        else:
            print_error("attack_generator.py failed to run")
            return False
    except Exception as e:
        print_error(f"Failed to test attack_generator: {e}")
        return False

def main():
    print("\n" + "🛡 "*20)
    print("    AI FIREWALL - COMPREHENSIVE TEST SUITE")
    print("🛡 "*20)
    
    tests = [
        ("Model Files", test_models_loaded),
        ("Firewall Module", test_deploy_firewall),
        ("nftables Availability", test_nft_availability),
        ("Log File Schema", test_log_file_schema),
        ("Attack Generator", test_attack_generator),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed))
        except Exception as e:
            print_error(f"Test '{name}' crashed: {e}")
            results.append((name, False))
    
    # Summary
    print_header("Test Summary")
    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status} - {name}")
    
    print(f"\nResult: {passed_count}/{total_count} tests passed")
    
    # Show recent events if any exist
    show_recent_events()
    
    print_header("Next Steps for Real-Time Testing")
    print("""
1. Open two terminals:

   Terminal 1 - Start the firewall monitor:
   $ sudo -E $(which python) packet_sniffer.py

   Terminal 2 - Start the dashboard:
   $ streamlit run soc_dashboard.py
   
   Open browser to: http://localhost:8501

2. In Terminal 3 - Generate test attacks:
   $ python attack_generator.py --mode portscan --count 200
   $ python attack_generator.py --mode large --count 20 --size 20000
   $ python attack_generator.py --mode udpflood --count 200

3. Watch the dashboard show:
   ✓ Blocked/quarantined event counts
   ✓ Recent events with attack labels
   ✓ Blocked IPs with unblock buttons
   ✓ "Attack observations" summary

4. View the attack report:
   $ python attack_report.py

This will show all detected and blocked attacks.
    """)

if __name__ == "__main__":
    main()
