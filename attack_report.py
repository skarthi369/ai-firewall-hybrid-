import pandas as pd

LOG_FILE = "firewall_logs.csv"

if __name__ == "__main__":
    try:
        df = pd.read_csv(LOG_FILE)
    except Exception as e:
        print(f"Failed to read log file: {e}")
        raise SystemExit(1)

    if df.empty:
        print("No events logged yet.")
        raise SystemExit(0)

    # Show latest detections
    attacks = df[df["decision"].isin(["BLOCK", "QUARANTINE"])].tail(20)

    if attacks.empty:
        print("No blocks/quarantines have been logged yet.")
    else:
        print("=== Recent blocked/quarantined events ===")
        print(attacks[["timestamp", "src_ip", "dst_ip", "decision", "event_label"]].to_string(index=False))

    # Summary
    counts = df["decision"].value_counts()
    print("\n=== Summary ===")
    for dec, cnt in counts.items():
        print(f"{dec}: {cnt}")

    if "event_label" in df.columns:
        labels = df["event_label"].value_counts().head(10)
        print("\nTop event labels:")
        print(labels.to_string())
