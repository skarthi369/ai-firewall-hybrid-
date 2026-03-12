import sys
import json
from deploy_firewall import DeployedAIFirewall


def test_firewall():
    """Test the deployed firewall"""
    print("🧪 Testing Deployed AI Firewall")
    print("=" * 50)

    # Initialize firewall
    firewall = DeployedAIFirewall()

    # Test packets
    test_packets = [
        {
            "name": "Normal HTTP Traffic",
            "data": {
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
        },
        {
            "name": "Suspicious Traffic",
            "data": {
                "duration": 0,
                "protocol_type": "tcp",
                "service": "private",
                "flag": "REJ",
                "src_bytes": 0,
                "dst_bytes": 0,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0
            }
        }
    ]

    # Run tests
    for test in test_packets:
        print(f"\n🔍 Testing: {test['name']}")

        result = firewall.analyze_packet(test["data"])

        print(f"   Result: {result['decision']}")
        print(f"   Confidence: {result['dnn_confidence']:.3f}")
        print(f"   Anomaly Ratio: {result['anomaly_ratio']:.3f}x")

        if result["decision"] in ["ALLOW", "BLOCK", "QUARANTINE"]:
            print("   ✅ Test passed")
        else:
            print("   ❌ Test failed")

    print("\n✅ Test harness completed!")


if __name__ == "__main__":
    test_firewall()
