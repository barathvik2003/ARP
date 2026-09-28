"""
TEST 3: Detection Engine Test
Runs the ARP attack detection engine against remote server data.
Run: python tests/03_test_detect.py
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.logs.parser import parse_logs
from arp_detection_system.logs.collector import CollectedLogs
from arp_detection_system.detection.engine import DetectionEngine, AttackType, Confidence
from arp_detection_system.config import load_config

def test_detect():
    print("=" * 60)
    print("  TEST 3: ARP Attack Detection")
    print("=" * 60)

    config = load_config()
    server = None
    for s in config.servers:
        if s.name == "RHEL":
            server = s
            break
    if not server:
        server = config.servers[0]
    conn = LinuxConnector(server)

    if not conn.connect():
        print("  [FAIL] Cannot connect")
        return False

    print(f"\n  Connected to: {server.name}")

    # Collect data from remote
    print("\n  Collecting ARP data from remote server...")
    arp_entries = conn.get_arp_table()
    gateway = conn.get_default_gateway()
    print(f"  ARP entries: {len(arp_entries)}")
    print(f"  Gateway: {gateway}")

    print("\n  Collecting logs from remote server...")
    log_entries = []
    try:
        syslog = conn.get_syslog_arp_entries(200)
        log_entries = parse_logs("\n".join(syslog), "linux")
    except Exception:
        pass
    try:
        dmesg = conn.get_dmesg_arp(100)
        log_entries.extend(parse_logs("\n".join(dmesg), "linux", "dmesg"))
    except Exception:
        pass
    print(f"  Log entries: {len(log_entries)}")

    # Run detection engine
    print("\n  Running detection engine...")
    engine = DetectionEngine(config)
    engine.set_baseline_from_table(arp_entries)

    if gateway:
        config.detection.gateway_ip = gateway
        print(f"  Gateway set: {gateway}")

    collected = CollectedLogs(
        server_name=server.name,
        os_type="linux",
        arp_table=[{"ip": e.get("ip", ""), "mac": e.get("mac", "")} for e in arp_entries],
        log_entries=log_entries,
        timestamp=time.time(),
    )

    validations = engine.analyze_all([], {server.name: collected})
    summary = engine.generate_summary(validations)

    # Results
    print("\n" + "-" * 40)
    print("  DETECTION RESULTS")
    print("-" * 40)
    print(f"  Total findings:    {summary['total_alerts']}")
    print(f"  Critical:          {summary['by_severity'].get('CRITICAL', 0)}")
    print(f"  High:              {summary['by_severity'].get('HIGH', 0)}")
    print(f"  Medium:            {summary['by_severity'].get('MEDIUM', 0)}")
    print(f"  Low:               {summary['by_severity'].get('LOW', 0)}")

    if validations:
        print("\n  FINDINGS:")
        for v in validations:
            print(f"\n  [{v.severity}] {v.attack_type.value} ({v.confidence.value})")
            print(f"    IP: {v.attacker_ip}  MAC: {v.attacker_mac}")
            print(f"    {v.description}")
            for e in v.evidence:
                print(f"    Evidence: {e}")
            for r in v.recommendations:
                print(f"    -> {r}")
    else:
        print("\n  No ARP attacks detected - network is CLEAN!")

    conn.disconnect()
    print("\n  [PASS] Detection engine working!")
    return True

if __name__ == "__main__":
    ok = test_detect()
    sys.exit(0 if ok else 1)
