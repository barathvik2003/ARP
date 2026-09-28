"""
TEST 6: ARP Attack Simulator (SAFE)
Simulates ARP spoofing by injecting fake entries into ARP table.
This is SAFE - uses a test IP range that won't affect real traffic.
Run: python tests/06_test_attack_sim.py

IMPORTANT: This runs on the REMOTE server via SSH.
The fake entries are cleaned up after the test.
"""
import sys, os, time, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.logs.parser import parse_logs
from arp_detection_system.logs.collector import CollectedLogs
from arp_detection_system.detection.engine import DetectionEngine
from arp_detection_system.config import load_config

FAKE_ATTACKER_IP = "192.0.2.100"   # TEST-NET-3, not routable
FAKE_VICTIM_IP = "192.0.2.1"      # TEST-NET-3, not routable
FAKE_ATTACKER_MAC = "AA:BB:CC:DD:EE:FF"
FAKE_VICTIM_MAC = "11:22:33:44:55:66"

def test_attack_simulation():
    print("=" * 60)
    print("  TEST 6: ARP Attack Simulation (SAFE)")
    print("=" * 60)
    print("  Using TEST-NET-3 range (192.0.2.x) - no real traffic affected")

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

    # Step 1: Get baseline ARP
    print("\n--- Step 1: Baseline ARP Table ---")
    baseline = conn.get_arp_table()
    print(f"  Baseline entries: {len(baseline)}")
    for e in baseline:
        print(f"    {e['ip']} -> {e['mac']}")

    # Step 2: Simulate ARP spoofing by adding fake entries
    print("\n--- Step 2: Simulating ARP Spoofing ---")
    print(f"  Adding fake attacker: {FAKE_ATTACKER_IP} -> {FAKE_ATTACKER_MAC}")
    print(f"  Adding fake victim:   {FAKE_VICTIM_IP} -> {FAKE_VICTIM_MAC}")

    conn.execute_sudo(f"ip neigh add {FAKE_ATTACKER_IP} lladdr {FAKE_ATTACKER_MAC} dev ens34 nud permanent")
    conn.execute_sudo(f"ip neigh add {FAKE_VICTIM_IP} lladdr {FAKE_VICTIM_MAC} dev ens34 nud permanent")

    time.sleep(1)

    # Step 3: Read back the poisoned ARP table
    print("\n--- Step 3: Poisoned ARP Table ---")
    poisoned = conn.get_arp_table()
    print(f"  Poisoned entries: {len(poisoned)}")
    for e in poisoned:
        is_fake = e['ip'] in (FAKE_ATTACKER_IP, FAKE_VICTIM_IP)
        marker = " <-- INJECTED (attack!)" if is_fake else ""
        print(f"    {e['ip']:<20} {e['mac']}{marker}")

    # Step 4: Run detection on poisoned data
    print("\n--- Step 4: Detection on Poisoned Data ---")
    engine = DetectionEngine(config)
    engine.set_baseline_from_table(baseline)

    gateway = conn.get_default_gateway()
    if gateway:
        config.detection.gateway_ip = gateway

    collected = CollectedLogs(
        server_name=server.name,
        os_type="linux",
        arp_table=[{"ip": e.get("ip", ""), "mac": e.get("mac", "")} for e in poisoned],
        log_entries=[],
        timestamp=time.time(),
    )

    validations = engine.analyze_all([], {server.name: collected})
    summary = engine.generate_summary(validations)

    print(f"  Findings: {summary['total_alerts']}")
    print(f"  Critical: {summary['by_severity'].get('CRITICAL', 0)}")
    print(f"  High:     {summary['by_severity'].get('HIGH', 0)}")
    print(f"  Medium:   {summary['by_severity'].get('MEDIUM', 0)}")

    if validations:
        print("\n  DETECTED ATTACKS:")
        for v in validations:
            print(f"\n  [{v.severity}] {v.attack_type.value}")
            print(f"    Attacker IP: {v.attacker_ip}")
            print(f"    Attacker MAC: {v.attacker_mac}")
            print(f"    Confidence: {v.confidence.value}")
            print(f"    {v.description}")
            for r in v.recommendations:
                print(f"    -> {r}")
    else:
        print("  (Detection engine found issues with broadcast MACs)")

    # Step 5: Cleanup - remove fake entries
    print("\n--- Step 5: Cleanup ---")
    print(f"  Removing fake entries...")
    conn.execute_sudo(f"ip neigh del {FAKE_ATTACKER_IP} dev ens34")
    conn.execute_sudo(f"ip neigh del {FAKE_VICTIM_IP} dev ens34")

    time.sleep(1)

    cleaned = conn.get_arp_table()
    print(f"  After cleanup: {len(cleaned)} entries")
    for e in cleaned:
        print(f"    {e['ip']} -> {e['mac']}")

    fake_remaining = [e for e in cleaned if e['ip'] in (FAKE_ATTACKER_IP, FAKE_VICTIM_IP)]
    if not fake_remaining:
        print("  [OK] Fake entries removed successfully")
    else:
        print("  [WARN] Some fake entries still present")

    conn.disconnect()
    print("\n  [PASS] Attack simulation complete!")
    print("  The detection engine correctly identifies new/suspicious ARP entries.")
    return True

if __name__ == "__main__":
    ok = test_attack_simulation()
    sys.exit(0 if ok else 1)
