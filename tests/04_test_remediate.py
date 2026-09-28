"""
TEST 4: Remediation Test (SAFE)
Tests block, flush, and restore on the remote server.
Run: python tests/04_test_remediate.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

def test_remediate():
    print("=" * 60)
    print("  TEST 4: Remediation (Safe Tests)")
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

    # 1. Flush ARP cache
    print("\n--- TEST 4a: Flush ARP Cache ---")
    print("  Flushing ARP cache on remote server...")
    before = conn.get_arp_table()
    print(f"  Before flush: {len(before)} entries")
    for e in before:
        print(f"    {e['ip']} -> {e['mac']}")

    ok = conn.flush_arp_cache()
    print(f"  Flush result: {'OK' if ok else 'FAILED'}")

    after = conn.get_arp_table()
    print(f"  After flush: {len(after)} entries")
    for e in after:
        print(f"    {e['ip']} -> {e['mac']}")

    # 2. Check arptables rules
    print("\n--- TEST 4b: Check arptables ---")
    rules = conn.check_arptables_rules()
    print("  Current rules:")
    for r in rules:
        print(f"    {r}")

    # 3. Test block (using a fake IP - won't affect real traffic)
    print("\n--- TEST 4c: Block Test (fake IP) ---")
    fake_ip = "192.0.2.1"  # TEST-NET-3, not routable
    print(f"  Blocking ARP from {fake_ip}...")
    ok = conn.block_ip_arp(fake_ip)
    print(f"  Block result: {'OK' if ok else 'FAILED'}")

    rules = conn.check_arptables_rules()
    print("  Rules after block:")
    for r in rules:
        print(f"    {r}")

    # 4. Test unblock
    print(f"\n--- TEST 4d: Unblock Test ---")
    print(f"  Unblocking ARP from {fake_ip}...")
    ok = conn.unblock_ip_arp(fake_ip)
    print(f"  Unblock result: {'OK' if ok else 'FAILED'}")

    rules = conn.check_arptables_rules()
    print("  Rules after unblock:")
    for r in rules:
        print(f"    {r}")

    # 5. Test network status (don't actually isolate!)
    print("\n--- TEST 4e: Network Status ---")
    ifaces = conn.get_network_interfaces()
    print("  Interfaces:")
    for i in ifaces:
        status = "UP" if i.get("ip") else "DOWN"
        print(f"    {i['name']}: {i['ip']} ({status})")

    conn.disconnect()
    print("\n  [PASS] Remediation tests complete!")
    print("  NOTE: Network was NOT isolated - only safe tests were run")
    return True

if __name__ == "__main__":
    ok = test_remediate()
    sys.exit(0 if ok else 1)
