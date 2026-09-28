#!/usr/bin/env python3
"""
TEST 7: Advanced Blocking & Remediation Verification
Tests ALL blocking methods on the remote RHEL server to confirm they work.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

TEST_IP = "192.0.2.50"
TEST_IP2 = "192.0.2.51"
TEST_MAC = "AA:BB:CC:DD:EE:FF"
PASS = 0
FAIL = 0


def ok(label, detail=""):
    global PASS
    PASS += 1
    print(f"  [PASS] {label}" + (f" - {detail}" if detail else ""))


def fail(label, detail=""):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {label}" + (f" - {detail}" if detail else ""))


def check_rule_exists(conn, ip):
    """Check if a block rule exists for the given IP."""
    # Check nft
    r = conn.execute(f"nft list chain ip arp_filter input 2>/dev/null | grep '{ip}'")
    if r.exit_code == 0 and ip in r.stdout:
        return "nft"

    # Check arptables
    r = conn.execute(f"arptables -L INPUT -n 2>/dev/null | grep '{ip}'")
    if r.exit_code == 0 and ip in r.stdout:
        return "arptables"

    # Check ip neigh
    r = conn.execute(f"ip neigh show | grep '{ip}'")
    if r.exit_code == 0 and ip in r.stdout and "00:00:00:00:00:00" in r.stdout:
        return "ip_neigh_blackhole"

    return None


def main():
    global PASS, FAIL

    print("=" * 60)
    print("  TEST 7: ADVANCED BLOCKING & REMEDIATION")
    print("=" * 60)

    config = load_config()
    # Find RHEL server
    rhel = None
    for s in config.servers:
        if s.name == "RHEL":
            rhel = s
            break
    if not rhel:
        print("  RHEL server not found in config.yaml")
        return

    conn = LinuxConnector(rhel)
    if not conn.connect():
        print("  Failed to connect to RHEL server")
        return

    print(f"\n  Connected to: {conn.name} ({conn.host})")
    print(f"  Firewall backend: {conn.firewall_backend}")

    # ── Test 1: Firewall Backend Detection ──
    print("\n--- TEST 7a: Firewall Backend Detection ---")
    backend = conn.firewall_backend
    if backend in ["nft", "arptables", "ebtables", "iptables", "ip_neigh"]:
        ok(f"Backend detected: {backend}")
    else:
        fail(f"Unknown backend: {backend}")

    # ── Test 2: System Info ──
    print("\n--- TEST 7b: System Info ---")
    info = conn.get_system_info()
    for k, v in info.items():
        print(f"    {k}: {v}")
    if info.get("os"):
        ok("System info retrieved")
    else:
        fail("Could not get system info")

    # ── Test 3: nft Block ──
    print("\n--- TEST 7c: nft-based Block ---")
    # Clean first
    conn.execute("nft flush chain ip arp_filter input 2>/dev/null")
    conn.execute(f"ip neigh del {TEST_IP} dev ens34 2>/dev/null")

    success = conn._block_nft(TEST_IP, "ens34")
    if success:
        ok("nft block created for " + TEST_IP)
        # Verify rule exists
        backend_found = check_rule_exists(conn, TEST_IP)
        if backend_found == "nft":
            ok("nft rule VERIFIED in kernel")
        else:
            fail(f"nft rule not found (found: {backend_found})")
    else:
        fail("nft block failed")

    # ── Test 4: Unblock ──
    print("\n--- TEST 7d: Unblock ---")
    success = conn.unblock_ip_arp(TEST_IP)
    if success:
        ok("Unblock returned success for " + TEST_IP)
        # Verify rule removed
        backend_found = check_rule_exists(conn, TEST_IP)
        if not backend_found:
            ok("Rule REMOVED from kernel")
        else:
            fail(f"Rule still exists: {backend_found}")
    else:
        fail("Unblock failed")

    # ── Test 5: Full block_ip_arp (multi-method) ──
    print("\n--- TEST 7e: Full block_ip_arp (multi-method) ---")
    conn.execute("nft flush chain ip arp_filter input 2>/dev/null")
    conn.execute(f"ip neigh del {TEST_IP} dev ens34 2>/dev/null")

    success = conn.block_ip_arp(TEST_IP)
    if success:
        ok("block_ip_arp succeeded for " + TEST_IP)
        backend_used = check_rule_exists(conn, TEST_IP)
        if backend_used:
            ok(f"Rule active via: {backend_used}")
        else:
            fail("No rule found after block_ip_arp")
    else:
        fail("block_ip_arp failed")

    # ── Test 6: Blackhole via ip neigh ──
    print("\n--- TEST 7f: Blackhole (ip neigh) ---")
    conn.execute(f"ip neigh del {TEST_IP2} dev ens34 2>/dev/null")
    success = conn._block_ip_neigh(TEST_IP2, "ens34")
    if success:
        ok("Blackhole entry created for " + TEST_IP2)
        r = conn.execute(f"ip neigh show {TEST_IP2}")
        if "00:00:00:00:00:00" in r.stdout and "PERMANENT" in r.stdout:
            ok("Blackhole MAC verified: 00:00:00:00:00:00")
        else:
            fail(f"Blackhole not correct: {r.stdout.strip()}")
    else:
        fail("Blackhole failed")

    # Cleanup blackhole
    conn.execute(f"ip neigh del {TEST_IP2} dev ens34 2>/dev/null")

    # ── Test 7: Set Static ARP ──
    print("\n--- TEST 7g: Set Static ARP ---")
    success = conn.set_arp_entry(TEST_IP2, TEST_MAC, "ens34")
    if success:
        ok("Static ARP entry set: " + TEST_IP2 + " -> " + TEST_MAC)
        r = conn.execute(f"ip neigh show {TEST_IP2}")
        if TEST_MAC.upper() in r.stdout.upper() and "PERMANENT" in r.stdout:
            ok("Static entry VERIFIED")
        else:
            fail(f"Entry not correct: {r.stdout.strip()}")
    else:
        fail("Set static ARP failed")

    # Cleanup
    conn.delete_arp_entry(TEST_IP2, "ens34")

    # ── Test 8: Flush ARP cache ──
    print("\n--- TEST 7h: Flush ARP Cache ---")
    success = conn.flush_arp_cache()
    if success:
        ok("ARP cache flushed")
    else:
        fail("Flush failed")

    # ── Test 9: Firewall Rules Inspection ──
    print("\n--- TEST 7i: Firewall Rules Inspection ---")
    rules = conn.check_firewall_rules()
    print(f"    Backend: {rules.get('backend', 'unknown')}")
    print(f"    Rules count: {len(rules.get('rules', []))}")
    if rules.get("nft_arp_table"):
        print(f"    nft arp_filter table: PRESENT")
    if rules.get("backend"):
        ok("Firewall rules inspected")
    else:
        fail("Could not inspect firewall rules")

    # ── Test 10: Full Block -> Verify -> Unblock cycle ──
    print("\n--- TEST 7j: Full Block-Verify-Unblock Cycle ---")
    conn.execute("nft flush chain ip arp_filter input 2>/dev/null")
    conn.execute(f"ip neigh del {TEST_IP} dev ens34 2>/dev/null")

    # Block
    success = conn.block_ip_arp(TEST_IP)
    if not success:
        fail("Block failed in cycle test")
    else:
        # Verify blocked
        found = check_rule_exists(conn, TEST_IP)
        if found:
            ok(f"Block VERIFIED via {found}")
        else:
            fail("Block not found after blocking")

        # Unblock
        success = conn.unblock_ip_arp(TEST_IP)
        if success:
            ok("Unblock succeeded in cycle test")
            found = check_rule_exists(conn, TEST_IP)
            if not found:
                ok("Unblock VERIFIED - rule removed")
            else:
                fail(f"Rule still exists after unblock: {found}")
        else:
            fail("Unblock failed in cycle test")

    # ── Final Cleanup ──
    print("\n--- Cleanup ---")
    conn.execute("nft flush chain ip arp_filter input 2>/dev/null")
    conn.execute(f"ip neigh del {TEST_IP} dev ens34 2>/dev/null")
    conn.execute(f"ip neigh del {TEST_IP2} dev ens34 2>/dev/null")
    print("  Cleaned up test entries")

    conn.disconnect()

    # ── Summary ──
    print("\n" + "=" * 60)
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    if FAIL == 0:
        print("  ALL BLOCKING TESTS PASSED!")
    else:
        print(f"  {FAIL} TESTS FAILED - Check output above")


if __name__ == "__main__":
    main()
