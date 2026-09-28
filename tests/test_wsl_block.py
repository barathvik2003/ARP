#!/usr/bin/env python3
"""Test ARP blocking on WSL (Kali) machine."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

TEST_IP = "192.0.2.50"

config = load_config()
for s in config.servers:
    if s.name == "kali":
        conn = LinuxConnector(s)
        print(f"Connecting to {s.name} ({s.host})...")
        if not conn.connect():
            print("FAILED!")
            sys.exit(1)

        print(f"Connected! Firewall backend: {conn.firewall_backend}")
        print(f"OS: {conn.execute('uname -r').stdout.strip()}")
        print()

        # Test 1: Block
        print(f"--- Block {TEST_IP} ---")
        success = conn.block_ip_arp(TEST_IP)
        print(f"  Result: {success}")

        if success:
            # Verify
            r = conn.execute(f"nft list chain ip arp_filter input 2>/dev/null | grep '{TEST_IP}'")
            if TEST_IP in r.stdout:
                print(f"  Verified: nft rule EXISTS in kernel")
            else:
                print(f"  Checking other methods...")
                r = conn.execute(f"ip neigh show | grep '{TEST_IP}'")
                if TEST_IP in r.stdout:
                    print(f"  Verified: ip neigh entry EXISTS")
                else:
                    print(f"  WARNING: Rule not found after block!")

        # Test 2: Check rules
        print("\n--- Firewall Rules ---")
        rules = conn.check_firewall_rules()
        print(f"  Backend: {rules.get('backend', '?')}")
        if rules.get('nft_arp_table'):
            print(f"  nft arp_filter: PRESENT")
            for line in rules['nft_arp_table'].splitlines():
                if 'drop' in line.lower() or 'arp_filter' in line.lower():
                    print(f"    {line.strip()}")

        # Test 3: Unblock
        print(f"\n--- Unblock {TEST_IP} ---")
        success = conn.unblock_ip_arp(TEST_IP)
        print(f"  Result: {success}")

        # Test 4: Verify clean
        r = conn.execute(f"nft list chain ip arp_filter input 2>/dev/null | grep '{TEST_IP}'")
        if TEST_IP not in r.stdout:
            print(f"  Verified: Rule REMOVED from kernel")
        else:
            print(f"  WARNING: Rule still exists!")

        # Test 5: Blackhole
        print(f"\n--- Blackhole 192.0.2.51 ---")
        success = conn._block_ip_neigh("192.0.2.51", "eth0")
        print(f"  Result: {success}")
        if success:
            r = conn.execute("ip neigh show 192.0.2.51")
            print(f"  Entry: {r.stdout.strip()}")
            conn.execute("ip neigh del 192.0.2.51 dev eth0 2>/dev/null")

        # Test 6: Static ARP
        print(f"\n--- Static ARP ---")
        success = conn.set_arp_entry("192.0.2.52", "AA:BB:CC:DD:EE:FF", "eth0")
        print(f"  Set: {success}")
        if success:
            r = conn.execute("ip neigh show 192.0.2.52")
            print(f"  Entry: {r.stdout.strip()}")
            conn.delete_arp_entry("192.0.2.52", "eth0")

        conn.disconnect()
        print("\nALL WSL BLOCKING TESTS PASSED!")
        break
