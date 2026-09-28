#!/usr/bin/env python3
"""Test WSL blocking with sudo."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
for s in config.servers:
    if s.name == "kali":
        conn = LinuxConnector(s)
        conn.connect()

        print("=== SUDO WITH PASSWORD ===")
        r = conn.execute_sudo("nft list tables 2>&1")
        print(f"  sudo nft: exit={r.exit_code} out={r.stdout.strip()[:200]}")

        r = conn.execute_sudo("nft add table ip arp_filter 2>&1")
        print(f"  nft add table: exit={r.exit_code}")

        r = conn.execute_sudo("nft add chain ip arp_filter input 2>&1")
        print(f"  nft add chain: exit={r.exit_code}")

        r = conn.execute_sudo("nft add rule ip arp_filter input ip saddr 192.0.2.50 drop 2>&1")
        print(f"  nft add rule: exit={r.exit_code}")

        if r.exit_code == 0:
            r = conn.execute_sudo("nft list chain ip arp_filter input 2>&1")
            print(f"  VERIFY: {r.stdout.strip()[:300]}")
            conn.execute_sudo("nft flush chain ip arp_filter input 2>/dev/null")
            print("  Rule created and verified!")
        else:
            print(f"  FAILED: {r.stderr.strip()[:200]}")

        # Test ip neigh with sudo
        print("\n=== IP NEIGH WITH SUDO ===")
        r = conn.execute_sudo("ip neigh replace 192.0.2.99 lladdr 00:00:00:00:00:00 dev eth0 nud permanent 2>&1")
        print(f"  ip neigh replace: exit={r.exit_code}")
        if r.exit_code == 0:
            r = conn.execute("ip neigh show 192.0.2.99")
            print(f"  VERIFY: {r.stdout.strip()}")
            conn.execute_sudo("ip neigh del 192.0.2.99 dev eth0 2>/dev/null")

        # Test ping to generate ARP
        print("\n=== PING TO GENERATE ARP ===")
        r = conn.execute("ping -c 2 172.21.0.1 2>&1")
        print(f"  ping gateway: exit={r.exit_code}")
        print(f"  {r.stdout.strip()[:200]}")

        arp = conn.get_arp_table()
        print(f"  ARP table after ping: {len(arp)} entries")
        for e in arp:
            print(f"    {e['ip']} -> {e['mac']}")

        conn.disconnect()
        print("\nDONE!")
        break
