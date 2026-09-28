#!/usr/bin/env python3
"""Quick test: Connect to WSL (Kali) and verify ARP collection works."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
for s in config.servers:
    if s.name == "kali":
        conn = LinuxConnector(s)
        print(f"Connecting to {s.name} ({s.host})...")
        if conn.connect():
            print("CONNECTED!")
            r = conn.execute("hostname")
            print(f"  Hostname: {r.stdout.strip()}")
            r = conn.execute("whoami")
            print(f"  User: {r.stdout.strip()}")
            r = conn.execute("uname -r")
            print(f"  Kernel: {r.stdout.strip()}")

            arp = conn.get_arp_table()
            print(f"  ARP entries: {len(arp)}")
            for e in arp:
                print(f"    {e['ip']} -> {e['mac']}")

            gw = conn.get_default_gateway()
            print(f"  Gateway: {gw}")

            ifaces = conn.get_network_interfaces()
            print("  Interfaces:")
            for i in ifaces:
                print(f"    {i['name']}: {i['ip']} MAC={i['mac']}")

            print(f"  Firewall: {conn.firewall_backend}")

            info = conn.get_system_info()
            print(f"  OS: {info.get('os', '?')}")

            conn.disconnect()
            print("\nSUCCESS - WSL machine is ready for testing!")
        else:
            print("FAILED to connect!")
        break
