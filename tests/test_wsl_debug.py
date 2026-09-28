#!/usr/bin/env python3
"""Debug: Check what's available on WSL."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
for s in config.servers:
    if s.name == "kali":
        conn = LinuxConnector(s)
        conn.connect()

        print("=== TOOL CHECK ===")
        for tool in ["nft", "arptables", "ebtables", "iptables", "ip"]:
            r = conn.execute(f"which {tool} 2>/dev/null || echo NOTFOUND")
            print(f"  {tool}: {r.stdout.strip()}")

        print("\n=== SUDO CHECK ===")
        r = conn.execute("sudo -n nft list tables 2>&1")
        print(f"  sudo nft: exit={r.exit_code} out={r.stdout.strip()[:200]} err={r.stderr.strip()[:200]}")

        r = conn.execute("id")
        print(f"  user: {r.stdout.strip()}")

        print("\n=== NFT DIRECT ===")
        r = conn.execute("nft list tables 2>&1")
        print(f"  nft list: exit={r.exit_code} out={r.stdout.strip()[:300]}")

        r = conn.execute("nft add table ip arp_filter 2>&1")
        print(f"  nft add table: exit={r.exit_code} out={r.stdout.strip()} err={r.stderr.strip()}")

        r = conn.execute("nft add chain ip arp_filter input 2>&1")
        print(f"  nft add chain: exit={r.exit_code} out={r.stdout.strip()} err={r.stderr.strip()}")

        r = conn.execute("nft add rule ip arp_filter input ip saddr 192.0.2.50 drop 2>&1")
        print(f"  nft add rule: exit={r.exit_code} out={r.stdout.strip()} err={r.stderr.strip()}")

        if r.exit_code == 0:
            r = conn.execute("nft list chain ip arp_filter input 2>&1")
            print(f"  verify: {r.stdout.strip()[:300]}")
            conn.execute("nft flush chain ip arp_filter input 2>/dev/null")

        print("\n=== IP NEIGH CHECK ===")
        r = conn.execute("ip neigh replace 192.0.2.99 lladdr 00:00:00:00:00:00 dev eth0 nud permanent 2>&1")
        print(f"  ip neigh replace: exit={r.exit_code} out={r.stdout.strip()} err={r.stderr.strip()}")

        if r.exit_code == 0:
            r = conn.execute("ip neigh show 192.0.2.99")
            print(f"  verify: {r.stdout.strip()}")
            conn.execute("ip neigh del 192.0.2.99 dev eth0 2>/dev/null")

        conn.disconnect()
        break
