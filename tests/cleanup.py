import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config
config = load_config()
for s in config.servers:
    if s.name == "kali":
        conn = LinuxConnector(s)
        conn.connect()
        conn.execute_sudo("ip neigh del 192.0.2.51 dev eth0 2>/dev/null")
        conn.execute_sudo("ip neigh del 192.0.2.52 dev eth0 2>/dev/null")
        conn.execute_sudo("nft flush table ip arp_filter 2>/dev/null")
        arp = conn.get_arp_table()
        print("Clean ARP:", len(arp), "entries")
        for e in arp:
            print("  " + e["ip"] + " -> " + e["mac"])
        conn.disconnect()
        break
