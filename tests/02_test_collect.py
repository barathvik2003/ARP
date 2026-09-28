"""
TEST 2: Remote ARP Data Collection
Collects ARP table, logs, and network info from remote server.
Run: python tests/02_test_collect.py
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.logs.parser import parse_logs
from arp_detection_system.config import load_config

def test_collect():
    print("=" * 60)
    print("  TEST 2: Remote Data Collection")
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

    print(f"\n  Connected to: {server.name} ({server.host})")

    # 1. ARP Table
    print("\n--- ARP TABLE (from remote /proc/net/arp) ---")
    arp = conn.get_arp_table()
    for e in arp:
        print(f"  {e['ip']:<20} {e['mac']}")
    print(f"  Total: {len(arp)} entries")

    # 2. ip neigh
    print("\n--- IP NEIGH (from remote ip neigh show) ---")
    neigh = conn.get_ip_neigh()
    for n in neigh:
        print(f"  {n['ip']:<20} {n['mac']:<20} state={n['state']} dev={n['interface']}")
    print(f"  Total: {len(neigh)} entries")

    # 3. Gateway
    print("\n--- DEFAULT GATEWAY ---")
    gw = conn.get_default_gateway()
    print(f"  Gateway: {gw or 'N/A'}")

    # 4. Interfaces
    print("\n--- NETWORK INTERFACES ---")
    ifaces = conn.get_network_interfaces()
    for i in ifaces:
        print(f"  {i['name']:<12} IP={i['ip']:<15} MAC={i['mac']}")

    # 5. dmesg ARP
    print("\n--- DMESG ARP LOGS ---")
    dmesg = conn.get_dmesg_arp(30)
    for d in dmesg:
        print(f"  {d[:100]}")
    print(f"  Total: {len(dmesg)} lines")

    # 6. syslog ARP
    print("\n--- SYSLOG ARP ENTRIES ---")
    syslog = conn.get_syslog_arp_entries(30)
    for s in syslog:
        print(f"  {s[:100]}")
    print(f"  Total: {len(syslog)} lines")

    # 7. /proc/net/arp raw
    print("\n--- /proc/net/arp (raw kernel) ---")
    r = conn.execute("cat /proc/net/arp")
    for line in r.stdout.strip().splitlines():
        print(f"  {line}")

    # 8. Parse logs
    print("\n--- PARSED LOG ENTRIES ---")
    all_logs = "\n".join(dmesg + syslog)
    parsed = parse_logs(all_logs, "linux")
    for p in parsed:
        print(f"  [{p.severity.value}] {p.category}: {p.message[:80]}")
    print(f"  Total parsed: {len(parsed)}")

    conn.disconnect()
    print("\n  [PASS] Data collection complete!")
    return True

if __name__ == "__main__":
    ok = test_collect()
    sys.exit(0 if ok else 1)
