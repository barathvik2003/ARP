import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
server = config.servers[0]  # RHEL server

print("=" * 60)
print(f"  PRACTICAL DEMO: ARP Detection from Server")
print(f"  Server: {server.name} ({server.host})")
print("=" * 60)

# Connect
conn = LinuxConnector(server)
if not conn.connect():
    print("FAILED to connect!")
    sys.exit(1)

print("\n[1] COLLECTING ARP TABLE...")
print("-" * 40)
arp = conn.get_arp_table()
for e in arp:
    print(f"  {e['ip']:<20} {e['mac']}")

print(f"\n  Total ARP entries: {len(arp)}")

print("\n[2] COLLECTING ip neigh (detailed)...")
print("-" * 40)
neigh = conn.get_ip_neigh()
for e in neigh:
    print(f"  {e['ip']:<20} {e['mac']:<20} state={e['state']} dev={e['interface']}")

print("\n[3] GETTING DEFAULT GATEWAY...")
print("-" * 40)
gw = conn.get_default_gateway()
print(f"  Gateway: {gw or 'N/A'}")

print("\n[4] GETTING NETWORK INTERFACES...")
print("-" * 40)
ifaces = conn.get_network_interfaces()
for i in ifaces:
    print(f"  {i['name']:<10} IP={i['ip']:<15} MAC={i['mac']}")

print("\n[5] COLLECTING ARP-RELATED LOGS (dmesg)...")
print("-" * 40)
dmesg = conn.get_dmesg_arp(lines=30)
if dmesg:
    for line in dmesg:
        print(f"  {line}")
else:
    print("  (no ARP entries in dmesg)")

print("\n[6] COLLECTING ARP-RELATED LOGS (syslog)...")
print("-" * 40)
syslog = conn.get_syslog_arp_entries(lines=30)
if syslog:
    for line in syslog:
        print(f"  {line}")
else:
    print("  (no ARP entries in syslog)")

print("\n[7] CHECKING arptables RULES...")
print("-" * 40)
rules = conn.check_arptables_rules()
for r in rules:
    print(f"  {r}")

print("\n[8] CHECKING ARP CACHE FROM KERNEL...")
print("-" * 40)
result = conn.execute("cat /proc/net/arp")
if result.exit_code == 0:
    for line in result.stdout.strip().splitlines():
        print(f"  {line}")

print("\n[9] CHECKING NETWORK INTERFACE STATS...")
print("-" * 40)
result = conn.execute("cat /proc/net/dev")
if result.exit_code == 0:
    for line in result.stdout.strip().splitlines()[:10]:
        print(f"  {line}")

print("\n[10] RUNNING ARP DETECTION ANALYSIS...")
print("-" * 40)
from arp_detection_system.logs.parser import parse_logs
from arp_detection_system.detection.engine import DetectionEngine

# Parse collected logs
all_logs = "\n".join(dmesg + syslog)
parsed = parse_logs(all_logs, "linux")
print(f"  Parsed log entries: {len(parsed)}")
for p in parsed:
    print(f"    [{p.severity.value}] {p.category}: {p.message[:80]}")

# Run detection engine
engine = DetectionEngine(config)
engine.set_baseline_from_table(arp)
arp_alerts = []  # Would be from live monitor
from arp_detection_system.logs.collector import CollectedLogs
collected = CollectedLogs(
    server_name=server.name,
    os_type="linux",
    arp_table=arp,
    log_entries=parsed,
    timestamp=time.time(),
)
validations = engine.analyze_all(arp_alerts, {server.name: collected})
summary = engine.generate_summary(validations)

print(f"\n  DETECTION RESULTS:")
print(f"  Total findings: {summary['total_alerts']}")
print(f"  Critical: {summary['by_severity'].get('CRITICAL', 0)}")
print(f"  High: {summary['by_severity'].get('HIGH', 0)}")
print(f"  Medium: {summary['by_severity'].get('MEDIUM', 0)}")

if validations:
    for v in validations:
        print(f"\n  [{v.severity}] {v.attack_type.value}")
        print(f"    IP: {v.attacker_ip}  MAC: {v.attacker_mac}")
        print(f"    {v.description}")
else:
    print("\n  No ARP attacks detected - network appears clean!")

conn.disconnect()
print("\n" + "=" * 60)
print("  PRACTICAL DEMO COMPLETE")
print("=" * 60)
