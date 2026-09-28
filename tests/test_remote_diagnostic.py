import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
server = config.servers[0]

print("=" * 60)
print("  REMOTE SERVER DIAGNOSTIC")
print(f"  Server: {server.name} ({server.host})")
print("=" * 60)

# Step 1: Direct SSH test
print("\n[1] DIRECT SSH CONNECTION TEST")
print("-" * 40)
conn = LinuxConnector(server)
ok = conn.connect()
print(f"  Connected: {ok}")
if not ok:
    print("  FAILED - cannot proceed")
    sys.exit(1)

# Step 2: Verify commands execute ON THE REMOTE MACHINE
print("\n[2] VERIFYING REMOTE EXECUTION")
print("-" * 40)

r = conn.execute("hostname")
print(f"  hostname: {r.stdout.strip()}")

r = conn.execute("whoami")
print(f"  whoami: {r.stdout.strip()}")

r = conn.execute("uname -a")
print(f"  uname: {r.stdout.strip()}")

r = conn.execute("ip addr show ens34 | grep 'inet '")
print(f"  ens34 IP: {r.stdout.strip()}")

r = conn.execute("cat /etc/redhat-release")
print(f"  OS: {r.stdout.strip()}")

# Step 3: Check if we get DIFFERENT data than local
print("\n[3] COMPARING REMOTE vs LOCAL")
print("-" * 40)

import socket
local_ip = socket.gethostbyname(socket.gethostname())
print(f"  Local machine IP: {local_ip}")

remote_ip = ""
r = conn.execute("hostname -I")
remote_ip = r.stdout.strip().split()[0] if r.stdout.strip() else "N/A"
print(f"  Remote machine IP: {remote_ip}")

if local_ip != remote_ip:
    print("  -> CONFIRMED: We are executing on the REMOTE machine!")
else:
    print("  -> WARNING: IPs match - might be same machine or VPN")

# Step 4: Collect REMOTE ARP data
print("\n[4] COLLECTING REMOTE ARP DATA")
print("-" * 40)

arp = conn.get_arp_table()
print(f"  Remote ARP entries: {len(arp)}")
for e in arp:
    print(f"    {e['ip']:<20} {e['mac']}")

gw = conn.get_default_gateway()
print(f"  Remote gateway: {gw}")

neigh = conn.get_ip_neigh()
print(f"  Remote neighbors: {len(neigh)}")
for n in neigh:
    print(f"    {n['ip']:<20} {n['mac']:<20} state={n['state']} dev={n['interface']}")

# Step 5: Collect REMOTE logs
print("\n[5] COLLECTING REMOTE LOGS")
print("-" * 40)

dmesg = conn.get_dmesg_arp(50)
print(f"  dmesg ARP lines: {len(dmesg)}")
for d in dmesg[:10]:
    print(f"    {d[:100]}")

syslog = conn.get_syslog_arp_entries(50)
print(f"  syslog ARP lines: {len(syslog)}")
for s in syslog[:10]:
    print(f"    {s[:100]}")

# Step 6: Check REMOTE arptables
print("\n[6] REMOTE ARPTABLES/EBTABLES")
print("-" * 40)
rules = conn.check_arptables_rules()
for r in rules:
    print(f"  {r}")

# Step 7: Check REMOTE /proc/net/arp directly
print("\n[7] REMOTE /proc/net/arp (kernel)")
print("-" * 40)
r = conn.execute("cat /proc/net/arp")
if r.exit_code == 0:
    for line in r.stdout.strip().splitlines():
        print(f"  {line}")

# Step 8: Check REMOTE iptables for ARP rules
print("\n[8] REMOTE iptables ARP rules")
print("-" * 40)
r = conn.execute("iptables -t arp -L -n 2>/dev/null || echo 'no arp table'")
for line in r.stdout.strip().splitlines():
    print(f"  {line}")

# Step 9: Check REMOTE log files
print("\n[9] REMOTE LOG FILES")
print("-" * 40)
r = conn.execute("ls -la /var/log/messages* /var/log/syslog* 2>/dev/null | head -5")
print(f"  Log files: {r.stdout.strip()}")

r = conn.execute("journalctl -k --no-pager 2>/dev/null | grep -i arp | tail -20")
if r.stdout.strip():
    print(f"  journalctl ARP entries:")
    for line in r.stdout.strip().splitlines():
        print(f"    {line}")
else:
    print("  No ARP entries in journalctl")

# Step 10: Test REMOTE remediation (dry run)
print("\n[10] REMEDIATION CAPABILITY TEST")
print("-" * 40)
r = conn.execute("arptables -L -n 2>/dev/null || echo 'arptables not available'")
print(f"  arptables: {r.stdout.strip()}")

r = conn.execute("ip neigh show | head -5")
print(f"  ip neigh: {r.stdout.strip()}")

r = conn.execute("ip neigh flush all 2>/dev/null && echo 'flush OK' || echo 'flush failed'")
print(f"  ARP flush test: {r.stdout.strip()}")

conn.disconnect()

print("\n" + "=" * 60)
print("  DIAGNOSTIC COMPLETE")
print("=" * 60)
