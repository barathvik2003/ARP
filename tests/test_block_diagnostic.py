import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

config = load_config()
server = config.servers[0]
conn = LinuxConnector(server)
conn.connect()

print("=" * 60)
print("  DIAGNOSING ARP BLOCK ISSUE")
print("=" * 60)

# Check what firewall tools are available
print("\n[1] CHECKING AVAILABLE TOOLS")
tools = ["arptables", "ebtables", "iptables", "nft", "firewall-cmd"]
for tool in tools:
    r = conn.execute(f"which {tool} 2>/dev/null || echo 'NOT FOUND'")
    status = "FOUND" if "NOT FOUND" not in r.stdout else "NOT FOUND"
    path = r.stdout.strip() if "NOT FOUND" not in r.stdout else ""
    print(f"  {tool:<15} {status} {path}")

# Check OS version
print("\n[2] OS VERSION")
r = conn.execute("cat /etc/redhat-release")
print(f"  {r.stdout.strip()}")

# Check if nftables is the backend
print("\n[3] NFTABLES CHECK")
r = conn.execute("nft list ruleset 2>/dev/null | head -20")
if r.stdout.strip():
    print(f"  nftables rules:\n{r.stdout}")
else:
    print(f"  No nft rules or nft not available")
    if r.stderr:
        print(f"  stderr: {r.stderr.strip()}")

# Check iptables
print("\n[4] IPTABLES CHECK")
r = conn.execute("iptables -L -n 2>/dev/null | head -10")
print(f"  iptables:\n{r.stdout.strip()}")

# Check iptables arp table
print("\n[5] IPTABLES ARP TABLE")
r = conn.execute("iptables -t arp -L -n 2>/dev/null")
print(f"  Result: {r.stdout.strip() or '(empty)'}")
if r.stderr:
    print(f"  Error: {r.stderr.strip()}")

# Check arptables
print("\n[6] ARPTABLES CHECK")
r = conn.execute("arptables -L -n 2>/dev/null")
print(f"  Result: {r.stdout.strip() or '(empty)'}")
if r.stderr:
    print(f"  Error: {r.stderr.strip()}")

# Check ebtables
print("\n[7] EBTABLES CHECK")
r = conn.execute("ebtables -L 2>/dev/null")
print(f"  Result: {r.stdout.strip() or '(empty)'}")
if r.stderr:
    print(f"  Error: {r.stderr.strip()}")

# Try different block methods
print("\n[8] TESTING BLOCK METHODS")
test_ip = "192.0.2.50"

print(f"\n  Method A: iptables -t arp")
r = conn.execute(f"iptables -t arp -A INPUT -s {test_ip} -j DROP 2>&1")
print(f"    Result: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    conn.execute(f"iptables -t arp -D INPUT -s {test_ip} -j DROP 2>/dev/null")

print(f"\n  Method B: ebtables -t arp")
r = conn.execute(f"ebtables -t arp -A INPUT --arp-ip-src {test_ip} -j DROP 2>&1")
print(f"    Result: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    conn.execute(f"ebtables -t arp -D INPUT --arp-ip-src {test_ip} -j DROP 2>/dev/null")

print(f"\n  Method C: nft add rule")
r = conn.execute(f'nft add rule ip arp input ip saddr {test_ip} drop 2>&1')
print(f"    Result: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    conn.execute(f'nft delete rule ip arp input handle 1 2>/dev/null')

print(f"\n  Method D: iptables layer 2")
r = conn.execute(f"iptables -A INPUT -s {test_ip} -j DROP 2>&1")
print(f"    Result: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    conn.execute(f"iptables -D INPUT -s {test_ip} -j DROP 2>/dev/null")

print(f"\n  Method E: ip neigh replace (ARP table poisoning)")
r = conn.execute(f"ip neigh replace {test_ip} lladdr 00:00:00:00:00:00 dev ens34 nud permanent 2>&1")
print(f"    Result: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    conn.execute(f"ip neigh del {test_ip} dev ens34 2>/dev/null")

# Check kernel modules
print("\n[9] KERNEL MODULES")
r = conn.execute("lsmod | grep -i 'arp\\|ebt\\|nf\\|table' 2>/dev/null | head -10")
print(f"  {r.stdout.strip() or '(none found)'}")

# Check if we can at least modify ARP table directly
print("\n[10] DIRECT ARP TABLE MODIFICATION")
r = conn.execute("ip neigh show dev ens34")
print(f"  Current ARP: {r.stdout.strip()}")
r = conn.execute(f"ip neigh replace 192.0.2.99 lladdr 00:00:00:00:00:00 dev ens34 nud permanent 2>&1")
print(f"  Add test entry: {r.stdout.strip()} {r.stderr.strip()}")
if r.exit_code == 0:
    r = conn.execute("ip neigh show dev ens34")
    print(f"  ARP after: {r.stdout.strip()}")
    conn.execute("ip neigh del 192.0.2.99 dev ens34 2>/dev/null")
    print(f"  Cleaned up")

conn.disconnect()
print("\n" + "=" * 60)
print("  DIAGNOSIS COMPLETE")
print("=" * 60)
