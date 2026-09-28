"""
TEST 1: Basic Connection Test
Verifies SSH connection to your RHEL server works.
Run: python tests/01_test_connection.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.config import load_config

def test_connection():
    print("=" * 60)
    print("  TEST 1: Remote Server Connection")
    print("=" * 60)

    config = load_config()
    server = None
    for s in config.servers:
        if s.name == "RHEL":
            server = s
            break
    if not server:
        server = config.servers[0]
    print(f"\n  Server: {server.name}")
    print(f"  Host:   {server.host}")
    print(f"  OS:     {server.os_type}")
    print(f"  User:   {server.username}")

    conn = LinuxConnector(server)

    print("\n  Connecting via SSH...")
    ok = conn.connect()

    if ok:
        print("  [PASS] SSH connection successful!")

        r = conn.execute("hostname")
        print(f"  Remote hostname: {r.stdout.strip()}")

        r = conn.execute("whoami")
        print(f"  Remote user:     {r.stdout.strip()}")

        r = conn.execute("uname -r")
        print(f"  Remote kernel:   {r.stdout.strip()}")

        r = conn.execute("ip addr show ens34 | grep inet")
        print(f"  Remote IP:       {r.stdout.strip()}")

        conn.disconnect()
        print("\n  [PASS] All connection tests passed!")
        return True
    else:
        print("  [FAIL] Connection failed!")
        print("  Check: host, port, username, password in config.yaml")
        return False

if __name__ == "__main__":
    ok = test_connection()
    sys.exit(0 if ok else 1)
