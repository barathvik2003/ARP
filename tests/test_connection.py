import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.config import load_config

config = load_config()
for s in config.servers:
    print(f"Server: {s.name}")
    print(f"  Host: {s.host}")
    print(f"  OS: {s.os_type}")
    print(f"  Port: {s.port}")
    print(f"  Username: '{s.username}'")
    has_pass = bool(s.password)
    print(f"  Password: {'(set)' if has_pass else '(EMPTY - need to set!)'}")
    has_key = bool(s.ssh_key_path)
    print(f"  SSH Key: {s.ssh_key_path if has_key else '(not set)'}")
    print(f"  WinRM Port: {s.winrm_port}")
    print()

# Test connectivity
print("=" * 50)
print("Testing connections...")
print("=" * 50)

import socket

for s in config.servers:
    print(f"\n--- {s.host} ---")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        port = s.port if s.os_type == "linux" else s.winrm_port
        result = sock.connect_ex((s.host, port))
        sock.close()
        if result == 0:
            print(f"  TCP port {port}: OPEN (reachable)")
        else:
            print(f"  TCP port {port}: CLOSED/FILTERED (result={result})")
    except Exception as e:
        print(f"  TCP test failed: {e}")

# Try SSH connection
for s in config.servers:
    if s.os_type == "linux":
        print(f"\n--- SSH Test: {s.name} ---")
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs = {"hostname": s.host, "port": s.port, "username": s.username, "timeout": 5}
            if s.ssh_key_path:
                key = os.path.expanduser(s.ssh_key_path)
                if os.path.exists(key):
                    kwargs["key_filename"] = key
                    print(f"  Using key: {key}")
                else:
                    print(f"  Key not found: {key}")
                    continue
            elif s.password:
                kwargs["password"] = s.password
            else:
                print("  No password or SSH key configured!")
                continue
            client.connect(**kwargs)
            print("  SSH CONNECTED!")
            client.close()
        except ImportError:
            print("  paramiko not installed! Run: pip install paramiko")
        except Exception as e:
            print(f"  SSH failed: {e}")

# Try WinRM connection
for s in config.servers:
    if s.os_type == "windows":
        print(f"\n--- WinRM Test: {s.name} ---")
        try:
            import winrm
            protocol = "https" if s.winrm_use_ssl else "http"
            endpoint = f"{protocol}://{s.host}:{s.winrm_port}/wsman"
            print(f"  Endpoint: {endpoint}")
            print(f"  Username: {s.username}")
            if not s.password:
                print("  No password configured!")
                continue
            session = winrm.Session(endpoint, auth=(s.username, s.password))
            result = session.run_cmd("echo ok")
            if result.status_code == 0:
                print("  WINRM CONNECTED!")
            else:
                print(f"  WinRM failed: {result.std_err}")
        except ImportError:
            print("  pywinrm not installed! Run: pip install pywinrm")
        except Exception as e:
            print(f"  WinRM failed: {e}")
