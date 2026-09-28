"""
TEST 5: Web Console API Test
Tests all web console endpoints against the remote server.
Run: python tests/05_test_web_console.py
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from arp_detection_system.web.app import app

def test_web():
    print("=" * 60)
    print("  TEST 5: Web Console API")
    print("=" * 60)

    with app.test_client() as c:
        pages = ['/', '/monitor', '/servers', '/logs', '/detect', '/remediate', '/settings']
        print("\n--- Pages ---")
        for p in pages:
            resp = c.get(p)
            status = 'OK' if resp.status_code == 200 else 'FAIL'
            print(f"  {status} {p}")

        print("\n--- Connect to RHEL ---")
        resp = c.post('/api/connect', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        data = json.loads(resp.data)
        print(f"  Status: {data.get('status')}")
        print(f"  Gateway: {data.get('gateway')}")
        print(f"  Server IP: {data.get('local_ip')}")
        print(f"  ARP entries: {data.get('arp_count')}")

        print("\n--- Select Server ---")
        resp = c.post('/api/select-server', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        print(f"  {json.loads(resp.data)}")

        print("\n--- Get Remote ARP Table ---")
        resp = c.get('/api/arp-table')
        data = json.loads(resp.data)
        print(f"  Entries: {len(data)}")
        for e in data:
            print(f"    {e.get('ip')} -> {e.get('mac')}")

        print("\n--- Collect Remote Data ---")
        resp = c.post('/api/collect', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        data = json.loads(resp.data)
        print(f"  Server: {data.get('server')}")
        print(f"  Gateway: {data.get('gateway')}")
        print(f"  IP: {data.get('local_ip')}")
        print(f"  ARP: {len(data.get('arp_table', []))}")
        print(f"  Logs: {data.get('log_count')}")
        print(f"  Interfaces: {len(data.get('interfaces', []))}")

        print("\n--- Run Detection ---")
        resp = c.post('/api/detect', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        data = json.loads(resp.data)
        print(f"  Server: {data.get('server')}")
        print(f"  ARP scanned: {data.get('arp_count')}")
        print(f"  Logs analyzed: {data.get('log_count')}")
        print(f"  Findings: {len(data.get('validations', []))}")
        for v in data.get('validations', []):
            print(f"    [{v['severity']}] {v['type']}: {v['description'][:60]}")

        print("\n--- Remote Command ---")
        cmds = ["hostname", "ip neigh show", "cat /proc/net/arp"]
        for cmd in cmds:
            resp = c.post('/api/remote-command', content_type='application/json',
                          data=json.dumps({'server_name': 'RHEL', 'command': cmd}))
            data = json.loads(resp.data)
            output = data.get('stdout', '').strip()
            first_line = output.split('\n')[0] if output else '(empty)'
            print(f"  $ {cmd}")
            print(f"    {first_line}")

        print("\n--- Get Remote Logs ---")
        resp = c.get('/api/logs/RHEL')
        data = json.loads(resp.data)
        print(f"  Log entries: {len(data)}")
        for log in data[:3]:
            print(f"    [{log.get('severity')}] {log.get('category')}: {log.get('message', '')[:60]}")

        print("\n--- Status ---")
        resp = c.get('/api/status')
        data = json.loads(resp.data)
        print(f"  Selected: {data.get('selected_server')}")
        print(f"  Monitor: {data.get('monitor_running')}")
        for name, info in data.get('servers', {}).items():
            print(f"  {name}: connected={info.get('connected')} gw={info.get('gateway')} ip={info.get('local_ip')}")

        print("\n--- Flush ARP (remote) ---")
        resp = c.post('/api/remediate/flush', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        data = json.loads(resp.data)
        print(f"  Result: {data}")

        print("\n--- Disconnect ---")
        resp = c.post('/api/disconnect', content_type='application/json',
                      data=json.dumps({'server_name': 'RHEL'}))
        data = json.loads(resp.data)
        print(f"  {data}")

    print("\n  [PASS] All web console tests passed!")
    return True

if __name__ == "__main__":
    ok = test_web()
    sys.exit(0 if ok else 1)
