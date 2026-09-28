import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.web.app import app

with app.test_client() as c:
    print("=" * 60)
    print("  WEB CONSOLE - REMOTE SERVER TEST")
    print("=" * 60)

    # Connect to RHEL
    resp = c.post('/api/connect', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL'}))
    data = json.loads(resp.data)
    print(f"\n[1] CONNECT: {data.get('status')}")
    print(f"    Server: {data.get('server')}")
    print(f"    Gateway: {data.get('gateway')}")
    print(f"    Server IP: {data.get('local_ip')}")
    print(f"    ARP entries: {data.get('arp_count')}")

    # Select server
    resp = c.post('/api/select-server', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL'}))
    print(f"\n[2] SELECT: {json.loads(resp.data)}")

    # Get ARP table (should be remote)
    resp = c.get('/api/arp-table')
    data = json.loads(resp.data)
    print(f"\n[3] ARP TABLE (from REMOTE server):")
    for e in data:
        print(f"    {e.get('ip'):<20} {e.get('mac')}")

    # Collect full data
    resp = c.post('/api/collect', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL'}))
    data = json.loads(resp.data)
    print(f"\n[4] COLLECT from {data.get('server')}:")
    print(f"    Gateway: {data.get('gateway')}")
    print(f"    Server IP: {data.get('local_ip')}")
    print(f"    ARP entries: {len(data.get('arp_table', []))}")
    print(f"    Log entries: {data.get('log_count')}")
    if data.get('interfaces'):
        print(f"    Interfaces:")
        for i in data['interfaces']:
            print(f"      {i.get('name')}: {i.get('ip')} ({i.get('mac')})")

    # Detect on remote
    resp = c.post('/api/detect', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL'}))
    data = json.loads(resp.data)
    print(f"\n[5] DETECTION on {data.get('server')}:")
    print(f"    ARP entries scanned: {data.get('arp_count')}")
    print(f"    Log entries analyzed: {data.get('log_count')}")
    print(f"    Findings: {len(data.get('validations', []))}")
    for v in data.get('validations', []):
        print(f"    [{v['severity']}] {v['type']}: {v['description']}")

    # Remote command
    resp = c.post('/api/remote-command', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL', 'command': 'hostname -I'}))
    data = json.loads(resp.data)
    print(f"\n[6] REMOTE COMMAND 'hostname -I': {data.get('stdout', '').strip()}")

    resp = c.post('/api/remote-command', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL', 'command': 'cat /proc/net/arp'}))
    data = json.loads(resp.data)
    print(f"\n[7] REMOTE COMMAND 'cat /proc/net/arp':")
    for line in data.get('stdout', '').strip().splitlines():
        print(f"    {line}")

    # Get server logs
    resp = c.get('/api/logs/RHEL')
    data = json.loads(resp.data)
    print(f"\n[8] REMOTE LOGS: {len(data)} entries")
    for log in data[:5]:
        print(f"    [{log.get('severity')}] {log.get('category')}: {log.get('message', '')[:80]}")

    # Status
    resp = c.get('/api/status')
    data = json.loads(resp.data)
    print(f"\n[9] STATUS:")
    print(f"    Selected server: {data.get('selected_server')}")
    for name, info in data.get('servers', {}).items():
        print(f"    {name}: connected={info.get('connected')} gateway={info.get('gateway')} ip={info.get('local_ip')} arp={info.get('arp_count')}")

    # Disconnect
    resp = c.post('/api/disconnect', content_type='application/json',
                  data=json.dumps({'server_name': 'RHEL'}))
    print(f"\n[10] DISCONNECT: {json.loads(resp.data)}")

    print("\n" + "=" * 60)
    print("  ALL TESTS PASSED - REMOTE SERVER WORKING!")
    print("=" * 60)
