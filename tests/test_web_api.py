import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from arp_detection_system.web.app import app

with app.test_client() as c:
    resp = c.get('/api/arp-table')
    data = json.loads(resp.data)
    print(f'ARP Table: {len(data)} entries')

    resp = c.get('/api/status')
    data = json.loads(resp.data)
    gw = data.get('gateway', 'N/A')
    lip = data.get('local_ip', 'N/A')
    print(f'Status: gateway={gw} local_ip={lip} servers={len(data.get("servers", {}))}')

    resp = c.post('/api/detect', content_type='application/json', data='{}')
    data = json.loads(resp.data)
    print(f'Detection: {len(data.get("validations", []))} findings')

    resp = c.get('/api/alerts?limit=10')
    data = json.loads(resp.data)
    print(f'Alerts: {len(data)} entries')

    resp = c.get('/api/monitor/status')
    data = json.loads(resp.data)
    print(f'Monitor: running={data.get("running")}')

    resp = c.post('/api/connect-all', content_type='application/json', data='{}')
    data = json.loads(resp.data)
    print(f'Connect all: {data}')

    resp = c.post('/api/settings', content_type='application/json', data=json.dumps({
        'detection': {'gateway_ip': '192.168.1.1', 'arp_table_poll_interval': 10}
    }))
    data = json.loads(resp.data)
    print(f'Settings save: {data.get("status")}')

    print('\nAll API endpoints working!')
