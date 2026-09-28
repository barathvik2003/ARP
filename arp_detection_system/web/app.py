import os
import sys
import json
import time
import threading
from datetime import datetime

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from arp_detection_system.config import Config, load_config, save_config, ServerConfig
from arp_detection_system.core.arp_monitor import ArpMonitor, ArpAlert
from arp_detection_system.core.network_utils import get_arp_table, get_default_gateway, get_local_ip, flush_arp_cache
from arp_detection_system.server.linux_connector import LinuxConnector
from arp_detection_system.server.windows_connector import WindowsConnector
from arp_detection_system.logs.collector import LogCollector
from arp_detection_system.logs.parser import parse_logs, LogSeverity
from arp_detection_system.detection.engine import DetectionEngine, AttackValidation, AttackType, Confidence
from arp_detection_system.remediation.engine import RemediationEngine, RemediationAction, RemediationStatus
from arp_detection_system.utils.logger import get_logger

logger = get_logger("web")

app = Flask(__name__)
app.config["SECRET_KEY"] = "arp-detection-system-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

config = load_config()
connectors = {}
monitor_thread = None
monitor_running = False
alert_buffer = []
detection_results = []
remediation_records = []
selected_server = ""


def get_connector(server_name):
    return connectors.get(server_name)


def get_first_connector():
    if connectors:
        return list(connectors.values())[0]
    return None


def connect_server(server_config):
    try:
        if server_config.os_type == "linux":
            conn = LinuxConnector(server_config)
        elif server_config.os_type == "windows":
            conn = WindowsConnector(server_config)
        else:
            return None

        if conn.connect():
            connectors[server_config.name] = conn
            return conn
    except Exception as e:
        logger.error("Failed to connect to %s: %s", server_config.name, e)
    return None


def disconnect_all():
    for name, conn in connectors.items():
        try:
            conn.disconnect()
        except Exception:
            pass
    connectors.clear()


def get_remote_arp(conn):
    try:
        return conn.get_arp_table()
    except Exception:
        return []


def get_remote_gateway(conn):
    try:
        return conn.get_default_gateway()
    except Exception:
        return ""


def get_remote_ip(conn):
    try:
        ifaces = conn.get_network_interfaces()
        for i in ifaces:
            if i.get("ip") and i["ip"] != "127.0.0.1":
                return i["ip"]
    except Exception:
        pass
    return ""


def get_server_info():
    info = {}
    for s in config.servers:
        conn = connectors.get(s.name)
        connected = conn is not None and conn.is_connected()
        server_info = {
            "connected": connected,
            "host": s.host,
            "os_type": s.os_type,
            "gateway": "",
            "local_ip": "",
            "arp_count": 0,
            "interfaces": [],
        }
        if connected:
            try:
                server_info["gateway"] = get_remote_gateway(conn)
                server_info["local_ip"] = get_remote_ip(conn)
                server_info["arp_count"] = len(get_remote_arp(conn))
                server_info["interfaces"] = conn.get_network_interfaces()
            except Exception as e:
                logger.error("Error getting info for %s: %s", s.name, e)
        info[s.name] = server_info
    return info


@app.route("/")
def dashboard():
    global selected_server
    server_info = get_server_info()

    arp_entries = []
    gateway = ""
    server_ip = ""

    if selected_server and selected_server in connectors:
        conn = connectors[selected_server]
        if conn.is_connected():
            arp_entries = get_remote_arp(conn)
            gateway = get_remote_gateway(conn)
            server_ip = get_remote_ip(conn)
    elif connectors:
        conn = get_first_connector()
        if conn and conn.is_connected():
            first_name = list(connectors.keys())[0]
            selected_server = first_name
            arp_entries = get_remote_arp(conn)
            gateway = get_remote_gateway(conn)
            server_ip = get_remote_ip(conn)

    critical_count = sum(1 for a in alert_buffer if a.get("severity") == "CRITICAL")
    high_count = sum(1 for a in alert_buffer if a.get("severity") == "HIGH")
    medium_count = sum(1 for a in alert_buffer if a.get("severity") == "MEDIUM")

    return render_template("dashboard.html",
        arp_entries=arp_entries,
        gateway=gateway,
        local_ip=server_ip,
        servers=config.servers,
        server_info=server_info,
        selected_server=selected_server,
        alerts=alert_buffer[-20:],
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        total_alerts=len(alert_buffer),
        monitor_running=monitor_running,
        detection_results=detection_results[-10:],
    )


@app.route("/monitor")
def monitor_page():
    return render_template("monitor.html",
        monitor_running=monitor_running,
        alerts=alert_buffer[-50:],
        servers=config.servers,
        selected_server=selected_server,
    )


@app.route("/servers")
def servers_page():
    server_info = get_server_info()
    server_data = []
    for s in config.servers:
        info = server_info.get(s.name, {})
        server_data.append({
            "config": s,
            "connected": info.get("connected", False),
            "arp_count": info.get("arp_count", 0),
            "gateway": info.get("gateway", ""),
            "local_ip": info.get("local_ip", ""),
            "interfaces": info.get("interfaces", []),
        })
    return render_template("servers.html", servers=server_data, selected_server=selected_server)


@app.route("/logs")
def logs_page():
    return render_template("logs.html", alerts=alert_buffer[-100:], servers=config.servers)


@app.route("/detect")
def detect_page():
    return render_template("detect.html",
        detection_results=detection_results,
        servers=config.servers,
        selected_server=selected_server,
    )


@app.route("/remediate")
def remediate_page():
    return render_template("remediate.html",
        servers=config.servers,
        remediation_records=remediation_records[-20:],
        selected_server=selected_server,
    )


@app.route("/settings")
def settings_page():
    return render_template("settings.html", config=config)


@app.route("/api/select-server", methods=["POST"])
def api_select_server():
    global selected_server
    data = request.json
    server_name = data.get("server_name", "")
    if server_name and server_name in connectors:
        selected_server = server_name
        return jsonify({"status": "selected", "server": server_name})
    elif server_name == "":
        selected_server = ""
        return jsonify({"status": "cleared"})
    return jsonify({"error": "Server not connected"}), 400


@app.route("/api/arp-table")
def api_arp_table():
    if selected_server and selected_server in connectors:
        conn = connectors[selected_server]
        if conn.is_connected():
            entries = get_remote_arp(conn)
            return jsonify(entries)
    entries = get_arp_table()
    return jsonify([{"ip": e.ip, "mac": e.mac, "static": e.static} for e in entries])


@app.route("/api/arp-table/<server_name>")
def api_server_arp_table(server_name):
    conn = get_connector(server_name)
    if not conn:
        return jsonify({"error": "Server not connected"}), 400
    try:
        entries = conn.get_arp_table()
        return jsonify(entries)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/connect", methods=["POST"])
def api_connect():
    data = request.json
    server_name = data.get("server_name", "")
    server_config = None
    for s in config.servers:
        if s.name == server_name:
            server_config = s
            break
    if not server_config:
        return jsonify({"error": "Server not found"}), 404

    conn = connect_server(server_config)
    if conn:
        global selected_server
        selected_server = server_name
        return jsonify({
            "status": "connected",
            "server": server_name,
            "gateway": get_remote_gateway(conn),
            "local_ip": get_remote_ip(conn),
            "arp_count": len(get_remote_arp(conn)),
        })
    return jsonify({"error": "Connection failed"}), 500


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    data = request.json
    server_name = data.get("server_name", "")
    conn = connectors.pop(server_name, None)
    if conn:
        try:
            conn.disconnect()
        except Exception:
            pass
        global selected_server
        if selected_server == server_name:
            selected_server = ""
        return jsonify({"status": "disconnected", "server": server_name})
    return jsonify({"error": "Server not connected"}), 400


@app.route("/api/connect-all", methods=["POST"])
def api_connect_all():
    global selected_server
    results = {}
    for s in config.servers:
        conn = connect_server(s)
        results[s.name] = conn is not None
        if conn and not selected_server:
            selected_server = s.name
    return jsonify(results)


@app.route("/api/disconnect-all", methods=["POST"])
def api_disconnect_all():
    disconnect_all()
    global selected_server
    selected_server = ""
    return jsonify({"status": "disconnected"})


@app.route("/api/monitor/start", methods=["POST"])
def api_monitor_start():
    global monitor_thread, monitor_running
    if monitor_running:
        return jsonify({"status": "already running"})

    data = request.json or {}
    server_name = data.get("server_name", selected_server)
    interval = data.get("interval", config.detection.arp_table_poll_interval)

    target_conn = None
    target_gateway = ""
    if server_name and server_name in connectors:
        target_conn = connectors[server_name]
        target_gateway = get_remote_gateway(target_conn)

    if not target_conn:
        target_gateway = data.get("gateway_ip", "") or get_default_gateway() or ""

    monitor = ArpMonitor(
        gateway_ip=target_gateway,
        poll_interval=interval,
        alert_threshold=config.detection.alert_threshold,
        mac_change_sensitivity=config.detection.mac_change_sensitivity,
    )

    def alert_handler(alert):
        alert_dict = {
            "type": alert.alert_type,
            "severity": alert.severity,
            "source_ip": alert.source_ip,
            "source_mac": alert.source_mac,
            "target_ip": alert.target_ip,
            "target_mac": alert.target_mac,
            "description": alert.description,
            "timestamp": alert.timestamp,
            "server": server_name or "local",
        }
        alert_buffer.append(alert_dict)
        if len(alert_buffer) > 500:
            alert_buffer.pop(0)
        socketio.emit("arp_alert", alert_dict)

    monitor.on_alert(alert_handler)
    monitor_running = True

    def run_monitor():
        global monitor_running
        try:
            if target_conn:
                poll_count = 0
                while monitor_running:
                    try:
                        arp_entries = target_conn.get_arp_table()
                        for entry in arp_entries:
                            monitor._known_mappings[entry.get("ip", "")] = entry.get("mac", "")
                        monitor._poll_once()
                    except Exception as e:
                        logger.error("Remote poll error: %s", e)
                    time.sleep(interval)
                    poll_count += 1
            else:
                monitor.start()
        except Exception as e:
            logger.error("Monitor error: %s", e)
        finally:
            monitor_running = False

    monitor_thread = threading.Thread(target=run_monitor, daemon=True)
    monitor_thread.start()

    return jsonify({"status": "started", "server": server_name or "local", "gateway": target_gateway})


@app.route("/api/monitor/stop", methods=["POST"])
def api_monitor_stop():
    global monitor_running
    monitor_running = False
    return jsonify({"status": "stopped"})


@app.route("/api/monitor/status")
def api_monitor_status():
    return jsonify({
        "running": monitor_running,
        "alert_count": len(alert_buffer),
        "selected_server": selected_server,
    })


@app.route("/api/collect", methods=["POST"])
def api_collect():
    data = request.json or {}
    server_name = data.get("server_name", selected_server)

    if not server_name:
        return jsonify({"error": "No server selected"}), 400

    conn = get_connector(server_name)
    if not conn:
        return jsonify({"error": "Server not connected"}), 400

    server_config = None
    for s in config.servers:
        if s.name == server_name:
            server_config = s
            break
    if not server_config:
        return jsonify({"error": "Server config not found"}), 404

    arp_table = get_remote_arp(conn)
    gateway = get_remote_gateway(conn)
    local_ip = get_remote_ip(conn)
    interfaces = []
    log_entries = []

    try:
        interfaces = conn.get_network_interfaces()
    except Exception:
        pass

    if server_config.os_type == "linux":
        try:
            syslog = conn.get_syslog_arp_entries(lines=200)
            log_entries = parse_logs("\n".join(syslog), "linux")
        except Exception:
            pass
        try:
            dmesg = conn.get_dmesg_arp(lines=100)
            log_entries.extend(parse_logs("\n".join(dmesg), "linux", "dmesg"))
        except Exception:
            pass
    else:
        try:
            events = conn.get_event_log_arp()
            raw = "\n".join(e.get("raw", "") for e in events)
            log_entries = parse_logs(raw, "windows")
        except Exception:
            pass

    return jsonify({
        "server": server_name,
        "gateway": gateway,
        "local_ip": local_ip,
        "arp_table": arp_table,
        "interfaces": interfaces,
        "log_count": len(log_entries),
        "logs": [{"severity": l.severity.value, "category": l.category, "message": l.message[:200]} for l in log_entries],
    })


@app.route("/api/detect", methods=["POST"])
def api_detect():
    data = request.json or {}
    server_name = data.get("server_name", selected_server)
    engine = DetectionEngine(config)

    collected = {}

    if server_name and server_name in connectors:
        conn = connectors[server_name]
        if conn.is_connected():
            server_config = None
            for s in config.servers:
                if s.name == server_name:
                    server_config = s
                    break

            if server_config:
                from arp_detection_system.logs.collector import CollectedLogs

                arp_entries = get_remote_arp(conn)
                engine.set_baseline_from_table(arp_entries)

                gateway = get_remote_gateway(conn)
                if gateway:
                    config.detection.gateway_ip = gateway

                data_obj = CollectedLogs(
                    server_name=server_name,
                    os_type=server_config.os_type,
                    arp_table=[{"ip": e.get("ip", ""), "mac": e.get("mac", "")} for e in arp_entries],
                    log_entries=[],
                    timestamp=time.time(),
                )

                if server_config.os_type == "linux":
                    try:
                        syslog = conn.get_syslog_arp_entries(lines=200)
                        data_obj.log_entries = parse_logs("\n".join(syslog), "linux")
                    except Exception:
                        pass
                    try:
                        dmesg = conn.get_dmesg_arp(lines=100)
                        data_obj.log_entries.extend(parse_logs("\n".join(dmesg), "linux", "dmesg"))
                    except Exception:
                        pass
                else:
                    try:
                        events = conn.get_event_log_arp()
                        raw = "\n".join(e.get("raw", "") for e in events)
                        data_obj.log_entries = parse_logs(raw, "windows")
                    except Exception:
                        pass

                collected[server_name] = data_obj

    arp_monitor = ArpMonitor(
        gateway_ip=config.detection.gateway_ip or get_default_gateway() or "",
        poll_interval=1,
        alert_threshold=1,
    )
    arp_alerts = arp_monitor.poll()

    validations = engine.analyze_all(arp_alerts, collected)
    summary = engine.generate_summary(validations)

    results = []
    for v in validations:
        results.append({
            "type": v.attack_type.value,
            "severity": v.severity,
            "confidence": v.confidence.value,
            "attacker_ip": v.attacker_ip,
            "attacker_mac": v.attacker_mac,
            "description": v.description,
            "evidence": v.evidence,
            "recommendations": v.recommendations,
            "requires_action": v.requires_immediate_action,
            "server": server_name,
        })

    detection_results.clear()
    detection_results.extend(results)

    return jsonify({
        "summary": summary,
        "validations": results,
        "server": server_name,
        "arp_count": sum(len(c.arp_table) for c in collected.values()),
        "log_count": sum(len(c.log_entries) for c in collected.values()),
    })


@app.route("/api/remediate/block", methods=["POST"])
def api_remediate_block():
    data = request.json
    target_ip = data.get("ip", "")
    target_mac = data.get("mac", "")
    server_name = data.get("server_name", selected_server)
    reason = data.get("reason", "Manual block via web console")
    if not target_ip:
        return jsonify({"error": "IP required"}), 400

    targets = {server_name: connectors[server_name]} if server_name and server_name in connectors else connectors
    results = {}
    for s_name, conn in targets.items():
        try:
            success = conn.block_ip_arp(target_ip)
            results[s_name] = {"success": success, "backend": getattr(conn, 'firewall_backend', 'unknown')}
            if success:
                remediation_records.append({
                    "action": "BLOCK", "target_ip": target_ip, "target_mac": target_mac,
                    "server": s_name, "status": "SUCCESS",
                    "backend": getattr(conn, 'firewall_backend', 'unknown'),
                    "reason": reason, "timestamp": time.time(),
                })
            else:
                remediation_records.append({
                    "action": "BLOCK", "target_ip": target_ip, "server": s_name,
                    "status": "FAILED", "error": "All block methods failed", "timestamp": time.time(),
                })
        except Exception as e:
            results[s_name] = {"success": False, "error": str(e)}

    return jsonify(results)


@app.route("/api/remediate/unblock", methods=["POST"])
def api_remediate_unblock():
    data = request.json
    target_ip = data.get("ip", "")
    server_name = data.get("server_name", selected_server)
    if not target_ip:
        return jsonify({"error": "IP required"}), 400

    targets = {server_name: connectors[server_name]} if server_name and server_name in connectors else connectors
    results = {}
    for s_name, conn in targets.items():
        try:
            success = conn.unblock_ip_arp(target_ip)
            results[s_name] = success
            if success:
                remediation_records.append({
                    "action": "UNBLOCK", "target_ip": target_ip,
                    "server": s_name, "status": "SUCCESS", "timestamp": time.time(),
                })
        except Exception as e:
            results[s_name] = False

    return jsonify(results)


@app.route("/api/remediate/unblock-all", methods=["POST"])
def api_remediate_unblock_all():
    data = request.json or {}
    server_name = data.get("server_name", selected_server)
    results = {}

    if server_name and server_name in connectors:
        conn = connectors[server_name]
        try:
            results[server_name] = conn.unblock_all() if hasattr(conn, 'unblock_all') else False
        except Exception:
            results[server_name] = False
    else:
        for s_name, conn in connectors.items():
            try:
                results[s_name] = conn.unblock_all() if hasattr(conn, 'unblock_all') else False
            except Exception:
                results[s_name] = False

    remediation_records.append({
        "action": "UNBLOCK_ALL", "server": server_name or "all",
        "status": "SUCCESS", "timestamp": time.time(),
    })
    return jsonify(results)


@app.route("/api/remediate/flush", methods=["POST"])
def api_remediate_flush():
    data = request.json or {}
    server_name = data.get("server_name", selected_server)
    results = {}

    if server_name and server_name in connectors:
        conn = connectors[server_name]
        try:
            results[server_name] = conn.flush_arp_cache()
        except Exception:
            results[server_name] = False
    else:
        for s_name, conn in connectors.items():
            try:
                results[s_name] = conn.flush_arp_cache()
            except Exception:
                results[s_name] = False

    remediation_records.append({
        "action": "FLUSH", "server": server_name or "all",
        "status": "SUCCESS", "timestamp": time.time(),
    })
    return jsonify(results)


@app.route("/api/remediate/isolate", methods=["POST"])
def api_remediate_isolate():
    data = request.json
    server_name = data.get("server_name", selected_server)
    if not server_name:
        return jsonify({"error": "Select a server"}), 400

    conn = get_connector(server_name)
    if not conn:
        return jsonify({"error": "Server not connected"}), 400

    success = conn.isolate_network()
    if success:
        remediation_records.append({
            "action": "ISOLATE", "server": server_name,
            "status": "SUCCESS", "timestamp": time.time(),
        })
    return jsonify({"success": success, "server": server_name})


@app.route("/api/remediate/restore", methods=["POST"])
def api_remediate_restore():
    data = request.json or {}
    server_name = data.get("server_name", selected_server)
    results = {}

    if server_name and server_name in connectors:
        conn = connectors[server_name]
        try:
            results[server_name] = conn.restore_network()
        except Exception:
            results[server_name] = False
    else:
        for s_name, conn in connectors.items():
            try:
                results[s_name] = conn.restore_network()
            except Exception:
                results[s_name] = False

    remediation_records.append({
        "action": "RESTORE", "server": server_name or "all",
        "status": "SUCCESS", "timestamp": time.time(),
    })
    return jsonify(results)


@app.route("/api/remediate/set-static", methods=["POST"])
def api_remediate_set_static():
    data = request.json
    ip = data.get("ip", "")
    mac = data.get("mac", "")
    server_name = data.get("server_name", selected_server)
    if not ip or not mac:
        return jsonify({"error": "IP and MAC required"}), 400
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, 'set_arp_entry'):
        success = conn.set_arp_entry(ip, mac)

    if success:
        remediation_records.append({
            "action": "SET_STATIC", "target_ip": ip, "target_mac": mac,
            "server": server_name, "status": "SUCCESS", "timestamp": time.time(),
        })
    return jsonify({"success": success, "server": server_name})


@app.route("/api/remediate/delete-entry", methods=["POST"])
def api_remediate_delete_entry():
    data = request.json
    ip = data.get("ip", "")
    server_name = data.get("server_name", selected_server)
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, 'delete_arp_entry'):
        success = conn.delete_arp_entry(ip)

    return jsonify({"success": success, "server": server_name})


@app.route("/api/remediate/blackhole", methods=["POST"])
def api_remediate_blackhole():
    data = request.json
    ip = data.get("ip", "")
    server_name = data.get("server_name", selected_server)
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, '_block_ip_neigh'):
        iface = getattr(conn, '_get_default_iface', lambda: "ens34")()
        success = conn._block_ip_neigh(ip, iface)

    if success:
        remediation_records.append({
            "action": "BLACKHOLE", "target_ip": ip,
            "server": server_name, "status": "SUCCESS", "timestamp": time.time(),
        })
    return jsonify({"success": success, "server": server_name})


@app.route("/api/remediate/rate-limit", methods=["POST"])
def api_remediate_rate_limit():
    data = request.json
    max_per_second = data.get("max_per_second", 10)
    server_name = data.get("server_name", selected_server)
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, 'rate_limit_arp'):
        success = conn.rate_limit_arp(max_per_second)

    if success:
        remediation_records.append({
            "action": "RATE_LIMIT", "server": server_name,
            "status": "SUCCESS", "max_per_second": max_per_second,
            "timestamp": time.time(),
        })
    return jsonify({"success": success, "server": server_name, "max_per_second": max_per_second})


@app.route("/api/remediate/isolate-interface", methods=["POST"])
def api_remediate_isolate_interface():
    data = request.json
    interface = data.get("interface", "")
    server_name = data.get("server_name", selected_server)
    if not interface:
        return jsonify({"error": "Interface name required"}), 400
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, 'isolate_interface'):
        success = conn.isolate_interface(interface)

    return jsonify({"success": success, "server": server_name, "interface": interface})


@app.route("/api/remediate/restore-interface", methods=["POST"])
def api_remediate_restore_interface():
    data = request.json
    interface = data.get("interface", "")
    server_name = data.get("server_name", selected_server)
    if not interface:
        return jsonify({"error": "Interface name required"}), 400
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    success = False
    if hasattr(conn, 'restore_interface'):
        success = conn.restore_interface(interface)

    return jsonify({"success": success, "server": server_name, "interface": interface})


@app.route("/api/remediate/firewall-rules")
def api_firewall_rules():
    server_name = request.args.get("server", selected_server)
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    if hasattr(conn, 'check_firewall_rules'):
        return jsonify(conn.check_firewall_rules())
    return jsonify({"error": "Not a Linux server"}), 400


@app.route("/api/remediate/system-info")
def api_system_info():
    server_name = request.args.get("server", selected_server)
    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400

    conn = connectors[server_name]
    if hasattr(conn, 'get_system_info'):
        return jsonify(conn.get_system_info())
    return jsonify({"error": "Not a Linux server"}), 400


@app.route("/api/remediate/history")
def api_remediate_history():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(remediation_records[-limit:])


@app.route("/api/servers/add", methods=["POST"])
def api_server_add():
    data = request.json
    try:
        server = ServerConfig(
            name=data.get("name", ""),
            host=data.get("host", ""),
            os_type=data.get("os_type", "linux"),
            port=int(data.get("port", 22)),
            username=data.get("username", ""),
            password=data.get("password", ""),
            ssh_key_path=data.get("ssh_key_path", ""),
            winrm_port=int(data.get("winrm_port", 5985)),
            winrm_use_ssl=data.get("winrm_use_ssl", False),
        )
        config.servers.append(server)
        save_config(config)
        return jsonify({"status": "added", "server": server.name})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/servers/remove", methods=["POST"])
def api_server_remove():
    data = request.json
    server_name = data.get("name", "")
    conn = connectors.pop(server_name, None)
    if conn:
        try:
            conn.disconnect()
        except Exception:
            pass
    global selected_server
    if selected_server == server_name:
        selected_server = ""
    config.servers = [s for s in config.servers if s.name != server_name]
    save_config(config)
    return jsonify({"status": "removed"})


@app.route("/api/settings", methods=["POST"])
def api_settings_update():
    data = request.json
    try:
        if "detection" in data:
            d = data["detection"]
            config.detection.arp_table_poll_interval = d.get("arp_table_poll_interval", config.detection.arp_table_poll_interval)
            config.detection.gateway_ip = d.get("gateway_ip", config.detection.gateway_ip)
            config.detection.alert_threshold = d.get("alert_threshold", config.detection.alert_threshold)
            config.detection.duplicate_ip_detection = d.get("duplicate_ip_detection", config.detection.duplicate_ip_detection)
            config.detection.gratuitous_arp_detection = d.get("gratuitous_arp_detection", config.detection.gratuitous_arp_detection)
            config.detection.rate_limit_detection = d.get("rate_limit_detection", config.detection.rate_limit_detection)
            config.detection.max_arp_rate_per_second = d.get("max_arp_rate_per_second", config.detection.max_arp_rate_per_second)

        if "remediation" in data:
            r = data["remediation"]
            config.remediation.auto_block = r.get("auto_block", config.remediation.auto_block)
            config.remediation.auto_isolate = r.get("auto_isolate", config.remediation.auto_isolate)
            config.remediation.block_duration_seconds = r.get("block_duration_seconds", config.remediation.block_duration_seconds)
            config.remediation.notify_only = r.get("notify_only", config.remediation.notify_only)

        save_config(config)
        return jsonify({"status": "updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/status")
def api_status():
    server_info = get_server_info()
    return jsonify({
        "servers": server_info,
        "selected_server": selected_server,
        "monitor_running": monitor_running,
        "total_alerts": len(alert_buffer),
    })


@app.route("/api/alerts")
def api_alerts():
    limit = request.args.get("limit", 50, type=int)
    severity = request.args.get("severity", "")
    server_filter = request.args.get("server", "")
    alerts = alert_buffer
    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    if server_filter:
        alerts = [a for a in alerts if a.get("server") == server_filter]
    return jsonify(alerts[-limit:])


@app.route("/api/logs/<server_name>")
def api_server_logs(server_name):
    conn = get_connector(server_name)
    if not conn:
        return jsonify({"error": "Server not connected"}), 400

    server_config = None
    for s in config.servers:
        if s.name == server_name:
            server_config = s
            break

    if not server_config:
        return jsonify({"error": "Config not found"}), 404

    log_entries = []
    if server_config.os_type == "linux":
        try:
            syslog = conn.get_syslog_arp_entries(lines=200)
            log_entries = parse_logs("\n".join(syslog), "linux")
        except Exception:
            pass
        try:
            dmesg = conn.get_dmesg_arp(lines=100)
            log_entries.extend(parse_logs("\n".join(dmesg), "linux", "dmesg"))
        except Exception:
            pass
    else:
        try:
            events = conn.get_event_log_arp(max_events=200)
            raw = "\n".join(e.get("raw", "") for e in events)
            log_entries = parse_logs(raw, "windows", "event")
        except Exception:
            pass

    return jsonify([{
        "severity": l.severity.value,
        "category": l.category,
        "message": l.message[:500],
        "source": l.source,
    } for l in log_entries])


@app.route("/api/remote-command", methods=["POST"])
def api_remote_command():
    data = request.json
    server_name = data.get("server_name", selected_server)
    command = data.get("command", "")

    if not server_name or server_name not in connectors:
        return jsonify({"error": "Server not connected"}), 400
    if not command:
        return jsonify({"error": "No command provided"}), 400

    conn = connectors[server_name]
    result = conn.execute(command)
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.exit_code,
        "duration": result.duration,
    })


@socketio.on("connect")
def handle_connect():
    emit("status", {"monitor_running": monitor_running, "alert_count": len(alert_buffer), "selected_server": selected_server})


@socketio.on("request_arp_table")
def handle_arp_request():
    if selected_server and selected_server in connectors:
        conn = connectors[selected_server]
        entries = get_remote_arp(conn)
        emit("arp_table", entries)
    else:
        entries = get_arp_table()
        emit("arp_table", [{"ip": e.ip, "mac": e.mac} for e in entries])


def create_app():
    return app


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, allow_unsafe_werkzeug=True)
