#!/usr/bin/env python3
"""
ARP Detection System - Main CLI Entry Point

Cross-platform ARP attack detection, validation, remediation, and isolation tool
for Linux and Windows servers.
"""

import argparse
import sys
import time
import signal
import json
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

from .config import Config, load_config, save_config, ServerConfig
from .core.arp_monitor import ArpMonitor, ArpAlert
from .core.network_utils import get_arp_table, get_default_gateway, get_local_ip, flush_arp_cache
from .server.linux_connector import LinuxConnector
from .server.windows_connector import WindowsConnector
from .logs.collector import LogCollector
from .detection.engine import DetectionEngine, AttackValidation, Confidence
from .remediation.engine import RemediationEngine, RemediationAction
from .utils.logger import get_logger

logger = get_logger("main")


def c(text, color=""):
    if not HAS_COLOR or not color:
        return str(text)
    colors = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.BLUE, "magenta": Fore.MAGENTA, "cyan": Fore.CYAN,
        "white": Fore.WHITE, "bright_red": Fore.LIGHTRED_EX,
        "bright_green": Fore.LIGHTGREEN_EX, "bright_yellow": Fore.LIGHTYELLOW_EX,
    }
    return f"{colors.get(color, '')}{text}{Style.RESET_ALL}"


def cmd_monitor(args, config: Config):
    print(c("=" * 60, "cyan"))
    print(c("  ARP Detection System - Real-Time Monitor", "bright_green"))
    print(c("=" * 60, "cyan"))
    print()

    monitor = ArpMonitor(
        gateway_ip=config.detection.gateway_ip or get_default_gateway() or "",
        poll_interval=config.detection.arp_table_poll_interval,
        alert_threshold=config.detection.alert_threshold,
        mac_change_sensitivity=config.detection.mac_change_sensitivity,
    )

    def alert_handler(alert: ArpAlert):
        severity_colors = {
            "CRITICAL": "bright_red", "HIGH": "red",
            "MEDIUM": "yellow", "LOW": "white",
        }
        color = severity_colors.get(alert.severity, "white")
        print()
        print(c(f"  [{alert.severity}] {alert.alert_type}", color))
        print(c(f"  IP: {alert.source_ip}  MAC: {alert.source_mac}", "cyan"))
        print(c(f"  {alert.description}", "white"))
        print()

    monitor.on_alert(alert_handler)

    running = True

    def signal_handler(sig, frame):
        nonlocal running
        print()
        print(c("  Stopping monitor...", "yellow"))
        running = False
        monitor.stop()

    signal.signal(signal.SIGINT, signal_handler)

    try:
        monitor.start()
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()


def cmd_scan(args, config: Config):
    print(c("Scanning local ARP table...", "cyan"))
    entries = get_arp_table()
    gateway = get_default_gateway()
    local_ip = get_local_ip()

    print()
    print(c(f"  Local IP:     {local_ip or 'N/A'}", "cyan"))
    print(c(f"  Gateway:      {gateway or 'N/A'}", "cyan"))
    print(c(f"  ARP entries:  {len(entries)}", "cyan"))
    print()

    if entries:
        print(c("  IP Address          MAC Address", "bright_green"))
        print(c("  " + "-" * 40, "green"))
        for e in entries:
            marker = " <-- gateway" if gateway and e.ip == gateway else ""
            marker += " <-- local" if local_ip and e.ip == local_ip else ""
            print(f"  {e.ip:<20} {e.mac}{c(marker, 'yellow')}")
    else:
        print(c("  No ARP entries found", "yellow"))

    if args.json:
        data = [{"ip": e.ip, "mac": e.mac, "static": e.static} for e in entries]
        print(json.dumps(data, indent=2))


def cmd_connect(args, config: Config):
    print(c("Connecting to configured servers...", "cyan"))
    print()

    collector = LogCollector(config)
    results = collector.connect_all()

    for server_name, success in results.items():
        status = c("CONNECTED", "green") if success else c("FAILED", "red")
        print(f"  {server_name}: {status}")

    if any(results.values()):
        print()
        print(c("Collecting data from connected servers...", "cyan"))
        collected = collector.collect_all()

        for server_name, data in collected.items():
            print()
            print(c(f"  === {server_name} ===", "bright_green"))
            print(f"  ARP entries: {len(data.arp_table)}")
            print(f"  Log entries: {len(data.log_entries)}")
            print(f"  Errors: {len(data.errors)}")

            if data.arp_table:
                print()
                print(c("  ARP Table:", "cyan"))
                for entry in data.arp_table[:10]:
                    print(f"    {entry.get('ip', 'N/A'):<20} {entry.get('mac', 'N/A')}")

            if data.log_entries:
                print()
                print(c(f"  Log entries ({len(data.log_entries)}):", "cyan"))
                for entry in data.log_entries[:5]:
                    print(f"    [{entry.severity.value}] {entry.category}: {entry.message[:80]}")

            if data.errors:
                print()
                print(c("  Errors:", "red"))
                for err in data.errors:
                    print(f"    {err}")

        print()
        print(c("Running detection engine...", "cyan"))
        engine = DetectionEngine(config)
        engine.set_baseline_from_table([
            {"ip": e.get("ip", ""), "mac": e.get("mac", "")}
            for data in collected.values()
            for e in data.arp_table
        ])
        validations = engine.analyze_all([], collected)

        if validations:
            print()
            print(c(f"  Detected {len(validations)} potential issues:", "bright_red"))
            for v in validations:
                color = "bright_red" if v.severity == "CRITICAL" else "red" if v.severity == "HIGH" else "yellow"
                print()
                print(c(f"  [{v.severity}] {v.attack_type.value} (Confidence: {v.confidence.value})", color))
                print(f"    Attacker IP: {v.attacker_ip}")
                print(f"    Description: {v.description}")
                for rec in v.recommendations:
                    print(c(f"    -> {rec}", "cyan"))
        else:
            print(c("  No issues detected", "green"))

        if args.remediate:
            print()
            print(c("Running remediation engine...", "cyan"))
            remediation = RemediationEngine(config)
            for name, data in collected.items():
                for server_config in config.servers:
                    if server_config.name == name:
                        if server_config.os_type == "linux":
                            connector = LinuxConnector(server_config)
                        else:
                            connector = WindowsConnector(server_config)
                        if connector.is_connected() or connector.connect():
                            remediation.register_connector(name, connector)

            remediation.process_validations(validations)

        collector.disconnect_all()


def cmd_detect(args, config: Config):
    print(c("Running ARP detection scan...", "cyan"))
    print()

    gateway = get_default_gateway()
    entries = get_arp_table()
    local_ip = get_local_ip()

    arp_table = [{"ip": e.ip, "mac": e.mac} for e in entries]

    engine = DetectionEngine(config)
    if gateway:
        engine.set_baseline_from_table(arp_table)

    arp_monitor = ArpMonitor(
        gateway_ip=gateway or "",
        poll_interval=1,
        alert_threshold=1,
    )
    arp_alerts = arp_monitor.poll()

    collected = {}
    if args.server:
        server_config = None
        for s in config.servers:
            if s.name == args.server:
                server_config = s
                break

        if server_config:
            collector = LogCollector(config)
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            else:
                connector = WindowsConnector(server_config)

            if connector.connect():
                collector.register_connector = lambda n, c: None
                from .logs.collector import CollectedLogs
                data = CollectedLogs(
                    server_name=server_config.name,
                    os_type=server_config.os_type,
                    arp_table=connector.get_arp_table(),
                    log_entries=[],
                    timestamp=time.time(),
                )
                if server_config.os_type == "linux":
                    syslog_entries = connector.get_syslog_arp_entries()
                    from .logs.parser import parse_logs
                    data.log_entries = parse_logs("\n".join(syslog_entries), "linux")
                else:
                    event_log = connector.get_event_log_arp()
                    from .logs.parser import parse_logs
                    raw = "\n".join(e.get("raw", "") for e in event_log)
                    data.log_entries = parse_logs(raw, "windows")

                collected[server_config.name] = data
                connector.disconnect()

    validations = engine.analyze_all(arp_alerts, collected)

    summary = engine.generate_summary(validations)

    print(c("  Detection Summary", "bright_green"))
    print(c("  " + "=" * 40, "green"))
    print(f"  Total alerts:       {summary['total_alerts']}")
    print(f"  Critical:           {c(summary['by_severity'].get('CRITICAL', 0), 'bright_red')}")
    print(f"  High:               {c(summary['by_severity'].get('HIGH', 0), 'red')}")
    print(f"  Medium:             {c(summary['by_severity'].get('MEDIUM', 0), 'yellow')}")
    print(f"  Low:                {summary['by_severity'].get('LOW', 0)}")
    print()

    if validations:
        print(c("  Detailed Findings", "bright_green"))
        print(c("  " + "=" * 40, "green"))
        for v in validations:
            color = "bright_red" if v.severity == "CRITICAL" else "red" if v.severity == "HIGH" else "yellow"
            print()
            print(c(f"  [{v.severity}] {v.attack_type.value}", color))
            print(f"    IP: {v.attacker_ip}  MAC: {v.attacker_mac}")
            print(f"    {v.description}")
            for ev in v.evidence:
                print(f"    Evidence: {ev}")
            for rec in v.recommendations:
                print(c(f"    -> {rec}", "cyan"))

    if summary["requires_immediate_action"]:
        print()
        print(c("  IMMEDIATE ACTION REQUIRED:", "bright_red"))
        for item in summary["requires_immediate_action"]:
            print(c(f"    {item['type']} from {item['attacker_ip']}", "bright_red"))

    if args.json:
        data = {
            "summary": summary,
            "validations": [
                {
                    "type": v.attack_type.value,
                    "severity": v.severity,
                    "confidence": v.confidence.value,
                    "attacker_ip": v.attacker_ip,
                    "attacker_mac": v.attacker_mac,
                    "description": v.description,
                    "evidence": v.evidence,
                    "recommendations": v.recommendations,
                }
                for v in validations
            ],
        }
        print(json.dumps(data, indent=2))


def cmd_remediate(args, config: Config):
    print(c("ARP Remediation Engine", "bright_green"))
    print()

    if args.unblock:
        print(c(f"Unblocking IP: {args.unblock}", "cyan"))
        for server_config in config.servers:
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            else:
                connector = WindowsConnector(server_config)
            if connector.connect():
                success = connector.unblock_ip_arp(args.unblock)
                status = c("SUCCESS", "green") if success else c("FAILED", "red")
                print(f"  {server_config.name}: {status}")
                connector.disconnect()
        return

    if args.restore:
        print(c("Restoring all network interfaces...", "cyan"))
        for server_config in config.servers:
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            else:
                connector = WindowsConnector(server_config)
            if connector.connect():
                success = connector.restore_network()
                status = c("SUCCESS", "green") if success else c("FAILED", "red")
                print(f"  {server_config.name}: {status}")
                connector.disconnect()
        return

    if args.flush:
        print(c("Flushing ARP cache on all servers...", "cyan"))
        for server_config in config.servers:
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            else:
                connector = WindowsConnector(server_config)
            if connector.connect():
                success = connector.flush_arp_cache()
                status = c("SUCCESS", "green") if success else c("FAILED", "red")
                print(f"  {server_config.name}: {status}")
                connector.disconnect()
        flush_arp_cache()
        print(c("  Local ARP cache: FLUSHED", "green"))
        return

    if args.block_ip:
        print(c(f"Blocking ARP from IP: {args.block_ip}", "cyan"))
        for server_config in config.servers:
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            else:
                connector = WindowsConnector(server_config)
            if connector.connect():
                success = connector.block_ip_arp(args.block_ip)
                status = c("SUCCESS", "green") if success else c("FAILED", "red")
                print(f"  {server_config.name}: {status}")
                connector.disconnect()
        return

    print(c("Remediation options:", "cyan"))
    print("  --block-ip IP     Block ARP from specific IP on all servers")
    print("  --unblock IP      Unblock ARP from specific IP")
    print("  --flush           Flush ARP cache on all servers")
    print("  --restore         Restore all network interfaces")


def cmd_status(args, config: Config):
    print(c("ARP Detection System Status", "bright_green"))
    print(c("=" * 50, "green"))
    print()
    print(f"  Config servers:    {len(config.servers)}")
    print(f"  Poll interval:     {config.detection.arp_table_poll_interval}s")
    print(f"  Gateway:           {config.detection.gateway_ip or get_default_gateway() or 'N/A'}")
    print(f"  Auto-block:        {config.remediation.auto_block}")
    print(f"  Auto-isolate:      {config.remediation.auto_isolate}")
    print(f"  Notify-only:       {config.remediation.notify_only}")
    print()

    print(c("  Testing server connections...", "cyan"))
    for server_config in config.servers:
        if server_config.os_type == "linux":
            connector = LinuxConnector(server_config)
        else:
            connector = WindowsConnector(server_config)

        success = connector.connect()
        status = c("ONLINE", "green") if success else c("OFFLINE", "red")
        print(f"  {server_config.name} ({server_config.host}): {status}")

        if success:
            arp_entries = connector.get_arp_table()
            print(f"    ARP entries: {len(arp_entries)}")
            gateway = connector.get_default_gateway()
            print(f"    Gateway: {gateway}")
            connector.disconnect()


def cmd_config(args, config: Config):
    if args.show:
        import yaml
        print(yaml.dump({
            "servers": [
                {"name": s.name, "host": s.host, "os_type": s.os_type}
                for s in config.servers
            ],
            "detection": {
                "arp_table_poll_interval": config.detection.arp_table_poll_interval,
                "gateway_ip": config.detection.gateway_ip,
                "alert_threshold": config.detection.alert_threshold,
            },
            "remediation": {
                "auto_block": config.remediation.auto_block,
                "auto_isolate": config.remediation.auto_isolate,
                "notify_only": config.remediation.notify_only,
            },
        }, default_flow_style=False))
        return

    if args.init:
        save_config(config)
        print(c(f"Config saved to: {args.config_path or 'config.yaml'}", "green"))


def main():
    parser = argparse.ArgumentParser(
        prog="arp-detect",
        description="ARP Detection System - Detect, Validate, Remediate, and Isolate ARP Attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s monitor                     Start real-time ARP monitoring
  %(prog)s scan                        Scan local ARP table
  %(prog)s detect                      Run ARP detection scan
  %(prog)s detect --server linux-1     Detect on specific server
  %(prog)s connect                     Connect to all configured servers
  %(prog)s remediate --flush           Flush ARP cache on all servers
  %(prog)s remediate --block-ip 192.168.1.50
  %(prog)s status                      Show system status
        """,
    )
    parser.add_argument(
        "-c", "--config", default=None,
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument("--json", action="store_true", help="Output in JSON format")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("monitor", help="Start real-time ARP monitoring")
    subparsers.add_parser("scan", help="Scan local ARP table")

    detect_parser = subparsers.add_parser("detect", help="Run ARP detection")
    detect_parser.add_argument("--server", help="Specific server to detect on")
    detect_parser.add_argument("--remediate", action="store_true", help="Auto-remediate detected issues")

    connect_parser = subparsers.add_parser("connect", help="Connect to servers and analyze")
    connect_parser.add_argument("--remediate", action="store_true", help="Auto-remediate detected issues")

    remediate_parser = subparsers.add_parser("remediate", help="Remediation actions")
    remediate_parser.add_argument("--block-ip", help="Block ARP from IP")
    remediate_parser.add_argument("--unblock", help="Unblock ARP from IP")
    remediate_parser.add_argument("--flush", action="store_true", help="Flush ARP cache")
    remediate_parser.add_argument("--restore", action="store_true", help="Restore network interfaces")

    subparsers.add_parser("status", help="Show system status")

    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_parser.add_argument("--show", action="store_true", help="Show current config")
    config_parser.add_argument("--init", action="store_true", help="Initialize default config")

    args = parser.parse_args()
    config = load_config(args.config)

    if not args.command:
        parser.print_help()
        return

    commands = {
        "monitor": cmd_monitor,
        "scan": cmd_scan,
        "detect": cmd_detect,
        "connect": cmd_connect,
        "remediate": cmd_remediate,
        "status": cmd_status,
        "config": cmd_config,
    }

    cmd_func = commands.get(args.command)
    if cmd_func:
        cmd_func(args, config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
