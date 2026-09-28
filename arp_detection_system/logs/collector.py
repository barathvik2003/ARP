import time
import threading
from typing import Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field

from ..config import Config, ServerConfig
from ..utils.logger import get_logger

if TYPE_CHECKING:
    from ..server.linux_connector import LinuxConnector
    from ..server.windows_connector import WindowsConnector

from ..server.linux_connector import LinuxConnector
from ..server.windows_connector import WindowsConnector
from .parser import parse_logs, ParsedLogEntry, LogSeverity

logger = get_logger("log_collector")


@dataclass
class CollectedLogs:
    server_name: str
    os_type: str
    arp_table: List[Dict[str, str]]
    log_entries: List[ParsedLogEntry]
    syslog_entries: List[ParsedLogEntry] = field(default_factory=list)
    timestamp: float = 0.0
    errors: List[str] = field(default_factory=list)


class LogCollector:
    def __init__(self, config: Config):
        self.config = config
        self._connectors: Dict[str, "LinuxConnector | WindowsConnector"] = {}
        self._collected: Dict[str, CollectedLogs] = {}
        self._lock = threading.Lock()

    def connect_all(self) -> Dict[str, bool]:
        results = {}
        for server_config in self.config.servers:
            if server_config.os_type == "linux":
                connector = LinuxConnector(server_config)
            elif server_config.os_type == "windows":
                connector = WindowsConnector(server_config)
            else:
                logger.error("Unknown OS type: %s for server %s", server_config.os_type, server_config.name)
                results[server_config.name] = False
                continue

            success = connector.connect()
            results[server_config.name] = success

            if success:
                with self._lock:
                    self._connectors[server_config.name] = connector
            else:
                logger.error("Failed to connect to server: %s", server_config.name)

        return results

    def disconnect_all(self):
        with self._lock:
            for name, connector in self._connectors.items():
                try:
                    connector.disconnect()
                except Exception as e:
                    logger.error("Error disconnecting from %s: %s", name, e)
            self._connectors.clear()

    def collect_from_server(self, server_name: str) -> Optional[CollectedLogs]:
        with self._lock:
            connector = self._connectors.get(server_name)

        if not connector:
            logger.error("No connector for server: %s", server_name)
            return None

        server_config = None
        for s in self.config.servers:
            if s.name == server_name:
                server_config = s
                break

        if not server_config:
            return None

        collected = CollectedLogs(
            server_name=server_name,
            os_type=server_config.os_type,
            arp_table=[],
            log_entries=[],
            timestamp=time.time(),
        )

        try:
            arp_entries = connector.get_arp_table()
            collected.arp_table = arp_entries
            logger.info("Collected %d ARP entries from %s", len(arp_entries), server_name)
        except Exception as e:
            collected.errors.append(f"ARP table collection failed: {e}")
            logger.error("Failed to collect ARP table from %s: %s", server_name, e)

        try:
            if server_config.os_type == "linux":
                self._collect_linux_logs(connector, collected, server_name)
            elif server_config.os_type == "windows":
                self._collect_windows_logs(connector, collected, server_name)
        except Exception as e:
            collected.errors.append(f"Log collection failed: {e}")
            logger.error("Failed to collect logs from %s: %s", server_name, e)

        with self._lock:
            self._collected[server_name] = collected

        return collected

    def collect_all(self) -> Dict[str, CollectedLogs]:
        results = {}
        with self._lock:
            server_names = list(self._connectors.keys())

        for name in server_names:
            collected = self.collect_from_server(name)
            if collected:
                results[name] = collected

        return results

    def _collect_linux_logs(
        self,
        connector: "LinuxConnector",
        collected: CollectedLogs,
        server_name: str,
    ):
        syslog_result = connector.get_syslog_arp_entries(lines=200)
        if syslog_result:
            content = "\n".join(syslog_result)
            parsed = parse_logs(content, "linux", "syslog")
            collected.log_entries.extend(parsed)
            collected.syslog_entries.extend(parsed)
            logger.info("Parsed %d syslog ARP entries from %s", len(parsed), server_name)

        dmesg_result = connector.get_dmesg_arp(lines=100)
        if dmesg_result:
            content = "\n".join(dmesg_result)
            parsed = parse_logs(content, "linux", "dmesg")
            collected.log_entries.extend(parsed)
            logger.info("Parsed %d dmesg ARP entries from %s", len(parsed), server_name)

        arptables_rules = connector.check_arptables_rules()
        if arptables_rules:
            collected.metadata = {"arptables_rules": arptables_rules}

    def _collect_windows_logs(
        self,
        connector: "WindowsConnector",
        collected: CollectedLogs,
        server_name: str,
    ):
        event_log = connector.get_event_log_arp(max_events=200)
        if event_log:
            raw_content = "\n".join(e.get("raw", "") for e in event_log)
            parsed = parse_logs(raw_content, "windows", "event")
            collected.log_entries.extend(parsed)
            logger.info("Parsed %d Windows event log entries from %s", len(parsed), server_name)

        arp_cache = connector.get_arp_cache()
        if arp_cache:
            collected.arp_table.extend(arp_cache)

    def get_collected(self) -> Dict[str, CollectedLogs]:
        with self._lock:
            return dict(self._collected)

    def get_high_severity_logs(self) -> List[ParsedLogEntry]:
        high_severity = []
        with self._lock:
            for collected in self._collected.values():
                for entry in collected.log_entries:
                    if entry.severity in (LogSeverity.HIGH, LogSeverity.CRITICAL):
                        high_severity.append(entry)
        return high_severity

    def test_all_connections(self) -> Dict[str, bool]:
        results = {}
        with self._lock:
            for name, connector in self._connectors.items():
                try:
                    results[name] = connector.test_connectivity()
                except Exception:
                    results[name] = False
        return results
