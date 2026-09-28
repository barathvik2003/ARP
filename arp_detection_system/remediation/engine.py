import time
import threading
import json
from typing import Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field, asdict
from enum import Enum

from ..config import Config
from ..detection.engine import AttackValidation, AttackType, Confidence
from ..utils.logger import get_logger, get_audit_logger

if TYPE_CHECKING:
    from ..server.linux_connector import LinuxConnector
    from ..server.windows_connector import WindowsConnector

logger = get_logger("remediation")
audit = get_audit_logger()


class RemediationAction(Enum):
    BLOCK_ARP = "block_arp"
    UNBLOCK_ARP = "unblock_arp"
    FLUSH_ARP = "flush_arp"
    ISOLATE_HOST = "isolate_host"
    ISOLATE_INTERFACE = "isolate_interface"
    RESTORE_NETWORK = "restore_network"
    RATE_LIMIT = "rate_limit"
    SET_STATIC_ARP = "set_static_arp"
    DELETE_ARP_ENTRY = "delete_arp_entry"
    BLACKHOLE = "blackhole"
    NOTIFY = "notify"
    LOG_ONLY = "log_only"


class RemediationStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class RemediationRecord:
    target_ip: str
    target_mac: str
    server_name: str
    action: RemediationAction
    status: RemediationStatus = RemediationStatus.PENDING
    reason: str = ""
    timestamp: float = 0.0
    completed_at: float = 0.0
    error: str = ""
    auto_triggered: bool = False
    interface: str = ""
    backend_used: str = ""
    rollback_data: str = ""

    def to_dict(self):
        return {
            "target_ip": self.target_ip,
            "target_mac": self.target_mac,
            "server_name": self.server_name,
            "action": self.action.value,
            "status": self.status.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "completed_at": self.completed_at,
            "error": self.error,
            "auto_triggered": self.auto_triggered,
            "interface": self.interface,
            "backend_used": self.backend_used,
            "rollback_data": self.rollback_data,
        }


class RemediationEngine:
    def __init__(self, config: Config):
        self.config = config
        self._connectors: Dict[str, "LinuxConnector | WindowsConnector"] = {}
        self._records: List[RemediationRecord] = []
        self._lock = threading.Lock()
        self._blocked_ips: Dict[str, float] = {}  # IP -> unblock_time
        self._rollback_stack: List[RemediationRecord] = []

    def register_connector(self, server_name: str, connector):
        with self._lock:
            self._connectors[server_name] = connector

    # ─── Manual Actions ──────────────────────────────────────────

    def block_ip(self, server_name: str, target_ip: str, target_mac: str = "",
                 reason: str = "Manual block") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record(target_ip, target_mac, server_name,
                                     RemediationAction.BLOCK_ARP, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record(target_ip, target_mac, server_name,
                                   RemediationAction.BLOCK_ARP, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            # Capture state before blocking for rollback
            entry_before = None
            if hasattr(conn, 'get_arp_entry'):
                entry_before = conn.get_arp_entry(target_ip)
                if entry_before:
                    record.rollback_data = json.dumps(entry_before)

            backend = getattr(conn, 'firewall_backend', 'unknown')
            success = conn.block_ip_arp(target_ip)
            record.backend_used = backend

            if success:
                record.status = RemediationStatus.SUCCESS
                self._blocked_ips[target_ip] = time.time() + self.config.remediation.block_duration_seconds
                audit.info("BLOCKED ARP from %s on %s via %s", target_ip, server_name, backend)
                logger.warning("Blocked ARP from %s on %s via %s", target_ip, server_name, backend)
            else:
                record.status = RemediationStatus.FAILED
                record.error = "All block methods failed"

        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def unblock_ip(self, server_name: str, target_ip: str,
                   reason: str = "Manual unblock") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record(target_ip, "", server_name,
                                     RemediationAction.UNBLOCK_ARP, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record(target_ip, "", server_name,
                                   RemediationAction.UNBLOCK_ARP, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            success = conn.unblock_ip_arp(target_ip)
            if success:
                record.status = RemediationStatus.SUCCESS
                with self._lock:
                    self._blocked_ips.pop(target_ip, None)
                audit.info("UNBLOCKED ARP from %s on %s", target_ip, server_name)
            else:
                record.status = RemediationStatus.FAILED
                record.error = "Unblock returned false"

        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def flush_cache(self, server_name: str, reason: str = "Manual flush") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record("", "", server_name,
                                     RemediationAction.FLUSH_ARP, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record("", "", server_name,
                                   RemediationAction.FLUSH_ARP, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            success = conn.flush_arp_cache()
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("FLUSHED ARP cache on %s", server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def isolate_host(self, server_name: str, interface: str = "",
                     reason: str = "Manual isolation") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record("", "", server_name,
                                     RemediationAction.ISOLATE_HOST, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record("", "", server_name,
                                   RemediationAction.ISOLATE_HOST, reason=reason,
                                   interface=interface)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            success = conn.isolate_network(interface)
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.warning("ISOLATED network on %s (interface: %s)", server_name, interface or "default")
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
            self._rollback_stack.append(record)
        return record

    def restore_host(self, server_name: str, interface: str = "",
                     reason: str = "Manual restore") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record("", "", server_name,
                                     RemediationAction.RESTORE_NETWORK, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record("", "", server_name,
                                   RemediationAction.RESTORE_NETWORK, reason=reason,
                                   interface=interface)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            success = conn.restore_network(interface)
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("RESTORED network on %s", server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def set_static_arp(self, server_name: str, target_ip: str, target_mac: str,
                       reason: str = "Static ARP entry") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record(target_ip, target_mac, server_name,
                                     RemediationAction.SET_STATIC_ARP, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record(target_ip, target_mac, server_name,
                                   RemediationAction.SET_STATIC_ARP, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            if hasattr(conn, 'set_arp_entry'):
                success = conn.set_arp_entry(target_ip, target_mac)
            else:
                success = False
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("Set static ARP %s -> %s on %s", target_ip, target_mac, server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def delete_arp_entry(self, server_name: str, target_ip: str,
                         reason: str = "Delete ARP entry") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record(target_ip, "", server_name,
                                     RemediationAction.DELETE_ARP_ENTRY, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record(target_ip, "", server_name,
                                   RemediationAction.DELETE_ARP_ENTRY, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            if hasattr(conn, 'delete_arp_entry'):
                success = conn.delete_arp_entry(target_ip)
            else:
                success = False
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("Deleted ARP entry for %s on %s", target_ip, server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def blackhole_ip(self, server_name: str, target_ip: str,
                     reason: str = "Blackhole ARP") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record(target_ip, "", server_name,
                                     RemediationAction.BLACKHOLE, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record(target_ip, "", server_name,
                                   RemediationAction.BLACKHOLE, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            if hasattr(conn, '_block_ip_neigh'):
                iface = getattr(conn, '_get_default_iface', lambda: "ens34")()
                success = conn._block_ip_neigh(target_ip, iface)
            else:
                success = False
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("Blackholed ARP for %s on %s", target_ip, server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def apply_rate_limit(self, server_name: str, max_per_second: int = 10,
                         reason: str = "ARP rate limiting") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record("", "", server_name,
                                     RemediationAction.RATE_LIMIT, RemediationStatus.FAILED,
                                     error="Server not connected")

        record = self._make_record("", "", server_name,
                                   RemediationAction.RATE_LIMIT, reason=reason)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            if hasattr(conn, 'rate_limit_arp'):
                success = conn.rate_limit_arp(max_per_second)
            else:
                success = False
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.info("Applied ARP rate limit %d/s on %s", max_per_second, server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    def isolate_interface(self, server_name: str, interface: str,
                          reason: str = "Interface isolation") -> RemediationRecord:
        conn = self._connectors.get(server_name)
        if not conn:
            return self._make_record("", "", server_name,
                                     RemediationAction.ISOLATE_INTERFACE, RemediationStatus.FAILED,
                                     error="Server not connected", interface=interface)

        record = self._make_record("", "", server_name,
                                   RemediationAction.ISOLATE_INTERFACE, reason=reason,
                                   interface=interface)
        record.status = RemediationStatus.IN_PROGRESS
        record.timestamp = time.time()

        try:
            if hasattr(conn, 'isolate_interface'):
                success = conn.isolate_interface(interface)
            else:
                success = False
            record.status = RemediationStatus.SUCCESS if success else RemediationStatus.FAILED
            if success:
                audit.warning("ISOLATED interface %s on %s", interface, server_name)
        except Exception as e:
            record.status = RemediationStatus.FAILED
            record.error = str(e)

        record.completed_at = time.time()
        with self._lock:
            self._records.append(record)
        return record

    # ─── Automated Detection Response ────────────────────────────

    def process_validations(self, validations: List[AttackValidation]) -> List[RemediationRecord]:
        records = []
        for validation in validations:
            record = self._decide_and_execute(validation)
            if record:
                records.append(record)
        return records

    def _decide_and_execute(self, validation: AttackValidation) -> Optional[RemediationRecord]:
        action = self._determine_action(validation)

        if action == RemediationAction.LOG_ONLY:
            audit.info(
                "ARP anomaly detected but no auto-action: %s from %s (%s)",
                validation.attack_type.value, validation.attacker_ip, validation.severity,
            )
            return None

        if action == RemediationAction.NOTIFY:
            self._send_notification(validation)
            return None

        server_name = self._find_server_for_ip(validation.attacker_ip)
        if not server_name:
            return None

        record = self.block_ip(
            server_name, validation.attacker_ip, validation.attacker_mac,
            reason=f"{validation.attack_type.value}: {validation.description}"
        )
        record.auto_triggered = self.config.remediation.auto_block
        return record

    def _determine_action(self, validation: AttackValidation) -> RemediationAction:
        if self.config.remediation.notify_only:
            if validation.severity == "CRITICAL":
                return RemediationAction.BLOCK_ARP if self.config.remediation.auto_block else RemediationAction.NOTIFY
            return RemediationAction.NOTIFY

        if validation.requires_immediate_action and self.config.remediation.auto_block:
            if self.config.remediation.auto_isolate:
                return RemediationAction.ISOLATE_HOST
            return RemediationAction.BLOCK_ARP

        if validation.severity == "CRITICAL" and self.config.remediation.auto_block:
            return RemediationAction.BLOCK_ARP

        if validation.severity == "HIGH":
            if self.config.remediation.auto_block:
                return RemediationAction.BLOCK_ARP
            return RemediationAction.FLUSH_ARP

        if validation.severity == "MEDIUM":
            return RemediationAction.FLUSH_ARP

        return RemediationAction.LOG_ONLY

    # ─── Auto-unblock expired ────────────────────────────────────

    def cleanup_expired_blocks(self):
        now = time.time()
        expired = [ip for ip, unblock_time in self._blocked_ips.items() if now >= unblock_time]

        for ip in expired:
            with self._lock:
                self._blocked_ips.pop(ip, None)
            for name, connector in self._connectors.items():
                try:
                    connector.unblock_ip_arp(ip)
                    audit.info("Auto-unblocked ARP from %s on %s (expired)", ip, name)
                except Exception:
                    pass

    # ─── Getters ─────────────────────────────────────────────────

    def get_records(self) -> List[RemediationRecord]:
        with self._lock:
            return list(self._records)

    def get_records_dicts(self) -> List[Dict]:
        with self._lock:
            return [r.to_dict() for r in self._records[-100:]]

    def get_blocked_ips(self) -> Dict[str, float]:
        with self._lock:
            return dict(self._blocked_ips)

    def get_firewall_rules(self, server_name: str) -> Dict:
        conn = self._connectors.get(server_name)
        if conn and hasattr(conn, 'check_firewall_rules'):
            return conn.check_firewall_rules()
        return {"error": "Server not connected or not Linux"}

    def get_system_info(self, server_name: str) -> Dict:
        conn = self._connectors.get(server_name)
        if conn and hasattr(conn, 'get_system_info'):
            return conn.get_system_info()
        return {"error": "Server not connected or not Linux"}

    # ─── Helpers ─────────────────────────────────────────────────

    def _make_record(self, target_ip, target_mac, server_name, action,
                     status=RemediationStatus.PENDING, reason="", error="", interface=""):
        return RemediationRecord(
            target_ip=target_ip,
            target_mac=target_mac,
            server_name=server_name,
            action=action,
            status=status,
            reason=reason,
            error=error,
            timestamp=time.time(),
            interface=interface,
        )

    def _send_notification(self, validation: AttackValidation):
        audit.warning(
            "ALERT: %s detected | IP: %s | MAC: %s | Severity: %s | Confidence: %s",
            validation.attack_type.value, validation.attacker_ip, validation.attacker_mac,
            validation.severity, validation.confidence.value,
        )
        for rec in validation.recommendations:
            audit.info("  -> %s", rec)

    def _find_server_for_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            for name in self._connectors:
                return name
        return None

    def restore_all(self) -> Dict[str, bool]:
        results = {}
        with self._lock:
            server_names = list(self._connectors.keys())
        for name in server_names:
            with self._lock:
                connector = self._connectors.get(name)
            if connector:
                try:
                    results[name] = connector.restore_network()
                except Exception:
                    results[name] = False
        return results
