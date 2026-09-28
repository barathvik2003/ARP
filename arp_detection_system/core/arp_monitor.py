import time
import threading
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..core.network_utils import (
    ArpEntry, get_arp_table, get_default_gateway, get_local_ip,
    get_local_mac, flush_arp_cache, is_valid_mac, is_valid_ip,
    is_broadcast_mac, is_multicast_mac, is_broadcast_ip,
)
from ..utils.logger import get_logger

logger = get_logger("arp_monitor")


@dataclass
class MacIpSnapshot:
    mac_to_ips: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    ip_to_macs: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    timestamp: float = 0.0


@dataclass
class ArpAlert:
    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str
    source_mac: str
    target_ip: str = ""
    target_mac: str = ""
    description: str = ""
    timestamp: float = 0.0
    evidence: Dict = field(default_factory=dict)


class ArpMonitor:
    def __init__(
        self,
        gateway_ip: str = "",
        poll_interval: int = 5,
        alert_threshold: int = 3,
        mac_change_sensitivity: int = 1,
    ):
        self.gateway_ip = gateway_ip or get_default_gateway() or ""
        self.poll_interval = poll_interval
        self.alert_threshold = alert_threshold
        self.mac_change_sensitivity = mac_change_sensitivity

        self._known_mappings: Dict[str, str] = {}  # IP -> MAC
        self._mac_history: Dict[str, List[str]] = defaultdict(list)  # IP -> [MACs]
        self._arp_rate: Dict[str, List[float]] = defaultdict(list)
        self._snapshots: List[MacIpSnapshot] = []
        self._alerts: List[ArpAlert] = []
        self._alert_callbacks: List[Callable[[ArpAlert], None]] = []
        self._running = False
        self._lock = threading.Lock()

    def on_alert(self, callback: Callable[[ArpAlert], None]):
        self._alert_callbacks.append(callback)

    def start(self):
        self._running = True
        logger.info(
            "ARP Monitor started | gateway=%s poll_interval=%ds",
            self.gateway_ip, self.poll_interval,
        )
        while self._running:
            try:
                self._poll_once()
            except Exception as e:
                logger.error("Poll error: %s", e)
            time.sleep(self.poll_interval)

    def stop(self):
        self._running = False
        logger.info("ARP Monitor stopped")

    def poll(self) -> List[ArpAlert]:
        return self._poll_once()

    def get_current_table(self) -> List[ArpEntry]:
        return get_arp_table()

    def get_alerts(self) -> List[ArpAlert]:
        with self._lock:
            return list(self._alerts)

    def get_known_mappings(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._known_mappings)

    def _poll_once(self) -> List[ArpAlert]:
        alerts = []
        entries = get_arp_table()
        snapshot = self._build_snapshot(entries)
        now = time.time()

        with self._lock:
            self._snapshots.append(snapshot)
            if len(self._snapshots) > 100:
                self._snapshots = self._snapshots[-100:]

        new_alerts = self._detect_mac_ip_conflicts(entries, snapshot)
        alerts.extend(new_alerts)

        new_alerts = self._detect_gateway_spoofing(entries)
        alerts.extend(new_alerts)

        new_alerts = self._detect_gratuitous_arp(entries)
        alerts.extend(new_alerts)

        new_alerts = self._detect_duplicate_ips(entries)
        alerts.extend(new_alerts)

        new_alerts = self._detect_arp_rate(entries, now)
        alerts.extend(new_alerts)

        with self._lock:
            self._alerts.extend(alerts)

        for alert in alerts:
            for cb in self._alert_callbacks:
                try:
                    cb(alert)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)

        if alerts:
            logger.warning("Detected %d alerts this poll cycle", len(alerts))

        return alerts

    def _build_snapshot(self, entries: List[ArpEntry]) -> MacIpSnapshot:
        snap = MacIpSnapshot(timestamp=time.time())
        for e in entries:
            if is_valid_mac(e.mac) and is_valid_ip(e.ip):
                snap.mac_to_ips[e.mac].add(e.ip)
                snap.ip_to_macs[e.ip].add(e.mac)
        return snap

    def _detect_mac_ip_conflicts(
        self, entries: List[ArpEntry], snapshot: MacIpSnapshot,
    ) -> List[ArpAlert]:
        alerts = []
        with self._lock:
            for entry in entries:
                if not is_valid_ip(entry.ip) or not is_valid_mac(entry.mac):
                    continue

                if entry.ip in self._known_mappings:
                    old_mac = self._known_mappings[entry.ip]
                    if old_mac != entry.mac:
                        self._mac_history[entry.ip].append(old_mac)
                        self._mac_history[entry.ip].append(entry.mac)

                        if len(self._mac_history[entry.ip]) > self.mac_change_sensitivity:
                            alert = ArpAlert(
                                alert_type="MAC_CHANGE",
                                severity="HIGH",
                                source_ip=entry.ip,
                                source_mac=entry.mac,
                                target_mac=old_mac,
                                description=(
                                    f"IP {entry.ip} changed MAC from {old_mac} to {entry.mac}"
                                ),
                                timestamp=time.time(),
                                evidence={
                                    "old_mac": old_mac,
                                    "new_mac": entry.mac,
                                    "change_count": len(self._mac_history[entry.ip]),
                                },
                            )
                            alerts.append(alert)
                            logger.warning(
                                "MAC change detected: %s %s -> %s",
                                entry.ip, old_mac, entry.mac,
                            )

                self._known_mappings[entry.ip] = entry.mac

        return alerts

    def _detect_gateway_spoofing(self, entries: List[ArpEntry]) -> List[ArpAlert]:
        alerts = []
        if not self.gateway_ip:
            return alerts

        gateway_macs = set()
        for entry in entries:
            if entry.ip == self.gateway_ip and is_valid_mac(entry.mac):
                gateway_macs.add(entry.mac)

        if len(gateway_macs) > 1:
            alert = ArpAlert(
                alert_type="GATEWAY_SPOOFING",
                severity="CRITICAL",
                source_ip=self.gateway_ip,
                source_mac=", ".join(sorted(gateway_macs)),
                description=(
                    f"Gateway {self.gateway_ip} has multiple MACs: {', '.join(sorted(gateway_macs))}"
                ),
                timestamp=time.time(),
                evidence={"gateway_macs": sorted(gateway_macs)},
            )
            alerts.append(alert)
            logger.critical("Gateway spoofing detected: %s -> %s", self.gateway_ip, gateway_macs)

        return alerts

    def _detect_gratuitous_arp(self, entries: List[ArpEntry]) -> List[ArpAlert]:
        alerts = []
        for entry in entries:
            if not is_valid_ip(entry.ip) or not is_valid_mac(entry.mac):
                continue

            if is_broadcast_mac(entry.mac) or is_multicast_mac(entry.mac):
                continue
            if is_broadcast_ip(entry.ip):
                continue

            ip_mac_pairs = []
            for e in entries:
                if e.mac == entry.mac and e.ip != entry.ip:
                    if not is_broadcast_ip(e.ip):
                        ip_mac_pairs.append(e.ip)

            if len(ip_mac_pairs) > 2:
                alert = ArpAlert(
                    alert_type="GRATUITOUS_ARP",
                    severity="MEDIUM",
                    source_ip=entry.ip,
                    source_mac=entry.mac,
                    description=(
                        f"MAC {entry.mac} claims {len(ip_mac_pairs) + 1} IPs: "
                        f"{entry.ip}, {', '.join(ip_mac_pairs[:5])}"
                    ),
                    timestamp=time.time(),
                    evidence={"claimed_ips": [entry.ip] + ip_mac_pairs},
                )
                alerts.append(alert)

        return alerts

    def _detect_duplicate_ips(self, entries: List[ArpEntry]) -> List[ArpAlert]:
        alerts = []
        ip_macs: Dict[str, List[str]] = defaultdict(list)

        for entry in entries:
            if is_valid_ip(entry.ip) and is_valid_mac(entry.mac):
                if is_broadcast_mac(entry.mac) or is_multicast_mac(entry.mac):
                    continue
                if is_broadcast_ip(entry.ip):
                    continue
                ip_macs[entry.ip].append(entry.mac)

        for ip, macs in ip_macs.items():
            unique_macs = set(macs)
            if len(unique_macs) > 1:
                alert = ArpAlert(
                    alert_type="DUPLICATE_IP",
                    severity="HIGH",
                    source_ip=ip,
                    source_mac=", ".join(sorted(unique_macs)),
                    description=(
                        f"IP {ip} has multiple MACs: {', '.join(sorted(unique_macs))}"
                    ),
                    timestamp=time.time(),
                    evidence={"ip": ip, "macs": sorted(unique_macs)},
                )
                alerts.append(alert)

        return alerts

    def _detect_arp_rate(self, entries: List[ArpEntry], now: float) -> List[ArpAlert]:
        alerts = []
        with self._lock:
            for entry in entries:
                if is_broadcast_ip(entry.ip) or is_broadcast_mac(entry.mac):
                    continue
                self._arp_rate[entry.ip].append(now)

            for ip in list(self._arp_rate.keys()):
                if is_broadcast_ip(ip):
                    continue
                cutoff = now - 1.0
                self._arp_rate[ip] = [t for t in self._arp_rate[ip] if t > cutoff]
                rate = len(self._arp_rate[ip])

                if rate > 50:
                    alert = ArpAlert(
                        alert_type="ARP_FLOOD",
                        severity="HIGH",
                        source_ip=ip,
                        source_mac="UNKNOWN",
                        description=f"ARP flood from {ip}: {rate} packets/sec",
                        timestamp=now,
                        evidence={"rate": rate, "threshold": 50},
                    )
                    alerts.append(alert)

        return alerts
