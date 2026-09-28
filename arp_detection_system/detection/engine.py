import time
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..config import Config
from ..core.arp_monitor import ArpAlert
from ..core.network_utils import is_broadcast_mac, is_multicast_mac, is_broadcast_ip
from ..logs.parser import ParsedLogEntry, LogSeverity
from ..logs.collector import CollectedLogs
from ..utils.logger import get_logger

logger = get_logger("detection_engine")


class AttackType(Enum):
    ARP_SPOOFING = "ARP Spoofing"
    ARP_POISONING = "ARP Poisoning"
    GATEWAY_SPOOFING = "Gateway Spoofing"
    MAN_IN_THE_MIDDLE = "Man-in-the-Middle"
    GRATUITOUS_ARP_FLOOD = "Gratuitous ARP Flood"
    ARP_TABLE_OVERFLOW = "ARP Table Overflow"
    MAC_DUPLICATION = "MAC Duplication"
    IP_CONFLICT = "IP Conflict"
    UNKNOWN = "Unknown"


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


@dataclass
class AttackValidation:
    attack_type: AttackType
    confidence: Confidence
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    attacker_ip: str
    attacker_mac: str = ""
    victim_ip: str = ""
    victim_mac: str = ""
    description: str = ""
    evidence: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: float = 0.0
    requires_immediate_action: bool = False


class DetectionEngine:
    def __init__(self, config: Config):
        self.config = config
        self._validations: List[AttackValidation] = []
        self._alert_history: List[ArpAlert] = []
        self._log_history: List[ParsedLogEntry] = []
        self._baseline_mac_map: Dict[str, str] = {}  # IP -> MAC baseline
        self._attack_scores: Dict[str, int] = {}  # IP -> accumulated score

    def analyze_arp_alerts(self, alerts: List[ArpAlert]) -> List[AttackValidation]:
        validations = []
        for alert in alerts:
            validation = self._validate_arp_alert(alert)
            if validation:
                validations.append(validation)
                self._validations.append(validation)
        return validations

    def analyze_collected_logs(self, collected: CollectedLogs) -> List[AttackValidation]:
        validations = []
        for entry in collected.log_entries:
            validation = self._validate_log_entry(entry, collected)
            if validation:
                validations.append(validation)
                self._validations.append(validation)
        return validations

    def analyze_all(
        self,
        arp_alerts: List[ArpAlert],
        collected_data: Dict[str, CollectedLogs],
    ) -> List[AttackValidation]:
        validations = []

        validations.extend(self.analyze_arp_alerts(arp_alerts))

        for server_name, collected in collected_data.items():
            validations.extend(self.analyze_collected_logs(collected))

        validations.extend(self._cross_correlate(collected_data))

        validations = self._deduplicate_validations(validations)

        return validations

    def get_validations(self) -> List[AttackValidation]:
        return list(self._validations)

    def get_high_risk_validations(self) -> List[AttackValidation]:
        return [
            v for v in self._validations
            if v.severity in ("HIGH", "CRITICAL") or v.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
        ]

    def update_baseline(self, ip: str, mac: str):
        self._baseline_mac_map[ip] = mac

    def set_baseline_from_table(self, arp_table: List[Dict[str, str]]):
        self._baseline_mac_map.clear()
        for entry in arp_table:
            if entry.get("ip") and entry.get("mac"):
                self._baseline_mac_map[entry["ip"]] = entry["mac"].upper()

    def _validate_arp_alert(self, alert: ArpAlert) -> Optional[AttackValidation]:
        if is_broadcast_mac(alert.source_mac) or is_multicast_mac(alert.source_mac):
            return None
        if alert.source_ip and is_broadcast_ip(alert.source_ip):
            return None

        attack_type = AttackType.UNKNOWN
        confidence = Confidence.MEDIUM
        evidence = []
        recommendations = []
        severity = "MEDIUM"

        if alert.alert_type == "MAC_CHANGE":
            attack_type = AttackType.ARP_SPOOFING
            evidence.append(f"IP {alert.source_ip} changed MAC from {alert.target_mac} to {alert.source_mac}")

            if alert.source_ip == self.config.detection.gateway_ip:
                attack_type = AttackType.GATEWAY_SPOOFING
                severity = "CRITICAL"
                confidence = Confidence.HIGH
                recommendations.append("CRITICAL: Gateway is being spoofed. Isolate affected hosts immediately.")
                recommendations.append("Check if the new MAC belongs to an unauthorized device.")
            else:
                severity = "HIGH"
                confidence = Confidence.MEDIUM

            if alert.source_ip in self._baseline_mac_map:
                expected_mac = self._baseline_mac_map[alert.source_ip]
                if expected_mac != alert.source_mac:
                    evidence.append(f"Expected MAC: {expected_mac}")
                    confidence = Confidence.HIGH

        elif alert.alert_type == "GATEWAY_SPOOFING":
            attack_type = AttackType.MAN_IN_THE_MIDDLE
            severity = "CRITICAL"
            confidence = Confidence.CONFIRMED
            evidence.append(f"Multiple MACs claiming gateway {alert.source_ip}: {alert.source_mac}")
            recommendations.append("CRITICAL: Man-in-the-Middle attack confirmed.")
            recommendations.append("Immediately isolate the network segment.")
            recommendations.append("Identify and block the rogue MAC address.")
            recommendations.append("Capture packets for forensic analysis.")

        elif alert.alert_type == "GRATUITOUS_ARP":
            attack_type = AttackType.GRATUITOUS_ARP_FLOOD
            severity = "MEDIUM"
            confidence = Confidence.MEDIUM
            evidence.append(f"MAC {alert.source_mac} claims multiple IPs: {alert.description}")
            recommendations.append("Monitor for further ARP anomalies.")
            recommendations.append("Consider rate-limiting ARP traffic.")

        elif alert.alert_type == "DUPLICATE_IP":
            attack_type = AttackType.IP_CONFLICT
            severity = "HIGH"
            confidence = Confidence.MEDIUM
            evidence.append(f"IP {alert.source_ip} has multiple MACs: {alert.source_mac}")
            recommendations.append("Identify the legitimate host for this IP.")
            recommendations.append("Check for unauthorized DHCP servers.")

        elif alert.alert_type == "ARP_FLOOD":
            attack_type = AttackType.ARP_TABLE_OVERFLOW
            severity = "HIGH"
            confidence = Confidence.HIGH
            evidence.append(f"ARP flood detected from {alert.source_ip}")
            recommendations.append("Rate-limit or block the flooding source.")
            recommendations.append("Check for DoS attack patterns.")

        else:
            return None

        self._update_attack_score(alert.source_ip, severity)

        return AttackValidation(
            attack_type=attack_type,
            confidence=confidence,
            severity=severity,
            attacker_ip=alert.source_ip,
            attacker_mac=alert.source_mac,
            victim_ip=alert.target_ip,
            victim_mac=alert.target_mac,
            description=alert.description,
            evidence=evidence,
            recommendations=recommendations,
            timestamp=alert.timestamp,
            requires_immediate_action=(severity == "CRITICAL"),
        )

    def _validate_log_entry(
        self, entry: ParsedLogEntry, collected: CollectedLogs,
    ) -> Optional[AttackValidation]:
        attack_type = AttackType.UNKNOWN
        confidence = Confidence.MEDIUM
        evidence = [entry.message]
        recommendations = []
        severity = entry.severity.value

        category_map = {
            "ARP_SPOOF": (AttackType.ARP_SPOOFING, Confidence.HIGH),
            "ARP_ATTACK": (AttackType.ARP_SPOOFING, Confidence.CONFIRMED),
            "ARP_POISON": (AttackType.ARP_POISONING, Confidence.HIGH),
            "MAC_CHANGE": (AttackType.ARP_SPOOFING, Confidence.MEDIUM),
            "DUPLICATE_IP": (AttackType.IP_CONFLICT, Confidence.MEDIUM),
            "IP_CONFLICT": (AttackType.IP_CONFLICT, Confidence.HIGH),
            "GRATUITOUS_ARP": (AttackType.GRATUITOUS_ARP_FLOOD, Confidence.MEDIUM),
            "ARP_TABLE_FULL": (AttackType.ARP_TABLE_OVERFLOW, Confidence.HIGH),
            "ARP_CACHE_OVERFLOW": (AttackType.ARP_TABLE_OVERFLOW, Confidence.CONFIRMED),
            "NEIGHBOR_FAILED": (AttackType.ARP_POISONING, Confidence.LOW),
        }

        if entry.category in category_map:
            attack_type, confidence = category_map[entry.category]

        if attack_type == AttackType.UNKNOWN:
            return None

        if severity in ("HIGH", "CRITICAL"):
            recommendations.append("Investigate the source of the ARP anomaly.")
            recommendations.append("Check ARP table for unauthorized entries.")
        if severity == "CRITICAL":
            recommendations.append("Consider isolating the affected network segment.")

        return AttackValidation(
            attack_type=attack_type,
            confidence=confidence,
            severity=severity,
            attacker_ip="",
            description=f"Log-based detection: {entry.category}",
            evidence=evidence,
            recommendations=recommendations,
            timestamp=entry.timestamp if hasattr(entry, "timestamp") else time.time(),
            requires_immediate_action=(severity == "CRITICAL"),
        )

    def _cross_correlate(self, collected_data: Dict[str, CollectedLogs]) -> List[AttackValidation]:
        validations = []
        all_arp: Dict[str, List[Tuple[str, str]]] = {}

        for server_name, collected in collected_data.items():
            for entry in collected.arp_table:
                ip = entry.get("ip", "")
                mac = entry.get("mac", "").upper()
                if ip and mac:
                    if is_broadcast_mac(mac) or is_multicast_mac(mac):
                        continue
                    if is_broadcast_ip(ip):
                        continue
                    if ip not in all_arp:
                        all_arp[ip] = []
                    all_arp[ip].append((mac, server_name))

        for ip, mac_server_list in all_arp.items():
            unique_macs = set(mac for mac, _ in mac_server_list)
            if len(unique_macs) > 1:
                servers = [f"{mac} (on {srv})" for mac, srv in mac_server_list]
                validations.append(AttackValidation(
                    attack_type=AttackType.MAC_DUPLICATION,
                    confidence=Confidence.HIGH,
                    severity="HIGH",
                    attacker_ip=ip,
                    description=f"Cross-server MAC conflict for IP {ip}: {', '.join(servers)}",
                    evidence=[f"IP {ip} seen with multiple MACs across servers"],
                    recommendations=[
                        "Verify which MAC is legitimate.",
                        "Check for ARP spoofing between servers.",
                        "Consider network segmentation.",
                    ],
                    timestamp=time.time(),
                ))

        return validations

    def _update_attack_score(self, ip: str, severity: str):
        scores = {"LOW": 1, "MEDIUM": 3, "HIGH": 7, "CRITICAL": 15}
        self._attack_scores[ip] = self._attack_scores.get(ip, 0) + scores.get(severity, 0)

    def get_attack_score(self, ip: str) -> int:
        return self._attack_scores.get(ip, 0)

    def _deduplicate_validations(self, validations: List[AttackValidation]) -> List[AttackValidation]:
        seen = set()
        deduped = []
        for v in validations:
            key = (v.attack_type, v.attacker_ip, v.confidence)
            if key not in seen:
                seen.add(key)
                deduped.append(v)
        return deduped

    def generate_summary(self, validations: List[AttackValidation]) -> Dict:
        summary = {
            "total_alerts": len(validations),
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_attack_type": {},
            "by_confidence": {},
            "requires_immediate_action": [],
            "top_attackers": [],
        }

        attacker_counts: Dict[str, int] = {}
        for v in validations:
            summary["by_severity"][v.severity] = summary["by_severity"].get(v.severity, 0) + 1
            summary["by_attack_type"][v.attack_type.value] = summary["by_attack_type"].get(v.attack_type.value, 0) + 1
            summary["by_confidence"][v.confidence.value] = summary["by_confidence"].get(v.confidence.value, 0) + 1

            if v.requires_immediate_action:
                summary["requires_immediate_action"].append({
                    "type": v.attack_type.value,
                    "attacker_ip": v.attacker_ip,
                    "severity": v.severity,
                })

            if v.attacker_ip:
                attacker_counts[v.attacker_ip] = attacker_counts.get(v.attacker_ip, 0) + 1

        summary["top_attackers"] = sorted(
            [{"ip": ip, "count": count} for ip, count in attacker_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        return summary
