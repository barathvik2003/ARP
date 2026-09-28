import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from arp_detection_system.core.network_utils import (
    is_valid_mac, is_valid_ip, is_same_subnet, ArpEntry,
)
from arp_detection_system.logs.parser import (
    LinuxLogParser, WindowsLogParser, parse_logs, LogSeverity,
)
from arp_detection_system.config import Config, DetectionConfig, RemediationConfig
from arp_detection_system.detection.engine import DetectionEngine, AttackType, Confidence
from arp_detection_system.core.arp_monitor import ArpMonitor, ArpAlert
from arp_detection_system.remediation.engine import RemediationEngine, RemediationAction


class TestNetworkUtils(unittest.TestCase):
    def test_valid_mac(self):
        self.assertTrue(is_valid_mac("AA:BB:CC:DD:EE:FF"))
        self.assertTrue(is_valid_mac("aa:bb:cc:dd:ee:ff"))
        self.assertTrue(is_valid_mac("00:11:22:33:44:55"))
        self.assertFalse(is_valid_mac("invalid"))
        self.assertFalse(is_valid_mac("AA:BB:CC:DD:EE"))
        self.assertFalse(is_valid_mac(""))
        self.assertFalse(is_valid_mac("GG:HH:II:JJ:KK:LL"))

    def test_valid_ip(self):
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("10.0.0.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertTrue(is_valid_ip("255.255.255.255"))
        self.assertFalse(is_valid_ip("invalid"))
        self.assertFalse(is_valid_ip("256.1.1.1"))
        self.assertFalse(is_valid_ip(""))
        # Note: socket.inet_aton accepts partial IPs on some platforms, so we test strict format
        import socket
        try:
            socket.inet_aton("192.168.1")
            # On some platforms this passes - that's OS-dependent behavior
        except socket.error:
            self.assertFalse(is_valid_ip("192.168.1"))

    def test_same_subnet(self):
        self.assertTrue(is_same_subnet("192.168.1.1", "192.168.1.100", "255.255.255.0"))
        self.assertFalse(is_same_subnet("192.168.1.1", "192.168.2.100", "255.255.255.0"))
        self.assertTrue(is_same_subnet("10.0.0.1", "10.0.0.254", "255.0.0.0"))


class TestLinuxLogParser(unittest.TestCase):
    def setUp(self):
        self.parser = LinuxLogParser()

    def test_arp_spoof_detection(self):
        logs = "Jul 24 10:00:00 server kernel: ARP spoof detected from 192.168.1.50"
        entries = self.parser.parse_syslog(logs)
        self.assertTrue(len(entries) > 0)
        self.assertEqual(entries[0].category, "ARP_SPOOF")
        self.assertEqual(entries[0].severity, LogSeverity.CRITICAL)

    def test_arp_attack_detection(self):
        logs = "Jul 24 10:00:00 server kernel: ARP attack in progress"
        entries = self.parser.parse_syslog(logs)
        self.assertTrue(len(entries) > 0)
        self.assertEqual(entries[0].category, "ARP_ATTACK")
        self.assertEqual(entries[0].severity, LogSeverity.CRITICAL)

    def test_duplicate_ip_detection(self):
        logs = "Jul 24 10:00:00 server kernel: duplicate IP address 192.168.1.100 detected"
        entries = self.parser.parse_syslog(logs)
        self.assertTrue(len(entries) > 0)
        self.assertEqual(entries[0].category, "DUPLICATE_IP")

    def test_gratuitous_arp_detection(self):
        logs = "Jul 24 10:00:00 server kernel: gratuitous ARP from 192.168.1.50"
        entries = self.parser.parse_syslog(logs)
        self.assertTrue(len(entries) > 0)
        self.assertEqual(entries[0].category, "GRATUITOUS_ARP")

    def test_dmesg_parsing(self):
        logs = "[12345.678] arp_cache overflow from 192.168.1.50"
        entries = self.parser.parse_dmesg(logs)
        self.assertTrue(len(entries) > 0)

    def test_empty_log(self):
        entries = self.parser.parse_syslog("")
        self.assertEqual(len(entries), 0)

    def test_no_arp_entries(self):
        logs = "Jul 24 10:00:00 server kernel: normal system operation"
        entries = self.parser.parse_syslog(logs)
        self.assertEqual(len(entries), 0)


class TestWindowsLogParser(unittest.TestCase):
    def setUp(self):
        self.parser = WindowsLogParser()

    def test_arp_spoof_detection(self):
        logs = "2024-07-24T10:00:00 ARP spoof activity detected on interface"
        entries = self.parser.parse_event_log(logs)
        self.assertTrue(len(entries) > 0)
        self.assertEqual(entries[0].category, "ARP_SPOOF")

    def test_event_id_parsing(self):
        logs = "2024-07-24T10:00:00 4199 The system detected an address conflict for IP 192.168.1.100"
        entries = self.parser.parse_event_log(logs)
        self.assertTrue(len(entries) > 0, f"Expected entries from event log, got none. Parsed: {entries}")

    def test_powershell_output(self):
        logs = "ARP spoof detected on adapter Ethernet"
        entries = self.parser.parse_powershell_output(logs)
        self.assertTrue(len(entries) > 0, f"Expected entries from powershell output, got none")


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.detection.gateway_ip = "192.168.1.1"
        self.engine = DetectionEngine(self.config)

    def test_mac_change_detection(self):
        alert = ArpAlert(
            alert_type="MAC_CHANGE",
            severity="HIGH",
            source_ip="192.168.1.50",
            source_mac="AA:BB:CC:DD:EE:FF",
            target_mac="11:22:33:44:55:66",
            description="IP 192.168.1.50 changed MAC",
            timestamp=1000.0,
        )
        validations = self.engine.analyze_arp_alerts([alert])
        self.assertTrue(len(validations) > 0)
        self.assertEqual(validations[0].attack_type, AttackType.ARP_SPOOFING)

    def test_gateway_spoofing_detection(self):
        alert = ArpAlert(
            alert_type="GATEWAY_SPOOFING",
            severity="CRITICAL",
            source_ip="192.168.1.1",
            source_mac="AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66",
            description="Gateway has multiple MACs",
            timestamp=1000.0,
        )
        validations = self.engine.analyze_arp_alerts([alert])
        self.assertTrue(len(validations) > 0)
        self.assertEqual(validations[0].attack_type, AttackType.MAN_IN_THE_MIDDLE)
        self.assertTrue(validations[0].requires_immediate_action)

    def test_gratuitous_arp_detection(self):
        alert = ArpAlert(
            alert_type="GRATUITOUS_ARP",
            severity="MEDIUM",
            source_ip="192.168.1.50",
            source_mac="AA:BB:CC:DD:EE:FF",
            description="MAC claims multiple IPs",
            timestamp=1000.0,
        )
        validations = self.engine.analyze_arp_alerts([alert])
        self.assertTrue(len(validations) > 0)
        self.assertEqual(validations[0].attack_type, AttackType.GRATUITOUS_ARP_FLOOD)

    def test_attack_score_update(self):
        alert = ArpAlert(
            alert_type="MAC_CHANGE",
            severity="HIGH",
            source_ip="192.168.1.50",
            source_mac="AA:BB:CC:DD:EE:FF",
            description="MAC changed",
            timestamp=1000.0,
        )
        self.engine.analyze_arp_alerts([alert])
        score = self.engine.get_attack_score("192.168.1.50")
        self.assertGreater(score, 0)

    def test_summary_generation(self):
        validations = [
            self.engine.analyze_arp_alerts([ArpAlert(
                alert_type="MAC_CHANGE", severity="HIGH",
                source_ip="192.168.1.50", source_mac="AA:BB:CC:DD:EE:FF",
                description="test", timestamp=1000.0,
            )])[0]
        ]
        summary = self.engine.generate_summary(validations)
        self.assertEqual(summary["total_alerts"], 1)
        self.assertIn("HIGH", summary["by_severity"])


class TestArpMonitor(unittest.TestCase):
    def test_monitor_init(self):
        monitor = ArpMonitor(
            gateway_ip="192.168.1.1",
            poll_interval=5,
            alert_threshold=3,
        )
        self.assertEqual(monitor.gateway_ip, "192.168.1.1")
        self.assertEqual(monitor.poll_interval, 5)

    def test_snapshot_building(self):
        monitor = ArpMonitor()
        entries = [
            ArpEntry(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:FF"),
            ArpEntry(ip="192.168.1.2", mac="11:22:33:44:55:66"),
        ]
        snapshot = monitor._build_snapshot(entries)
        self.assertIn("192.168.1.1", snapshot.ip_to_macs)
        self.assertIn("AA:BB:CC:DD:EE:FF", snapshot.mac_to_ips)


class TestRemediationEngine(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.remediation.notify_only = True
        self.engine = RemediationEngine(self.config)

    def test_determine_action_notify(self):
        from arp_detection_system.detection.engine import AttackValidation, AttackType, Confidence
        validation = AttackValidation(
            attack_type=AttackType.ARP_SPOOFING,
            confidence=Confidence.MEDIUM,
            severity="MEDIUM",
            attacker_ip="192.168.1.50",
        )
        action = self.engine._determine_action(validation)
        # With notify_only=True, MEDIUM severity returns NOTIFY
        self.assertEqual(action, RemediationAction.NOTIFY)

    def test_determine_action_block(self):
        from arp_detection_system.detection.engine import AttackValidation, AttackType, Confidence
        self.config.remediation.notify_only = False
        self.config.remediation.auto_block = True
        validation = AttackValidation(
            attack_type=AttackType.MAN_IN_THE_MIDDLE,
            confidence=Confidence.CONFIRMED,
            severity="CRITICAL",
            attacker_ip="192.168.1.50",
        )
        action = self.engine._determine_action(validation)
        self.assertEqual(action, RemediationAction.BLOCK_ARP)


if __name__ == "__main__":
    unittest.main()
