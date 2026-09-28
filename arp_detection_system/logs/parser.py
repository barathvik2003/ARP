import re
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from ..utils.logger import get_logger

logger = get_logger("log_parser")


class LogSeverity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    WARNING = "WARNING"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ParsedLogEntry:
    timestamp: str = ""
    source: str = ""
    severity: LogSeverity = LogSeverity.INFO
    category: str = ""
    message: str = ""
    raw: str = ""
    metadata: Dict = field(default_factory=dict)


class LinuxLogParser:
    ARP_PATTERNS = [
        (r"ARP.*spoof", LogSeverity.CRITICAL, "ARP_SPOOF"),
        (r"ARP.*attack", LogSeverity.CRITICAL, "ARP_ATTACK"),
        (r"ARP.*poison", LogSeverity.HIGH, "ARP_POISON"),
        (r"duplicate IP", LogSeverity.HIGH, "DUPLICATE_IP"),
        (r"MAC address.*changed", LogSeverity.HIGH, "MAC_CHANGE"),
        (r"IP conflict", LogSeverity.HIGH, "IP_CONFLICT"),
        (r"gratuitous ARP", LogSeverity.MEDIUM, "GRATUITOUS_ARP"),
        (r"arp_table.*full", LogSeverity.MEDIUM, "ARP_TABLE_FULL"),
        (r"arp_cache.*overflow", LogSeverity.HIGH, "ARP_CACHE_OVERFLOW"),
        (r"neighbor.*unreachable", LogSeverity.INFO, "NEIGHBOR_UNREACHABLE"),
        (r"neighbor.*stale", LogSeverity.INFO, "NEIGHBOR_STALE"),
        (r"neighbor.*failed", LogSeverity.WARNING, "NEIGHBOR_FAILED"),
        (r"arp.*filter", LogSeverity.INFO, "ARP_FILTER"),
        (r"ebtables.*arp", LogSeverity.INFO, "EBTABLES_ARP"),
        (r"kernel.*arp", LogSeverity.INFO, "KERNEL_ARP"),
    ]

    GENERAL_PATTERNS = [
        (r"SYN.*flood", LogSeverity.HIGH, "SYN_FLOOD"),
        (r"DoS|denial.of.service", LogSeverity.HIGH, "DOS"),
        (r"brute.force", LogSeverity.HIGH, "BRUTE_FORCE"),
        (r"unauthorized", LogSeverity.MEDIUM, "UNAUTHORIZED"),
        (r"failed login", LogSeverity.LOW, "FAILED_LOGIN"),
        (r"segfault", LogSeverity.MEDIUM, "SEGFAULT"),
    ]

    def parse_syslog(self, content: str) -> List[ParsedLogEntry]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line)
            if entry:
                entries.append(entry)
        return entries

    def parse_dmesg(self, content: str) -> List[ParsedLogEntry]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line, source="dmesg")
            if entry:
                entries.append(entry)
        return entries

    def parse_journalctl(self, content: str) -> List[ParsedLogEntry]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line, source="journalctl")
            if entry:
                entries.append(entry)
        return entries

    def _parse_line(self, line: str, source: str = "syslog") -> Optional[ParsedLogEntry]:
        timestamp_match = re.match(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line
        )
        timestamp = timestamp_match.group(1) if timestamp_match else ""

        all_patterns = self.ARP_PATTERNS + self.GENERAL_PATTERNS

        for pattern, severity, category in all_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return ParsedLogEntry(
                    timestamp=timestamp,
                    source=source,
                    severity=severity,
                    category=category,
                    message=line,
                    raw=line,
                )

        return None


class WindowsLogParser:
    ARP_PATTERNS = [
        (r"ARP.*spoof", LogSeverity.CRITICAL, "ARP_SPOOF"),
        (r"ARP.*attack", LogSeverity.CRITICAL, "ARP_ATTACK"),
        (r"MAC.*change", LogSeverity.HIGH, "MAC_CHANGE"),
        (r"IP.*conflict", LogSeverity.HIGH, "IP_CONFLICT"),
        (r"gratuitous.*ARP", LogSeverity.MEDIUM, "GRATUITOUS_ARP"),
        (r"duplicate.*address", LogSeverity.HIGH, "DUPLICATE_IP"),
        (r"neighbor.*problem", LogSeverity.WARNING, "NEIGHBOR_PROBLEM"),
    ]

    EVENT_ID_MAP = {
        4199: ("IP_CONFLICT", LogSeverity.HIGH),
        10016: ("COM_SECURITY", LogSeverity.MEDIUM),
        4624: ("LOGON_SUCCESS", LogSeverity.INFO),
        4625: ("LOGON_FAILURE", LogSeverity.WARNING),
        4720: ("ACCOUNT_CREATED", LogSeverity.INFO),
        4726: ("ACCOUNT_DELETED", LogSeverity.INFO),
        4732: ("MEMBER_ADDED", LogSeverity.INFO),
        5379: ("CREDENTIAL_ACCESS", LogSeverity.MEDIUM),
        4688: ("PROCESS_CREATED", LogSeverity.INFO),
    }

    def parse_event_log(self, content: str) -> List[ParsedLogEntry]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            entry = self._parse_event_line(line)
            if entry:
                entries.append(entry)
        return entries

    def parse_powershell_output(self, content: str) -> List[ParsedLogEntry]:
        entries = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            for pattern, severity, category in self.ARP_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    entries.append(ParsedLogEntry(
                        source="powershell",
                        severity=severity,
                        category=category,
                        message=line,
                        raw=line,
                    ))
                    break

        return entries

    def _parse_event_line(self, line: str) -> Optional[ParsedLogEntry]:
        timestamp_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        timestamp = timestamp_match.group(1) if timestamp_match else ""

        search_from = timestamp_match.end() if timestamp_match else 0
        remaining = line[search_from:]
        event_id_match = re.search(r"\b(\d{4,5})\b", remaining)
        if event_id_match:
            event_id = int(event_id_match.group(1))
            if event_id in self.EVENT_ID_MAP:
                category, severity = self.EVENT_ID_MAP[event_id]
                return ParsedLogEntry(
                    timestamp=timestamp,
                    source="windows_event",
                    severity=severity,
                    category=category,
                    message=line,
                    raw=line,
                    metadata={"event_id": event_id},
                )

        for pattern, severity, category in self.ARP_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return ParsedLogEntry(
                    timestamp=timestamp,
                    source="windows_event",
                    severity=severity,
                    category=category,
                    message=line,
                    raw=line,
                )

        return None


def parse_logs(content: str, os_type: str, log_type: str = "auto") -> List[ParsedLogEntry]:
    if os_type == "linux":
        parser = LinuxLogParser()
        if log_type == "dmesg":
            return parser.parse_dmesg(content)
        elif log_type == "journalctl":
            return parser.parse_journalctl(content)
        return parser.parse_syslog(content)
    elif os_type == "windows":
        parser = WindowsLogParser()
        if log_type == "event":
            return parser.parse_event_log(content)
        return parser.parse_powershell_output(content)
    return []
