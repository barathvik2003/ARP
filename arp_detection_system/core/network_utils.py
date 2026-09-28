import platform
import subprocess
import re
import socket
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ArpEntry:
    ip: str
    mac: str
    interface: str = ""
    static: bool = False
    first_seen: float = 0.0
    last_seen: float = 0.0
    occurrence_count: int = 1


@dataclass
class NetworkInterface:
    name: str
    ip: str
    mac: str
    netmask: str = ""
    is_up: bool = True


def get_platform() -> str:
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    elif system == "darwin":
        return "macos"
    return system


def get_default_gateway() -> Optional[str]:
    system = get_platform()
    try:
        if system == "linux":
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                return match.group(1)
        elif system == "windows":
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    return parts[2]
        elif system == "macos":
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=10,
            )
            match = re.search(r"gateway:\s+(\S+)", result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def get_arp_table() -> List[ArpEntry]:
    system = get_platform()
    entries = []

    try:
        if system == "linux":
            entries = _get_arp_table_linux()
        elif system == "windows":
            entries = _get_arp_table_windows()
        elif system == "macos":
            entries = _get_arp_table_macos()
    except Exception:
        pass

    return entries


def _get_arp_table_linux() -> List[ArpEntry]:
    entries = []
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if len(parts) > 4 and ":" in parts[4] else ""
                state = parts[2] if len(parts) > 2 else ""
                if mac and mac != "FAILED":
                    entries.append(ArpEntry(
                        ip=ip,
                        mac=mac.upper(),
                        static=(state == "permanent"),
                    ))
    except FileNotFoundError:
        try:
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if match:
                    entries.append(ArpEntry(
                        ip=match.group(1),
                        mac=match.group(2).upper(),
                    ))
        except Exception:
            pass

    return entries


def _get_arp_table_windows() -> List[ArpEntry]:
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=10,
        )
        current_interface = ""
        for line in result.stdout.strip().splitlines():
            if "Interface:" in line:
                match = re.search(r"Interface:\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    current_interface = match.group(1)
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1]
                if re.match(r"^[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}$", mac):
                    entries.append(ArpEntry(
                        ip=ip,
                        mac=mac.upper().replace("-", ":"),
                        interface=current_interface,
                        static=(parts[2] == "static" if len(parts) > 2 else False),
                    ))
    except Exception:
        pass
    return entries


def _get_arp_table_macos() -> List[ArpEntry]:
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-an"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if match:
                entries.append(ArpEntry(
                    ip=match.group(1),
                    mac=match.group(2).upper(),
                ))
    except Exception:
        pass
    return entries


def send_arp_request(target_ip: str, source_ip: str = "0.0.0.0", timeout: float = 3.0) -> Optional[str]:
    system = get_platform()
    try:
        if system == "windows":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "2000", target_ip],
                capture_output=True, text=True, timeout=timeout + 2,
            )
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(int(timeout)), target_ip],
                capture_output=True, text=True, timeout=timeout + 2,
            )
        arp_table = get_arp_table()
        for entry in arp_table:
            if entry.ip == target_ip:
                return entry.mac
    except Exception:
        pass
    return None


def flush_arp_cache(target_ip: Optional[str] = None) -> bool:
    system = get_platform()
    try:
        if system == "linux":
            if target_ip:
                subprocess.run(
                    ["ip", "neigh", "del", target_ip, "dev", "all"],
                    capture_output=True, timeout=10,
                )
            else:
                subprocess.run(
                    ["ip", "neigh", "flush", "all"],
                    capture_output=True, timeout=10,
                )
            return True
        elif system == "windows":
            if target_ip:
                subprocess.run(
                    ["arp", "-d", target_ip],
                    capture_output=True, timeout=10,
                )
            else:
                subprocess.run(
                    ["arp", "-d", "*"],
                    capture_output=True, timeout=10,
                )
            return True
    except Exception:
        pass
    return False


def get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_mac() -> Optional[str]:
    system = get_platform()
    try:
        if system == "linux":
            result = subprocess.run(
                ["cat", "/sys/class/net/eth0/address"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().upper()
        elif system == "windows":
            result = subprocess.run(
                ["getmac", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split(",")
                if len(parts) >= 1:
                    mac = parts[0].strip('"').replace("-", ":")
                    return mac.upper()
    except Exception:
        pass
    return None


def is_valid_mac(mac: str) -> bool:
    pattern = r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$"
    return bool(re.match(pattern, mac.upper()))


def is_broadcast_mac(mac: str) -> bool:
    m = mac.upper().replace("-", ":")
    return m == "FF:FF:FF:FF:FF:FF" or m == "00:00:00:00:00:00"


def is_multicast_mac(mac: str) -> bool:
    m = mac.upper().replace("-", ":")
    if not is_valid_mac(m):
        return False
    first_octet = int(m.split(":")[0], 16)
    return bool(first_octet & 0x01)


def is_broadcast_ip(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        return parts[3] == "255"
    except Exception:
        return False


def is_valid_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_same_subnet(ip1: str, ip2: str, netmask: str = "255.255.255.0") -> bool:
    try:
        ip1_int = struct.unpack("!I", socket.inet_aton(ip1))[0]
        ip2_int = struct.unpack("!I", socket.inet_aton(ip2))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        return (ip1_int & mask_int) == (ip2_int & mask_int)
    except Exception:
        return False
