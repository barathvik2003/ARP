import re
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..config import ServerConfig
from ..utils.logger import get_logger

logger = get_logger("linux_connector")


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timestamp: float = 0.0
    duration: float = 0.0


class LinuxConnector:
    def __init__(self, config: ServerConfig):
        self.config = config
        self._client = None
        self._connected = False
        self._firewall_backend = None  # auto-detected: nft, arptables, ebtables, iptables

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def host(self) -> str:
        return self.config.host

    def connect(self) -> bool:
        try:
            import paramiko

            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.config.host,
                "port": self.config.port,
                "username": self.config.username,
                "timeout": 15,
            }

            if self.config.ssh_key_path:
                connect_kwargs["key_filename"] = self.config.ssh_key_path
            elif self.config.password:
                connect_kwargs["password"] = self.config.password

            self._client.connect(**connect_kwargs)
            self._connected = True
            self._detect_firewall_backend()
            logger.info("Connected to Linux server: %s (%s)", self.config.name, self.config.host)
            return True

        except ImportError:
            logger.error("paramiko not installed. Run: pip install paramiko")
            return False
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.config.host, e)
            return False

    def disconnect(self):
        if self._client:
            self._client.close()
            self._connected = False
            logger.info("Disconnected from Linux server: %s", self.config.name)

    def is_connected(self) -> bool:
        return self._connected

    def execute(self, command: str, timeout: int = 30) -> CommandResult:
        if not self._connected or not self._client:
            return CommandResult(command=command, stdout="", stderr="Not connected", exit_code=-1)

        start = time.time()
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            duration = time.time() - start

            result = CommandResult(
                command=command,
                stdout=stdout.read().decode("utf-8", errors="replace"),
                stderr=stderr.read().decode("utf-8", errors="replace"),
                exit_code=exit_code,
                timestamp=start,
                duration=duration,
            )
            return result

        except Exception as e:
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                timestamp=start,
                duration=time.time() - start,
            )

    def execute_sudo(self, command: str, password: str = "", timeout: int = 30) -> CommandResult:
        if not password and self.config.password:
            password = self.config.password

        sudo_cmd = f"echo '{password}' | sudo -S {command}"
        return self.execute(sudo_cmd, timeout=timeout)

    # ─── Firewall Backend Detection ───────────────────────────────

    def _detect_firewall_backend(self):
        """Auto-detect the best ARP blocking method for this system."""
        # Check if we're root (uid=0) or need sudo
        r = self.execute("id -u")
        is_root = r.stdout.strip() == "0"

        for tool in ["nft", "arptables", "ebtables", "iptables"]:
            if is_root:
                r = self.execute(f"which {tool} 2>/dev/null")
            else:
                r = self.execute_sudo(f"which {tool} 2>/dev/null")
            if r.exit_code == 0 and r.stdout.strip() and "NOTFOUND" not in r.stdout:
                if tool == "nft":
                    if is_root:
                        r2 = self.execute("nft list tables 2>/dev/null")
                    else:
                        r2 = self.execute_sudo("nft list tables 2>/dev/null")
                    if r2.exit_code == 0:
                        self._firewall_backend = "nft"
                        logger.info("Detected firewall backend: nftables (nft)")
                        return
                elif tool == "arptables":
                    self._firewall_backend = "arptables"
                    logger.info("Detected firewall backend: arptables")
                    return
                elif tool == "ebtables":
                    self._firewall_backend = "ebtables"
                    logger.info("Detected firewall backend: ebtables")
                    return
                elif tool == "iptables":
                    self._firewall_backend = "iptables"
                    logger.info("Detected firewall backend: iptables")
                    return

        self._firewall_backend = "ip_neigh"
        logger.warning("No firewall tools found, using ip neigh replacement only")

    @property
    def firewall_backend(self) -> str:
        return self._firewall_backend or "ip_neigh"

    # ─── ARP Table ───────────────────────────────────────────────

    def get_arp_table(self) -> List[Dict[str, str]]:
        result = self.execute("arp -an")
        entries = []
        for line in result.stdout.strip().splitlines():
            match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
            if match:
                entries.append({"ip": match.group(1), "mac": match.group(2).upper()})
        return entries

    def get_ip_neigh(self) -> List[Dict[str, str]]:
        result = self.execute("ip neigh show")
        entries = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                entries.append({
                    "ip": parts[0],
                    "mac": parts[4].upper() if len(parts) > 4 and ":" in parts[4] else "",
                    "state": parts[2] if len(parts) > 2 else "",
                    "interface": parts[5] if len(parts) > 5 else "",
                })
        return entries

    def get_network_interfaces(self) -> List[Dict[str, str]]:
        result = self.execute("ip -o link show")
        interfaces = []
        for line in result.stdout.strip().splitlines():
            match = re.search(r"(\d+):\s+(\S+)", line)
            if match:
                name = match.group(2)
                if name == "lo":
                    continue
                ip_result = self.execute(f"ip addr show {name}")
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", ip_result.stdout)
                mac_match = re.search(r"link/ether ([0-9a-fA-F:]+)", ip_result.stdout)
                interfaces.append({
                    "name": name,
                    "ip": ip_match.group(1) if ip_match else "",
                    "mac": mac_match.group(1).upper() if mac_match else "",
                    "netmask": str(32 - int(ip_match.group(2))) if ip_match else "",
                })
        return interfaces

    def get_default_gateway(self) -> str:
        result = self.execute("ip route show default")
        match = re.search(r"default via (\S+)", result.stdout)
        return match.group(1) if match else ""

    def get_syslog_arp_entries(self, lines: int = 100) -> List[str]:
        result = self.execute(f"grep -i arp /var/log/syslog 2>/dev/null | tail -n {lines}")
        if result.exit_code != 0:
            result = self.execute(f"dmesg | grep -i arp | tail -n {lines}")
        return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]

    def get_dmesg_arp(self, lines: int = 50) -> List[str]:
        result = self.execute(f"dmesg | grep -i arp | tail -n {lines}")
        return [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]

    # ─── Firewall Rules Inspection ───────────────────────────────

    def check_firewall_rules(self) -> Dict[str, any]:
        """Inspect current firewall rules across all backends."""
        info = {"backend": self.firewall_backend, "rules": [], "raw": ""}

        if self.firewall_backend == "nft":
            r = self.execute_sudo("nft list ruleset 2>/dev/null")
            info["raw"] = r.stdout.strip()
            info["rules"] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        elif self.firewall_backend == "arptables":
            r = self.execute_sudo("arptables -L -n -v 2>/dev/null")
            info["raw"] = r.stdout.strip()
            info["rules"] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        elif self.firewall_backend == "ebtables":
            r = self.execute_sudo("ebtables -L 2>/dev/null")
            info["raw"] = r.stdout.strip()
            info["rules"] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        elif self.firewall_backend == "iptables":
            r = self.execute_sudo("iptables -L INPUT -n -v 2>/dev/null")
            info["raw"] = r.stdout.strip()
            info["rules"] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]

        r = self.execute_sudo("nft list table ip arp_filter 2>/dev/null")
        if r.exit_code == 0 and r.stdout.strip():
            info["nft_arp_table"] = r.stdout.strip()

        return info

    # ─── BLOCK Methods (Multi-backend) ───────────────────────────

    def block_ip_arp(self, target_ip: str, interface: str = "") -> bool:
        """
        Block ARP traffic from target_ip using the best available method.
        Tries: nft → arptables → ebtables → iptables → ip_neigh
        """
        dev = interface or self._get_default_iface()

        # Method 1: nftables (RHEL 9+, modern systems)
        if self.firewall_backend == "nft" or True:  # always try nft first
            if self._block_nft(target_ip, dev):
                return True

        # Method 2: arptables (legacy systems)
        if self._block_arptables(target_ip):
            return True

        # Method 3: ebtables (bridged networks)
        if self._block_ebtables(target_ip, dev):
            return True

        # Method 4: iptables L2 (basic)
        if self._block_iptables(target_ip):
            return True

        # Method 5: ip neigh poison prevention (last resort)
        if self._block_ip_neigh(target_ip, dev):
            return True

        logger.error("All block methods failed for %s on %s", target_ip, self.config.name)
        return False

    def _block_nft(self, target_ip: str, dev: str) -> bool:
        """Block using nftables ARP table (RHEL 9 compatible)."""
        self.execute_sudo("nft add table ip arp_filter 2>/dev/null")
        self.execute_sudo("nft add chain ip arp_filter input '{ type filter hook input priority -15; policy accept; }' 2>/dev/null")

        check = self.execute_sudo(f"nft list chain ip arp_filter input 2>/dev/null | grep '{target_ip}'")
        if target_ip in check.stdout:
            logger.info("ARP block rule already exists for %s (nft)", target_ip)
            return True

        r = self.execute_sudo(f"nft add rule ip arp_filter input ip saddr {target_ip} drop 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blocked ARP from %s on %s via nft", target_ip, self.config.name)
            return True

        r = self.execute_sudo(f"nft add rule ip arp_filter input arp ip saddr {target_ip} drop 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blocked ARP from %s on %s via nft arp", target_ip, self.config.name)
            return True

        return False

    def _block_arptables(self, target_ip: str) -> bool:
        """Block using legacy arptables."""
        r = self.execute_sudo(f"arptables -A INPUT -s {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blocked ARP from %s on %s via arptables", target_ip, self.config.name)
            return True
        return False

    def _block_ebtables(self, target_ip: str, dev: str) -> bool:
        """Block using ebtables ARP chain."""
        self.execute_sudo("ebtables -N ARP_FILTER 2>/dev/null")
        self.execute_sudo("ebtables -A INPUT -p arp -j ARP_FILTER 2>/dev/null")
        r = self.execute_sudo(f"ebtables -A ARP_FILTER --arp-ip-src {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blocked ARP from %s on %s via ebtables", target_ip, self.config.name)
            return True
        return False

    def _block_iptables(self, target_ip: str) -> bool:
        """Block using iptables (basic L2, works on some systems)."""
        r = self.execute_sudo(f"iptables -A INPUT -s {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blocked ARP from %s on %s via iptables", target_ip, self.config.name)
            return True
        return False

    def _block_ip_neigh(self, target_ip: str, dev: str) -> bool:
        """Poison the ARP entry to a null MAC (blackhole the traffic)."""
        r = self.execute_sudo(f"ip neigh replace {target_ip} lladdr 00:00:00:00:00:00 dev {dev} nud permanent 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Blackholed ARP for %s on %s via ip neigh", target_ip, self.config.name)
            return True
        return False

    # ─── UNBLOCK Methods ─────────────────────────────────────────

    def unblock_ip_arp(self, target_ip: str, interface: str = "") -> bool:
        """Remove all block rules for target_ip across all backends."""
        dev = interface or self._get_default_iface()
        success = False

        # nft
        r = self.execute_sudo(f"nft --check list chain ip arp_filter input 2>/dev/null | grep -q '{target_ip}'")
        if r.exit_code == 0:
            self.execute_sudo("nft flush chain ip arp_filter input 2>/dev/null")
            success = True

        # arptables
        r = self.execute_sudo(f"arptables -D INPUT -s {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            success = True

        # ebtables
        r = self.execute_sudo(f"ebtables -D ARP_FILTER --arp-ip-src {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            success = True

        # iptables
        r = self.execute_sudo(f"iptables -D INPUT -s {target_ip} -j DROP 2>/dev/null")
        if r.exit_code == 0:
            success = True

        # ip neigh
        r = self.execute_sudo(f"ip neigh del {target_ip} dev {dev} 2>/dev/null")
        if r.exit_code == 0:
            success = True

        if success:
            logger.info("Unblocked ARP from %s on %s", target_ip, self.config.name)
        return success

    def unblock_all(self) -> bool:
        """Remove all nft ARP filter rules (flush the table)."""
        self.execute_sudo("nft flush table ip arp_filter 2>/dev/null")
        self.execute_sudo("arptables -F 2>/dev/null")
        self.execute_sudo("ebtables -F ARP_FILTER 2>/dev/null")
        logger.info("Flushed all ARP filter rules on %s", self.config.name)
        return True

    # ─── ARP Cache Operations ────────────────────────────────────

    def flush_arp_cache(self) -> bool:
        result = self.execute_sudo("ip neigh flush all")
        return result.exit_code == 0

    def get_arp_entry(self, ip: str) -> Optional[Dict[str, str]]:
        """Get a specific ARP entry."""
        r = self.execute(f"ip neigh show {ip}")
        if r.stdout.strip():
            parts = r.stdout.strip().split()
            if len(parts) >= 5:
                return {
                    "ip": parts[0],
                    "mac": parts[4].upper() if ":" in parts[4] else "",
                    "state": parts[2],
                    "interface": parts[5] if len(parts) > 5 else "",
                }
        return None

    def set_arp_entry(self, ip: str, mac: str, dev: str = "") -> bool:
        """Set a permanent ARP entry (for whitelisting)."""
        dev = dev or self._get_default_iface()
        r = self.execute_sudo(f"ip neigh replace {ip} lladdr {mac} dev {dev} nud permanent 2>/dev/null")
        return r.exit_code == 0

    def delete_arp_entry(self, ip: str, dev: str = "") -> bool:
        """Delete a specific ARP entry."""
        dev = dev or self._get_default_iface()
        r = self.execute_sudo(f"ip neigh del {ip} dev {dev} 2>/dev/null")
        return r.exit_code == 0

    def get_arp_count(self) -> int:
        """Get number of ARP entries."""
        r = self.execute("ip neigh show | wc -l")
        try:
            return int(r.stdout.strip())
        except ValueError:
            return 0

    # ─── Network Isolation ───────────────────────────────────────

    def isolate_network(self, interface: str = "") -> bool:
        if not interface:
            interface = self._get_default_iface()

        r = self.execute_sudo(f"ip link set {interface} down 2>/dev/null")
        if r.exit_code == 0:
            logger.warning("Network interface %s isolated on %s", interface, self.config.name)
            return True

        self.execute_sudo("nft add table ip isolate 2>/dev/null")
        self.execute_sudo("nft add chain ip isolate forward '{ type filter hook forward priority 0; policy drop; }' 2>/dev/null")
        r = self.execute_sudo("nft add rule ip isolate forward drop 2>/dev/null")
        if r.exit_code == 0:
            logger.warning("Network isolated via nft on %s", self.config.name)
            return True

        return False

    def restore_network(self, interface: str = "") -> bool:
        if not interface:
            interface = self._get_default_iface()

        r = self.execute_sudo(f"ip link set {interface} up 2>/dev/null")
        self.execute_sudo("nft delete table ip isolate 2>/dev/null")
        if r.exit_code == 0:
            logger.info("Network interface %s restored on %s", interface, self.config.name)
            return True
        return False

    # ─── Advanced: Rate Limiting ─────────────────────────────────

    def rate_limit_arp(self, max_per_second: int = 10, interface: str = "") -> bool:
        """Apply ARP rate limiting via nft."""
        dev = interface or self._get_default_iface()
        self.execute_sudo("nft add table ip arp_ratelimit 2>/dev/null")
        self.execute_sudo("nft add chain ip arp_ratelimit input '{ type filter hook input priority -15; policy accept; }' 2>/dev/null")
        r = self.execute_sudo(
            f"nft add rule ip arp_ratelimit input meta iifname {dev} arp limit rate {max_per_second}/burst "
            f"accept 2>/dev/null"
        )
        if r.exit_code == 0:
            self.execute_sudo("nft add rule ip arp_ratelimit input arp drop 2>/dev/null")
            logger.info("ARP rate limit set to %d/s on %s", max_per_second, self.config.name)
            return True
        return False

    def remove_rate_limit(self) -> bool:
        self.execute_sudo("nft delete table ip arp_ratelimit 2>/dev/null")
        return True

    # ─── Advanced: Port/Interface Isolation ──────────────────────

    def isolate_interface(self, interface: str) -> bool:
        """Bring down a specific interface."""
        r = self.execute(f"ip link set {interface} down 2>/dev/null")
        return r.exit_code == 0

    def restore_interface(self, interface: str) -> bool:
        r = self.execute(f"ip link set {interface} up 2>/dev/null")
        return r.exit_code == 0

    # ─── Advanced: DHCP Snooping Simulation ─────────────────────

    def check_dhcp_leases(self) -> List[Dict[str, str]]:
        """Read DHCP leases for cross-reference."""
        r = self.execute("cat /var/lib/NetworkManager/dhclient-*.lease 2>/dev/null || "
                         "cat /var/lib/dhclient/dhclient.leases 2>/dev/null || "
                         "cat /var/lib/dhcp/dhclient.leases 2>/dev/null")
        leases = []
        current = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if "lease {" in line:
                current = {}
            elif "fixed-address" in line:
                m = re.search(r"fixed-address\s+([\d.]+)", line)
                if m:
                    current["ip"] = m.group(1)
            elif "hardware ethernet" in line:
                m = re.search(r"hardware ethernet\s+([0-9a-fA-F:]+)", line)
                if m:
                    current["mac"] = m.group(1)
            elif "}" in line and current:
                leases.append(current)
                current = {}
        return leases

    # ─── System Info ─────────────────────────────────────────────

    def get_system_info(self) -> Dict[str, str]:
        info = {}
        r = self.execute("cat /etc/redhat-release 2>/dev/null || cat /etc/os-release 2>/dev/null | head -1")
        info["os"] = r.stdout.strip()
        r = self.execute("uname -r")
        info["kernel"] = r.stdout.strip()
        r = self.execute("hostname")
        info["hostname"] = r.stdout.strip()
        info["firewall_backend"] = self.firewall_backend
        return info

    def get_process_list(self) -> str:
        result = self.execute("ps aux")
        return result.stdout

    def test_connectivity(self) -> bool:
        result = self.execute("echo ok", timeout=5)
        return result.exit_code == 0 and "ok" in result.stdout

    def _get_default_iface(self) -> str:
        r = self.execute("ip route show default")
        match = re.search(r"dev (\S+)", r.stdout)
        return match.group(1) if match else "ens34"

    # ─── Legacy compatibility ────────────────────────────────────

    def check_arptables_rules(self) -> List[str]:
        info = self.check_firewall_rules()
        return info.get("rules", [])
