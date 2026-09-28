import re
import time
from typing import Dict, List, Optional
from dataclasses import dataclass

from ..config import ServerConfig
from ..utils.logger import get_logger

logger = get_logger("windows_connector")


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int
    timestamp: float = 0.0
    duration: float = 0.0


class WindowsConnector:
    def __init__(self, config: ServerConfig):
        self.config = config
        self._session = None
        self._connected = False

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def host(self) -> str:
        return self.config.host

    def connect(self) -> bool:
        try:
            import winrm

            protocol = "https" if self.config.winrm_use_ssl else "http"
            endpoint = f"{protocol}://{self.config.host}:{self.config.winrm_port}/wsman"

            if self.config.ssh_key_path:
                self._session = winrm.Session(
                    endpoint,
                    auth=(self.config.username, self.config.password),
                    transport="kerberos",
                )
            else:
                self._session = winrm.Session(
                    endpoint,
                    auth=(self.config.username, self.config.password),
                )

            test_result = self._session.run_cmd("echo ok")
            if test_result.status_code == 0:
                self._connected = True
                logger.info("Connected to Windows server: %s (%s)", self.config.name, self.config.host)
                return True
            else:
                logger.error("WinRM test failed for %s: %s", self.config.host, test_result.std_err)
                return False

        except ImportError:
            logger.error("pywinrm not installed. Run: pip install pywinrm")
            return False
        except Exception as e:
            logger.error("Failed to connect to %s: %s", self.config.host, e)
            return False

    def disconnect(self):
        self._session = None
        self._connected = False
        logger.info("Disconnected from Windows server: %s", self.config.name)

    def is_connected(self) -> bool:
        return self._connected

    def execute(self, command: str, timeout: int = 30) -> CommandResult:
        if not self._connected or not self._session:
            return CommandResult(command=command, stdout="", stderr="Not connected", exit_code=-1)

        start = time.time()
        try:
            result = self._session.run_cmd(command)
            duration = time.time() - start

            return CommandResult(
                command=command,
                stdout=result.std_out.decode("utf-8", errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out),
                stderr=result.std_err.decode("utf-8", errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err),
                exit_code=result.status_code,
                timestamp=start,
                duration=duration,
            )

        except Exception as e:
            return CommandResult(
                command=command,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                timestamp=start,
                duration=time.time() - start,
            )

    def execute_ps(self, script: str) -> CommandResult:
        if not self._connected or not self._session:
            return CommandResult(command=script, stdout="", stderr="Not connected", exit_code=-1)

        start = time.time()
        try:
            result = self._session.run_ps(script)
            duration = time.time() - start

            return CommandResult(
                command=script,
                stdout=result.std_out.decode("utf-8", errors="replace") if isinstance(result.std_out, bytes) else str(result.std_out),
                stderr=result.std_err.decode("utf-8", errors="replace") if isinstance(result.std_err, bytes) else str(result.std_err),
                exit_code=result.status_code,
                timestamp=start,
                duration=duration,
            )
        except Exception as e:
            return CommandResult(
                command=script,
                stdout="",
                stderr=str(e),
                exit_code=-1,
                timestamp=start,
                duration=time.time() - start,
            )

    def get_arp_table(self) -> List[Dict[str, str]]:
        result = self.execute("arp -a")
        entries = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                mac = parts[1].replace("-", ":")
                if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac):
                    entries.append({
                        "ip": parts[0],
                        "mac": mac.upper(),
                    })
        return entries

    def get_arp_cache(self) -> List[Dict[str, str]]:
        script = "Get-NetNeighbor | Select-Object IPAddress, LinkLayerAddress, State | Format-Table -AutoSize"
        result = self.execute_ps(script)
        entries = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                mac = parts[1].replace("-", ":")
                entries.append({
                    "ip": parts[0],
                    "mac": mac.upper() if mac != "N/A" else "",
                    "state": parts[2] if len(parts) > 2 else "",
                })
        return entries

    def get_network_interfaces(self) -> List[Dict[str, str]]:
        script = """
        Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
            $adapter = $_
            $ip = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name = $adapter.Name
                MacAddress = $adapter.MacAddress
                IPAddress = if ($ip) { $ip.IPAddress } else { '' }
                SubnetMask = if ($ip) { $ip.PrefixLength } else { '' }
            }
        } | Format-Table -AutoSize
        """
        result = self.execute_ps(script)
        interfaces = []
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("-") and not line.startswith("Name"):
                interfaces.append({
                    "name": parts[0],
                    "mac": parts[1].replace("-", ":") if len(parts) > 1 else "",
                    "ip": parts[2] if len(parts) > 2 else "",
                    "netmask": parts[3] if len(parts) > 3 else "",
                })
        return interfaces

    def get_default_gateway(self) -> str:
        result = self.execute("ipconfig")
        for line in result.stdout.splitlines():
            if "Default Gateway" in line:
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)
        return ""

    def get_event_log_arp(self, max_events: int = 100) -> List[Dict[str, str]]:
        script = f"""
        Get-WinEvent -LogName "System" -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Message -match 'ARP|MAC|spoof|poison' }} |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Format-Table -AutoSize
        """
        result = self.execute_ps(script)
        events = []
        for line in result.stdout.strip().splitlines():
            if line.strip() and not line.startswith("-") and not line.startswith("TimeCreated"):
                events.append({"raw": line})
        return events

    def get_powershell_arp_monitor(self) -> str:
        script = """
        Get-NetNeighbor -State Unreachable | Select-Object IPAddress, LinkLayerAddress, State
        """
        result = self.execute_ps(script)
        return result.stdout

    def block_ip_arp(self, target_ip: str) -> bool:
        script = f"""
        New-NetFirewallRule -DisplayName "ARP Block {target_ip}" `
            -Direction Inbound `
            -Protocol ARP `
            -RemoteAddress {target_ip} `
            -Action Block `
            -ErrorAction SilentlyContinue
        """
        result = self.execute_ps(script)
        if result.exit_code == 0:
            logger.info("Blocked ARP from %s on %s", target_ip, self.config.name)
            return True

        netsh_cmd = f'netsh advfirewall firewall add rule name="ARP Block {target_ip}" protocol=any dir=in remoteip={target_ip} action=block'
        result = self.execute(netsh_cmd)
        if result.exit_code == 0:
            logger.info("Blocked ARP from %s via netsh on %s", target_ip, self.config.name)
            return True

        logger.error("Failed to block ARP from %s on %s", target_ip, self.config.name)
        return False

    def unblock_ip_arp(self, target_ip: str) -> bool:
        script = f'Remove-NetFirewallRule -DisplayName "ARP Block {target_ip}" -ErrorAction SilentlyContinue'
        result = self.execute_ps(script)

        netsh_cmd = f'netsh advfirewall firewall delete rule name="ARP Block {target_ip}"'
        result2 = self.execute(netsh_cmd)

        return result.exit_code == 0 or result2.exit_code == 0

    def flush_arp_cache(self) -> bool:
        result = self.execute("arp -d *")
        return result.exit_code == 0

    def isolate_network(self, interface: str = "") -> bool:
        script = """
        Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} |
        Disable-NetAdapter -Confirm:$false
        """
        result = self.execute_ps(script)
        if result.exit_code == 0:
            logger.warning("Network isolated on %s", self.config.name)
            return True
        return False

    def restore_network(self, interface: str = "") -> bool:
        if interface:
            script = f"Enable-NetAdapter -Name '{interface}' -Confirm:$false"
        else:
            script = """
            Get-NetAdapter | Where-Object {$_.Status -eq 'Disabled'} |
            Enable-NetAdapter -Confirm:$false
            """
        result = self.execute_ps(script)
        if result.exit_code == 0:
            logger.info("Network restored on %s", self.config.name)
            return True
        return False

    def get_security_event_log(self, max_events: int = 200) -> List[Dict[str, str]]:
        script = f"""
        Get-WinEvent -LogName "Security" -MaxEvents {max_events} -ErrorAction SilentlyContinue |
        Where-Object {{ $_.Id -in @(4624, 4625, 4720, 4726, 4732) }} |
        Select-Object TimeCreated, Id, Message |
        Format-Table -AutoSize
        """
        result = self.execute_ps(script)
        events = []
        for line in result.stdout.strip().splitlines():
            if line.strip() and not line.startswith("-") and not line.startswith("TimeCreated"):
                events.append({"raw": line})
        return events

    def test_connectivity(self) -> bool:
        result = self.execute("echo ok", timeout=5)
        return result.exit_code == 0 and "ok" in result.stdout.lower()
