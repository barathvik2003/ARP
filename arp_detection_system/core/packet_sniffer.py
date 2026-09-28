import time
import threading
import socket
import struct
from typing import Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from ..utils.logger import get_logger

logger = get_logger("packet_sniffer")


@dataclass
class RawArpPacket:
    operation: int  # 1=request, 2=reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    timestamp: float = 0.0
    source_interface: str = ""


@dataclass
class SnifferStats:
    total_packets: int = 0
    arp_requests: int = 0
    arp_replies: int = 0
    unique_sources: int = 0
    started_at: float = 0.0


class PacketSniffer:
    def __init__(self, interface: str = ""):
        self.interface = interface
        self._running = False
        self._packets: List[RawArpPacket] = []
        self._packet_callbacks: List[Callable[[RawArpPacket], None]] = []
        self._stats = SnifferStats(started_at=time.time())
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def on_packet(self, callback: Callable[[RawArpPacket], None]):
        self._packet_callbacks.append(callback)

    def start(self, use_scapy: bool = True):
        self._running = True
        self._stats.started_at = time.time()

        if use_scapy:
            self._thread = threading.Thread(target=self._sniff_scapy, daemon=True)
        else:
            self._thread = threading.Thread(target=self._sniff_raw, daemon=True)

        self._thread.start()
        logger.info("Packet sniffer started on interface: %s", self.interface or "auto")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Packet sniffer stopped")

    def get_packets(self, limit: int = 100) -> List[RawArpPacket]:
        with self._lock:
            return list(self._packets[-limit:])

    def get_stats(self) -> SnifferStats:
        with self._lock:
            return self._stats

    def _sniff_scapy(self):
        try:
            from scapy.all import sniff, ARP, conf

            iface = self.interface or None
            bpf_filter = "arp"

            logger.info("Starting Scapy sniff on %s", iface or "default")

            def process_packet(pkt):
                if not self._running:
                    return False
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    packet = RawArpPacket(
                        operation=int(arp.op),
                        sender_mac=arp.hwsrc.upper() if arp.hwsrc else "",
                        sender_ip=arp.psrc if arp.psrc else "",
                        target_mac=arp.hwdst.upper() if arp.hwdst else "",
                        target_ip=arp.pdst if arp.pdst else "",
                        timestamp=time.time(),
                        source_interface=str(pkt.sniffed_on) if hasattr(pkt, "sniffed_on") else "",
                    )
                    self._process_packet(packet)
                return None

            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=process_packet,
                store=0,
                stop_filter=lambda _: not self._running,
            )

        except ImportError:
            logger.warning("Scapy not available, falling back to raw socket sniffing")
            self._sniff_raw()
        except Exception as e:
            logger.error("Scapy sniff error: %s", e)
            self._sniff_raw()

    def _sniff_raw(self):
        try:
            if socket.hasattr(socket, "AF_PACKET"):
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ARP)
                if hasattr(socket, "SIO_RCVALL"):
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

            logger.info("Starting raw socket ARP sniff")
            sock.settimeout(1.0)

            while self._running:
                try:
                    data, addr = sock.recvfrom(65535)
                    packet = self._parse_raw_arp(data)
                    if packet:
                        self._process_packet(packet)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug("Raw socket recv error: %s", e)

            sock.close()

        except PermissionError:
            logger.error("Raw socket requires administrator/root privileges")
        except Exception as e:
            logger.error("Raw socket error: %s", e)

    def _parse_raw_arp(self, data: bytes) -> Optional[RawArpPacket]:
        try:
            if len(data) < 28:
                return None

            eth_header = struct.unpack("!6s6sH", data[:14])
            ethertype = eth_header[2]

            if ethertype == 0x0806:
                arp_data = data[14:]
            else:
                return None

            if len(arp_data) < 20:
                return None

            arp_header = struct.unpack("!HHBBH", arp_data[:8])
            opcode = arp_header[4]

            if opcode not in (1, 2):
                return None

            sender_mac = ":".join(f"{b:02X}" for b in struct.unpack("!6BB", arp_data[8:14]))
            sender_ip = ".".join(str(b) for b in struct.unpack("!BBBB", arp_data[14:18]))
            target_mac = ":".join(f"{b:02X}" for b in struct.unpack("!6BB", arp_data[18:24]))
            target_ip = ".".join(str(b) for b in struct.unpack("!BBBB", arp_data[24:28]))

            return RawArpPacket(
                operation=opcode,
                sender_mac=sender_mac,
                sender_ip=sender_ip,
                target_mac=target_mac,
                target_ip=target_ip,
                timestamp=time.time(),
            )
        except Exception:
            return None

    def _process_packet(self, packet: RawArpPacket):
        with self._lock:
            self._packets.append(packet)
            if len(self._packets) > 10000:
                self._packets = self._packets[-5000:]

            self._stats.total_packets += 1
            if packet.operation == 1:
                self._stats.arp_requests += 1
            elif packet.operation == 2:
                self._stats.arp_replies += 1

        for cb in self._packet_callbacks:
            try:
                cb(packet)
            except Exception as e:
                logger.error("Packet callback error: %s", e)
