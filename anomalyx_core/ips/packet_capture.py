import threading
import time


class PacketCapture:
    """Best-effort live packet capture wrapper using scapy when available."""

    def __init__(self, packet_handler):
        self.packet_handler = packet_handler
        self._running = False
        self._thread = None
        self._sniffer = None
        self._interface = None
        self.last_error = None

    def _to_packet_dict(self, packet):
        src_ip = None
        dst_ip = None
        ip_version = None

        if packet.haslayer("IP"):
            src_ip = getattr(packet["IP"], "src", None)
            dst_ip = getattr(packet["IP"], "dst", None)
            ip_version = 4
        elif packet.haslayer("IPv6"):
            src_ip = getattr(packet["IPv6"], "src", None)
            dst_ip = getattr(packet["IPv6"], "dst", None)
            ip_version = 6
        elif packet.haslayer("ARP"):
            src_ip = getattr(packet["ARP"], "psrc", None)
            dst_ip = getattr(packet["ARP"], "pdst", None)
            ip_version = 0

        src_port = None
        dst_port = None
        protocol = "other"
        tcp_flags = ""

        if packet.haslayer("TCP"):
            protocol = "tcp"
            src_port = int(packet["TCP"].sport)
            dst_port = int(packet["TCP"].dport)
            tcp_flags = str(packet["TCP"].flags)
        elif packet.haslayer("UDP"):
            protocol = "udp"
            src_port = int(packet["UDP"].sport)
            dst_port = int(packet["UDP"].dport)
        elif packet.haslayer("ICMP"):
            protocol = "icmp"

        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_version": ip_version,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": int(len(packet)),
            "tcp_flags": tcp_flags,
        }

    def start(self, interface=None):
        if self._running:
            return True

        try:
            __import__("scapy.all", fromlist=["AsyncSniffer"])
        except Exception as exc:
            self.last_error = f"Scapy capture runtime unavailable: {exc}"
            self._running = False
            return False

        self._running = True
        self._interface = interface
        self.last_error = None

        def _runner():
            try:
                AsyncSniffer = __import__("scapy.all", fromlist=["AsyncSniffer"]).AsyncSniffer

                def _on_packet(pkt):
                    if not self._running:
                        return
                    try:
                        packet_dict = self._to_packet_dict(pkt)
                        self.packet_handler(packet_dict)
                    except Exception as exc:
                        self.last_error = str(exc)

                self._sniffer = AsyncSniffer(prn=_on_packet, store=False, iface=self._interface)
                self._sniffer.start()
                self._sniffer.join()
            except Exception as exc:
                self.last_error = str(exc)
                self._running = False

        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                self.last_error = str(exc)
            finally:
                self._sniffer = None

    @property
    def is_running(self):
        return self._running
