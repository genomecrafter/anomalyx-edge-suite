from collections import deque
from datetime import datetime
import socket
import subprocess
import re
import time
import os
import ipaddress

from anomalyx_core.models.classifier import get_classifier

from .feature_extractor import FeatureExtractor
from .packet_capture import PacketCapture
from .policy_engine import PolicyEngine
from .signature_engine import SignatureEngine
from .zero_day_detector import ZeroDayDetector
from .enforcer import IPSEnforcer


class IPSOrchestrator:
    """Coordinates live capture, hybrid detection, and IPS decisions."""

    def __init__(self):
        self.classifier = get_classifier()
        self.extractor = FeatureExtractor()
        self.signature = SignatureEngine()
        self.zero_day = ZeroDayDetector()
        self.policy = PolicyEngine()
        self.enforcer = IPSEnforcer()

        self.capture = PacketCapture(self.process_packet)
        self.events = deque(maxlen=300)
        self.total_processed = 0
        self.total_actions = {"allow": 0, "alert": 0, "temp_block_ip": 0, "block_ip": 0}
        self.socketio = None
        self.local_ips = self._discover_local_ips()
        self._local_ips_refreshed_at = time.time()
        self._reverse_dns_cache = {}
        self.enable_reverse_dns = os.getenv("IPS_ENABLE_REVERSE_DNS", "0") == "1"

    def bind_socket(self, socketio):
        self.socketio = socketio

    def start(self, interface=None):
        started = self.capture.start(interface=interface)
        self._emit_status()
        return started

    def stop(self):
        self.capture.stop()
        self._emit_status()

    def process_packet(self, packet):
        packet = {**packet, "traffic_source": self._classify_traffic_source(packet)}

        if self._is_background_noise(packet):
            event = self._build_bypass_event(packet)
            self.total_processed += 1
            self.total_actions["allow"] = self.total_actions.get("allow", 0) + 1
            self.events.appendleft(event)

            if self.socketio:
                self.socketio.emit("ips_event", event)
                self._emit_status()

            source = packet.get("traffic_source", {})
            print(
                f"[IPS] {packet.get('src_ip', '?')}:{packet.get('src_port', '-') } -> "
                f"{packet.get('dst_ip', '?')}:{packet.get('dst_port', '-') } | "
                f"{source.get('direction', 'unknown')} | "
                f"remote={source.get('remote_ip', 'n/a')} ({source.get('remote_host', 'unknown')}) | "
                "action=allow risk=0.0 (noise_bypass)"
            )
            return event

        features_41 = self.extractor.extract(packet)
        signature_result = self.signature.evaluate(packet, features_41)
        ml_result = self.classifier.classify_packet(features_41)
        zero_day_result = self.zero_day.score(features_41, ml_result=ml_result)
        decision = self.policy.decide(signature_result, ml_result, zero_day_result, packet)

        # Normalize action names across policy versions.
        decision["action"] = self._normalize_action(decision.get("action"))
        enforcement = self.enforcer.enforce(decision, packet)

        self.total_processed += 1
        self.total_actions[decision["action"]] = self.total_actions.get(decision["action"], 0) + 1

        event = {
            "timestamp": packet.get("timestamp", datetime.utcnow().isoformat()),
            "packet": packet,
            "features": features_41,
            "signature": signature_result,
            "ml": ml_result,
            "zero_day": zero_day_result,
            "decision": decision,
            "enforcement": enforcement,
        }
        self.events.appendleft(event)

        if decision["action"] == "block_ip":
            src_ip = packet.get("src_ip")
            if src_ip:
                self.signature.add_blocklist(src_ip)

        if self.socketio:
            self.socketio.emit("ips_event", event)
            self._emit_status()

        source = packet.get("traffic_source", {})
        print(
            f"[IPS] {packet.get('src_ip', '?')}:{packet.get('src_port', '-') } -> "
            f"{packet.get('dst_ip', '?')}:{packet.get('dst_port', '-') } | "
            f"{source.get('direction', 'unknown')} | "
            f"remote={source.get('remote_ip', 'n/a')} ({source.get('remote_host', 'unknown')}) | "
            f"action={decision.get('action')} risk={decision.get('risk')}"
        )

        return event

    def _build_bypass_event(self, packet):
        return {
            "timestamp": packet.get("timestamp", datetime.utcnow().isoformat()),
            "packet": packet,
            "features": {},
            "signature": {
                "severity": 0,
                "matches": [],
                "is_match": False,
                "engine": "bypass",
                "suricata_enabled": False,
            },
            "ml": {
                "attack_type": "normal",
                "confidence": 100,
                "category": "normal",
            },
            "zero_day": {
                "anomaly_score": 0.0,
                "is_zero_day": False,
                "reason": "noise_bypass",
                "components": {"shift": 0, "spike": 0, "rarity": 0, "threshold": 1},
                "top_shift_features": [],
                "override_normal": False,
            },
            "decision": {
                "risk": 0.0,
                "action": "allow",
                "reason": "noise_bypass_multicast_or_local_discovery",
            },
            "enforcement": {
                "timestamp": datetime.utcnow().isoformat(),
                "action": "allow",
                "status": "no_action",
                "details": "noise_bypass",
                "rule_name": None,
                "applied": False,
            },
        }

    def _is_background_noise(self, packet):
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        proto = str(packet.get("protocol", "")).lower()
        dport = int(packet.get("dst_port") or 0)
        sport = int(packet.get("src_port") or 0)

        noisy_ports = {137, 138, 139, 1900, 5353, 5355}
        if dport in noisy_ports or sport in noisy_ports:
            return True

        for ip in (src_ip, dst_ip):
            if not ip:
                continue
            candidate = str(ip).split("%", 1)[0]
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if addr.is_multicast:
                return True
            if addr.version == 4 and str(addr).endswith(".255"):
                return True

        # Scapy may emit empty/placeholder packets while interfaces warm up.
        if (src_ip in {None, "0.0.0.0"} and dst_ip in {None, "0.0.0.0"}) or proto in {"", "other"}:
            return True

        return False

    def inject_packet(self, packet):
        return self.process_packet(packet)

    def status(self):
        allow = int(self.total_actions.get("allow", 0))
        alert = int(self.total_actions.get("alert", 0))
        temp_block_ip = (
            int(self.total_actions.get("temp_block_ip", 0))
            + int(self.total_actions.get("drop_packet", 0))
            + int(self.total_actions.get("drop", 0))
        )
        block_ip = int(self.total_actions.get("block_ip", 0)) + int(self.total_actions.get("block", 0))

        return {
            "running": self.capture.is_running,
            "capture_error": self.capture.last_error,
            "processed_packets": self.total_processed,
            "actions": {
                "allow": allow,
                "alert": alert,
                "temp_block_ip": temp_block_ip,
                "block_ip": block_ip,
            },
            "blocklisted_ips": sorted(self.signature.blocklisted_ips),
            "signature": self.signature.runtime_status(),
            "policy": self.policy.status(),
            "enforcement": self.enforcer.status(),
        }

    def get_events(self, limit=50):
        return list(self.events)[:limit]

    def get_enforcement_logs(self, limit=50):
        return self.enforcer.tail_logs(limit=limit)

    def execute_command(self, command):
        cmd = command or {}
        action = str(cmd.get("action") or "").lower()

        if action == "unblock_ip":
            target_ip = cmd.get("remote_ip") or cmd.get("ip")
            if not target_ip:
                return {
                    "ok": False,
                    "details": "missing_remote_ip",
                    "action": action,
                }
            result = self.enforcer.unblock_ip(target_ip, reason="remote_command")
            return {
                "ok": result.get("status") == "applied",
                "action": action,
                "remote_ip": target_ip,
                "result": result,
            }

        return {
            "ok": False,
            "details": f"unsupported_command:{action}",
            "action": action,
        }

    def _emit_status(self):
        if self.socketio:
            self.socketio.emit("ips_status", self.status())

    def _discover_local_ips(self):
        local_ips = {"127.0.0.1", "::1"}

        # Best effort via resolver for current host addresses.
        try:
            hostname = socket.gethostname()
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                if family in (socket.AF_INET, socket.AF_INET6):
                    ip = sockaddr[0]
                    if ip:
                        local_ips.add(ip)
        except Exception:
            pass

        # Capture active routed addresses (including temporary IPv6 where possible).
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.connect(("8.8.8.8", 80))
            local_ips.add(s4.getsockname()[0])
            s4.close()
        except Exception:
            pass

        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s6.connect(("2001:4860:4860::8888", 80))
            local_ips.add(s6.getsockname()[0])
            s6.close()
        except Exception:
            pass

        # Windows-specific fallback: parse ipconfig output for all assigned IPs.
        try:
            output = subprocess.check_output(["ipconfig"], text=True, errors="ignore")
            for line in output.splitlines():
                if "IPv4 Address" in line or "IPv6 Address" in line or "Temporary IPv6 Address" in line or "Link-local IPv6 Address" in line:
                    matches = re.findall(r"([0-9a-fA-F:.]+)", line)
                    for candidate in matches:
                        if "." in candidate or ":" in candidate:
                            # Remove scope IDs like fe80::1%13
                            local_ips.add(candidate.split("%", 1)[0])
        except Exception:
            pass

        return local_ips

    def _resolve_host(self, ip):
        if not self.enable_reverse_dns:
            return "disabled"
        if not ip:
            return "unknown"
        if ip in self._reverse_dns_cache:
            return self._reverse_dns_cache[ip]
        try:
            socket.setdefaulttimeout(0.3)
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = "unknown"
        finally:
            socket.setdefaulttimeout(None)
        self._reverse_dns_cache[ip] = host
        return host

    def _classify_traffic_source(self, packet):
        # Temporary IPv6 addresses rotate; refresh local IP set periodically.
        if time.time() - self._local_ips_refreshed_at > 30:
            self.local_ips = self._discover_local_ips()
            self._local_ips_refreshed_at = time.time()

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")

        if isinstance(src_ip, str):
            src_ip = src_ip.split("%", 1)[0]
        if isinstance(dst_ip, str):
            dst_ip = dst_ip.split("%", 1)[0]

        src_local = src_ip in self.local_ips if src_ip else False
        dst_local = dst_ip in self.local_ips if dst_ip else False

        if src_local and not dst_local:
            direction = "outgoing"
            remote_ip = dst_ip
        elif dst_local and not src_local:
            direction = "incoming"
            remote_ip = src_ip
        elif src_local and dst_local:
            direction = "local"
            remote_ip = dst_ip
        else:
            direction = "external_or_unknown"
            remote_ip = dst_ip or src_ip

        return {
            "direction": direction,
            "remote_ip": remote_ip,
            "remote_host": self._resolve_host(remote_ip),
        }

    def _normalize_action(self, action):
        normalized = str(action or "allow").lower()
        mapping = {
            "allow": "allow",
            "alert": "alert",
            "drop": "temp_block_ip",
            "drop_packet": "temp_block_ip",
            "temp_block_ip": "temp_block_ip",
            "block": "block_ip",
            "block_ip": "block_ip",
        }
        return mapping.get(normalized, "allow")


_orchestrator = None


def get_ips_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = IPSOrchestrator()
    return _orchestrator
