from collections import defaultdict, deque
from datetime import datetime

from .feature_schema import NSL_KDD_FEATURES


class FeatureExtractor:
    """Extracts NSL-KDD like features from live packet metadata."""

    def __init__(self):
        self.flow_first_seen = {}
        self.host_events = defaultdict(lambda: deque(maxlen=400))

    def _safe_float(self, value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def _safe_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default)

    def _normalize_protocol(self, protocol):
        proto = str(protocol or "tcp").lower()
        if proto in {"6", "tcp"}:
            return "tcp"
        if proto in {"17", "udp"}:
            return "udp"
        if proto in {"1", "icmp"}:
            return "icmp"
        return "tcp"

    def _extract_service(self, packet):
        service = packet.get("service")
        if service:
            return str(service).lower()
        dport = self._safe_int(packet.get("dst_port", 0))
        service_map = {
            80: "http",
            443: "http",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "domain_u",
            123: "ntp_u",
            110: "pop_3",
            143: "imap4",
        }
        return service_map.get(dport, "other")

    def _extract_flag(self, packet):
        flag = packet.get("flag")
        if flag:
            return str(flag)
        tcp_flags = str(packet.get("tcp_flags", "")).upper()
        if "S" in tcp_flags and "A" not in tcp_flags:
            return "S0"
        if "S" in tcp_flags and "A" in tcp_flags:
            return "SF"
        if "R" in tcp_flags:
            return "REJ"
        return "OTH"

    def extract(self, packet):
        now = datetime.utcnow().timestamp()

        src_ip = packet.get("src_ip", "0.0.0.0")
        dst_ip = packet.get("dst_ip", "0.0.0.0")
        src_port = self._safe_int(packet.get("src_port", 0))
        dst_port = self._safe_int(packet.get("dst_port", 0))

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        if flow_key not in self.flow_first_seen:
            self.flow_first_seen[flow_key] = now

        duration = max(0.0, now - self.flow_first_seen[flow_key])

        protocol_type = self._normalize_protocol(packet.get("protocol"))
        service = self._extract_service(packet)
        flag = self._extract_flag(packet)

        src_bytes = self._safe_float(packet.get("src_bytes", packet.get("length", 0)))
        dst_bytes = self._safe_float(packet.get("dst_bytes", 0))
        land = 1 if src_ip == dst_ip and src_port == dst_port and src_port != 0 else 0

        event = {
            "ts": now,
            "service": service,
            "dst_ip": dst_ip,
            "flag": flag,
            "src_port": src_port,
        }
        bucket = self.host_events[src_ip]
        bucket.append(event)

        last_2s = [e for e in bucket if now - e["ts"] <= 2.0]
        count = len(last_2s)
        srv_count = len([e for e in last_2s if e["service"] == service])

        def rate(matches, total):
            return float(matches) / float(total) if total > 0 else 0.0

        serror_rate = rate(len([e for e in last_2s if e["flag"] in {"S0", "S1", "S2", "S3"}]), count)
        rerror_rate = rate(len([e for e in last_2s if e["flag"] in {"REJ", "RST"}]), count)
        srv_serror_rate = rate(len([e for e in last_2s if e["service"] == service and e["flag"] in {"S0", "S1", "S2", "S3"}]), srv_count)
        srv_rerror_rate = rate(len([e for e in last_2s if e["service"] == service and e["flag"] in {"REJ", "RST"}]), srv_count)
        same_srv_rate = rate(srv_count, count)
        diff_srv_rate = 1.0 - same_srv_rate if count > 0 else 0.0

        unique_dst_hosts = len(set(e["dst_ip"] for e in last_2s))
        srv_diff_host_rate = rate(len([e for e in last_2s if e["service"] == service and e["dst_ip"] != dst_ip]), srv_count)

        features = {
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": land,
            "wrong_fragment": self._safe_int(packet.get("wrong_fragment", 0)),
            "urgent": self._safe_int(packet.get("urgent", 0)),
            "hot": self._safe_int(packet.get("hot", 0)),
            "num_failed_logins": self._safe_int(packet.get("num_failed_logins", 0)),
            "logged_in": self._safe_int(packet.get("logged_in", 0)),
            "num_compromised": self._safe_int(packet.get("num_compromised", 0)),
            "root_shell": self._safe_int(packet.get("root_shell", 0)),
            "su_attempted": self._safe_int(packet.get("su_attempted", 0)),
            "num_root": self._safe_int(packet.get("num_root", 0)),
            "num_file_creations": self._safe_int(packet.get("num_file_creations", 0)),
            "num_shells": self._safe_int(packet.get("num_shells", 0)),
            "num_access_files": self._safe_int(packet.get("num_access_files", 0)),
            "num_outbound_cmds": self._safe_int(packet.get("num_outbound_cmds", 0)),
            "is_host_login": self._safe_int(packet.get("is_host_login", 0)),
            "is_guest_login": self._safe_int(packet.get("is_guest_login", 0)),
            "count": float(count),
            "srv_count": float(srv_count),
            "serror_rate": serror_rate,
            "srv_serror_rate": srv_serror_rate,
            "rerror_rate": rerror_rate,
            "srv_rerror_rate": srv_rerror_rate,
            "same_srv_rate": same_srv_rate,
            "diff_srv_rate": diff_srv_rate,
            "srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_count": float(unique_dst_hosts),
            "dst_host_srv_count": float(srv_count),
            "dst_host_same_srv_rate": same_srv_rate,
            "dst_host_diff_srv_rate": diff_srv_rate,
            "dst_host_same_src_port_rate": rate(len([e for e in last_2s if e["src_port"] == src_port]), count),
            "dst_host_srv_diff_host_rate": srv_diff_host_rate,
            "dst_host_serror_rate": serror_rate,
            "dst_host_srv_serror_rate": srv_serror_rate,
            "dst_host_rerror_rate": rerror_rate,
            "dst_host_srv_rerror_rate": srv_rerror_rate,
        }

        for feature_name in NSL_KDD_FEATURES:
            features.setdefault(feature_name, 0.0)

        return features
