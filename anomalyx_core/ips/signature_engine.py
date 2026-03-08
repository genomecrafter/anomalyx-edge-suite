# class SignatureEngine:
#     """Standalone signature detector using handcrafted multi-rule scoring."""

#     def __init__(self):
#         self.blocklisted_ips = set()
#         self.last_engine = "fallback_rules_v2"
#         self.rule_hit_count = 0
#         self.critical_rule_hits = 0
#         self.sensitive_ports = {
#             21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
#             389, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900,
#             6379, 8080,
#         }

#     def add_blocklist(self, ip):
#         if ip:
#             self.blocklisted_ips.add(str(ip))

#     def _to_float(self, value, default=0.0):
#         try:
#             return float(value)
#         except (TypeError, ValueError):
#             return float(default)

#     def _to_int(self, value, default=0):
#         try:
#             return int(value)
#         except (TypeError, ValueError):
#             return int(default)

#     def _fallback_rules(self, packet, features):
#         src_ip = packet.get("src_ip")
#         dst_ip = packet.get("dst_ip")
#         protocol = str(packet.get("protocol", "")).lower()
#         dport = self._to_int(packet.get("dst_port", 0), 0)
#         sport = self._to_int(packet.get("src_port", 0), 0)
#         flag = str(features.get("flag", ""))

#         count = self._to_float(features.get("count", 0))
#         srv_count = self._to_float(features.get("srv_count", 0))
#         serror_rate = self._to_float(features.get("serror_rate", 0))
#         srv_serror_rate = self._to_float(features.get("srv_serror_rate", 0))
#         rerror_rate = self._to_float(features.get("rerror_rate", 0))
#         same_srv_rate = self._to_float(features.get("same_srv_rate", 0))
#         diff_srv_rate = self._to_float(features.get("diff_srv_rate", 0))
#         src_bytes = self._to_float(features.get("src_bytes", packet.get("length", 0)))
#         dst_bytes = self._to_float(features.get("dst_bytes", 0))
#         wrong_fragment = self._to_int(features.get("wrong_fragment", 0), 0)
#         urgent = self._to_int(features.get("urgent", 0), 0)
#         num_failed_logins = self._to_int(features.get("num_failed_logins", 0), 0)
#         hot = self._to_int(features.get("hot", 0), 0)
#         num_compromised = self._to_int(features.get("num_compromised", 0), 0)
#         root_shell = self._to_int(features.get("root_shell", 0), 0)
#         su_attempted = self._to_int(features.get("su_attempted", 0), 0)
#         num_root = self._to_int(features.get("num_root", 0), 0)
#         num_shells = self._to_int(features.get("num_shells", 0), 0)
#         num_access_files = self._to_int(features.get("num_access_files", 0), 0)
#         is_guest_login = self._to_int(features.get("is_guest_login", 0), 0)
#         land = self._to_int(features.get("land", 0), 0)
#         dst_host_srv_diff_host_rate = self._to_float(features.get("dst_host_srv_diff_host_rate", 0))
#         dst_host_serror_rate = self._to_float(features.get("dst_host_serror_rate", 0))

#         severity = 0.0
#         matches = []

#         def add_rule(name, score):
#             nonlocal severity
#             severity += float(score)
#             matches.append(name)

#         if src_ip in self.blocklisted_ips or dst_ip in self.blocklisted_ips:
#             add_rule("ioc_blocklist_hit", 95)

#         if land == 1:
#             add_rule("land_attack", 90)

#         if protocol == "tcp" and flag in {"S0", "S1", "S2", "S3"} and count > 25:
#             add_rule("syn_flood_pattern", 60)
#         if protocol == "tcp" and flag in {"S0", "S1", "S2", "S3"} and serror_rate > 0.6:
#             add_rule("syn_error_rate_spike", 28)

#         if protocol == "tcp" and dport in self.sensitive_ports and count > 10 and src_bytes < 180:
#             add_rule("sensitive_port_scan", 55)
#         if protocol == "tcp" and dport in {22, 23, 3389} and num_failed_logins >= 3:
#             add_rule("credential_attack_pattern", 35)

#         if diff_srv_rate > 0.85 and same_srv_rate < 0.15 and count > 20:
#             add_rule("horizontal_service_scan", 65)
#         if dst_host_srv_diff_host_rate > 0.7 and count > 18:
#             add_rule("distributed_host_scan", 35)

#         if rerror_rate > 0.6 and count > 12:
#             add_rule("rerror_scan_pattern", 48)
#         if dst_host_serror_rate > 0.8 and srv_serror_rate > 0.8:
#             add_rule("service_failure_storm", 28)

#         if protocol == "udp" and dport == 53 and src_bytes < 100 and dst_bytes > 1500:
#             add_rule("dns_amplification_like", 72)
#         if protocol == "udp" and count > 45 and diff_srv_rate > 0.8:
#             add_rule("udp_flood_sweep", 52)

#         if num_failed_logins >= 4 and count > 8:
#             add_rule("bruteforce_login_pattern", 58)
#         if is_guest_login == 1 and hot > 8:
#             add_rule("guest_account_abuse", 35)

#         if hot >= 10 or num_compromised >= 6:
#             add_rule("host_compromise_activity", 68)
#         if num_access_files >= 4 and num_compromised >= 3:
#             add_rule("sensitive_file_access_pattern", 36)

#         if root_shell == 1 or su_attempted == 1 or num_root >= 5 or num_shells >= 2:
#             add_rule("privilege_escalation_pattern", 85)

#         if wrong_fragment > 0 or urgent > 0:
#             add_rule("malformed_packet_pattern", 45)

#         if protocol == "tcp" and srv_count > 20 and srv_serror_rate > 0.8 and sport > 49152:
#             add_rule("high_rate_connection_reset_pattern", 50)

#         # Compound indicators increase severity substantially.
#         match_set = set(matches)
#         if {"syn_flood_pattern", "sensitive_port_scan"}.issubset(match_set):
#             add_rule("combo_scan_flood_escalation", 20)
#         if {"host_compromise_activity", "privilege_escalation_pattern"}.issubset(match_set):
#             add_rule("post_exploitation_escalation", 25)
#         if len(matches) >= 4:
#             add_rule("multi_indicator_consensus", 18)

#         severity = min(round(severity, 2), 100.0)

#         return {
#             "severity": severity,
#             "matches": matches,
#             "is_match": bool(matches),
#             "engine": "fallback_rules_v2",
#         }

#     def evaluate(self, packet, features):
#         fallback = self._fallback_rules(packet, features)

#         severity = fallback.get("severity", 0)
#         matches = list(fallback.get("matches", []))
#         engine = fallback.get("engine", "fallback_rules_v2")
#         self.last_engine = engine
#         if matches:
#             self.rule_hit_count += 1
#             if severity >= 85:
#                 self.critical_rule_hits += 1

#         return {
#             "severity": severity,
#             "matches": matches,
#             "is_match": bool(matches),
#             "engine": engine,
#             "suricata_enabled": False,
#         }

#     def runtime_status(self):
#         return {
#             "mode": self.last_engine,
#             "suricata_enabled": False,
#             "suricata_eve_path": None,
#             "suricata_hit_count": 0,
#             "suricata": None,
#             "rule_hit_count": self.rule_hit_count,
#             "critical_rule_hits": self.critical_rule_hits,
#         }



class SignatureEngine:
    """Standalone signature detector using handcrafted multi-rule scoring."""

    def __init__(self):
        self.blocklisted_ips = set()
        self.last_engine = "fallback_rules_v2"
        self.rule_hit_count = 0
        self.critical_rule_hits = 0
        self.sensitive_ports = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            389, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900,
            6379, 8080,
        }
        # Additional sensitive port groups for finer-grained rules
        self.db_ports = {1433, 1521, 3306, 5432, 27017, 5984, 6379, 9200, 9300}
        self.voip_ports = {5060, 5061, 4569, 10000, 10001}
        self.iot_ports = {1883, 8883, 5683, 5684, 47808}
        self.industrial_ports = {102, 502, 20000, 44818, 47808, 2404, 4840}
        self.remote_access_ports = {22, 23, 3389, 5900, 5901, 5902, 4899, 6881}

    def add_blocklist(self, ip):
        if ip:
            self.blocklisted_ips.add(str(ip))

    def _to_float(self, value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def _to_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default)

    def _fallback_rules(self, packet, features):
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        protocol = str(packet.get("protocol", "")).lower()
        dport = self._to_int(packet.get("dst_port", 0), 0)
        sport = self._to_int(packet.get("src_port", 0), 0)
        flag = str(features.get("flag", ""))
        service = str(features.get("service", "")).lower()

        count = self._to_float(features.get("count", 0))
        srv_count = self._to_float(features.get("srv_count", 0))
        serror_rate = self._to_float(features.get("serror_rate", 0))
        srv_serror_rate = self._to_float(features.get("srv_serror_rate", 0))
        rerror_rate = self._to_float(features.get("rerror_rate", 0))
        srv_rerror_rate = self._to_float(features.get("srv_rerror_rate", 0))
        same_srv_rate = self._to_float(features.get("same_srv_rate", 0))
        diff_srv_rate = self._to_float(features.get("diff_srv_rate", 0))
        src_bytes = self._to_float(features.get("src_bytes", packet.get("length", 0)))
        dst_bytes = self._to_float(features.get("dst_bytes", 0))
        wrong_fragment = self._to_int(features.get("wrong_fragment", 0), 0)
        urgent = self._to_int(features.get("urgent", 0), 0)
        num_failed_logins = self._to_int(features.get("num_failed_logins", 0), 0)
        hot = self._to_int(features.get("hot", 0), 0)
        num_compromised = self._to_int(features.get("num_compromised", 0), 0)
        root_shell = self._to_int(features.get("root_shell", 0), 0)
        su_attempted = self._to_int(features.get("su_attempted", 0), 0)
        num_root = self._to_int(features.get("num_root", 0), 0)
        num_shells = self._to_int(features.get("num_shells", 0), 0)
        num_access_files = self._to_int(features.get("num_access_files", 0), 0)
        is_guest_login = self._to_int(features.get("is_guest_login", 0), 0)
        land = self._to_int(features.get("land", 0), 0)
        dst_host_srv_diff_host_rate = self._to_float(features.get("dst_host_srv_diff_host_rate", 0))
        dst_host_serror_rate = self._to_float(features.get("dst_host_serror_rate", 0))
        dst_host_count = self._to_float(features.get("dst_host_count", 0))
        dst_host_srv_count = self._to_float(features.get("dst_host_srv_count", 0))
        dst_host_same_srv_rate = self._to_float(features.get("dst_host_same_srv_rate", 0))
        dst_host_diff_srv_rate = self._to_float(features.get("dst_host_diff_srv_rate", 0))
        dst_host_same_src_port_rate = self._to_float(features.get("dst_host_same_src_port_rate", 0))
        dst_host_srv_serror_rate = self._to_float(features.get("dst_host_srv_serror_rate", 0))
        dst_host_rerror_rate = self._to_float(features.get("dst_host_rerror_rate", 0))
        dst_host_srv_rerror_rate = self._to_float(features.get("dst_host_srv_rerror_rate", 0))
        duration = self._to_float(features.get("duration", 0))
        srv_diff_host_rate = self._to_float(features.get("srv_diff_host_rate", 0))
        num_file_creations = self._to_int(features.get("num_file_creations", 0), 0)
        num_outbound_cmds = self._to_int(features.get("num_outbound_cmds", 0), 0)
        is_host_login = self._to_int(features.get("is_host_login", 0), 0)
        logged_in = self._to_int(features.get("logged_in", 0), 0)
        payload = str(features.get("payload", "")).lower()
        ttl = self._to_int(features.get("ttl", 64), 64)
        pkt_size = self._to_int(packet.get("length", 0), 0)

        severity = 0.0
        matches = []

        def add_rule(name, score):
            nonlocal severity
            severity += float(score)
            matches.append(name)

        # ---------------------------------------------------------------
        # BLOCKLIST / IOC
        # ---------------------------------------------------------------
        if src_ip in self.blocklisted_ips or dst_ip in self.blocklisted_ips:
            add_rule("ioc_blocklist_hit", 95)

        # ---------------------------------------------------------------
        # LAND / LOOPBACK ATTACKS
        # ---------------------------------------------------------------
        if land == 1:
            add_rule("land_attack", 90)

        # Same src/dst IP but different ports (variant LAND)
        if src_ip and dst_ip and src_ip == dst_ip and sport != dport and protocol == "tcp":
            add_rule("loopback_spoof_variant", 70)

        # ---------------------------------------------------------------
        # DoS / FLOOD ATTACKS
        # ---------------------------------------------------------------
        # SYN Flood
        if protocol == "tcp" and flag in {"S0", "S1", "S2", "S3"} and count > 25:
            add_rule("syn_flood_pattern", 60)
        if protocol == "tcp" and flag in {"S0", "S1", "S2", "S3"} and serror_rate > 0.6:
            add_rule("syn_error_rate_spike", 28)

        # ACK Flood (large count of ACK-only packets with no data)
        if protocol == "tcp" and flag == "A" and count > 50 and src_bytes < 100:
            add_rule("ack_flood_pattern", 55)

        # RST Flood
        if protocol == "tcp" and flag in {"RSTO", "RSTOS0", "RSTR"} and count > 30:
            add_rule("rst_flood_pattern", 52)

        # FIN Flood
        if protocol == "tcp" and flag in {"FIN", "F"} and count > 30 and src_bytes < 150:
            add_rule("fin_flood_pattern", 50)

        # UDP Flood / Sweep
        if protocol == "udp" and count > 45 and diff_srv_rate > 0.8:
            add_rule("udp_flood_sweep", 52)

        # ICMP Flood (ping flood)
        if protocol == "icmp" and count > 60 and src_bytes > 0:
            add_rule("icmp_flood_pattern", 55)

        # ICMP Smurf (broadcast amplification signature)
        if protocol == "icmp" and dst_bytes > src_bytes * 10 and count > 20:
            add_rule("icmp_smurf_amplification", 72)

        # High-rate connection reset
        if protocol == "tcp" and srv_count > 20 and srv_serror_rate > 0.8 and sport > 49152:
            add_rule("high_rate_connection_reset_pattern", 50)

        # Slowloris / slow-read DoS: long-lived connections with tiny transfers
        if protocol == "tcp" and duration > 120 and src_bytes < 500 and dst_bytes < 500 and count > 10:
            add_rule("slowloris_dos_pattern", 58)

        # HTTP POST flood (large payload, many connections to port 80/443)
        if protocol == "tcp" and dport in {80, 443, 8080, 8443} and count > 40 and src_bytes > 5000:
            add_rule("http_flood_pattern", 52)

        # Teardrop / fragment-overlap DoS
        if wrong_fragment > 2:
            add_rule("teardrop_fragment_dos", 65)

        # NTP amplification
        if protocol == "udp" and dport == 123 and dst_bytes > src_bytes * 8 and count > 5:
            add_rule("ntp_amplification_attack", 72)

        # SSDP amplification
        if protocol == "udp" and dport == 1900 and dst_bytes > src_bytes * 5:
            add_rule("ssdp_amplification_attack", 68)

        # Memcached amplification
        if protocol == "udp" and dport == 11211 and dst_bytes > src_bytes * 10:
            add_rule("memcached_amplification_attack", 75)

        # CHARGEN amplification
        if protocol == "udp" and dport == 19 and dst_bytes > src_bytes * 4:
            add_rule("chargen_amplification_attack", 65)

        # DNS amplification
        if protocol == "udp" and dport == 53 and src_bytes < 100 and dst_bytes > 1500:
            add_rule("dns_amplification_like", 72)

        # ---------------------------------------------------------------
        # RECONNAISSANCE / SCANNING
        # ---------------------------------------------------------------
        # Sensitive port scan
        if protocol == "tcp" and dport in self.sensitive_ports and count > 10 and src_bytes < 180:
            add_rule("sensitive_port_scan", 55)

        # Horizontal service scan (many different services)
        if diff_srv_rate > 0.85 and same_srv_rate < 0.15 and count > 20:
            add_rule("horizontal_service_scan", 65)

        # Distributed host scan
        if dst_host_srv_diff_host_rate > 0.7 and count > 18:
            add_rule("distributed_host_scan", 35)

        # Rerror-based scan (closed-port probing)
        if rerror_rate > 0.6 and count > 12:
            add_rule("rerror_scan_pattern", 48)

        # Service failure storm
        if dst_host_serror_rate > 0.8 and srv_serror_rate > 0.8:
            add_rule("service_failure_storm", 28)

        # NULL scan (no flags set)
        if protocol == "tcp" and flag in {"", "NULL"} and count > 5:
            add_rule("tcp_null_scan", 55)

        # FIN scan (stealth)
        if protocol == "tcp" and flag in {"FIN", "F"} and count > 5 and src_bytes < 60:
            add_rule("tcp_fin_stealth_scan", 55)

        # XMAS scan (all flags set)
        if protocol == "tcp" and flag in {"XMAS", "URG_PSH_FIN"} and count > 5:
            add_rule("tcp_xmas_scan", 58)

        # UDP port scan (many dst ports, high rerror)
        if protocol == "udp" and diff_srv_rate > 0.7 and rerror_rate > 0.5 and count > 15:
            add_rule("udp_port_scan", 52)

        # ICMP host discovery sweep
        if protocol == "icmp" and diff_srv_rate > 0.6 and count > 20 and src_bytes < 100:
            add_rule("icmp_host_sweep", 48)

        # OS fingerprinting via TTL anomaly
        if ttl <= 5 and protocol == "tcp" and count > 8:
            add_rule("os_fingerprint_ttl_probe", 42)

        # Version scan: tiny packets to many ports (banner grab)
        if protocol == "tcp" and count > 20 and src_bytes < 80 and diff_srv_rate > 0.6:
            add_rule("banner_grab_version_scan", 45)

        # Database port scan
        if dport in self.db_ports and count > 8 and src_bytes < 200:
            add_rule("database_port_scan", 58)

        # Industrial / SCADA port probe
        if dport in self.industrial_ports and count > 3:
            add_rule("scada_ics_port_probe", 65)

        # IoT protocol probe
        if dport in self.iot_ports and count > 5 and src_bytes < 150:
            add_rule("iot_protocol_probe", 50)

        # ---------------------------------------------------------------
        # BRUTE FORCE / CREDENTIAL ATTACKS
        # ---------------------------------------------------------------
        # Generic credential attack on remote-access ports
        if protocol == "tcp" and dport in {22, 23, 3389} and num_failed_logins >= 3:
            add_rule("credential_attack_pattern", 35)

        # Brute force login
        if num_failed_logins >= 4 and count > 8:
            add_rule("bruteforce_login_pattern", 58)

        # Guest account abuse
        if is_guest_login == 1 and hot > 8:
            add_rule("guest_account_abuse", 35)

        # FTP brute force
        if protocol == "tcp" and dport == 21 and num_failed_logins >= 3:
            add_rule("ftp_bruteforce_pattern", 55)

        # SSH brute force (high serror + many connections)
        if protocol == "tcp" and dport == 22 and count > 15 and serror_rate > 0.5:
            add_rule("ssh_bruteforce_flood", 60)

        # Telnet brute force
        if protocol == "tcp" and dport == 23 and num_failed_logins >= 2 and count > 5:
            add_rule("telnet_bruteforce_pattern", 58)

        # SMTP auth brute force
        if protocol == "tcp" and dport == 25 and num_failed_logins >= 3 and count > 10:
            add_rule("smtp_auth_bruteforce", 55)

        # RDP brute force
        if protocol == "tcp" and dport == 3389 and count > 10 and num_failed_logins >= 2:
            add_rule("rdp_bruteforce_pattern", 62)

        # VNC brute force
        if protocol == "tcp" and dport in {5900, 5901, 5902} and num_failed_logins >= 2:
            add_rule("vnc_bruteforce_pattern", 58)

        # HTTP Basic/Form auth brute force (high count, small payloads to web port)
        if protocol == "tcp" and dport in {80, 443, 8080, 8443} and num_failed_logins >= 5:
            add_rule("http_auth_bruteforce", 55)

        # LDAP brute force
        if protocol == "tcp" and dport == 389 and num_failed_logins >= 3:
            add_rule("ldap_bruteforce_pattern", 58)

        # Database brute force
        if dport in self.db_ports and num_failed_logins >= 3:
            add_rule("database_bruteforce_pattern", 62)

        # Credential stuffing: rapid successful logins from same host
        if logged_in == 1 and count > 20 and same_srv_rate > 0.9 and duration < 5:
            add_rule("credential_stuffing_pattern", 52)

        # ---------------------------------------------------------------
        # PRIVILEGE ESCALATION / POST-EXPLOITATION
        # ---------------------------------------------------------------
        if root_shell == 1 or su_attempted == 1 or num_root >= 5 or num_shells >= 2:
            add_rule("privilege_escalation_pattern", 85)

        if hot >= 10 or num_compromised >= 6:
            add_rule("host_compromise_activity", 68)

        if num_access_files >= 4 and num_compromised >= 3:
            add_rule("sensitive_file_access_pattern", 36)

        # Multiple shells opened post-login
        if num_shells >= 1 and logged_in == 1 and hot > 5:
            add_rule("interactive_shell_spawned", 78)

        # Outbound command execution (reverse shell indicator)
        if num_outbound_cmds > 0 and logged_in == 1:
            add_rule("outbound_command_execution", 80)

        # File creation after compromise
        if num_file_creations > 3 and num_compromised >= 2:
            add_rule("post_compromise_file_drop", 70)

        # Root access via non-root entry path
        if num_root >= 1 and is_guest_login == 1:
            add_rule("guest_to_root_escalation", 90)

        # Host login anomaly (direct host login without normal auth flow)
        if is_host_login == 1 and logged_in == 0:
            add_rule("host_login_bypass_anomaly", 75)

        # ---------------------------------------------------------------
        # NETWORK PACKET MANIPULATION / EVASION
        # ---------------------------------------------------------------
        if wrong_fragment > 0 or urgent > 0:
            add_rule("malformed_packet_pattern", 45)

        # Fragmentation evasion (many small fragments)
        if wrong_fragment > 0 and pkt_size < 100:
            add_rule("fragment_evasion_pattern", 55)

        # Oversized ICMP (ping of death)
        if protocol == "icmp" and pkt_size > 65000:
            add_rule("ping_of_death_pattern", 85)

        # IP spoofing indicator: TTL extremely low (packet been re-crafted)
        if ttl < 10 and protocol in {"tcp", "udp"} and count > 5:
            add_rule("low_ttl_spoof_indicator", 48)

        # ---------------------------------------------------------------
        # EXFILTRATION / DATA THEFT
        # ---------------------------------------------------------------
        # Large outbound data to single destination
        if src_bytes > 500000 and dst_bytes < 5000 and logged_in == 1:
            add_rule("large_outbound_data_exfiltration", 72)

        # DNS tunneling (large DNS payload)
        if protocol == "udp" and dport == 53 and src_bytes > 500:
            add_rule("dns_tunneling_pattern", 68)

        # ICMP tunneling (data-carrying ICMP)
        if protocol == "icmp" and src_bytes > 300 and count > 10:
            add_rule("icmp_tunneling_pattern", 65)

        # FTP data exfiltration
        if protocol == "tcp" and dport in {20, 21} and src_bytes > 200000 and logged_in == 1:
            add_rule("ftp_data_exfiltration", 70)

        # Abnormally high upload ratio (PUT/POST flood to a server)
        if src_bytes > dst_bytes * 20 and src_bytes > 100000 and dport in {80, 443, 8080}:
            add_rule("http_upload_exfiltration", 65)

        # Beaconing: very regular, small periodic connections (C2 indicator)
        if duration > 0 and src_bytes < 300 and dst_bytes < 300 and count > 30 and same_srv_rate > 0.95:
            add_rule("c2_beaconing_pattern", 68)

        # ---------------------------------------------------------------
        # LATERAL MOVEMENT
        # ---------------------------------------------------------------
        # SMB lateral movement (Pass-the-Hash, worm spreading)
        if protocol == "tcp" and dport == 445 and count > 10 and diff_srv_rate < 0.2:
            add_rule("smb_lateral_movement", 72)

        # WMI/RPC lateral movement
        if protocol == "tcp" and dport in {135, 593} and count > 8 and src_bytes > 500:
            add_rule("wmi_rpc_lateral_movement", 65)

        # RDP lateral movement (authenticated, spreading)
        if protocol == "tcp" and dport == 3389 and logged_in == 1 and dst_host_diff_srv_rate > 0.5 and count > 5:
            add_rule("rdp_lateral_movement", 68)

        # SSH lateral movement
        if protocol == "tcp" and dport == 22 and logged_in == 1 and srv_diff_host_rate > 0.5 and count > 8:
            add_rule("ssh_lateral_movement", 65)

        # Internal host spread (high dst_host_diff_srv_rate post-login)
        if logged_in == 1 and dst_host_diff_srv_rate > 0.7 and count > 15:
            add_rule("internal_spread_pattern", 68)

        # ---------------------------------------------------------------
        # WEB / APPLICATION ATTACKS
        # ---------------------------------------------------------------
        # SQL injection indicators in payload
        if payload and any(kw in payload for kw in ("select ", "union ", "' or ", "1=1", "--", "xp_cmdshell", "waitfor delay")):
            add_rule("sql_injection_payload", 78)

        # XSS indicators in payload
        if payload and any(kw in payload for kw in ("<script", "javascript:", "onerror=", "onload=", "alert(")):
            add_rule("xss_payload_pattern", 70)

        # Directory traversal / path traversal
        if payload and any(kw in payload for kw in ("../", "..\\", "%2e%2e", "%252e%252e", "/etc/passwd", "boot.ini")):
            add_rule("path_traversal_pattern", 75)

        # Command injection indicators
        if payload and any(kw in payload for kw in ("; ls", "; cat ", "| whoami", "& net user", "`id`", "$(id)", ";wget ", ";curl ")):
            add_rule("command_injection_payload", 80)

        # Remote file inclusion
        if payload and any(kw in payload for kw in ("http://", "https://", "ftp://")) and ("include=" in payload or "file=" in payload or "page=" in payload):
            add_rule("remote_file_inclusion_pattern", 78)

        # XML/XXE injection
        if payload and any(kw in payload for kw in ("<!entity", "<!doctype", "system \"file://", "system 'file://")):
            add_rule("xxe_injection_pattern", 75)

        # SSRF pattern
        if payload and any(kw in payload for kw in ("169.254.169.254", "localhost", "127.0.0.1", "::1")) and dport in {80, 443, 8080, 8443}:
            add_rule("ssrf_pattern", 72)

        # HTTP method abuse (non-standard methods)
        if payload and any(kw in payload for kw in ("trace ", "debug ", "connect ", "options ")):
            add_rule("http_method_abuse", 45)

        # ---------------------------------------------------------------
        # PROTOCOL-SPECIFIC ATTACKS
        # ---------------------------------------------------------------
        # FTP bounce attack
        if protocol == "tcp" and dport == 21 and src_bytes > 2000 and dst_bytes > 2000 and count > 5:
            add_rule("ftp_bounce_attack", 65)

        # SMTP spam / open relay abuse
        if protocol == "tcp" and dport == 25 and src_bytes > 50000 and count > 20:
            add_rule("smtp_spam_relay_abuse", 60)

        # SNMP community string sweep
        if protocol == "udp" and dport == 161 and count > 10 and src_bytes < 200:
            add_rule("snmp_community_sweep", 55)

        # TFTP abuse (unauthenticated file transfer)
        if protocol == "udp" and dport == 69 and count > 3:
            add_rule("tftp_abuse_pattern", 50)

        # NFS unauthorized mount probe
        if protocol in {"tcp", "udp"} and dport in {2049, 111} and count > 5:
            add_rule("nfs_unauthorized_probe", 60)

        # Kerberos pre-auth brute force (AS-REP roasting)
        if protocol in {"tcp", "udp"} and dport == 88 and count > 15 and serror_rate > 0.4:
            add_rule("kerberos_as_rep_roasting", 68)

        # LDAP anonymous bind / enumeration
        if protocol == "tcp" and dport == 389 and src_bytes < 200 and count > 8:
            add_rule("ldap_anonymous_enum", 52)

        # VoIP toll fraud / SIP flooding
        if dport in self.voip_ports and protocol in {"tcp", "udp"} and count > 20:
            add_rule("voip_sip_flood_pattern", 55)

        # BGP / routing protocol abuse
        if protocol == "tcp" and dport == 179 and src_ip not in (self.blocklisted_ips or set()) and count > 5 and flag in {"S0", "S1"}:
            add_rule("bgp_session_disruption", 70)

        # DHCP starvation / rogue DHCP
        if protocol == "udp" and dport in {67, 68} and count > 25 and diff_srv_rate < 0.1:
            add_rule("dhcp_starvation_pattern", 65)

        # ARP spoofing indicator (very high same_srv_rate on short duration bursts)
        if duration < 1 and same_srv_rate > 0.98 and count > 30 and src_bytes < 100:
            add_rule("arp_spoof_flood_pattern", 60)

        # ---------------------------------------------------------------
        # MALWARE / BOTNET BEHAVIOR
        # ---------------------------------------------------------------
        # IRC-based botnet C2 (port 6667/6697)
        if protocol == "tcp" and dport in {6667, 6697, 6660, 7000} and count > 5:
            add_rule("irc_botnet_c2_pattern", 68)

        # Peer-to-peer botnet traffic (many unique hosts, ephemeral ports)
        if sport > 49152 and dport > 49152 and diff_srv_rate > 0.7 and count > 25:
            add_rule("p2p_botnet_traffic_pattern", 55)

        # Ransomware C2 beacon (regular small HTTPS to many hosts)
        if protocol == "tcp" and dport in {443, 8443} and count > 40 and srv_diff_host_rate > 0.6 and src_bytes < 500:
            add_rule("ransomware_c2_beacon", 72)

        # Cryptomining pool connection (stratum protocol ports)
        if protocol == "tcp" and dport in {3333, 4444, 5555, 7777, 9999, 14444, 45560} and count > 3:
            add_rule("cryptomining_pool_connection", 60)

        # Fast-flux DNS (many short-lived connections to rapidly changing IPs)
        if protocol == "udp" and dport == 53 and srv_diff_host_rate > 0.8 and count > 20:
            add_rule("fast_flux_dns_pattern", 62)

        # ---------------------------------------------------------------
        # INSIDER THREAT / ANOMALOUS USER BEHAVIOR
        # ---------------------------------------------------------------
        # High hot indicator with login (sensitive command execution)
        if hot >= 5 and logged_in == 1 and num_compromised >= 1:
            add_rule("insider_sensitive_cmd_pattern", 58)

        # Mass file access post-login
        if num_access_files >= 6 and logged_in == 1:
            add_rule("mass_file_access_post_login", 55)

        # Unusual off-hours behavior (long duration, guest login)
        if is_guest_login == 1 and duration > 300 and src_bytes > 10000:
            add_rule("guest_long_session_anomaly", 52)

        # ---------------------------------------------------------------
        # COMPOUND / MULTI-INDICATOR ESCALATION (original + new)
        # ---------------------------------------------------------------
        match_set = set(matches)

        if {"syn_flood_pattern", "sensitive_port_scan"}.issubset(match_set):
            add_rule("combo_scan_flood_escalation", 20)

        if {"host_compromise_activity", "privilege_escalation_pattern"}.issubset(match_set):
            add_rule("post_exploitation_escalation", 25)

        if {"bruteforce_login_pattern", "privilege_escalation_pattern"}.issubset(match_set):
            add_rule("bruteforce_to_escalation_chain", 25)

        if {"c2_beaconing_pattern", "large_outbound_data_exfiltration"}.issubset(match_set):
            add_rule("c2_exfiltration_chain", 28)

        if {"smb_lateral_movement", "privilege_escalation_pattern"}.issubset(match_set):
            add_rule("smb_privilege_lateral_chain", 25)

        if {"dns_amplification_like", "udp_flood_sweep"}.issubset(match_set):
            add_rule("amplification_flood_combo", 22)

        if {"sql_injection_payload", "command_injection_payload"}.issubset(match_set):
            add_rule("web_exploit_chain", 20)

        if {"internal_spread_pattern", "post_compromise_file_drop"}.issubset(match_set):
            add_rule("worm_propagation_chain", 28)

        if {"ransomware_c2_beacon", "large_outbound_data_exfiltration"}.issubset(match_set):
            add_rule("ransomware_exfil_chain", 28)

        if len(matches) >= 4:
            add_rule("multi_indicator_consensus", 18)

        if len(matches) >= 7:
            add_rule("high_confidence_complex_attack", 22)

        severity = min(round(severity, 2), 100.0)

        return {
            "severity": severity,
            "matches": matches,
            "is_match": bool(matches),
            "engine": "fallback_rules_v2",
        }

    def evaluate(self, packet, features):
        fallback = self._fallback_rules(packet, features)

        severity = fallback.get("severity", 0)
        matches = list(fallback.get("matches", []))
        engine = fallback.get("engine", "fallback_rules_v2")
        self.last_engine = engine
        if matches:
            self.rule_hit_count += 1
            if severity >= 85:
                self.critical_rule_hits += 1

        return {
            "severity": severity,
            "matches": matches,
            "is_match": bool(matches),
            "engine": engine,
            "suricata_enabled": False,
        }

    def runtime_status(self):
        return {
            "mode": self.last_engine,
            "suricata_enabled": False,
            "suricata_eve_path": None,
            "suricata_hit_count": 0,
            "suricata": None,
            "rule_hit_count": self.rule_hit_count,
            "critical_rule_hits": self.critical_rule_hits,
        }