# class PolicyEngine:
#     """Combines detection outcomes into a single action."""

#     def decide(self, signature_result, ml_result, zero_day_result, packet):
#         sig_severity = float(signature_result.get("severity", 0))
#         ml_conf = float(ml_result.get("confidence", 0))
#         is_attack = ml_result.get("attack_type", "normal") != "normal"
#         anomaly_score = float(zero_day_result.get("anomaly_score", 0))
#         override_normal = bool(zero_day_result.get("override_normal", False))

#         risk = 0.0
#         risk += sig_severity * 0.45
#         risk += (ml_conf if is_attack else 0.0) * 0.30
#         # If ML says normal, raise anomaly influence to catch unknown attacks.
#         anomaly_weight = 0.25 if is_attack else 0.42
#         risk += anomaly_score * 100.0 * anomaly_weight

#         if override_normal:
#             risk += 12.0
#         if (not is_attack) and anomaly_score >= 0.8:
#             risk += 10.0

#         if risk >= 85:
#             action = "block_ip"
#         elif risk >= 70:
#             action = "drop_packet"
#         elif risk >= 50:
#             action = "alert"
#         else:
#             action = "allow"

#         reasons = []
#         if signature_result.get("matches"):
#             reasons.append("signature=" + ",".join(signature_result.get("matches", [])))
#         if is_attack:
#             reasons.append(f"ml={ml_result.get('attack_type')}:{ml_conf:.1f}%")
#         if zero_day_result.get("is_zero_day"):
#             reasons.append(f"zero_day_score={anomaly_score:.2f}")
#         if override_normal:
#             reasons.append("normal_override_by_anomaly")
#         if not reasons:
#             reasons.append("no_high_risk_signal")

#         return {
#             "risk": round(risk, 2),
#             "action": action,
#             "reason": " | ".join(reasons),
#         }


"""
PolicyEngine — Tri-Source Adaptive Fusion (TSAF)
=================================================
Algorithm design principles
----------------------------
1.  **No fixed weights.**  The three detectors (signature, ML, zero-day) are
    each assigned a *context-adaptive* weight that is re-evaluated every call
    based on how much evidence each source is currently producing.  A source
    that is "speaking loudly" (high severity / high confidence / high anomaly)
    gets proportionally MORE influence on the final risk score, preventing any
    single weak signal from being drowned out by the others.

2.  **Attack-class aware amplification.**  NSL-KDD attack families (DoS, Probe,
    R2L, U2R) have very different statistical profiles.  The engine maps the
    ML model's attack_type to a family and applies a family-specific confidence
    multiplier so that stealthy attacks (R2L / U2R) are not penalised for
    having lower raw ML confidence.

3.  **Cross-source coherence bonus.**  When two or more sources independently
    agree that traffic is malicious, the risk score receives a coherence bonus
    on top of the individual contributions.  Genuine attacks tend to light up
    multiple detectors; noise and false positives rarely do.

4.  **Vetoed allow.**  A single high-evidence source can veto an "allow"
    decision even when the other two sources are silent, preventing the classic
    "30% weight means I'm always outvoted" failure mode.

5.  **Graduated confidence decay.**  ML confidence is penalised when the
    attack-type label is "normal" but the ML itself is uncertain (low
    confidence score), preventing an uncertain "normal" label from masking
    genuine anomalies.

6.  **Persistent source reliability tracking.**  Each source accumulates a
    short-term reliability score based on recent cross-source agreements and
    disagreements.  Over time, a source that frequently disagrees with both
    others has its weight nudged downward (false-positive dampening).

Risk scale: 0–100  →  allow(<40) | alert(40–59) | drop(60–79) | block(≥80)
"""

from collections import defaultdict, deque
import ipaddress
import os
import time


# ---------------------------------------------------------------------------
# NSL-KDD attack-family registry
# ---------------------------------------------------------------------------
# Maps ML model output labels → (family, stealthiness_multiplier)
# stealthiness_multiplier > 1.0 amplifies the ML contribution for attack
# families known to be hard to detect and under-represented in raw confidence.
_ATTACK_FAMILY_MAP = {
    # DoS
    "neptune":      ("dos",   1.00),
    "smurf":        ("dos",   1.00),
    "pod":          ("dos",   1.05),
    "teardrop":     ("dos",   1.05),
    "land":         ("dos",   1.10),
    "back":         ("dos",   1.00),
    "apache2":      ("dos",   1.05),
    "udpstorm":     ("dos",   1.00),
    "processtable": ("dos",   1.00),
    "mailbomb":     ("dos",   1.00),
    # Probe
    "portsweep":    ("probe", 1.00),
    "ipsweep":      ("probe", 1.00),
    "nmap":         ("probe", 1.05),
    "satan":        ("probe", 1.00),
    "mscan":        ("probe", 1.05),
    "saint":        ("probe", 1.05),
    # R2L  (remote-to-local — stealthy, low volume)
    "guess_passwd": ("r2l",   1.25),
    "ftp_write":    ("r2l",   1.25),
    "imap":         ("r2l",   1.20),
    "phf":          ("r2l",   1.20),
    "multihop":     ("r2l",   1.30),
    "warezmaster":  ("r2l",   1.25),
    "warezclient":  ("r2l",   1.20),
    "spy":          ("r2l",   1.35),
    "snmpgetattack":("r2l",   1.20),
    "named":        ("r2l",   1.20),
    "xlock":        ("r2l",   1.20),
    "xsnoop":       ("r2l",   1.20),
    "sendmail":     ("r2l",   1.20),
    "httptunnel":   ("r2l",   1.25),
    "worm":         ("r2l",   1.30),
    # U2R  (user-to-root — very stealthy, critical impact)
    "buffer_overflow": ("u2r", 1.40),
    "loadmodule":      ("u2r", 1.40),
    "perl":            ("u2r", 1.35),
    "rootkit":         ("u2r", 1.50),
    "sqlattack":       ("u2r", 1.45),
    "xterm":           ("u2r", 1.35),
    "ps":              ("u2r", 1.35),
    # Normal
    "normal":          ("normal", 0.00),
}

# Base risk floor per family (added when ML is confident about that family)
_FAMILY_FLOOR = {
    "dos":    30.0,
    "probe":  25.0,
    "r2l":    35.0,
    "u2r":    45.0,
    "normal":  0.0,
}

# Minimum confidence threshold below which "normal" label is treated as
# uncertain and the anomaly detector is given a larger say.
_NORMAL_UNCERTAIN_THRESHOLD = 75.0

# How many recent decisions to track per source for reliability scoring
_RELIABILITY_WINDOW = 200


class PolicyEngine:
    """
    Tri-Source Adaptive Fusion (TSAF) policy engine.

    Inputs
    ------
    signature_result  : dict  — output of SignatureEngine.evaluate()
    ml_result         : dict  — output of ML model inference
    zero_day_result   : dict  — output of ZeroDayDetector.score()
    packet            : dict  — raw packet metadata

    Output
    ------
    {
        "risk"        : float,   # 0–100
        "action"      : str,     # allow | alert | drop | block_ip
        "reason"      : str,     # human-readable breakdown
        "decision_log": dict,    # full internal state for audit / explainability
    }
    """

    def __init__(self):
        # Short-term agreement tracking for reliability adjustment
        # Each deque holds 1 (agreement) or 0 (disagreement) per recent event
        self._sig_agree   = deque(maxlen=_RELIABILITY_WINDOW)
        self._ml_agree    = deque(maxlen=_RELIABILITY_WINDOW)
        self._zd_agree    = deque(maxlen=_RELIABILITY_WINDOW)

        self._total_decisions = 0
        self._action_counts = {"allow": 0, "alert": 0, "temp_block_ip": 0, "block_ip": 0}

        self.escalation_enabled = os.getenv("IPS_ESCALATION_ENABLED", "1") == "1"
        self.escalation_window_sec = int(os.getenv("IPS_ESCALATION_WINDOW_SEC", "300"))
        self.escalate_temp_hits = int(os.getenv("IPS_ESCALATE_TO_TEMP_BLOCK_HITS", "4"))
        self.escalate_block_hits = int(os.getenv("IPS_ESCALATE_TO_BLOCK_HITS", "12"))
        self.block_min_risk = float(os.getenv("IPS_BLOCK_MIN_RISK", "90"))
        self._ip_event_window = defaultdict(deque)

        self.allowlist_ips = set()
        self.allowlist_cidrs = []
        self._load_allowlist()

    def _parse_csv(self, raw):
        return [item.strip() for item in str(raw or "").split(",") if item.strip()]

    def _load_allowlist(self):
        for raw_ip in self._parse_csv(os.getenv("IPS_ALLOWLIST_IPS", "")):
            normalized = raw_ip.split("%", 1)[0]
            try:
                ipaddress.ip_address(normalized)
                self.allowlist_ips.add(normalized)
            except ValueError:
                continue

        for raw_cidr in self._parse_csv(os.getenv("IPS_ALLOWLIST_CIDRS", "")):
            try:
                self.allowlist_cidrs.append(ipaddress.ip_network(raw_cidr, strict=False))
            except ValueError:
                continue

    def _extract_remote_ip(self, packet):
        return (
            (packet.get("traffic_source") or {}).get("remote_ip")
            or packet.get("dst_ip")
            or packet.get("src_ip")
        )

    def _is_allowlisted(self, remote_ip):
        if not remote_ip:
            return False
        candidate = str(remote_ip).split("%", 1)[0]
        if candidate in self.allowlist_ips:
            return True
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return any(addr in network for network in self.allowlist_cidrs)

    def _apply_staged_escalation(self, base_action, risk, remote_ip):
        if (not self.escalation_enabled) or (not remote_ip) or base_action == "allow":
            return base_action, {"escalated": False, "hits": 0, "base_action": base_action}

        now = time.time()
        key = str(remote_ip).split("%", 1)[0]
        bucket = self._ip_event_window[key]
        bucket.append(now)
        cutoff = now - max(5, self.escalation_window_sec)
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        hits = len(bucket)

        # Immediate critical override for extreme risk.
        if risk >= 95:
            return "block_ip", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "critical_override"}

        if base_action == "alert":
            if hits >= self.escalate_temp_hits and risk >= 55:
                return "temp_block_ip", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "alert_to_temp_block"}
            return "alert", {"escalated": False, "hits": hits, "base_action": base_action}

        if base_action == "temp_block_ip":
            if hits < self.escalate_temp_hits:
                return "alert", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "insufficient_repeat_downgrade"}
            if hits >= self.escalate_block_hits and risk >= self.block_min_risk:
                return "block_ip", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "temp_to_block"}
            return "temp_block_ip", {"escalated": False, "hits": hits, "base_action": base_action}

        if base_action == "block_ip":
            if hits >= self.escalate_block_hits and risk >= self.block_min_risk:
                return "block_ip", {"escalated": False, "hits": hits, "base_action": base_action}
            if hits >= self.escalate_temp_hits:
                return "temp_block_ip", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "block_to_temp_until_repeat"}
            return "alert", {"escalated": True, "hits": hits, "base_action": base_action, "reason": "block_to_alert_until_repeat"}

        return base_action, {"escalated": False, "hits": hits, "base_action": base_action}

    # ------------------------------------------------------------------
    # Reliability helpers
    # ------------------------------------------------------------------

    def _reliability(self, agree_deque):
        """Return [0.75, 1.10] reliability multiplier for a source."""
        if len(agree_deque) < 20:
            return 1.0
        rate = sum(agree_deque) / len(agree_deque)
        # Map 0→0.75, 0.5→1.0, 1.0→1.10
        return round(0.75 + (rate * 0.35), 4)

    def _record_agreement(self, sig_hot, ml_hot, zd_hot):
        """Track whether each source agrees with the majority verdict."""
        hot_count = sum([sig_hot, ml_hot, zd_hot])
        majority_is_attack = hot_count >= 2

        self._sig_agree.append(1 if (sig_hot == majority_is_attack) else 0)
        self._ml_agree.append(1 if (ml_hot  == majority_is_attack) else 0)
        self._zd_agree.append(1 if (zd_hot  == majority_is_attack) else 0)

    # ------------------------------------------------------------------
    # Attack-family helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_family(attack_type):
        label = str(attack_type or "normal").lower().replace("-", "_")
        return _ATTACK_FAMILY_MAP.get(label, ("unknown", 1.10))

    # ------------------------------------------------------------------
    # Per-source score normalisation  →  [0, 100]
    # ------------------------------------------------------------------

    @staticmethod
    def _sig_score(sig_result):
        """Signature severity is already 0-100."""
        return float(sig_result.get("severity", 0.0))

    @staticmethod
    def _ml_score(ml_result, family, stealth_mult):
        """
        ML contribution is NOT just raw confidence.
        - If attack:  confidence × stealth_mult, floored by family floor
        - If normal:  0 (used separately via uncertain-normal penalty)
        """
        attack_type = str(ml_result.get("attack_type", "normal")).lower()
        conf = float(ml_result.get("confidence", 0.0) or 0.0)

        if family == "normal":
            return 0.0

        raw = conf * stealth_mult
        floored = max(raw, _FAMILY_FLOOR.get(family, 25.0))
        return min(floored, 100.0)

    @staticmethod
    def _zd_score(zd_result):
        """Anomaly score is 0-1; scale to 0-100."""
        return float(zd_result.get("anomaly_score", 0.0) or 0.0) * 100.0

    # ------------------------------------------------------------------
    # Adaptive weight computation
    # ------------------------------------------------------------------

    def _compute_weights(self, sig_s, ml_s, zd_s,
                         sig_reliability, ml_reliability, zd_reliability):
        """
        Dynamic weight = (normalised score contribution) × reliability.

        Sources that are currently producing strong evidence are trusted more.
        If all sources are silent the weights fall back to equal thirds.
        """
        # Raw "voice" of each source this packet
        sig_voice = sig_s * sig_reliability
        ml_voice  = ml_s  * ml_reliability
        zd_voice  = zd_s  * zd_reliability

        total_voice = sig_voice + ml_voice + zd_voice

        if total_voice < 1e-6:
            # All silent — equal weights, result will be near zero anyway
            return 1/3, 1/3, 1/3

        w_sig = sig_voice / total_voice
        w_ml  = ml_voice  / total_voice
        w_zd  = zd_voice  / total_voice

        return w_sig, w_ml, w_zd

    # ------------------------------------------------------------------
    # Cross-source coherence bonus
    # ------------------------------------------------------------------

    @staticmethod
    def _coherence_bonus(sig_hot, ml_hot, zd_hot, sig_s, ml_s, zd_s):
        """
        Bonus risk points awarded when sources independently agree on an attack.
        The bonus scales with the geometric mean of the agreeing sources'
        scores so that weak agreements give a small bonus.
        """
        hot_sources = [(s > 0) for s in [sig_s * sig_hot,
                                          ml_s  * ml_hot,
                                          zd_s  * zd_hot]]
        n_agree = sum(hot_sources)

        if n_agree < 2:
            return 0.0

        agreeing_scores = [s for s, h in zip([sig_s, ml_s, zd_s], hot_sources) if h]
        geom = 1.0
        for s in agreeing_scores:
            geom *= max(s, 1.0)
        geom = geom ** (1.0 / len(agreeing_scores))

        # 2 sources agree → up to +12;  3 sources agree → up to +20
        if n_agree == 3:
            return min((geom / 100.0) * 20.0, 20.0)
        else:
            return min((geom / 100.0) * 12.0, 12.0)

    # ------------------------------------------------------------------
    # Uncertain-normal penalty
    # ------------------------------------------------------------------

    @staticmethod
    def _uncertain_normal_penalty(ml_result, zd_score):
        """
        If ML says 'normal' but is not very confident, and the anomaly
        detector sees something unusual, add a penalty proportional to
        how uncertain the ML is and how anomalous the traffic is.
        """
        attack_type = str(ml_result.get("attack_type", "normal")).lower()
        conf = float(ml_result.get("confidence", 0.0) or 0.0)

        if attack_type != "normal":
            return 0.0

        if conf >= _NORMAL_UNCERTAIN_THRESHOLD:
            return 0.0

        uncertainty_factor = (1.0 - (conf / _NORMAL_UNCERTAIN_THRESHOLD))
        # anomaly scaled 0-1
        anomaly_factor = zd_score / 100.0
        return round(uncertainty_factor * anomaly_factor * 18.0, 2)

    # ------------------------------------------------------------------
    # Veto logic  (single source can veto an "allow")
    # ------------------------------------------------------------------

    @staticmethod
    def _veto_check(sig_s, ml_s, zd_s, family, sig_result, zd_result):
        """
        Returns (veto_active: bool, veto_reason: str, veto_floor: float).
        A veto forces the risk to at least `veto_floor`.
        """
        # Signature veto: critical rule match regardless of other sources
        if sig_s >= 85:
            return True, "sig_critical_veto", 80.0

        # ML veto: high-confidence U2R/R2L even if signature is quiet
        if family in ("u2r", "r2l") and ml_s >= 70:
            return True, f"ml_{family}_high_conf_veto", 75.0

        # Blocklist hit is always a hard veto
        if "ioc_blocklist_hit" in sig_result.get("matches", []):
            return True, "ioc_blocklist_veto", 90.0

        # Zero-day veto: extremely high anomaly with override_normal flag
        if zd_s >= 88 and zd_result.get("override_normal", False):
            return True, "zd_high_anomaly_veto", 72.0

        # Zero-day veto: is_zero_day flag set with meaningful score
        if zd_result.get("is_zero_day", False) and zd_s >= 72:
            return True, "zd_confirmed_veto", 68.0

        return False, "", 0.0

    # ------------------------------------------------------------------
    # Action mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _risk_to_action(risk):
        if risk >= 80:
            return "block_ip"
        elif risk >= 60:
            return "temp_block_ip"
        elif risk >= 40:
            return "alert"
        else:
            return "allow"

    # ------------------------------------------------------------------
    # Main decision method
    # ------------------------------------------------------------------

    def decide(self, signature_result, ml_result, zero_day_result, packet):
        self._total_decisions += 1

        # ── 1. Extract raw signals ──────────────────────────────────────
        attack_type = str(ml_result.get("attack_type", "normal") or "normal")
        family, stealth_mult = self._resolve_family(attack_type)

        sig_s = self._sig_score(signature_result)
        ml_s  = self._ml_score(ml_result, family, stealth_mult)
        zd_s  = self._zd_score(zero_day_result)

        sig_hot = sig_s > 0
        ml_hot  = family != "normal"
        zd_hot  = zd_s >= 40

        # ── 2. Per-source reliability multipliers ──────────────────────
        sig_rel = self._reliability(self._sig_agree)
        ml_rel  = self._reliability(self._ml_agree)
        zd_rel  = self._reliability(self._zd_agree)

        # ── 3. Adaptive weights ────────────────────────────────────────
        w_sig, w_ml, w_zd = self._compute_weights(
            sig_s, ml_s, zd_s, sig_rel, ml_rel, zd_rel
        )

        # ── 4. Weighted base risk ──────────────────────────────────────
        base_risk = (sig_s * w_sig) + (ml_s * w_ml) + (zd_s * w_zd)

        # ── 5. Coherence bonus ─────────────────────────────────────────
        coherence = self._coherence_bonus(sig_hot, ml_hot, zd_hot,
                                           sig_s, ml_s, zd_s)

        # ── 6. Uncertain-normal penalty ────────────────────────────────
        unc_penalty = self._uncertain_normal_penalty(ml_result, zd_s)

        # ── 7. Family floor (ensure ML-detected attacks are not buried) ─
        family_floor = _FAMILY_FLOOR.get(family, 0.0) if family != "normal" else 0.0
        # Only apply floor when ML confidence is meaningful
        ml_conf_raw = float(ml_result.get("confidence", 0.0) or 0.0)
        if ml_conf_raw < 40.0:
            family_floor = 0.0

        # ── 8. Raw combined risk ───────────────────────────────────────
        combined = base_risk + coherence + unc_penalty
        combined = max(combined, family_floor)
        combined = min(round(combined, 2), 100.0)

        # ── 9. Veto override ───────────────────────────────────────────
        veto_active, veto_reason, veto_floor = self._veto_check(
            sig_s, ml_s, zd_s, family, signature_result, zero_day_result
        )
        if veto_active:
            combined = max(combined, veto_floor)

        # ── 10. Action (allowlist + staged escalation) ────────────────
        remote_ip = self._extract_remote_ip(packet)
        if self._is_allowlisted(remote_ip):
            action = "allow"
            esc_meta = {"escalated": False, "hits": 0, "base_action": "allow", "reason": "allowlisted_ip"}
        else:
            base_action = self._risk_to_action(combined)
            action, esc_meta = self._apply_staged_escalation(base_action, combined, remote_ip)

        self._action_counts[action] = self._action_counts.get(action, 0) + 1

        # ── 11. Reliability tracking ───────────────────────────────────
        self._record_agreement(sig_hot, ml_hot, zd_hot)

        # ── 12. Reason assembly ────────────────────────────────────────
        reasons = []

        if signature_result.get("matches"):
            top_matches = signature_result["matches"][:5]
            reasons.append("sig=[" + ", ".join(top_matches) + "]"
                            + f"(sev={sig_s:.0f})")

        if family != "normal":
            reasons.append(
                f"ml={attack_type}({family})"
                f":conf={ml_conf_raw:.1f}%"
                f":stealth_x{stealth_mult:.2f}"
            )
        elif ml_conf_raw < _NORMAL_UNCERTAIN_THRESHOLD and zd_s > 0:
            reasons.append(
                f"ml=normal(uncertain:{ml_conf_raw:.1f}%)"
                f":unc_penalty={unc_penalty:.1f}"
            )

        if zd_s > 0:
            zd_reason = zero_day_result.get("reason", "")
            reasons.append(
                f"zero_day={zd_s:.1f}"
                f":reason={zd_reason}"
                + (":override" if zero_day_result.get("override_normal") else "")
            )

        if coherence > 0:
            reasons.append(f"coherence_bonus=+{coherence:.1f}")

        if veto_active:
            reasons.append(f"VETO:{veto_reason}(floor={veto_floor:.0f})")

        if esc_meta.get("reason"):
            reasons.append(f"policy={esc_meta.get('reason')}:hits={esc_meta.get('hits', 0)}")

        reasons.append(
            f"weights(sig={w_sig:.2f},ml={w_ml:.2f},zd={w_zd:.2f})"
        )

        if not reasons:
            reasons.append("no_high_risk_signal")

        # ── 13. Decision log (audit / explainability) ──────────────────
        decision_log = {
            "raw_scores":       {"sig": sig_s, "ml": ml_s, "zd": zd_s},
            "reliability":      {"sig": sig_rel, "ml": ml_rel, "zd": zd_rel},
            "adaptive_weights": {"sig": w_sig, "ml": w_ml, "zd": w_zd},
            "base_risk":        round(base_risk, 2),
            "coherence_bonus":  round(coherence, 2),
            "unc_normal_penalty": round(unc_penalty, 2),
            "family_floor":     family_floor,
            "veto":             {"active": veto_active, "reason": veto_reason,
                                 "floor": veto_floor},
            "attack_family":    family,
            "stealth_mult":     stealth_mult,
            "top_shift_features": zero_day_result.get("top_shift_features", []),
            "zd_components":    zero_day_result.get("components", {}),
            "total_decisions":  self._total_decisions,
            "action_counts":    dict(self._action_counts),
            "staged_escalation": esc_meta,
            "remote_ip": remote_ip,
        }

        return {
            "risk":         combined,
            "action":       action,
            "reason":       " | ".join(reasons),
            "decision_log": decision_log,
        }

    # ------------------------------------------------------------------
    # Runtime introspection
    # ------------------------------------------------------------------

    def status(self):
        return {
            "total_decisions": self._total_decisions,
            "action_counts":   dict(self._action_counts),
            "allowlist": {
                "ips": sorted(self.allowlist_ips),
                "cidr_count": len(self.allowlist_cidrs),
            },
            "staged_escalation": {
                "enabled": self.escalation_enabled,
                "window_sec": self.escalation_window_sec,
                "temp_block_hits": self.escalate_temp_hits,
                "block_hits": self.escalate_block_hits,
                "block_min_risk": self.block_min_risk,
            },
            "source_reliability": {
                "signature": self._reliability(self._sig_agree),
                "ml":        self._reliability(self._ml_agree),
                "zero_day":  self._reliability(self._zd_agree),
            },
        }