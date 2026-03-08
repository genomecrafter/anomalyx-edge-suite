import math
from collections import defaultdict


class _OnlineStat:
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0

    def update(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self):
        if self.n < 2:
            return 0.0
        return self.m2 / (self.n - 1)

    @property
    def std(self):
        return math.sqrt(max(self.variance, 1e-12))


class _EwmaStat:
    def __init__(self, alpha=0.2):
        self.alpha = alpha
        self.initialized = False
        self.value = 0.0

    def update(self, x):
        if not self.initialized:
            self.value = x
            self.initialized = True
        else:
            self.value = (self.alpha * x) + ((1.0 - self.alpha) * self.value)


class ZeroDayDetector:
    """Online zero-day detector using ensemble anomaly signals.

    Combines:
    - Distribution shift (z-scores)
    - Short-term spike score (EWMA residual)
    - Categorical rarity (protocol/service/flag novelty)
    """

    NUMERIC_FEATURES = [
        "duration", "src_bytes", "dst_bytes", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    ]

    def __init__(self, warmup=120):
        self.stats = defaultdict(_OnlineStat)
        self.ewma = defaultdict(lambda: _EwmaStat(alpha=0.18))
        self.score_stats = _OnlineStat()
        self.category_counts = {
            "protocol_type": defaultdict(int),
            "service": defaultdict(int),
            "flag": defaultdict(int),
        }
        self.warmup = warmup
        self.seen = 0
        self.base_threshold = 0.72

    def _safe_float(self, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    def _score_distribution_shift(self, features):
        z_scores = []
        top_feature_z = []

        for key in self.NUMERIC_FEATURES:
            x = self._safe_float(features.get(key, 0.0))
            stat = self.stats[key]

            z = 0.0
            if stat.n >= 6:
                z = abs((x - stat.mean) / stat.std)
                z = min(z, 10.0)
                z_scores.append(z)
                top_feature_z.append((key, z))

            stat.update(x)

        if not z_scores:
            return 0.0, []

        z_scores_sorted = sorted(z_scores, reverse=True)
        top_k = z_scores_sorted[: min(5, len(z_scores_sorted))]
        shift_score = min((sum(top_k) / max(len(top_k), 1)) / 8.0, 1.0)
        explain = sorted(top_feature_z, key=lambda item: item[1], reverse=True)[:4]
        return shift_score, explain

    def _score_spike(self, features):
        spike_features = ["src_bytes", "dst_bytes", "count", "srv_count", "serror_rate", "rerror_rate"]
        residuals = []

        for key in spike_features:
            x = self._safe_float(features.get(key, 0.0))
            tracker = self.ewma[key]
            baseline = tracker.value if tracker.initialized else x
            denom = max(abs(baseline), 1.0)
            residual = min(abs(x - baseline) / denom, 8.0)
            residuals.append(residual)
            tracker.update(x)

        if not residuals:
            return 0.0
        top = sorted(residuals, reverse=True)[:3]
        return min((sum(top) / len(top)) / 5.0, 1.0)

    def _score_rarity(self, features):
        rarity_scores = []

        for key in ("protocol_type", "service", "flag"):
            value = str(features.get(key, "unknown"))
            total = sum(self.category_counts[key].values())
            seen_count = self.category_counts[key][value]

            if total < 30:
                rarity = 0.0
            else:
                freq = (seen_count + 1.0) / (total + len(self.category_counts[key]) + 1.0)
                rarity = max(0.0, min(1.0, 1.0 - min(freq * 4.0, 1.0)))

            rarity_scores.append(rarity)
            self.category_counts[key][value] += 1

        return sum(rarity_scores) / max(len(rarity_scores), 1)

    def _adaptive_threshold(self):
        # Adaptive threshold after warmup to handle changing traffic baselines.
        if self.score_stats.n < max(self.warmup, 120):
            return self.base_threshold

        adaptive = self.score_stats.mean + (2.2 * self.score_stats.std)
        return min(max(adaptive, self.base_threshold), 0.93)

    def score(self, features, ml_result=None):
        self.seen += 1

        shift_score, top_shift_features = self._score_distribution_shift(features)
        spike_score = self._score_spike(features)
        rarity_score = self._score_rarity(features)

        anomaly_score = min((shift_score * 0.55) + (spike_score * 0.30) + (rarity_score * 0.15), 1.0)
        threshold = self._adaptive_threshold()

        self.score_stats.update(anomaly_score)

        if self.seen < self.warmup:
            return {
                "anomaly_score": 0.0,
                "is_zero_day": False,
                "reason": "warmup",
                "components": {
                    "shift": round(shift_score, 4),
                    "spike": round(spike_score, 4),
                    "rarity": round(rarity_score, 4),
                    "threshold": round(threshold, 4),
                },
                "top_shift_features": [name for name, _ in top_shift_features],
                "override_normal": False,
            }

        is_zero_day = anomaly_score >= threshold
        ml_attack_type = (ml_result or {}).get("attack_type", "normal")
        ml_conf = float((ml_result or {}).get("confidence", 0) or 0)
        suspicious_normal = (ml_attack_type == "normal") and (anomaly_score >= max(threshold - 0.08, 0.62)) and (ml_conf <= 88)

        if is_zero_day:
            reason = "high_ensemble_anomaly"
        elif suspicious_normal:
            reason = "suspicious_normal_override"
        else:
            reason = "within_profile"

        return {
            "anomaly_score": round(anomaly_score, 4),
            "is_zero_day": is_zero_day,
            "reason": reason,
            "components": {
                "shift": round(shift_score, 4),
                "spike": round(spike_score, 4),
                "rarity": round(rarity_score, 4),
                "threshold": round(threshold, 4),
            },
            "top_shift_features": [name for name, _ in top_shift_features],
            "override_normal": suspicious_normal,
        }
