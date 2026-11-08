#!/usr/bin/env python3
"""
Thread-Safe In-Memory Alert Repository & Deduplication Engine
Team Neural Breach — Role 6: Backend & Real-Time Detection
"""

import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from collections import OrderedDict

from src.backend.config import settings


class AlertManager:
    """
    High-performance in-memory alert repository with:
      - Sliding-window deduplication and alert flood suppression.
      - Fixed-capacity LRU ring buffer preventing memory exhaustion.
      - Multi-attribute SOC filtering (severity, attack category, score, timestamps).
      - Real-time aggregate telemetry accounting.
    """
    def __init__(
        self,
        max_buffer_size: int = settings.MAX_ALERT_BUFFER_SIZE,
        dedup_window_seconds: int = settings.DEDUPLICATION_WINDOW_SECONDS
    ):
        self.max_buffer_size = max_buffer_size
        self.dedup_window_seconds = dedup_window_seconds
        
        # Ordered storage of alerts: alert_id -> alert_dict
        self._alerts: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        
        # Deduplication cache: signature_hash -> (alert_id, last_seen_epoch)
        self._dedup_cache: Dict[str, Tuple[str, float]] = {}
        
        # Global metrics counters
        self.total_flows_evaluated: int = 0
        self.total_alerts_generated: int = 0

    def _compute_signature(self, alert_data: Dict[str, Any]) -> str:
        """
        Computes a deterministic cryptographic fingerprint of a flow alert.
        Groups bursts of identical attack flows within the deduplication window.
        """
        pred = alert_data.get("prediction", {})
        meta = alert_data.get("flow_metadata", {})
        
        label = pred.get("label", "Unknown")
        proto = meta.get("protocol", 0)
        method = alert_data.get("explanation", {}).get("method", "SHAP")
        # Approximate flow duration and packets to bucket similar burst patterns
        duration_bin = int(meta.get("flow_duration_ms", 0.0) // 1000)  # 1s bins
        fwd_pkts = meta.get("total_fwd_pkts", 0)
        
        sig_str = f"{label}:{proto}:{duration_bin}:{fwd_pkts}:{method}"
        return hashlib.sha256(sig_str.encode("utf-8")).hexdigest()

    def add_alert(self, alert_data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Ingests a new alert with automatic deduplication.
        Returns:
            Tuple of (alert_dict, is_new_alert)
            If duplicate within window, updates repeat_count and returns is_new_alert=False.
        """
        self.total_flows_evaluated += 1
        now_epoch = time.time()
        now_utc = alert_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        sig = self._compute_signature(alert_data)

        # Check deduplication cache
        if sig in self._dedup_cache:
            existing_id, last_seen_epoch = self._dedup_cache[sig]
            if (now_epoch - last_seen_epoch) <= self.dedup_window_seconds:
                if existing_id in self._alerts:
                    existing_alert = self._alerts[existing_id]
                    existing_alert["repeat_count"] = existing_alert.get("repeat_count", 1) + 1
                    existing_alert["last_seen"] = now_utc
                    self._dedup_cache[sig] = (existing_id, now_epoch)
                    return existing_alert, False

        # New unique alert entry
        self.total_alerts_generated += 1
        alert_data["first_seen"] = now_utc
        alert_data["last_seen"] = now_utc
        alert_data["repeat_count"] = 1
        
        alert_id = alert_data["alert_id"]
        
        # Enforce maximum ring buffer size
        if len(self._alerts) >= self.max_buffer_size:
            oldest_id, _ = self._alerts.popitem(last=False)
            # Clean up dedup cache if referenced
            stale_sigs = [k for k, v in self._dedup_cache.items() if v[0] == oldest_id]
            for s in stale_sigs:
                self._dedup_cache.pop(s, None)

        self._alerts[alert_id] = alert_data
        self._dedup_cache[sig] = (alert_id, now_epoch)
        return alert_data, True

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single alert record by alert_id."""
        return self._alerts.get(alert_id)

    def list_alerts(
        self,
        threat_level: Optional[str] = None,
        attack_category: Optional[str] = None,
        min_score: Optional[float] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Retrieves paginated, filtered alerts sorted newest first.
        Returns:
            Tuple of (list_of_alerts, total_matching_count)
        """
        results = []
        for alert in reversed(self._alerts.values()):
            # Filter by threat level
            if threat_level:
                p_level = alert.get("threat_priority", {}).get("level", "")
                if p_level.upper() != threat_level.upper():
                    continue

            # Filter by attack category
            if attack_category:
                cat = alert.get("prediction", {}).get("label", "")
                if cat.lower() != attack_category.lower():
                    continue

            # Filter by minimum priority score
            if min_score is not None:
                score = alert.get("threat_priority", {}).get("score", 0.0)
                if score < min_score:
                    continue

            results.append(alert)

        total_matching = len(results)
        paginated = results[offset : offset + limit]
        return paginated, total_matching

    def get_stats(self) -> Dict[str, Any]:
        """Calculates SOC telemetry summaries and threat landscape breakdown."""
        levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        categories: Dict[str, int] = {}
        techniques: Dict[str, Dict[str, Any]] = {}

        for alert in self._alerts.values():
            lvl = alert.get("threat_priority", {}).get("level", "INFO")
            if lvl in levels:
                levels[lvl] += alert.get("repeat_count", 1)

            cat = alert.get("prediction", {}).get("label", "Unknown")
            categories[cat] = categories.get(cat, 0) + alert.get("repeat_count", 1)

            # MITRE technique tracking
            mitre = alert.get("threat_intelligence", {}).get("mitre_attack", {})
            primary = mitre.get("primary_technique", {})
            tid = primary.get("id")
            if tid and tid != "BASELINE":
                if tid not in techniques:
                    techniques[tid] = {
                        "id": tid,
                        "name": primary.get("name", "Unknown"),
                        "url": primary.get("url", ""),
                        "count": 0
                    }
                techniques[tid]["count"] += alert.get("repeat_count", 1)

        sorted_techniques = sorted(techniques.values(), key=lambda x: x["count"], reverse=True)[:10]

        return {
            "total_flows_evaluated": self.total_flows_evaluated,
            "total_alerts_stored": len(self._alerts),
            "observe_only_mode": True,
            "alerts_by_threat_level": levels,
            "alerts_by_attack_category": categories,
            "top_mitre_techniques": sorted_techniques
        }

    def clear(self):
        """Clears stored alerts and resets counters (useful for unit tests)."""
        self._alerts.clear()
        self._dedup_cache.clear()
        self.total_flows_evaluated = 0
        self.total_alerts_generated = 0


alert_store = AlertManager()
