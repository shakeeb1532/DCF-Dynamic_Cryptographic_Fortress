# policy_engine.py
"""
Pluggable policy engine for Dynamic Cryptographic Fortress.

This module lets you choose a policy backend that, given a Context,
returns a Recipe describing: cipher sequence, number of layers, compression,
and an explainable rationale for auditability.

Backends included:
- RuleBasedEngine (default): heuristic scoring (destination, data type, size)
- DeviceAwareRuleEngine: extends RuleBased with device class and constraints
- (stub) MLClassifierEngine: shape of an ML-based engine with deterministic fallback

Usage:
    from policy_engine import get_engine, Context
    engine = get_engine("rule")  # or "device_rule"
    recipe = engine.plan(Context(...))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Protocol
import ipaddress
import hashlib

# ---------- Data models ----------

@dataclass
class Context:
    dest_ip: str
    file_type: str         # e.g., "video", "data", "document", "binary"
    file_size_bytes: int   # to decide compression vs speed
    device_class: str = "server"  # "server" | "laptop" | "phone" | "iot"
    constraints: Dict[str, float] = field(default_factory=dict)
    # constraints examples:
    # {"latency_budget_ms": 500, "cpu_cores": 4, "battery_saver": 1, "bandwidth_mbps": 50}

@dataclass
class Recipe:
    profile: str
    score: float
    compression: str
    layers: int
    ciphers: List[str]
    rationale: List[str]   # human-readable reasons
    # Deterministic seed so the same Context yields the same plan when needed
    seed: int

# ---------- Policy interface ----------

class PolicyEngine(Protocol):
    def plan(self, ctx: Context) -> Recipe: ...

# ---------- Helpers ----------

FAST_COMPRESSORS = ["lz4", "zstd"]
SLOW_COMPRESSORS = ["zlib"]

def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _hash_seed(ctx: Context) -> int:
    h = hashlib.sha256(f"{ctx.dest_ip}|{ctx.file_type}|{ctx.file_size_bytes}|{ctx.device_class}".encode()).digest()
    return int.from_bytes(h[:8], "big")

# ---------- Rule-based engine(s) ----------

class RuleBasedEngine:
    """Heuristic score → profile → recipe.
    Dimensions: dest IP (private/public/suspicious blocks), file type, size.
    """
    def plan(self, ctx: Context) -> Recipe:
        rationale: List[str] = []
        score = 3.0
        if not _is_rfc1918(ctx.dest_ip):
            score += 1.0; rationale.append("Public destination (+1)")
        if ctx.dest_ip == "216.3.128.12":
            score = max(score, 9.0); rationale.append("Known high-risk IP (set to ≥9.0)")
        # file type sensitivity
        if ctx.file_type.lower() in {"keys", "secrets", "db", "data", "document"}:
            score += 1.5; rationale.append(f"Sensitive file type '{ctx.file_type}' (+1.5)")
        # size-based compression choice
        compression = "lz4" if ctx.file_size_bytes >= 5 * 1024 * 1024 else "zlib"
        if compression == "lz4":
            rationale.append("Large file: prefer fast compression (lz4)")
        else:
            rationale.append("Small file: allow stronger ratio (zlib)")
        # score clamps
        score = min(10.0, max(0.0, score))

        # profile mapping
        if score < 3.5:
            profile, layers, ciphers = "low_risk", 2, ["AESGCM", "ChaCha20"]
        elif score < 6.5:
            profile, layers, ciphers = "medium_risk", 3, ["AESGCM", "ChaCha20"]
        elif score < 8.5:
            profile, layers, ciphers = "high_risk", 3, ["AESGCM", "ChaCha20", "AESGCM"]
        else:
            profile, layers, ciphers = "extreme_risk", 4, ["AESGCM", "ChaCha20", "AESGCM", "ChaCha20"]
            rationale.append("Extreme profile: 4 layers, mixed ciphers")

        return Recipe(
            profile=profile,
            score=round(score, 2),
            compression=compression,
            layers=layers,
            ciphers=ciphers[:layers],
            rationale=rationale,
            seed=_hash_seed(ctx),
        )

class DeviceAwareRuleEngine(RuleBasedEngine):
    """Extends RuleBased with device capabilities/constraints."""
    def plan(self, ctx: Context) -> Recipe:
        base = super().plan(ctx)
        rationale = list(base.rationale)

        # Device capabilities
        dev = ctx.device_class.lower()
        if dev in {"phone", "iot"}:
            # prefer ChaCha on low-power devices
            base.ciphers = ["ChaCha20"] + [c for c in base.ciphers[1:]]
            rationale.append(f"Device '{dev}': prioritize ChaCha20 for CPU efficiency")
            # limit layers if latency/battery constrained
            if ctx.constraints.get("battery_saver", 0) or ctx.constraints.get("latency_budget_ms", 0) < 300:
                old_layers = base.layers
                base.layers = max(2, min(base.layers, 3))
                if base.layers != old_layers:
                    rationale.append("Tight constraints: limit layers to ≤3")
        elif dev in {"laptop"}:
            rationale.append("Laptop: balanced AESGCM/ChaCha20 mix")
        else:
            rationale.append("Server: allow higher layers and AES-GCM (AES-NI)")

        # Bandwidth-driven compression
        bw = ctx.constraints.get("bandwidth_mbps", 1000)
        if bw < 50 and base.compression == "lz4":
            rationale.append("Low bandwidth: keep lz4 to reduce egress size quickly")
        elif bw >= 200:
            # With high bandwidth, compression may be skipped for already compressed types
            if ctx.file_type.lower() in {"video", "archive"}:
                base.compression = "none"
                rationale.append("High bandwidth & incompressible type: skip compression")

        base.rationale = rationale
        return base

# ---------- ML stub ----------

class MLClassifierEngine:
    """Sketch of a learned policy. Deterministic fallback via seed when model is absent.
    Real implementation would load a model and produce a score and features → recipe.
    """
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.model = None  # placeholder

    def plan(self, ctx: Context) -> Recipe:
        # Fallback behavior: map seed to a stable set of outputs
        seed = _hash_seed(ctx)
        score = 5.5 + (seed % 30) / 10.0  # 5.5 .. 8.4
        compression = "lz4" if ctx.file_size_bytes > 8 * 1024 * 1024 else "zstd"
        layers = 3 if score < 8.0 else 4
        ciphers = ["AESGCM", "ChaCha20", "AESGCM", "ChaCha20"][:layers]
        rationale = [
            "ML stub: deterministic seed-based plan",
            f"Derived score {score:.2f} from hashed context",
        ]
        return Recipe(
            profile="ml_adaptive",
            score=round(min(10.0, score), 2),
            compression=compression,
            layers=layers,
            ciphers=ciphers,
            rationale=rationale,
            seed=seed,
        )

# ---------- Factory ----------

def get_engine(name: str) -> PolicyEngine:
    name = (name or "rule").lower()
    if name in {"rule", "rules"}:
        return RuleBasedEngine()
    if name in {"device_rule", "device", "device-aware"}:
        return DeviceAwareRuleEngine()
    if name in {"ml", "ml_stub"}:
        return MLClassifierEngine()
    raise ValueError(f"Unknown policy backend '{name}'")
