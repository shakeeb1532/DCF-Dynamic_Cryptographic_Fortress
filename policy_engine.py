# Copyright 2025 shakeeb1532
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
# --- Self-aware engine deps (add these) ---
from DCF.features import ctx_to_feature_dict, feats_to_vector, FEATURE_KEYS
from DCF.optimizer_bandit import BanditOptimizer
import logging

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
# ===== Self-Aware Engine (Advisor + Bandit + Guardrails) =====

# Secure, allowed cipher sets — ensure these EXACT strings match your executor
SAFE_ACTIONS = {
    # action_id -> recipe spec
    "safe_l2_aes_chacha": dict(layers=2, ciphers=["AESGCM", "ChaCha20-Poly1305"]),
    "safe_l3_mix":        dict(layers=3, ciphers=["AESGCM", "ChaCha20-Poly1305", "AESGCM"]),
    "safe_l4_extreme":    dict(layers=4, ciphers=["AESGCM", "ChaCha20-Poly1305", "AESGCM", "ChaCha20-Poly1305"]),
}

def _recipe_is_safe(r: "Recipe") -> bool:
    """Guardrail: enforce minimum security and allowed ciphers before use."""
    try:
        if int(r.layers) < 2:
            return False
        names = [str(c).lower() for c in (r.ciphers or [])]
        has_aesgcm = any("aesgcm" in n for n in names)
        has_chacha = any("chacha20" in n for n in names)
        return has_aesgcm and has_chacha
    except Exception:
        return False

def _choose_compression(size_bytes: int) -> str:
    mb = (size_bytes or 0) / (1024 * 1024)
    if mb < 1:
        return "none"
    if mb < 64:
        return "zlib"
    return "lz4"

def _extract_confidence(recipe: "Recipe"):
    """Parse 'conf=0.xx' from ML rationale if present; else None."""
    for line in getattr(recipe, "rationale", []) or []:
        if "conf=" in line:
            try:
                return float(line.split("conf=")[1].split(")")[0])
            except Exception:
                pass
    return None

def _ml_available() -> bool:
    try:
        e = get_engine("ml")
        return getattr(e, "model", None) is not None
    except Exception:
        return False

class SelfAwareEngine:
    """
    Chooses policies by combining:
      - Advisor: your ML or rules engine (for initial suggestion + confidence)
      - Optimizer: LinUCB contextual bandit (learns best safe action per context)
      - Guardrails: enforce minimum security and safe cipher allow-list
    """
    def __init__(self, min_confidence: float = 0.60, alpha: float = 0.8):
        self.min_conf = float(min_confidence)
        self.bandit = BanditOptimizer(d=len(FEATURE_KEYS), alpha=alpha)
        # Prefer ML if available; otherwise rules
        try:
            self._advisor = get_engine("ml") if _ml_available() else get_engine("rule")
        except Exception:
            self._advisor = get_engine("rule")

    def plan(self, ctx: "Context") -> "Recipe":
        feats = ctx_to_feature_dict(ctx)
        x_vec = feats_to_vector(feats)

        # Ask advisor first
        base = self._advisor.plan(ctx)
        advisor_conf = _extract_confidence(base)
        compression = _choose_compression(getattr(ctx, "file_size_bytes", 0))

        # If advisor is confident AND safe, use it directly
        if advisor_conf is not None and advisor_conf >= self.min_conf and _recipe_is_safe(base):
            base.compression = compression
            (base.rationale or []).insert(0, f"Advisor confident ({advisor_conf:.2f}); using advisor recipe.")
            return base

        # Otherwise: pick among SAFE actions via bandit
        action_ids = list(SAFE_ACTIONS.keys())
        chosen_action, scores = self.bandit.choose(action_ids, x_vec)
        spec = SAFE_ACTIONS[chosen_action]

        r = Recipe(
            profile=f"bandit::{chosen_action}",
            score=getattr(base, "score", 7.5),  # initial score; improves over time via learning
            compression=compression,
            layers=spec["layers"],
            ciphers=spec["ciphers"][: spec["layers"]],
            rationale=[
                f"Advisor conf={advisor_conf if advisor_conf is not None else 'n/a'} < {self.min_conf}; bandit selected {chosen_action}.",
                f"LinUCB scores: {{ {', '.join([f'{k}:{scores[k]:.3f}' for k in scores])} }}",
                f"Features: {{ {', '.join([f'{k}:{feats[k]:.3f}' for k in feats])} }}",
            ],
            seed=_hash_seed(ctx),
        )
        return r

# ---------- Factory ----------

def get_engine(name: str) -> "PolicyEngine":
    """
    Factory for policy engines.

    Supported names:
      - "selfaware", "auto"  -> SelfAwareEngine (advisor + bandit + guardrails)
      - "ml", "ml_stub"      -> MLClassifierEngine (static ML advisor)
      - "rule", "rules", "heuristic" -> RuleEngine (deterministic heuristics)
    """
    n = (name or "rule").lower()

    if n in {"selfaware", "auto"}:
        return SelfAwareEngine()

    if n in {"ml", "ml_stub"}:
        return MLClassifierEngine()

    if n in {"rule", "rules", "heuristic"}:
        return RuleEngine()

    raise ValueError(f"Unknown engine: {name!r}. "
                     f"Valid options: selfaware, ml, rule")
