# Copyright 2025 shakeeb1532
# policy_engine.py
# Dynamic Cryptographic Fortress — Policy engines
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Protocol, Any

# Optional ML deps
try:
    import joblib  # keep optional; engine still loads without it
except Exception:
    joblib = None

# ===== Models / Protocols =====

@dataclass
class Context:
    dest_ip: str
    file_type: str
    file_size_bytes: int
    device_class: str = "server"  # server|laptop|phone|iot
    constraints: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Recipe:
    profile: str
    score: float
    compression: str
    layers: int
    ciphers: List[str]
    rationale: List[str]
    seed: int

class PolicyEngine(Protocol):
    def plan(self, ctx: Context) -> Recipe: ...

# ===== Helpers =====

logger = logging.getLogger(__name__)

def _is_rfc1918(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def _hash_seed(ctx: Context) -> int:
    h = hashlib.sha256(
        f"{ctx.dest_ip}|{ctx.file_type}|{ctx.file_size_bytes}|{ctx.device_class}".encode("utf-8")
    ).digest()
    return int.from_bytes(h[:8], "big", signed=False)

def _choose_compression_by_size(size_bytes: int) -> str:
    mb = (size_bytes or 0) / (1024 * 1024)
    if mb < 1:
        return "none"
    if mb < 64:
        return "zlib"
    return "lz4"

# ===== Simple Rule/Heuristic Engine (safe baseline) =====

class RuleEngine:
    """
    Deterministic, conservative baseline:
      - RFC1918 and small files → lighter policy
      - public destinations and large files → stronger policy
      - AEAD only, minimum 2 layers
    """
    def plan(self, ctx: Context) -> Recipe:
        mb = ctx.file_size_bytes / (1024 * 1024)
        private = _is_rfc1918(ctx.dest_ip)
        compression = _choose_compression_by_size(ctx.file_size_bytes)

        if private and mb < 8:
            profile = "rule_low_risk"
            layers = 2
        elif mb < 64:
            profile = "rule_medium_risk"
            layers = 3
        elif mb < 256:
            profile = "rule_high_risk"
            layers = 3
        else:
            profile = "rule_extreme_risk"
            layers = 4

        ciphers = ["AESGCM", "ChaCha20-Poly1305", "AESGCM", "ChaCha20-Poly1305"]
        rationale = [
            f"private_dest={private}, size_mb={mb:.2f}, compression={compression}",
            "AEAD-only allow-list; minimum 2 layers enforced.",
        ]
        return Recipe(
            profile=profile,
            score={"rule_low_risk":5.5, "rule_medium_risk":7.0, "rule_high_risk":8.5, "rule_extreme_risk":9.5}[profile],
            compression=compression,
            layers=layers,
            ciphers=ciphers[:layers],
            rationale=rationale,
            seed=_hash_seed(ctx),
        )

# ===== ML Classifier Engine (optional advisor) =====

class MLClassifierEngine:
    """
    ML-backed advisor. Uses a scikit-learn model saved via joblib.
    Safe even if joblib/model missing: we fall back to RuleEngine.
    """
    MODEL_FILENAME = "dcf_model.joblib"
    META_FILENAME  = "dcf_model.meta.json"

    def __init__(self, model_path: Optional[str] = None, min_confidence: float = 0.55):
        self.model_path = model_path or self.MODEL_FILENAME
        self.meta_path  = os.path.join(os.path.dirname(self.model_path), self.META_FILENAME)
        self.model = None
        self.min_confidence = float(min_confidence)
        self._feature_names: Optional[List[str]] = None
        self.meta: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if joblib is None:
            logger.warning("joblib not available; ML engine disabled.")
            return
        if not os.path.exists(self.model_path):
            logger.info("ML model not found at %s; ML engine disabled.", self.model_path)
            return
        try:
            self.model = joblib.load(self.model_path)
        except Exception as e:
            logger.exception("Failed to load ML model: %s", e)
            self.model = None
            return
        self._feature_names = getattr(self.model, "feature_names_", None)
        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r", encoding="utf-8") as f:
                    self.meta = json.load(f)
            except Exception:
                pass
        logger.info("✅ ML model loaded")

    # --- features ---
    def _feats_dict(self, ctx: Context) -> Dict[str, float]:
        mb = ctx.file_size_bytes / (1024 * 1024)
        feats = {
            "file_size_mb": float(mb),
            "is_private_ip": 1.0 if _is_rfc1918(ctx.dest_ip) else 0.0,
            "bandwidth_mbps": float(ctx.constraints.get("bandwidth_mbps", 100.0)),
            "file_type=data": 1.0 if ctx.file_type == "data" else 0.0,
            "file_type=document": 1.0 if ctx.file_type == "document" else 0.0,
            "file_type=video": 1.0 if ctx.file_type == "video" else 0.0,
            "device_class=server": 1.0 if ctx.device_class == "server" else 0.0,
            "device_class=laptop": 1.0 if ctx.device_class == "laptop" else 0.0,
            "device_class=iot": 1.0 if ctx.device_class == "iot" else 0.0,
        }
        return feats

    def _vectorize(self, feats: Dict[str, float]):
        if self._feature_names:
            return [[feats.get(k, 0.0) for k in self._feature_names]]
        # deterministic order fallback
        keys = sorted(feats.keys())
        return [[feats[k] for k in keys]]

    def plan(self, ctx: Context) -> Recipe:
        if self.model is None:
            return RuleEngine().plan(ctx)
        feats = self._feats_dict(ctx)
        X = self._vectorize(feats)

        try:
            label = int(self.model.predict(X)[0])
        except Exception:
            return RuleEngine().plan(ctx)

        conf = None
        if hasattr(self.model, "predict_proba"):
            try:
                proba = self.model.predict_proba(X)[0]
                conf = float(max(proba))
            except Exception:
                conf = None

        # map label -> policy
        profile_map = {
            0: ("ml_low_risk",    2, ["AESGCM","ChaCha20-Poly1305"]),
            1: ("ml_medium_risk", 3, ["AESGCM","ChaCha20-Poly1305","AESGCM"]),
            2: ("ml_high_risk",   3, ["AESGCM","ChaCha20-Poly1305","AESGCM"]),
            3: ("ml_extreme_risk",4, ["AESGCM","ChaCha20-Poly1305","AESGCM","ChaCha20-Poly1305"]),
        }
        profile, layers, ciphers = profile_map.get(label, profile_map[1])
        compression = _choose_compression_by_size(ctx.file_size_bytes)
        base = (label + 1) * 2.5
        score = round(base * (0.9 + 0.2 * (conf if conf is not None else 0.5)), 2)

        rationale = [
            f"ML predicted label={label}{f' (conf={conf:.2f})' if conf is not None else ''}.",
            f"Features: file_size_mb={feats['file_size_mb']:.3f}, private={bool(feats['is_private_ip'])}, bw={feats['bandwidth_mbps']}",
            "Compression chosen by size heuristic.",
        ]
        return Recipe(
            profile=profile,
            score=score,
            compression=compression,
            layers=layers,
            ciphers=ciphers[:layers],
            rationale=rationale,
            seed=_hash_seed(ctx),
        )

# ===== Self-Aware Engine (Advisor + Bandit + Guardrails) =====

from DCF.features import ctx_to_feature_dict, feats_to_vector, FEATURE_KEYS
from DCF.optimizer_bandit import BanditOptimizer

SAFE_ACTIONS = {
    "safe_l2_aes_chacha": dict(layers=2, ciphers=["AESGCM","ChaCha20-Poly1305"]),
    "safe_l3_mix":        dict(layers=3, ciphers=["AESGCM","ChaCha20-Poly1305","AESGCM"]),
    "safe_l4_extreme":    dict(layers=4, ciphers=["AESGCM","ChaCha20-Poly1305","AESGCM","ChaCha20-Poly1305"]),
}

def _recipe_is_safe(r: Recipe) -> bool:
    if int(r.layers) < 2:
        return False
    names = [str(c).lower() for c in (r.ciphers or [])]
    return any("aesgcm" in n for n in names) and any("chacha20" in n for n in names)

def _extract_confidence_from_rationale(rationale: List[str]) -> Optional[float]:
    for line in rationale or []:
        if "conf=" in line:
            try:
                return float(line.split("conf=")[1].split(")")[0])
            except Exception:
                pass
    return None

class SelfAwareEngine:
    """
    Combines:
      - Advisor (ML if available; else rules)
      - Optimizer (LinUCB contextual bandit across SAFE_ACTIONS)
      - Guardrails (minimum security; AEAD-only)
    """
    def __init__(self, min_confidence: float = 0.60, alpha: float = 0.8):
        self.min_conf = float(min_confidence)
        self.bandit = BanditOptimizer(d=len(FEATURE_KEYS), alpha=alpha)
        try:
            self._advisor = MLClassifierEngine() if joblib is not None else RuleEngine()
        except Exception:
            self._advisor = RuleEngine()

    def plan(self, ctx: Context) -> Recipe:
        feats = ctx_to_feature_dict(ctx)
        x_vec = feats_to_vector(feats)

        base = self._advisor.plan(ctx)
        advisor_conf = _extract_confidence_from_rationale(base.rationale)
        compression = _choose_compression_by_size(ctx.file_size_bytes)

        # confident advisor + safe policy → accept
        if advisor_conf is not None and advisor_conf >= self.min_conf and _recipe_is_safe(base):
            base.compression = compression
            (base.rationale or []).insert(0, f"Advisor confident ({advisor_conf:.2f}); using advisor recipe.")
            return base

        # otherwise bandit over safe actions
        action_ids = list(SAFE_ACTIONS.keys())
        chosen_action, scores = self.bandit.choose(action_ids, x_vec)
        spec = SAFE_ACTIONS[chosen_action]

        return Recipe(
            profile=f"bandit::{chosen_action}",
            score=getattr(base, "score", 7.5),
            compression=compression,
            layers=spec["layers"],
            ciphers=spec["ciphers"][: spec["layers"]],
            rationale=[
                f"Advisor conf={advisor_conf if advisor_conf is not None else 'n/a'} < {self.min_conf}; bandit selected {chosen_action}.",
                "LinUCB scores: " + ", ".join([f"{k}:{scores[k]:.3f}" for k in scores]),
                "Features: " + ", ".join([f"{k}:{feats[k]:.3f}" for k in feats]),
            ],
            seed=_hash_seed(ctx),
        )

# ===== Engine factory =====

def get_engine(name: str) -> PolicyEngine:
    """
    Factory for policy engines.
      - selfaware | auto  → SelfAwareEngine
      - ml | ml_stub      → MLClassifierEngine
      - rule | rules | device_rule | heuristic → RuleEngine
    """
    n = (name or "rule").lower()

    if n in {"selfaware", "auto"}:
        return SelfAwareEngine()
    if n in {"ml", "ml_stub"}:
        return MLClassifierEngine()
    if n in {"rule", "rules", "device_rule", "heuristic"}:
        return RuleEngine()

    raise ValueError(f"Unknown engine: {name!r}. Valid: selfaware, ml, rule")
