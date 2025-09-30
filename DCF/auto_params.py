# copyright 2025 shakeeb1532
# DCF/auto_params.py
from __future__ import annotations
import json, os, time
from dataclasses import dataclass, asdict

_STATE = "auto_params_state.json"

@dataclass
class AutoParamsState:
    min_confidence: float = 0.60
    bandit_alpha: float = 0.80
    ewma_fail: float = 0.0   # rolling failure rate
    ewma_perf: float = 0.0   # rolling perf proxy
    last_update_ts: float = 0.0

def _load_state(path=_STATE) -> AutoParamsState:
    if not os.path.exists(path):
        return AutoParamsState()
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        return AutoParamsState(**d)
    except Exception:
        return AutoParamsState()

def _save_state(st: AutoParamsState, path=_STATE):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(asdict(st), f, indent=2)
    os.replace(tmp, path)

def suggest_params() -> AutoParamsState:
    """Read current auto params (no mutation)."""
    return _load_state()

def observe_outcome(success: bool, perf_score: float, fail_weight: float = 0.2, perf_weight: float = 0.1):
    """
    Feed outcome from a run to adapt parameters.
    - success: True if end-to-end decrypt verified OK (or preliminary encrypt success)
    - perf_score: user-defined [0..1+] summarizing throughput/compression
    """
    st = _load_state()
    # EWMA updates
    st.ewma_fail = (1 - fail_weight) * st.ewma_fail + fail_weight * (0.0 if success else 1.0)
    st.ewma_perf = (1 - perf_weight) * st.ewma_perf + perf_weight * max(0.0, perf_score)

    # Adapt: raise min_conf when failures increase; lower when perf is great & failures low
    # clamp to [0.50, 0.90]
    target_conf = 0.60 + 0.25 * st.ewma_fail - 0.05 * min(1.0, st.ewma_perf)
    st.min_confidence = max(0.50, min(0.90, target_conf))

    # Adapt bandit exploration: more failures → more exploration; more perf → less exploration
    # clamp to [0.5, 1.2]
    target_alpha = 0.80 + 0.40 * st.ewma_fail - 0.20 * min(1.0, st.ewma_perf)
    st.bandit_alpha = max(0.50, min(1.20, target_alpha))

    st.last_update_ts = time.time()
    _save_state(st)

def reset_params():
    _save_state(AutoParamsState())
