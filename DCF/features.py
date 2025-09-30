# DCF/features.py

from __future__ import annotations

import ipaddress
from typing import Dict
import numpy as np

FEATURE_KEYS = [
    "file_size_mb",
    "is_private_ip",
    "bandwidth_mbps",
    "file_type=data",
    "file_type=document",
    "file_type=video",
    "device_class=server",
    "device_class=laptop",
    "device_class=iot",
]

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def ctx_to_feature_dict(ctx) -> Dict[str, float]:
    size_mb = (getattr(ctx, "file_size_bytes", 0) or 0) / (1024 * 1024)
    bw = 0.0
    if getattr(ctx, "constraints", None):
        try:
            bw = float(ctx.constraints.get("bandwidth_mbps", 100.0))
        except Exception:
            bw = 100.0
    return {
        "file_size_mb": float(size_mb),
        "is_private_ip": 1.0 if _is_private(getattr(ctx, "dest_ip", "")) else 0.0,
        "bandwidth_mbps": float(bw),
        "file_type=data": 1.0 if getattr(ctx, "file_type", None) == "data" else 0.0,
        "file_type=document": 1.0 if getattr(ctx, "file_type", None) == "document" else 0.0,
        "file_type=video": 1.0 if getattr(ctx, "file_type", None) == "video" else 0.0,
        "device_class=server": 1.0 if getattr(ctx, "device_class", None) == "server" else 0.0,
        "device_class=laptop": 1.0 if getattr(ctx, "device_class", None) == "laptop" else 0.0,
        "device_class=iot": 1.0 if getattr(ctx, "device_class", None) == "iot" else 0.0,
    }

def feats_to_vector(d: Dict[str, float]) -> np.ndarray:
    return np.array([float(d.get(k, 0.0)) for k in FEATURE_KEYS], dtype=float)
