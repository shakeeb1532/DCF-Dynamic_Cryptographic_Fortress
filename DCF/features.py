# dcf/features.py
from typing import Dict, List
import numpy as np

FEATURE_KEYS = [
    "file_size_mb", "is_private_ip", "bandwidth_mbps",
    "file_type=data", "file_type=document", "file_type=video",
    "device_class=server", "device_class=laptop", "device_class=iot",
]

def ctx_to_feature_dict(ctx) -> Dict[str, float]:
    size_mb = ctx.file_size_bytes / (1024 * 1024)
    return {
        "file_size_mb": size_mb,
        "is_private_ip": 1.0 if _is_rfc1918(ctx.dest_ip) else 0.0,  # assumes your helper
        "bandwidth_mbps": float(ctx.constraints.get("bandwidth_mbps", 100)),
        "file_type=data": 1.0 if ctx.file_type == "data" else 0.0,
        "file_type=document": 1.0 if ctx.file_type == "document" else 0.0,
        "file_type=video": 1.0 if ctx.file_type == "video" else 0.0,
        "device_class=server": 1.0 if ctx.device_class == "server" else 0.0,
        "device_class=laptop": 1.0 if ctx.device_class == "laptop" else 0.0,
        "device_class=iot": 1.0 if ctx.device_class == "iot" else 0.0,
    }

def feats_to_vector(d: Dict[str, float]) -> np.ndarray:
    return np.array([d.get(k, 0.0) for k in FEATURE_KEYS], dtype=float)
