# DCF/features.py
from typing import Dict
import numpy as np

# Keep the order stable — the bandit expects a fixed-length vector.
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

def ctx_to_feature_dict(ctx) -> Dict[str, float]:
    """
    Build a small, stable feature dictionary from your Context.
    Assumes these attributes exist on your existing Context:
      - file_size_bytes: int
      - dest_ip: str
      - file_type: str in {'data','document','video',...}
      - device_class: str in {'server','laptop','iot',...}
      - constraints: dict, may contain 'bandwidth_mbps'
    Also assumes you already have a helper _is_rfc1918 somewhere.
    """
    # Import here to avoid circulars if your utils live beside policy code.
    from policy_engine import _is_rfc1918  # re-use your helper

    size_mb = (ctx.file_size_bytes or 0) / (1024 * 1024)
    return {
        "file_size_mb": float(size_mb),
        "is_private_ip": 1.0 if _is_rfc1918(ctx.dest_ip) else 0.0,
        "bandwidth_mbps": float(ctx.constraints.get("bandwidth_mbps", 100.0) if getattr(ctx, "constraints", None) else 100.0),

        "file_type=data": 1.0 if getattr(ctx, "file_type", None) == "data" else 0.0,
        "file_type=document": 1.0 if getattr(ctx, "file_type", None) == "document" else 0.0,
        "file_type=video": 1.0 if getattr(ctx, "file_type", None) == "video" else 0.0,

        "device_class=server": 1.0 if getattr(ctx, "device_class", None) == "server" else 0.0,
        "device_class=laptop": 1.0 if getattr(ctx, "device_class", None) == "laptop" else 0.0,
        "device_class=iot": 1.0 if getattr(ctx, "device_class", None) == "iot" else 0.0,
    }

def feats_to_vector(d: Dict[str, float]) -> np.ndarray:
    """
    Convert the feature dict to a dense vector in FEATURE_KEYS order.
    """
    return np.array([float(d.get(k, 0.0)) for k in FEATURE_KEYS], dtype=float)
