# DCF/model_manager.py
from __future__ import annotations
import json, os, shutil, hashlib, time
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict

# crypto for signature verification
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding as asy_padding

MODELS_DIR = "models"
REGISTRY = os.path.join(MODELS_DIR, "registry.json")
CONSENT  = os.path.join(MODELS_DIR, "owner_consent.json")
AUDITLOG = os.path.join(MODELS_DIR, "audit.log")  # JSONL audit trail
BACKUPS_DIR = os.path.join(MODELS_DIR, "backups")

@dataclass
class ModelEntry:
    version: str
    created_utc: str
    sha256: str
    path_model: str
    path_meta: str
    installed_ts: float

# ------------- utils -------------
def _ensure_dirs():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(BACKUPS_DIR, exist_ok=True)

def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def _audit(event: str, **fields):
    _ensure_dirs()
    rec: Dict[str, object] = {"ts": time.time(), "event": event}
    rec.update(fields)
    with open(AUDITLOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def _load_registry() -> List[ModelEntry]:
    if not os.path.exists(REGISTRY):
        return []
    try:
        data = json.load(open(REGISTRY, "r", encoding="utf-8"))
        return [ModelEntry(**x) for x in data]
    except Exception:
        return []

def _save_registry(entries: List[ModelEntry]):
    tmp = REGISTRY + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump([asdict(e) for e in entries], f, indent=2)
    os.replace(tmp, REGISTRY)

def _has_consent() -> bool:
    if not os.path.exists(CONSENT):
        return False
    try:
        d = json.load(open(CONSENT, "r", encoding="utf-8"))
        return bool(d.get("allow_updates", False))
    except Exception:
        return False

# ------------- public API -------------
def approve_updates():
    _ensure_dirs()
    payload = {"allow_updates": True, "ts": time.time()}
    with open(CONSENT, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    _audit("approve_updates")

def revoke_updates():
    if os.path.exists(CONSENT):
        os.remove(CONSENT)
    _audit("revoke_updates")

def list_models() -> List[ModelEntry]:
    return sorted(_load_registry(), key=lambda e: e.installed_ts, reverse=True)

def current_model_paths() -> Optional[ModelEntry]:
    model = os.path.join(MODELS_DIR, "dcf_model.joblib")
    meta  = os.path.join(MODELS_DIR, "dcf_model.meta.json")
    if os.path.exists(model) and os.path.exists(meta):
        sha = _sha256(model)
        try:
            m = json.load(open(meta, "r", encoding="utf-8"))
            version = str(m.get("version", "unknown"))
            created = str(m.get("created_utc", ""))
        except Exception:
            version, created = "unknown", ""
        return ModelEntry(version, created, sha, model, meta, os.path.getmtime(model))
    return None

# ------------- signature verification -------------
def _load_public_key(pubkey_path: str):
    with open(pubkey_path, "rb") as f:
        blob = f.read()
    try:
        return serialization.load_pem_public_key(blob)
    except ValueError:
        # try OpenSSH format (Ed25519)
        return serialization.load_ssh_public_key(blob)

def _verify_signature(model_path: str, sig_path: str, pubkey_path: str) -> None:
    """
    Verifies detached signature over the model file.
    Supports:
      - Ed25519 public keys
      - RSA public keys (PSS + MGF1(SHA256))
    Raises ValueError if verification fails.
    """
    if not os.path.exists(pubkey_path):
        raise FileNotFoundError("Public key not found.")
    if not os.path.exists(sig_path):
        raise FileNotFoundError("Signature file not found.")
    pubkey = _load_public_key(pubkey_path)
    with open(model_path, "rb") as f:
        msg = f.read()
    sig = open(sig_path, "rb").read()

    try:
        if isinstance(pubkey, ed25519.Ed25519PublicKey):
            pubkey.verify(sig, msg)
            return
        if isinstance(pubkey, rsa.RSAPublicKey):
            pubkey.verify(
                sig, msg,
                asy_padding.PSS(mgf=asy_padding.MGF1(hashes.SHA256()), salt_length=asy_padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return
    except Exception:
        raise ValueError("Signature verification failed.")
    raise ValueError("Unsupported public key type for verification.")

# ------------- install / rollback -------------
def install_model(from_model_path: str,
                  from_meta_path: str,
                  *,
                  sig_path: str,
                  pubkey_path: str,
                  require_meta_hash: bool = True) -> ModelEntry:
    """
    Install a new model from local files (requires consent + valid signature).
    - Verifies detached signature using provided public key.
    - Optionally checks meta's declared sha256 against the file.
    - Backs up the current active model before switching.
    """
    _ensure_dirs()
    if not _has_consent():
        _audit("install_denied_no_consent", model=from_model_path)
        raise PermissionError("Owner consent required to update model. Run: model approve-updates")

    # validate inputs
    if not os.path.exists(from_model_path) or not os.path.exists(from_meta_path):
        _audit("install_missing_files", model=from_model_path, meta=from_meta_path)
        raise FileNotFoundError("Model or meta file not found.")

    # verify signature
    _verify_signature(from_model_path, sig_path, pubkey_path)
    file_sha = _sha256(from_model_path)

    # meta sanity & hash match (defense-in-depth)
    try:
        meta = json.load(open(from_meta_path, "r", encoding="utf-8"))
    except Exception as e:
        _audit("install_bad_meta", error=str(e))
        raise ValueError("Invalid meta JSON.")

    declared_sha = str(meta.get("sha256", "")).lower()
    if require_meta_hash and declared_sha and declared_sha != file_sha:
        _audit("install_hash_mismatch", declared=declared_sha, actual=file_sha)
        raise ValueError("Model sha256 does not match meta 'sha256'.")

    # backup current
    cur = current_model_paths()
    ts = time.strftime("%Y%m%d-%H%M%S")
    if cur:
        shutil.copy2(cur.path_model, os.path.join(BACKUPS_DIR, f"dcf_model.{ts}.joblib"))
        shutil.copy2(cur.path_meta,  os.path.join(BACKUPS_DIR, f"dcf_model.{ts}.meta.json"))

    # install new (atomic-ish)
    dst_model = os.path.join(MODELS_DIR, "dcf_model.joblib")
    dst_meta  = os.path.join(MODELS_DIR, "dcf_model.meta.json")
    shutil.copy2(from_model_path, dst_model)
    shutil.copy2(from_meta_path,  dst_meta)

    version = str(meta.get("version", ts))
    created = str(meta.get("created_utc", ""))
    entry = ModelEntry(version, created, file_sha, dst_model, dst_meta, time.time())
    entries = _load_registry()
    entries.append(entry)
    _save_registry(entries)
    _audit("install_success", version=version, sha256=file_sha, model=dst_model, meta=dst_meta)
    return entry

def rollback_to_backup(stamp_prefix: Optional[str] = None) -> str:
    """
    Rollback from models/backups/ by timestamp prefix; if None → most recent backup.
    Returns the timestamp key of the backup used.
    """
    files = sorted([f for f in os.listdir(BACKUPS_DIR)] if os.path.exists(BACKUPS_DIR) else [])
    pairs = {}
    for f in files:
        if f.endswith(".joblib"):
            stem = f.replace("dcf_model.", "").replace(".joblib", "")
            pairs.setdefault(stem, {})["model"] = os.path.join(BACKUPS_DIR, f)
        elif f.endswith(".meta.json"):
            stem = f.replace("dcf_model.", "").replace(".meta.json", "")
            pairs.setdefault(stem, {})["meta"] = os.path.join(BACKUPS_DIR, f)
    if not pairs:
        _audit("rollback_failed", reason="no_backups")
        raise FileNotFoundError("No backups found.")

    key = None
    if stamp_prefix:
        candidates = sorted([k for k in pairs if k.startswith(stamp_prefix)], reverse=True)
        if candidates:
            key = candidates[0]
    if key is None:
        key = sorted(pairs.keys(), reverse=True)[0]

    src_model = pairs[key].get("model")
    src_meta  = pairs[key].get("meta")
    if not (src_model and src_meta):
        _audit("rollback_failed", reason="incomplete_backup", key=key)
        raise FileNotFoundError(f"Incomplete backup for {key}")

    dst_model = os.path.join(MODELS_DIR, "dcf_model.joblib")
    dst_meta  = os.path.join(MODELS_DIR, "dcf_model.meta.json")
    shutil.copy2(src_model, dst_model)
    shutil.copy2(src_meta,  dst_meta)
    new_sha = _sha256(dst_model)
    _audit("rollback_success", key=key, new_sha256=new_sha)
    return key
