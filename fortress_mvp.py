# fortress_mvp.py
# Copyright 2025 shakeeb1532
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import sys
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

from policy_engine import get_engine, Context

# Optional compression
try:
    import lz4.frame as lz4f
    HAVE_LZ4 = True
except Exception:
    HAVE_LZ4 = False
import zlib

# Crypto
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes, constant_time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends.openssl import backend as openssl_backend

# Model admin + adaptive params
from DCF.model_manager import (
    approve_updates, revoke_updates, install_model, rollback_to_backup,
    list_models, current_model_paths
)
from DCF.auto_params import observe_outcome

MAGIC = b"FORTV6"
VERSION = 1
HEADER_STRUCT = ">I"  # uint32 header length

# Cipher allow-list
ALLOWED_CIPHERS = {
    "AESGCM": {"key_len": 32, "nonce_len": 12},
    "CHACHA20": {"key_len": 32, "nonce_len": 12},  # normalize ChaCha20-Poly1305 to CHACHA20
}
CHACHA_ALIASES = {"CHACHA20", "CHACHA20-POLY1305"}

# ---------- utils ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def is_fips_mode() -> bool:
    try:
        return openssl_backend.fips_mode_is_enabled()
    except Exception:
        return False

def normalize_cipher_name(name: str) -> str:
    n = (name or "").strip().upper()
    if n in CHACHA_ALIASES:
        return "CHACHA20"
    return n

def validate_layer_params(alg: str, key: bytes, nonce: bytes) -> None:
    alg_norm = normalize_cipher_name(alg)
    if alg_norm not in ALLOWED_CIPHERS:
        raise ValueError(f"Cipher not allowed: {alg}")
    exp = ALLOWED_CIPHERS[alg_norm]
    if len(key) != exp["key_len"]:
        raise ValueError(f"{alg} key must be {exp['key_len']} bytes, got {len(key)}")
    if len(nonce) != exp["nonce_len"]:
        raise ValueError(f"{alg} nonce must be {exp['nonce_len']} bytes, got {len(nonce)}")

# ---------- compression ----------
def compress_blob(data: bytes, method: str) -> Tuple[bytes, Dict[str, str]]:
    m = (method or "none").lower()
    if m == "lz4" and HAVE_LZ4:
        c = lz4f.compress(data)
        return c, {"alg": "lz4", "orig": str(len(data))}
    if m == "zlib":
        c = zlib.compress(data, 9)
        return c, {"alg": "zlib", "orig": str(len(data))}
    return data, {"alg": "none", "orig": str(len(data))}

def decompress_blob(data: bytes, meta: Dict[str, str]) -> bytes:
    alg = (meta or {}).get("alg", "none")
    if alg == "lz4":
        if not HAVE_LZ4:
            raise RuntimeError("lz4 not available to decompress")
        return lz4f.decompress(data)
    if alg == "zlib":
        return zlib.decompress(data)
    return data

# ---------- layered AEAD ----------
@dataclass
class LayerSpec:
    alg: str
    key: bytes
    nonce: bytes

def aead_encrypt(alg: str, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes]=None) -> bytes:
    alg_norm = normalize_cipher_name(alg)
    validate_layer_params(alg_norm, key, nonce)
    if alg_norm == "AESGCM":
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    elif alg_norm == "CHACHA20":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    raise ValueError(f"Unknown AEAD alg {alg}")

def aead_decrypt(alg: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes]=None) -> bytes:
    alg_norm = normalize_cipher_name(alg)
    validate_layer_params(alg_norm, key, nonce)
    if alg_norm == "AESGCM":
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    elif alg_norm == "CHACHA20":
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    raise ValueError(f"Unknown AEAD alg {alg}")

def apply_layers(plaintext: bytes, layers: List[LayerSpec]) -> bytes:
    out = plaintext
    aad = MAGIC
    for layer in layers:
        out = aead_encrypt(layer.alg, layer.key, layer.nonce, out, aad)
    return out

def peel_layers(ciphertext: bytes, layers: List[LayerSpec]) -> bytes:
    out = ciphertext
    aad = MAGIC
    for layer in reversed(layers):
        out = aead_decrypt(layer.alg, layer.key, layer.nonce, out, aad)
    return out

# ---------- RSA header sealing ----------
def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path: str, password: Optional[bytes] = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)

def rsa_encrypt(pubkey, blob: bytes) -> bytes:
    return pubkey.encrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(privkey, blob: bytes) -> bytes:
    return privkey.decrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

# ---------- artifact I/O ----------
def write_artifact(out_path: str, header_json: dict, payload: bytes) -> None:
    header_bytes = json.dumps(header_json, separators=(",", ":")).encode("utf-8")
    with open(out_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(HEADER_STRUCT, len(header_bytes)))
        f.write(header_bytes)
        f.write(payload)

def read_artifact(in_path: str) -> Tuple[dict, bytes]:
    with open(in_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if not constant_time.bytes_eq(magic, MAGIC):
            raise ValueError("Not a FORTV6 artifact")
        (hlen,) = struct.unpack(HEADER_STRUCT, f.read(struct.calcsize(HEADER_STRUCT)))
        header = json.loads(f.read(hlen).decode("utf-8"))
        payload = f.read()
    return header, payload

# ---------- commands ----------
def cmd_keygen(args: argparse.Namespace) -> None:
    os.makedirs(args.out_dir, exist_ok=True)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pub = priv.public_key()

    enc = serialization.Encoding.PEM
    priv_bytes = priv.private_bytes(enc, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_bytes = pub.public_bytes(enc, serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(os.path.join(args.out_dir, "private.pem"), "wb") as f:
        f.write(priv_bytes)
    with open(os.path.join(args.out_dir, "public.pem"), "wb") as f:
        f.write(pub_bytes)
    print(f"Wrote {args.out_dir}/private.pem and {args.out_dir}/public.pem")

def cmd_encrypt(args: argparse.Namespace) -> None:
    with open(args.in_path, "rb") as f:
        raw = f.read()

    file_type = args.file_type if args.file_type != "auto" else infer_file_type(args.in_path)

    engine = get_engine(args.policy_backend)
    ctx = Context(
        dest_ip=args.dest_ip,
        file_type=file_type,
        file_size_bytes=len(raw),
        device_class=args.device_class,
        constraints={
            'latency_budget_ms': args.latency_budget_ms,
            'cpu_cores': args.cpu_cores,
            'battery_saver': 1 if args.battery_saver else 0,
            'bandwidth_mbps': args.bandwidth_mbps,
        },
    )
    plan = engine.plan(ctx)

    # compress per plan
    comp_blob, comp_meta = compress_blob(raw, plan.compression)

    # build layers
    ciphers = list(plan.ciphers or [])
    if len(ciphers) < int(plan.layers):
        ciphers = (ciphers * ((int(plan.layers) // max(1, len(ciphers))) + 1))[: int(plan.layers)]

    layers: List[LayerSpec] = []
    for i in range(int(plan.layers)):
        alg = normalize_cipher_name(ciphers[i])
        key = os.urandom(ALLOWED_CIPHERS[alg]["key_len"])
        nonce = os.urandom(ALLOWED_CIPHERS[alg]["nonce_len"])
        validate_layer_params(alg, key, nonce)
        layers.append(LayerSpec(alg, key, nonce))

    layered_ct = apply_layers(comp_blob, layers)

    recipe = {
        "version": VERSION,
        "profile": plan.profile,
        "score": plan.score,
        "compression": comp_meta,
        "layers": [
            {"alg": L.alg, "key": b64e(L.key), "nonce": b64e(L.nonce)} for L in layers
        ],
        "aad": b64e(MAGIC),
        "file_type": file_type,
        "timestamp": int(time.time()),
        "dest_ip": args.dest_ip,
        "policy_backend": args.policy_backend,
        "policy_rationale": plan.rationale,
        "fips_mode": bool(is_fips_mode()),
    }

    # seal recipe (AES-GCM) and wrap session key (RSA-OAEP)
    session_key = os.urandom(32)
    header_nonce = os.urandom(12)
    enc_recipe = AESGCM(session_key).encrypt(
        header_nonce,
        json.dumps(recipe, separators=(",", ":")).encode("utf-8"),
        MAGIC,
    )

    pub = load_public_key(args.recipient_pub)
    enc_session_key = rsa_encrypt(pub, session_key)

    header = {
        "artifact_version": VERSION,
        "rsa_alg": "RSA-4096-OAEP-SHA256",
        "kem": b64e(enc_session_key),
        "header_nonce": b64e(header_nonce),
        "enc_recipe": b64e(enc_recipe),
    }

    write_artifact(args.out_path, header, layered_ct)

    print(
        "Encrypted -> {}\nProfile={} score={:.2f} layers={} compression={} (orig {} bytes)".format(
            args.out_path, plan.profile, float(plan.score), int(plan.layers),
            comp_meta['alg'], comp_meta['orig']
        )
    )
    if args.explain:
        print("Policy rationale:")
        for idx, r in enumerate(plan.rationale or [], 1):
            print(f"  {idx}. {r}")

    # ---- Adaptive feedback (preliminary) ----
    try:
        enc_size = os.path.getsize(args.out_path)
        comp_ratio = max(0.0, 1.0 - (enc_size / max(1, len(raw))))  # ↑ better
        perf_score = min(1.0, comp_ratio + (0.1 if plan.compression != "none" else 0.0) + (0.1 if plan.layers >= 3 else 0.0))
        observe_outcome(success=True, perf_score=float(perf_score))
    except Exception:
        pass

def cmd_decrypt(args: argparse.Namespace) -> None:
    header, payload = read_artifact(args.in_path)

    priv = load_private_key(args.recipient_priv)
    session_key = rsa_decrypt(priv, b64d(header["kem"]))
    recipe_bytes = AESGCM(session_key).decrypt(
        b64d(header["header_nonce"]), b64d(header["enc_recipe"]), MAGIC
    )
    recipe = json.loads(recipe_bytes.decode("utf-8"))

    layers = [
        LayerSpec(
            normalize_cipher_name(L["alg"]),
            b64d(L["key"]),
            b64d(L["nonce"]),
        )
        for L in recipe["layers"]
    ]
    for L in layers:
        validate_layer_params(L.alg, L.key, L.nonce)

    comp_blob = peel_layers(payload, layers)
    raw = decompress_blob(comp_blob, recipe["compression"])

    with open(args.out_path, "wb") as f:
        f.write(raw)

    print(
        f"Decrypted -> {args.out_path}\n"
        f"Profile={recipe['profile']} score={recipe['score']} "
        f"layers={len(layers)} compression={recipe['compression']['alg']}"
    )

    # ---- Adaptive feedback (authoritative) ----
    try:
        orig = recipe.get("compression", {}).get("orig")
        if orig is not None:
            orig = float(orig)
            enc_size = os.path.getsize(args.in_path)
            comp_ratio = max(0.0, 1.0 - (enc_size / max(1.0, orig)))
        else:
            comp_ratio = 0.0
        perf_score = min(1.0, comp_ratio + (0.1 if len(layers) >= 3 else 0.0))
        observe_outcome(success=True, perf_score=float(perf_score))
    except Exception:
        pass

# ---------- helpers ----------
def infer_file_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower().strip('.')
    if ext in ("mp4", "mov", "mkv", "avi"):
        return "video"
    if ext in ("zip", "gz", "xz", "7z"):
        return "archive"
    if ext in ("json", "csv", "db", "sqlite"):
        return "data"
    if ext in ("txt", "md", "pdf", "doc", "docx"):
        return "document"
    return ext or "binary"

# ---------- CLI ----------
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Dynamic Cryptographic Fortress — MVP")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_key = sub.add_parser("keygen", help="generate RSA-4096 keypair")
    p_key.add_argument("--out-dir", default="keys")
    p_key.set_defaults(func=cmd_keygen)

    p_enc = sub.add_parser("encrypt", help="encrypt a file into .fortress artifact")
    p_enc.add_argument("--in", dest="in_path", required=True)
    p_enc.add_argument("--out", dest="out_path", required=True)
    p_enc.add_argument("--dest-ip", required=True)
    p_enc.add_argument("--recipient-pub", required=True)
    p_enc.add_argument("--file-type", default="auto",
                       help="auto|video|archive|data|document|binary|<ext>")
    p_enc.add_argument("--policy-backend", default="selfaware",
                       help="selfaware|ml|rule|rules|device_rule")
    p_enc.add_argument("--device-class", default="server",
                       help="server|laptop|phone|iot")
    p_enc.add_argument("--cpu-cores", type=int, default=4)
    p_enc.add_argument("--bandwidth-mbps", type=float, default=100.0)
    p_enc.add_argument("--latency-budget-ms", type=int, default=1000)
    p_enc.add_argument("--battery-saver", action="store_true")
    p_enc.add_argument("--explain", action="store_true", help="print rationale for chosen policy")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="decrypt a .fortress artifact")
    p_dec.add_argument("--in", dest="in_path", required=True)
    p_dec.add_argument("--out", dest="out_path", required=True)
    p_dec.add_argument("--recipient-priv", required=True)
    p_dec.set_defaults(func=cmd_decrypt)

    # ---- model admin ----
    p_m = sub.add_parser("model", help="model admin commands")
    msub = p_m.add_subparsers(dest="mcmd", required=True)

    p_m_approve = msub.add_parser("approve-updates", help="owner consent for updates")
    p_m_approve.set_defaults(func=lambda args: (approve_updates(), print("✅ Updates approved by owner")))

    p_m_revoke = msub.add_parser("revoke-updates", help="revoke owner consent")
    p_m_revoke.set_defaults(func=lambda args: (revoke_updates(), print("🛑 Updates revoked")))

    p_m_install = msub.add_parser("install", help="install model from local files (signature required)")
    p_m_install.add_argument("--model", required=True, help="path to dcf_model.joblib")
    p_m_install.add_argument("--meta", required=True, help="path to dcf_model.meta.json")
    p_m_install.add_argument("--sig",  required=True, help="path to detached signature for the model")
    p_m_install.add_argument("--pubkey", required=True, help="path to signer public key (Ed25519 or RSA)")
    def _do_install(a):
        entry = install_model(a.model, a.meta, sig_path=a.sig, pubkey_path=a.pubkey)
        print(f"✅ Installed model v={entry.version} sha256={entry.sha256[:12]}…")
    p_m_install.set_defaults(func=_do_install)

    p_m_list = msub.add_parser("list", help="list installed/current model(s)")
    def _do_list(a):
        cur = current_model_paths()
        if cur:
            print(f"Current: v={cur.version} sha256={cur.sha256[:12]}… at {cur.path_model}")
        else:
            print("No current model")
        for e in list_models():
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e.installed_ts))
            print(f"- v={e.version} sha256={e.sha256[:12]}… installed={ts}")
    p_m_list.set_defaults(func=_do_list)

    p_m_rb = msub.add_parser("rollback", help="rollback to a backup")
    p_m_rb.add_argument("--to", default=None, help="timestamp prefix (e.g., 20250930-12)")
    def _do_rb(a):
        stamp = rollback_to_backup(a.to)
        print(f"🔁 Rolled back to backup {stamp}")
    p_m_rb.set_defaults(func=_do_rb)

    return p

def main(argv: Optional[List[str]] = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = build_cli()
    args = p.parse_args(argv)
    try:
        args.func(args)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())



