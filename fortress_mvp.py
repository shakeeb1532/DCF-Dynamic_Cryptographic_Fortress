#!/usr/bin/env python3
"""
Dynamic Cryptographic Fortress — Minimal Viable Product (single-file CLI)

Implements the core ideas from the white paper:
 - Threat-adaptive policy (destination-aware risk score → security profile)
 - Content-aware pre-processing (compression strategy)
 - Layered AEAD encryption (AES-GCM / ChaCha20-Poly1305)
 - Hybrid header encapsulation (RSA-4096 → AES-GCM encrypts the recipe)
 - Self-contained .fortress artifact with magic header and JSON metadata

Usage
-----
# Create an RSA keypair
python fortress_mvp.py keygen --out-dir keys

# Encrypt a file
python fortress_mvp.py encrypt \
  --in secret.bin --out secret.fortress \
  --dest-ip 216.3.128.12 \
  --recipient-pub keys/public.pem \
  --file-type auto

# Decrypt a file
python fortress_mvp.py decrypt \
  --in secret.fortress --out recovered.bin \
  --recipient-priv keys/private.pem

Notes
-----
* Requires Python 3.9+
* Depends on: cryptography, lz4 (optional)
* This is an MVP intended for experimentation and extension — not production

"""
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

# NEW: policy engine
from policy_engine import get_engine, Context

# --- Optional compression backend(s) ---
try:
    import lz4.frame as lz4f
    HAVE_LZ4 = True
except Exception:
    HAVE_LZ4 = False
import zlib

# --- Crypto primitives ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends.openssl import backend as openssl_backend
from cryptography.hazmat.primitives import constant_time

MAGIC = b"FORTV6"  # 6 bytes
VERSION = 1         # 1 byte in header JSON for clarity as well
HEADER_STRUCT = ">I"  # 4-byte big-endian unsigned for header length

# -------- Utilities --------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def is_fips_mode() -> bool:
    try:
        return openssl_backend.fips_mode_is_enabled()
    except Exception:
        return False


# -------- Risk Profiling (simulated SecureAI_API_Simulator) --------
@dataclass
class SecurityProfile:
    name: str
    layers: int
    ciphers: List[str]  # pool to choose per layer from
    compression: str    # 'lz4' | 'zlib' | 'none'


def risk_score_for_destination(dest_ip: str, file_type: str) -> float:
    """Return a deterministic risk score in [0,10]. Purely simulated.

    A few special cases to mirror the paper's example; otherwise hash-ish mapping.
    """
    # Extreme example from the whitepaper
    if dest_ip == "216.3.128.12":
        return 9.0

    # Crude heuristic knobs
    score = 3.0
    if any(t in file_type.lower() for t in ("video", "raw", "db", "keys", "secret", "pdf")):
        score += 1.5
    if dest_ip.startswith(("5.", "45.", "95.", "101.")):
        score += 1.0
    if dest_ip.endswith(".0") or dest_ip.endswith(".255"):
        score += 0.5
    # Make it deterministic per destination octets
    try:
        octets = [int(x) for x in dest_ip.split(".")]
        score += (sum(octets) % 40) / 40.0  # 0..0.975
    except Exception:
        score += 0.0
    return min(10.0, max(0.0, score))


def choose_profile(score: float) -> SecurityProfile:
    """Map risk score → profile.
    low    : <3.5  → 2 layers, zlib, mixed ciphers
    medium : <6.5  → 3 layers, zlib/lz4, mixed ciphers
    high   : <8.5  → 3-4 layers, prefer lz4 if available
    extreme: ≥8.5  → 4 layers, prefer lz4, broad cipher mix
    """
    if score < 3.5:
        return SecurityProfile("low_risk", 2, ["AESGCM", "ChaCha20"], "zlib")
    if score < 6.5:
        return SecurityProfile("medium_risk", 3, ["AESGCM", "ChaCha20"], "lz4" if HAVE_LZ4 else "zlib")
    if score < 8.5:
        return SecurityProfile("high_risk", 4 if HAVE_LZ4 else 3, ["AESGCM", "ChaCha20"], "lz4" if HAVE_LZ4 else "zlib")
    return SecurityProfile("extreme_risk", 4, ["AESGCM", "ChaCha20"], "lz4" if HAVE_LZ4 else "zlib")


# -------- Compression --------

def compress_blob(data: bytes, method: str) -> Tuple[bytes, Dict[str, str]]:
    if method == "lz4" and HAVE_LZ4:
        c = lz4f.compress(data)
        return c, {"alg": "lz4", "orig": str(len(data))}
    elif method == "zlib":
        c = zlib.compress(data, 9)
        return c, {"alg": "zlib", "orig": str(len(data))}
    return data, {"alg": "none", "orig": str(len(data))}


def decompress_blob(data: bytes, meta: Dict[str, str]) -> bytes:
    alg = meta.get("alg", "none")
    if alg == "lz4":
        if not HAVE_LZ4:
            raise RuntimeError("lz4 not available to decompress")
        return lz4f.decompress(data)
    if alg == "zlib":
        return zlib.decompress(data)
    return data


# -------- Layered AEAD --------
def rand_bytes(n: int) -> bytes:
    return os.urandom(n)


def aead_encrypt(alg: str, key: bytes, nonce: bytes, plaintext: bytes, aad: Optional[bytes]=None) -> bytes:
    if alg == "AESGCM":
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    elif alg == "ChaCha20":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    else:
        raise ValueError(f"Unknown AEAD alg {alg}")


def aead_decrypt(alg: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: Optional[bytes]=None) -> bytes:
    if alg == "AESGCM":
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    elif alg == "ChaCha20":
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    else:
        raise ValueError(f"Unknown AEAD alg {alg}")


@dataclass
class LayerSpec:
    alg: str
    key: bytes
    nonce: bytes


def apply_layers(plaintext: bytes, layers: List[LayerSpec]) -> bytes:
    out = plaintext
    aad = MAGIC  # bind artifact type across layers
    for layer in layers:
        out = aead_encrypt(layer.alg, layer.key, layer.nonce, out, aad)
    return out


def peel_layers(ciphertext: bytes, layers: List[LayerSpec]) -> bytes:
    out = ciphertext
    aad = MAGIC
    for layer in reversed(layers):
        out = aead_decrypt(layer.alg, layer.key, layer.nonce, out, aad)
    return out


# -------- Hybrid Header (RSA-4096 → AES-GCM for recipe) --------
def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path: str, password: Optional[bytes] = None):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def rsa_encrypt(pubkey, blob: bytes) -> bytes:
    return pubkey.encrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt(privkey, blob: bytes) -> bytes:
    return privkey.decrypt(
        blob,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


# -------- Artifact framing --------
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


# -------- Commands --------
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
    # Load input
    with open(args.in_path, "rb") as f:
        raw = f.read()

    file_type = args.file_type if args.file_type != "auto" else infer_file_type(args.in_path)

    # Policy engine plan → recipe
    engine = get_engine(args.policy_backend)
    ctx = Context(dest_ip=args.dest_ip, file_type=file_type, file_size_bytes=len(raw),
                  device_class=args.device_class, constraints={
                      'latency_budget_ms': args.latency_budget_ms,
                      'cpu_cores': args.cpu_cores,
                      'battery_saver': 1 if args.battery_saver else 0,
                      'bandwidth_mbps': args.bandwidth_mbps,
                  })
    plan = engine.plan(ctx)

    # Compress according to plan
    comp_blob, comp_meta = compress_blob(raw, plan.compression)

    # Build layered cipher plan from policy output
    layers: List[LayerSpec] = []
    # Ensure plan.ciphers has enough elements for plan.layers
    ciphers = plan.ciphers
    if len(ciphers) < plan.layers:
        # Repeat or extend the cipher list to match layers
        ciphers = (ciphers * ((plan.layers // len(ciphers)) + 1))[:plan.layers]
    for i in range(plan.layers):
        alg = ciphers[i]
        key = os.urandom(32)
        nonce = os.urandom(12)
        layers.append(LayerSpec(alg, key, nonce))

    # Apply encryption layers to compressed blob
    layered_ct = apply_layers(comp_blob, layers)

    # Build recipe JSON (keys, nonces, order, compression, meta)
    recipe = {
        "version": VERSION,
        "profile": plan.profile,
        "score": plan.score,
        "compression": comp_meta,  # {'alg': 'lz4'|'zlib'|'none', 'orig': str(n)}
        "layers": [
            {"alg": L.alg, "key": b64e(L.key), "nonce": b64e(L.nonce)} for L in layers
        ],
        "aad": b64e(MAGIC),
        "file_type": file_type,
        "timestamp": int(time.time()),
        "dest_ip": args.dest_ip,
        "policy_backend": args.policy_backend,
        "policy_rationale": plan.rationale,
    }

    # Envelope-encrypt recipe with AES-GCM; AES key is RSA-encrypted
    session_key = os.urandom(32)
    header_nonce = os.urandom(12)
    enc_recipe = AESGCM(session_key).encrypt(header_nonce, json.dumps(recipe, separators=(",", ":")).encode("utf-8"), MAGIC)

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

    print("Encrypted -> {}\nProfile={} score={:.2f} layers={} compression={} (orig {} bytes)".format(
        args.out_path, plan.profile, plan.score, plan.layers, comp_meta['alg'], comp_meta['orig']))
    if args.explain:
        print("Policy rationale:")
        for idx, r in enumerate(plan.rationale, 1):
            print(f"  {idx}. {r}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    header, payload = read_artifact(args.in_path)

    priv = load_private_key(args.recipient_priv)
    session_key = rsa_decrypt(priv, b64d(header["kem"]))
    recipe_bytes = AESGCM(session_key).decrypt(
        b64d(header["header_nonce"]), b64d(header["enc_recipe"]), MAGIC
    )
    recipe = json.loads(recipe_bytes.decode("utf-8"))

    # Rebuild layers
    layers = [LayerSpec(L["alg"], b64d(L["key"]), b64d(L["nonce"])) for L in recipe["layers"]]

    # Peel layers
    comp_blob = peel_layers(payload, layers)

    # Decompress
    raw = decompress_blob(comp_blob, recipe["compression"])

    with open(args.out_path, "wb") as f:
        f.write(raw)

    print(f"Decrypted -> {args.out_path}\nProfile={recipe['profile']} score={recipe['score']} layers={len(layers)} compression={recipe['compression']['alg']}")


# -------- Helpers --------
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


# -------- CLI --------
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
    p_enc.add_argument("--file-type", default="auto", help="auto|video|archive|data|document|binary|<ext>")
    p_enc.add_argument("--policy-backend", default="device_rule", help="rule|device_rule|ml")
    p_enc.add_argument("--device-class", default="server", help="server|laptop|phone|iot")
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

