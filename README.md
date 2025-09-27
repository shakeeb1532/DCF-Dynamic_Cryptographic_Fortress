# Dynamic Cryptographic Fortress — MVP

Single-file Python CLI that demonstrates the white paper's core mechanics:
- Destination-aware risk scoring → threat-adaptive profile
- Content-aware compression (lz4 or zlib)
- Multi-layer AEAD (AES-GCM, ChaCha20-Poly1305)
- Hybrid header: RSA-4096 + AES-GCM encapsulated "recipe"
- Self-describing `.fortress` artifact

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Generate test keys
python fortress_mvp.py keygen --out-dir keys

# Prepare a sample file
echo "hello fortress" > sample.txt

# Encrypt
python fortress_mvp.py encrypt --in sample.txt --out sample.fortress \  --dest-ip 216.3.128.12 --recipient-pub keys/public.pem --file-type auto

# Decrypt
python fortress_mvp.py decrypt --in sample.fortress --out sample.out \  --recipient-priv keys/private.pem

diff -u sample.txt sample.out  # should be empty (files equal)
```

> **Note:** `lz4` is optional. If not installed, the tool falls back to `zlib`.


## Policy engine (AI/rules) usage

Use the pluggable policy engine to adapt ciphers/layers/compression to destination, device, and constraints.

```bash
# Default device-aware rule backend with explanation
python fortress_mvp.py encrypt --in sample.txt --out sample.fortress \
  --dest-ip 216.3.128.12 --recipient-pub keys/public.pem \
  --device-class laptop --bandwidth-mbps 20 --cpu-cores 4 --battery-saver \
  --explain

# Choose a specific backend
python fortress_mvp.py encrypt --in sample.txt --out sample.fortress \
  --dest-ip 10.0.0.5 --recipient-pub keys/public.pem \
  --policy-backend rule --explain
```

