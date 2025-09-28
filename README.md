# 🛡️ Dynamic Cryptographic Fortress (DCF)

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/YOUR_USERNAME/YOUR_REPO/actions)
[![PyPI Version](https://img.shields.io/badge/pypi-v0.1.0-blue)](https://pypi.org/project/dcf/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An intelligent, adaptive encryption tool that hardens your security based on context.

DCF moves beyond static, one-size-fits-all encryption. It uses a pluggable policy engine to analyze the context of a file transfer—like destination risk, data sensitivity, and device capabilities—to apply the optimal level of security and performance for every operation.

---

### ✨ Key Features

* **Threat-Adaptive Profiles**: Automatically adjusts encryption strength based on destination-aware risk scoring.
* **Content-Aware Compression**: Intelligently chooses between `lz4` for speed or `zlib` for size, based on file type.
* **Multi-Layer AEAD**: Applies multiple layers of modern, authenticated ciphers like `AES-GCM` and `ChaCha20-Poly1305` for robust security.
* **Hybrid Encryption**: Secures the encryption "recipe" using an `RSA-4069` + `AES-GCM` hybrid scheme.
* **Self-Describing Artifacts**: The output `.fortress` file contains everything needed to decrypt it, ensuring portability.

---

### 🚀 Quick Start

#### 1. Installation

First, clone the repository and set up the virtual environment. DCF requires Python 3.8+.

```bash
git clone [https://github.com/YOUR_USERNAME/YOUR_REPO.git](https://github.com/YOUR_USERNAME/YOUR_REPO.git)
cd YOUR_REPO

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # on Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
2. Usage Example
Follow these steps for a basic encrypt/decrypt cycle.

Step 1: Generate your RSA keys
This command creates public.pem and private.pem in the keys/ directory.

Bash

python fortress_mvp.py keygen --out-dir keys
Step 2: Prepare a sample file

Bash

echo "hello fortress" > sample.txt
Step 3: Encrypt the file
Here, we're simulating a high-risk destination (--dest-ip) to trigger a stronger security profile.

Bash

python fortress_mvp.py encrypt \
  --in sample.txt \
  --out sample.fortress \
  --dest-ip 216.3.128.12 \
  --recipient-pub keys/public.pem
Step 4: Decrypt the file

Bash

python fortress_mvp.py decrypt \
  --in sample.fortress \
  --out sample.out \
  --recipient-priv keys/private.pem
Step 5: Verify the integrity
This command should produce no output, confirming the original and decrypted files are identical.

Bash

diff -u sample.txt sample.out
🧠 Using the Policy Engine
DCF's real power comes from its adaptive policy engine. You can provide additional context to influence the encryption strategy. The --explain flag shows the rationale behind the chosen security profile.

Example 1: A constrained laptop on a slow network
This context will likely cause the engine to select a balanced profile, possibly with more aggressive compression.

Bash

python fortress_mvp.py encrypt \
  --in sample.txt \
  --out sample.fortress \
  --dest-ip 216.3.128.12 \
  --recipient-pub keys/public.pem \
  --device-class laptop \
  --bandwidth-mbps 20 \
  --cpu-cores 4 \
  --battery-saver \
  --explain
Example 2: A trusted destination with a specific policy backend
Here, we're simulating a low-risk internal IP and explicitly using the simpler rule backend.

Bash

python fortress_mvp.py encrypt \
  --in sample.txt \
  --out sample.fortress \
  --dest-ip 10.0.0.5 \
  --recipient-pub keys/public.pem \
  --policy-backend rule \
  --explain
Note: lz4 is an optional dependency for faster compression. If it is not installed, the tool gracefully falls back to the built-in zlib library.

🤝 Contributing
Contributions are welcome! Whether it's bug reports, feature requests, or pull requests, please feel free to get involved.

Please read our CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.

📄 License
This project is licensed under the MIT License - see the LICENSE.md file for details.
