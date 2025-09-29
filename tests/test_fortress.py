# Copyright 2025 shakeeb1532
import os
import subprocess

def test_keygen():
    result = subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"], capture_output=True)
    assert result.returncode == 0
    assert os.path.exists("keys/public.pem")
    assert os.path.exists("keys/private.pem")

def test_encrypt_decrypt():
    with open("sample.txt", "w") as f:
        f.write("hello fortress")

    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "sample.txt", "--out", "sample.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "sample.fortress", "--out", "sample.out",
        "--recipient-priv", "keys/private.pem"
    ])

    with open("sample.txt") as original, open("sample.out") as decrypted:
        assert original.read() == decrypted.read()
