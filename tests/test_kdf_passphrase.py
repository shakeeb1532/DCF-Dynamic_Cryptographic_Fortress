import subprocess
import os

def main():
    import time
    import hashlib
    keygen = subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"], capture_output=True, text=True)
    weak_pass = "123"
    orig_size = os.path.getsize("header.txt") if os.path.exists("header.txt") else 0
    t0 = time.time()
    encrypt = subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "header.txt", "--out", "weakpass.fortress",
        "--passphrase", weak_pass,
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ], capture_output=True, text=True)
    t1 = time.time()
    enc_time = t1 - t0
    enc_size = os.path.getsize("weakpass.fortress") if os.path.exists("weakpass.fortress") else 0
    def sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    orig_hash = sha256("header.txt") if os.path.exists("header.txt") else ""
    enc_hash = sha256("weakpass.fortress") if os.path.exists("weakpass.fortress") else ""
    success = encrypt.returncode != 0
    with open("kdf_passphrase_result.txt", "w") as f:
        f.write(f"Keygen output:\n{keygen.stdout}\nKeygen errors:\n{keygen.stderr}\n")
        f.write(f"Encrypt output:\n{encrypt.stdout}\nEncrypt errors:\n{encrypt.stderr}\n")
        f.write(f"Original file size: {orig_size} bytes\nEncrypted file size: {enc_size} bytes\n")
        f.write(f"Original SHA256: {orig_hash}\nEncrypted SHA256: {enc_hash}\n")
        f.write(f"Encryption time: {enc_time:.4f} seconds\n")
        f.write(f"KDF & passphrase policy test result: {success}\nEncrypt exit code: {encrypt.returncode}\n")
    print(f"KDF & passphrase policy test complete. Success: {success}")

if __name__ == "__main__":
    main()
