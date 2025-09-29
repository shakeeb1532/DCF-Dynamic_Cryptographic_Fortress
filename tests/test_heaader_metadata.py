import subprocess
import os

def main():
    import time
    import hashlib
    keygen = subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"], capture_output=True, text=True)
    with open("header.txt", "w") as f:
        f.write("header test")
    orig_size = os.path.getsize("header.txt")
    t0 = time.time()
    encrypt = subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "header.txt", "--out", "header.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ], capture_output=True, text=True)
    t1 = time.time()
    enc_time = t1 - t0
    enc_size = os.path.getsize("header.fortress")
    # Truncate header
    with open("header.fortress", "r+b") as f:
        f.truncate(10)
    t2 = time.time()
    decrypt = subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "header.fortress", "--out", "header.out",
        "--recipient-priv", "keys/private.pem"
    ], capture_output=True, text=True)
    t3 = time.time()
    dec_time = t3 - t2
    dec_size = os.path.getsize("header.out") if os.path.exists("header.out") else 0
    def sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    orig_hash = sha256("header.txt")
    enc_hash = sha256("header.fortress")
    dec_hash = sha256("header.out") if os.path.exists("header.out") else ""
    success = decrypt.returncode != 0
    with open("header_metadata_result.txt", "w") as f:
        f.write(f"Keygen output:\n{keygen.stdout}\nKeygen errors:\n{keygen.stderr}\n")
        f.write(f"Encrypt output:\n{encrypt.stdout}\nEncrypt errors:\n{encrypt.stderr}\n")
        f.write(f"Decrypt output:\n{decrypt.stdout}\nDecrypt errors:\n{decrypt.stderr}\n")
        f.write(f"Original file size: {orig_size} bytes\nTruncated encrypted file size: {enc_size} bytes\nDecrypted file size: {dec_size} bytes\n")
        f.write(f"Original SHA256: {orig_hash}\nTruncated encrypted SHA256: {enc_hash}\nDecrypted SHA256: {dec_hash}\nMatch: {orig_hash == dec_hash}\n")
        f.write(f"Encryption time: {enc_time:.4f} seconds\nDecryption time: {dec_time:.4f} seconds\n")
        f.write(f"Header/metadata validation test result: {success}\nDecrypt exit code: {decrypt.returncode}\n")
    print(f"Header/metadata validation test complete. Success: {success}")

if __name__ == "__main__":
    main()
