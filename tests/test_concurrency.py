import subprocess
import threading
import os

def encrypt_decrypt(idx):
    import time
    import hashlib
    fname = f"concurrent_{idx}.txt"
    with open(fname, "w") as f:
        f.write(f"file {idx}")
    orig_size = os.path.getsize(fname)
    keygen = subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", f"keys_{idx}"], capture_output=True, text=True)
    t0 = time.time()
    encrypt = subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", fname, "--out", f"{fname}.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", f"keys_{idx}/public.pem"
    ], capture_output=True, text=True)
    t1 = time.time()
    enc_time = t1 - t0
    enc_size = os.path.getsize(f"{fname}.fortress")
    t2 = time.time()
    decrypt = subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", f"{fname}.fortress", "--out", f"{fname}.out",
        "--recipient-priv", f"keys_{idx}/private.pem"
    ], capture_output=True, text=True)
    t3 = time.time()
    dec_time = t3 - t2
    dec_size = os.path.getsize(f"{fname}.out") if os.path.exists(f"{fname}.out") else 0
    def sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    orig_hash = sha256(fname)
    enc_hash = sha256(f"{fname}.fortress")
    dec_hash = sha256(f"{fname}.out") if os.path.exists(f"{fname}.out") else ""
    match = orig_hash == dec_hash
    with open(f"concurrency_result_{idx}.txt", "w") as f:
        f.write(f"Thread: {idx}\nKeygen output:\n{keygen.stdout}\nKeygen errors:\n{keygen.stderr}\n")
        f.write(f"Encrypt output:\n{encrypt.stdout}\nEncrypt errors:\n{encrypt.stderr}\n")
        f.write(f"Decrypt output:\n{decrypt.stdout}\nDecrypt errors:\n{decrypt.stderr}\n")
        f.write(f"Original file size: {orig_size} bytes\nEncrypted file size: {enc_size} bytes\nDecrypted file size: {dec_size} bytes\n")
        f.write(f"Original SHA256: {orig_hash}\nEncrypted SHA256: {enc_hash}\nDecrypted SHA256: {dec_hash}\nMatch: {match}\n")
        f.write(f"Encryption time: {enc_time:.4f} seconds\nDecryption time: {dec_time:.4f} seconds\n")
    return match

def main():
    threads = []
    results = [None] * 5
    def worker(i):
        results[i] = encrypt_decrypt(i)
    for i in range(5):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    with open("concurrency_result.txt", "w") as f:
        f.write(f"Concurrency test results: {results}\nAll passed: {all(results)}\nSee concurrency_result_<idx>.txt for per-thread details.\n")
    print(f"Concurrency test complete. All passed: {all(results)}")

if __name__ == "__main__":
    main()
