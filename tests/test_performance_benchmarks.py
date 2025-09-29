import subprocess
import os
import time

def main():
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    with open("perf.txt", "w") as f:
        f.write("performance test" * 100000)
    start = time.time()
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "perf.txt", "--out", "perf.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    enc_time = time.time() - start
    start = time.time()
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "perf.fortress", "--out", "perf.out",
        "--recipient-priv", "keys/private.pem"
    ])
    dec_time = time.time() - start
    with open("performance_benchmarks_result.txt", "w") as f:
        f.write(f"Encrypt time: {enc_time:.2f}s\nDecrypt time: {dec_time:.2f}s\n")
    print(f"Performance benchmarks test complete. Encrypt: {enc_time:.2f}s, Decrypt: {dec_time:.2f}s")

if __name__ == "__main__":
    main()
