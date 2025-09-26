import subprocess
import time
import os
import random

# Create a large sample file for benchmark (e.g., 100MB)
def generate_sample_file(filename="benchmark_input.txt", size_mb=100):
    with open(filename, "wb") as f:
        f.write(os.urandom(size_mb * 1024 * 1024))

def run_command(cmd):
    start = time.time()
    subprocess.run(cmd, shell=True, check=True)
    return time.time() - start

def benchmark(encryption_args="", label="default"):
    print(f"\n🚀 Benchmarking: {label}")

    # Keygen
    subprocess.run("python fortress_mvp.py keygen --out-dir keys", shell=True, check=True)

    # Encrypt
    encrypt_time = run_command(
        f"python fortress_mvp.py encrypt --in benchmark_input.txt --out encrypted.fortress "
        f"--dest-ip 1.1.1.1 --recipient-pub keys/public.pem {encryption_args}"
    )
    print(f"🔐 Encrypt time: {encrypt_time:.2f}s")

    # Decrypt
    decrypt_time = run_command(
        "python fortress_mvp.py decrypt --in encrypted.fortress --out decrypted_output.txt "
        "--recipient-priv keys/private.pem"
    )
    print(f"🔓 Decrypt time: {decrypt_time:.2f}s")

    # Compare size
    original_size = os.path.getsize("benchmark_input.txt")
    encrypted_size = os.path.getsize("encrypted.fortress")
    decrypted_size = os.path.getsize("decrypted_output.txt")

    print(f"📦 Original size:   {original_size / 1e6:.2f} MB")
    print(f"🔐 Encrypted size: {encrypted_size / 1e6:.2f} MB")
    print(f"🗃️ Decrypted size: {decrypted_size / 1e6:.2f} MB")

if __name__ == "__main__":
    generate_sample_file()
    benchmark(label="Default (zlib or fallback)")
    benchmark("--use-lz4", label="With LZ4 Compression")
    benchmark("--device-class laptop --cpu-cores 4 --bandwidth-mbps 50", label="Device-aware policy")
