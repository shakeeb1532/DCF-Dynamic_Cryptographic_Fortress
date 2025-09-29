# Copyright 2025 shakeeb1532
import subprocess
import time
import os
import psutil
import hashlib
import pandas as pd
import matplotlib.pyplot as plt

# Create a large random file (default: 100MB)
def generate_sample_file(filename="benchmark_input.txt", size_mb=100):
    if not os.path.exists(filename) or os.path.getsize(filename) != size_mb * 1024 * 1024:
        with open(filename, "wb") as f:
            f.write(os.urandom(size_mb * 1024 * 1024))
        print(f"✅ Created test file: {filename} ({size_mb} MB)")
    else:
        print(f"⚠️ File already exists: {filename}")

# Run shell command and time it
def run_command(cmd):
    print(f"▶️ {cmd}")
    start = time.time()
    process = psutil.Process()
    mem_before = process.memory_info().rss
    cpu_before = process.cpu_times().user + process.cpu_times().system
    peak_mem = mem_before
    result = subprocess.run(cmd, shell=True, check=True)
    mem_after = process.memory_info().rss
    cpu_after = process.cpu_times().user + process.cpu_times().system
    elapsed = time.time() - start
    mem_usage = (mem_after - mem_before) / (1024 * 1024)  # MB
    peak_mem = max(peak_mem, mem_after) / (1024 * 1024)
    cpu_time = cpu_after - cpu_before
    return elapsed, mem_usage, peak_mem, cpu_time

# Benchmark encryption and decryption

def sha256sum(filename):
    h = hashlib.sha256()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def benchmark(encryption_args="", label="Default", size_mb=100, results=None):
    print(f"\n🚀 Benchmarking: {label} | Size: {size_mb}MB")

    # Generate keys
    subprocess.run("python fortress_mvp.py keygen --out-dir keys", shell=True, check=True)

    # Encrypt
    encrypt_cmd = (
        f"python fortress_mvp.py encrypt "
        f"--in benchmark_input.txt --out encrypted.fortress "
        f"--dest-ip 1.1.1.1 --recipient-pub keys/public.pem "
        f"--file-type auto {encryption_args}"
    )
    encrypt_time, encrypt_mem, encrypt_peak, encrypt_cpu = run_command(encrypt_cmd)
    print(f"🔐 Encrypt time: {encrypt_time:.2f}s | Mem: {encrypt_mem:.2f}MB | Peak: {encrypt_peak:.2f}MB | CPU: {encrypt_cpu:.2f}s")

    # Decrypt
    decrypt_cmd = (
        "python fortress_mvp.py decrypt "
        "--in encrypted.fortress --out decrypted_output.txt "
        "--recipient-priv keys/private.pem"
    )
    decrypt_time, decrypt_mem, decrypt_peak, decrypt_cpu = run_command(decrypt_cmd)
    print(f"🔓 Decrypt time: {decrypt_time:.2f}s | Mem: {decrypt_mem:.2f}MB | Peak: {decrypt_peak:.2f}MB | CPU: {decrypt_cpu:.2f}s")

    # Report sizes
    original_size = os.path.getsize("benchmark_input.txt")
    encrypted_size = os.path.getsize("encrypted.fortress")
    decrypted_size = os.path.getsize("decrypted_output.txt")

    throughput_enc = original_size / encrypt_time / 1e6 if encrypt_time > 0 else 0
    throughput_dec = decrypted_size / decrypt_time / 1e6 if decrypt_time > 0 else 0

    # Security check: verify decrypted file matches input
    with open("benchmark_input.txt", "rb") as f1, open("decrypted_output.txt", "rb") as f2:
        security_ok = f1.read() == f2.read()
    security_status = "PASS" if security_ok else "FAIL"

    # Hashes
    orig_hash = sha256sum("benchmark_input.txt")
    dec_hash = sha256sum("decrypted_output.txt")

    # Write results to txt file
    with open("benchmark_results.txt", "a") as out:
        out.write(f"{size_mb}MB | {label} | {encrypt_time:.2f}s | {decrypt_time:.2f}s | {encrypt_mem:.2f}MB | {decrypt_mem:.2f}MB | {encrypt_peak:.2f}MB | {decrypt_peak:.2f}MB | {encrypt_cpu:.2f}s | {decrypt_cpu:.2f}s | {throughput_enc:.2f}MB/s | {throughput_dec:.2f}MB/s | {original_size/1e6:.2f}MB | {encrypted_size/1e6:.2f}MB | {decrypted_size/1e6:.2f}MB | {security_status} | {orig_hash} | {dec_hash}\n")
    # Store results for visualization
    if results is not None:
        results.append({
            "SizeMB": size_mb,
            "Method": label,
            "EncryptTime": encrypt_time,
            "DecryptTime": decrypt_time,
            "EncryptMem": encrypt_mem,
            "DecryptMem": decrypt_mem,
            "EncryptPeak": encrypt_peak,
            "DecryptPeak": decrypt_peak,
            "EncryptCPU": encrypt_cpu,
            "DecryptCPU": decrypt_cpu,
            "ThroughputEnc": throughput_enc,
            "ThroughputDec": throughput_dec,
            "OrigSize": original_size/1e6,
            "EncSize": encrypted_size/1e6,
            "DecSize": decrypted_size/1e6,
            "Security": security_status,
            "OrigHash": orig_hash,
            "DecHash": dec_hash
        })


if __name__ == "__main__":
    sizes_mb = [10, 30, 50, 60, 100, 300, 500, 700, 1000]
    methods = [
        {"args": "", "label": "Default (zlib or fallback)"},
        {"args": "--file-type data", "label": "With LZ4 Compression"},
        {"args": "--device-class laptop --cpu-cores 4 --bandwidth-mbps 50", "label": "Device-Aware Policy"}
    ]
    results = []
    try:
        for size in sizes_mb:
            generate_sample_file(size_mb=size)
            for method in methods:
                benchmark(method["args"], method["label"], size_mb=size, results=results)
        # Save CSV
        df = pd.DataFrame(results)
        df.to_csv("benchmark_results.csv", index=False)
        # Visualization: plot speed and memory
        plt.figure(figsize=(12,6))
        for method in df["Method"].unique():
            subset = df[df["Method"]==method]
            plt.plot(subset["SizeMB"], subset["EncryptTime"], label=f"Encrypt: {method}")
            plt.plot(subset["SizeMB"], subset["DecryptTime"], linestyle='--', label=f"Decrypt: {method}")
        plt.xlabel("File Size (MB)")
        plt.ylabel("Time (s)")
        plt.title("Encryption/Decryption Time by File Size and Method")
        plt.legend()
        plt.grid(True)
        plt.savefig("benchmark_time.png")

        plt.figure(figsize=(12,6))
        for method in df["Method"].unique():
            subset = df[df["Method"]==method]
            plt.plot(subset["SizeMB"], subset["EncryptPeak"], label=f"Encrypt Peak Mem: {method}")
            plt.plot(subset["SizeMB"], subset["DecryptPeak"], linestyle='--', label=f"Decrypt Peak Mem: {method}")
        plt.xlabel("File Size (MB)")
        plt.ylabel("Peak Memory (MB)")
        plt.title("Peak Memory Usage by File Size and Method")
        plt.legend()
        plt.grid(True)
        plt.savefig("benchmark_memory.png")

        plt.figure(figsize=(12,6))
        for method in df["Method"].unique():
            subset = df[df["Method"]==method]
            plt.plot(subset["SizeMB"], subset["ThroughputEnc"], label=f"Encrypt Throughput: {method}")
            plt.plot(subset["SizeMB"], subset["ThroughputDec"], linestyle='--', label=f"Decrypt Throughput: {method}")
        plt.xlabel("File Size (MB)")
        plt.ylabel("Throughput (MB/s)")
        plt.title("Throughput by File Size and Method")
        plt.legend()
        plt.grid(True)
        plt.savefig("benchmark_throughput.png")

    except subprocess.CalledProcessError as e:
        print(f"💥 Command failed: {e}")
        exit(1)
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        exit(1)


