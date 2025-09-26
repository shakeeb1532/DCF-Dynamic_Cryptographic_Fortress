import subprocess
import time
import os

# Create a large random file (default: 100MB)
def generate_sample_file(filename="benchmark_input.txt", size_mb=100):
    if not os.path.exists(filename):
        with open(filename, "wb") as f:
            f.write(os.urandom(size_mb * 1024 * 1024))
        print(f"✅ Created test file: {filename} ({size_mb} MB)")
    else:
        print(f"⚠️ File already exists: {filename}")

# Run shell command and time it
def run_command(cmd):
    print(f"▶️ {cmd}")
    start = time.time()
    subprocess.run(cmd, shell=True, check=True)
    return time.time() - start

# Benchmark encryption and decryption
def benchmark(encryption_args="", label="Default"):
    print(f"\n🚀 Benchmarking: {label}")

    # Generate keys
    subprocess.run("python fortress_mvp.py keygen --out-dir keys", shell=True, check=True)

    # Encrypt
    encrypt_cmd = (
        f"python fortress_mvp.py encrypt "
        f"--in benchmark_input.txt --out encrypted.fortress "
        f"--dest-ip 1.1.1.1 --recipient-pub keys/public.pem "
        f"--file-type auto {encryption_args}"
    )
    encrypt_time = run_command(encrypt_cmd)
    print(f"🔐 Encrypt time: {encrypt_time:.2f}s")

    # Decrypt
    decrypt_cmd = (
        "python fortress_mvp.py decrypt "
        "--in encrypted.fortress --out decrypted_output.txt "
        "--recipient-priv keys/private.pem"
    )
    decrypt_time = run_command(decrypt_cmd)
    print(f"🔓 Decrypt time: {decrypt_time:.2f}s")

    # Report sizes
    original_size = os.path.getsize("benchmark_input.txt")
    encrypted_size = os.path.getsize("encrypted.fortress")
    decrypted_size = os.path.getsize("decrypted_output.txt")

    print(f"📦 Original size:   {original_size / 1e6:.2f} MB")
    print(f"🔐 Encrypted size: {encrypted_size / 1e6:.2f} MB")
    print(f"🗃️ Decrypted size: {decrypted_size / 1e6:.2f} MB")


if __name__ == "__main__":
    try:
        generate_sample_file()
        benchmark(label="Default (zlib or fallback)")
        benchmark("--use-lz4", label="With LZ4 Compression")
        benchmark("--device-class laptop --cpu-cores 4 --bandwidth-mbps 50", label="Device-Aware Policy")
    except subprocess.CalledProcessError as e:
        print(f"💥 Command failed: {e}")
        exit(1)
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        exit(1)

