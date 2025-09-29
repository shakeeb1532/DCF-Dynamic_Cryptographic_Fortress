# Copyright 2025 shakeeb1532
import subprocess
import os

def main():
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    with open("compress.txt", "w") as f:
        f.write("compress test" * 1000)
    # zlib compression: use low risk dest-ip
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "compress.txt", "--out", "compress_zlib.fortress",
        "--dest-ip", "1.2.3.4", "--file-type", "data", "--recipient-pub", "keys/public.pem"
    ])
    # lz4 compression: use high risk dest-ip
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "compress.txt", "--out", "compress_lz4.fortress",
        "--dest-ip", "216.3.128.12", "--file-type", "video", "--recipient-pub", "keys/public.pem"
    ])
    orig_size = os.path.getsize("compress.txt")
    enc_zlib_size = os.path.getsize("compress_zlib.fortress")
    enc_lz4_size = os.path.getsize("compress_lz4.fortress")
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "compress_zlib.fortress", "--out", "compress_zlib.out",
        "--recipient-priv", "keys/private.pem"
    ])
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "compress_lz4.fortress", "--out", "compress_lz4.out",
        "--recipient-priv", "keys/private.pem"
    ])
    dec_zlib_size = os.path.getsize("compress_zlib.out")
    dec_lz4_size = os.path.getsize("compress_lz4.out")
    with open("compression_behavior_result.txt", "w") as f:
        f.write(f"Original size: {orig_size}\nZlib encrypted size: {enc_zlib_size}\nLZ4 encrypted size: {enc_lz4_size}\nZlib decrypted size: {dec_zlib_size}\nLZ4 decrypted size: {dec_lz4_size}\nZlib match: {orig_size == dec_zlib_size}\nLZ4 match: {orig_size == dec_lz4_size}\n")
    print(f"Compression behavior test complete. Zlib match: {orig_size == dec_zlib_size}, LZ4 match: {orig_size == dec_lz4_size}")

if __name__ == "__main__":
    main()
