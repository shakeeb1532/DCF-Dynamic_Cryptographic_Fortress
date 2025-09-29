import subprocess
import os

def main():
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    # Create a large file (100MB for test)
    with open("largefile.txt", "wb") as f:
        f.write(os.urandom(100 * 1024 * 1024))
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "largefile.txt", "--out", "largefile.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "largefile.fortress", "--out", "largefile.out",
        "--recipient-priv", "keys/private.pem"
    ])
    orig_size = os.path.getsize("largefile.txt")
    dec_size = os.path.getsize("largefile.out")
    with open("large_file_streaming_result.txt", "w") as f:
        f.write(f"Original size: {orig_size}\nDecrypted size: {dec_size}\nMatch: {orig_size == dec_size}\n")
    print(f"Large-file streaming test complete. Match: {orig_size == dec_size}")

if __name__ == "__main__":
    main()
