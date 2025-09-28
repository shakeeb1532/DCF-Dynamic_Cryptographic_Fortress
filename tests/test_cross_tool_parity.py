import subprocess
import os

def main():
    with open("cross.txt", "w") as f:
        f.write("cross tool parity test")
    # fortress
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "cross.txt", "--out", "cross.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "cross.fortress", "--out", "cross.out",
        "--recipient-priv", "keys/private.pem"
    ])
    fortress_ok = os.path.exists("cross.out")
    # OpenSSL
    subprocess.run(["openssl", "enc", "-aes-256-cbc", "-in", "cross.txt", "-out", "cross.openssl", "-pass", "pass:testpass"])
    subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-in", "cross.openssl", "-out", "cross.openssl.out", "-pass", "pass:testpass"])
    openssl_ok = os.path.exists("cross.openssl.out")
    with open("cross_tool_parity_result.txt", "w") as f:
        f.write(f"Fortress OK: {fortress_ok}\nOpenSSL OK: {openssl_ok}\n")
    print(f"Cross-tool parity test complete. Fortress: {fortress_ok}, OpenSSL: {openssl_ok}")

if __name__ == "__main__":
    main()
