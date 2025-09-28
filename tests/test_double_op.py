import subprocess
import os

def main():
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    with open("double.txt", "w") as f:
        f.write("double ops test")
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "double.txt", "--out", "double.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    # Double encrypt
    result = subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "double.fortress", "--out", "double2.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ], capture_output=True)
    double_encrypt_error = result.returncode != 0
    # Double decrypt
    subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "double.fortress", "--out", "double.out",
        "--recipient-priv", "keys/private.pem"
    ])
    result2 = subprocess.run([
        "python", "fortress_mvp.py", "decrypt",
        "--in", "double.out", "--out", "double2.out",
        "--recipient-priv", "keys/private.pem"
    ], capture_output=True)
    double_decrypt_error = result2.returncode != 0
    with open("double_ops_result.txt", "w") as f:
        f.write(f"Double encrypt error: {double_encrypt_error}\nDouble decrypt error: {double_decrypt_error}\n")
    print(f"Double-ops safety test complete. Encrypt error: {double_encrypt_error}, Decrypt error: {double_decrypt_error}")

if __name__ == "__main__":
    main()
