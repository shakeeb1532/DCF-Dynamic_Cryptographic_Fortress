import subprocess
import os

def main():
    # Bad args
    result = subprocess.run(["python", "fortress_mvp.py", "encrypt", "--badarg"], capture_output=True)
    bad_args_error = result.returncode != 0
    # Overwrite handling
    with open("cli.txt", "w") as f:
        f.write("cli ux test")
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "cli.txt", "--out", "cli.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    # Try to overwrite
    result2 = subprocess.run([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "cli.txt", "--out", "cli.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ], capture_output=True)
    overwrite_error = result2.returncode != 0
    with open("cli_ux_result.txt", "w") as f:
        f.write(f"Bad args error: {bad_args_error}\nOverwrite error: {overwrite_error}\n")
    print(f"CLI UX test complete. Bad args error: {bad_args_error}, Overwrite error: {overwrite_error}")

if __name__ == "__main__":
    main()
