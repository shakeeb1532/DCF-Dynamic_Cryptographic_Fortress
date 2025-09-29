import subprocess
import os
import signal
import time

def main():
    subprocess.run(["python", "fortress_mvp.py", "keygen", "--out-dir", "keys"])
    with open("interrupt.txt", "w") as f:
        f.write("interrupt test" * 1000000)
    # Start encryption and interrupt
    proc = subprocess.Popen([
        "python", "fortress_mvp.py", "encrypt",
        "--in", "interrupt.txt", "--out", "interrupt.fortress",
        "--dest-ip", "216.3.128.12", "--recipient-pub", "keys/public.pem"
    ])
    time.sleep(1)
    proc.send_signal(signal.SIGINT)
    proc.wait()
    # Check for leaks
    exists = os.path.exists("interrupt.fortress")
    with open("interrupt_resume_result.txt", "w") as f:
        f.write(f"Interrupt/resume robustness test: partial file exists: {exists}\n")
    print(f"Interrupt/resume robustness test complete. Partial file exists: {exists}")

if __name__ == "__main__":
    main()
