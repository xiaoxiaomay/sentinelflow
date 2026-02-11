import subprocess
import sys
import os
import time
from pathlib import Path

# Define the color output to facilitate the observation of prgoress.
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def run_step(name, command):
    print(f"{Colors.BLUE}>>> Executeion Phase: {name}...{Colors.ENDC}")
    print(f"Commands: {' '.join(command)}")
    start_time = time.time()
    
    try:
        # Usring subprocess to execute the command and print output in real-time
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(f"  {line.strip()}")
        
        process.wait()
        
        if process.returncode == 0:
            elapsed = round(time.time() - start_time, 2)
            print(f"{Colors.GREEN}✔ {name} completed ({elapsed}s){Colors.ENDC}\n")
            return True
        else:
            print(f"{Colors.FAIL}✘ {name} failed (exit code: {process.returncode}){Colors.ENDC}\n")
            return False
    except Exception as e:
        print(f"{Colors.FAIL}✘ running error: {str(e)}{Colors.ENDC}\n")
        return False

def main():
    print(f"{Colors.HEADER}=== SentinelFlow Automated Engine Start ==={Colors.ENDC}\n")

    # Phase 1: Data Preparation
    steps = [
        ("Generating Secrets...", [sys.executable, "scripts/generate_secrets.py", "--mode", "overwrite"]),
        ("Cleaning Processing Data...", [sys.executable, "scripts/prepare_public_corpus.py"]),
    ]

    # Phase 2: Index Building for RAG
    steps += [
        ("Building Public Knowledge Index...", [sys.executable, "scripts/build_faiss_index.py"]),
        ("BUilding Private Intercept Index...", [sys.executable, "scripts/build_secret_faiss_index.py"]),
    ]

    # Phase 3: Security Calibration (DFP)
    steps += [
        ("Calibrating DFP Algorithm...", [sys.executable, "scripts/calibrate_dfp.py"]),
    ]

    # Execute sequentially
    for name, cmd in steps:
        success = run_step(name, cmd)
        if not success:
            print(f"{Colors.FAIL} Pipeline Interrupted! Please fix the errors above. {Colors.ENDC}")
            sys.exit(1)

    print(f"{Colors.HEADER} All backend logic construction completed！{Colors.ENDC}")
    print(f"{Colors.YELLOW} Next, you can launch the interaction interface：{Colors.ENDC}")
    print(f" streamlit run web_chat_app.py\n")

if __name__ == "__main__":
    main()