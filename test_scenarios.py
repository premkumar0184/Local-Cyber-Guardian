import os
import sys
import time
import subprocess

def create_script(path: str, content: str):
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o755)

def b1_normal_app():
    print("[Benign 1] Launching normal application (sleep)")
    subprocess.Popen(["sleep", "2"])

def b2_browser_network():
    print("[Benign 2] Simulating browser network activity")
    subprocess.Popen(["curl", "-s", "http://example.com"], stdout=subprocess.DEVNULL)

def b3_local_dev_server():
    print("[Benign 3] Starting local development server")
    p = subprocess.Popen(["python", "-m", "http.server", "8080"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    p.terminate()

def b4_harmless_bashrc():
    print("[Benign 4] Modifying .bashrc harmlessly")
    bashrc = os.path.expanduser("~/.bashrc")
    if os.path.exists(bashrc):
        with open(bashrc, "a") as f:
            f.write("\n# Harmless comment\n")

def s1_executable_in_tmp():
    print("[Suspicious 1] Creating executable in /tmp")
    create_script("/tmp/suspicious_script.sh", "#!/bin/bash\necho 'hello'")

def s2_persistence_and_process():
    print("[Suspicious 2] Persistence created + process launched")
    script = "/tmp/suspicious_pers.sh"
    create_script(script, "#!/bin/bash\nsleep 5\n")
    service = os.path.expanduser("~/.config/systemd/user/suspicious.service")
    os.makedirs(os.path.dirname(service), exist_ok=True)
    with open(service, "w") as f:
        f.write(f"[Service]\nExecStart={script}\n")
    time.sleep(1)
    subprocess.Popen([script])

def s3_suspicious_process_listener():
    print("[Suspicious 3] Suspicious process + listener")
    script = "/tmp/suspicious_list.sh"
    create_script(script, "#!/bin/bash\npython -m http.server 4446 &\n")
    subprocess.Popen([script])

def s4_persistence_listener_outbound():
    print("[Suspicious 4] Persistence + listener + outbound connection")
    script = "/tmp/suspicious_plo.sh"
    create_script(script, "#!/bin/bash\npython -m http.server 4447 &\nsleep 2\ncurl -s http://example.com > /dev/null\n")
    service = os.path.expanduser("~/.config/systemd/user/suspicious2.service")
    with open(service, "w") as f:
        f.write(f"[Service]\nExecStart={script}\n")
    time.sleep(1)
    subprocess.Popen([script])

def s5_complete_chain():
    print("[Suspicious 5] Complete multi-stage chain (The Full Kill-Chain)")
    script = "/tmp/unknown_app_sim"
    create_script(script, "#!/bin/bash\npython -m http.server 4448 &\nsleep 2\ncurl -s http://example.com > /dev/null\nsleep 10\n")
    service = os.path.expanduser("~/.config/systemd/user/unknown_app.service")
    with open(service, "w") as f:
        f.write(f"[Service]\nExecStart={script}\n")
    time.sleep(1)
    subprocess.Popen([script])

if __name__ == "__main__":
    print("Select a scenario to run:")
    print("BENIGN:")
    print("  1. Normal application launch")
    print("  2. Browser network activity")
    print("  3. Local development server")
    print("  4. Harmless .bashrc modification")
    print("SUSPICIOUS:")
    print("  5. Executable created in /tmp")
    print("  6. Persistence created + process launched")
    print("  7. Suspicious process + listener")
    print("  8. Persistence + listener + outbound connection")
    print("  9. Complete multi-stage simulated chain")
    
    if len(sys.argv) > 1:
        choice = sys.argv[1]
    else:
        choice = input("\nEnter scenario number (1-9): ")
        
    if choice == '1': b1_normal_app()
    elif choice == '2': b2_browser_network()
    elif choice == '3': b3_local_dev_server()
    elif choice == '4': b4_harmless_bashrc()
    elif choice == '5': s1_executable_in_tmp()
    elif choice == '6': s2_persistence_and_process()
    elif choice == '7': s3_suspicious_process_listener()
    elif choice == '8': s4_persistence_listener_outbound()
    elif choice == '9': s5_complete_chain()
    else:
        print("Invalid choice")
