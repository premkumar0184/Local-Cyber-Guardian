import os
import time
import socket
import subprocess

def main():
    print("Simulating a suspicious process...")
    
    # Create a dummy script in /tmp
    script_path = "/tmp/unknown_app_sim"
    with open(script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("echo 'Running suspicious simulation...'\n")
        # Run a simple python http server to open a listener
        f.write("python -m http.server 4444 &\n")
        f.write("sleep 5\n")
        # Make an outbound connection
        f.write("curl -s http://example.com > /dev/null\n")
        f.write("sleep 10\n")
        
    os.chmod(script_path, 0o755)
    
    print(f"Executing {script_path}...")
    subprocess.Popen([script_path])
    
    print("Simulation started. Check the Security Guardian dashboard.")
    print("The incident should appear within a few seconds.")

if __name__ == "__main__":
    main()
