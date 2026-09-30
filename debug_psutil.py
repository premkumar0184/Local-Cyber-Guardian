import psutil
import subprocess
import time

script = "/tmp/test_psutil.sh"
with open(script, "w") as f:
    f.write("#!/bin/bash\nsleep 10\n")
import os
os.chmod(script, 0o755)

p = subprocess.Popen([script])
time.sleep(1)

proc = psutil.Process(p.pid)
print(f"name: {proc.name()}")
print(f"exe: {proc.exe()}")
print(f"cmdline: {proc.cmdline()}")
p.kill()
