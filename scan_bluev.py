import subprocess
import re

print("🔍 Scan via bluetoothctl (10s)...\n")

# Lance le scan
proc = subprocess.run(
    ["bluetoothctl", "--timeout", "10", "scan", "on"],
    capture_output=True, text=True
)

output = proc.stdout + proc.stderr


pattern = re.compile(r"Device ([0-9A-F:]{17})\s+(.+)")
found = {}

for line in output.splitlines():
    match = pattern.search(line)
    if match:
        mac, name = match.groups()
        found[mac] = name.strip()

if not found:
    print("❌ Aucun appareil. Vérifie que le Bluetooth est activé :")
    print("   sudo systemctl start bluetooth")
else:
    print(f"✅ {len(found)} appareil(s) :\n")
    for mac, name in found.items():
        print(f"  {mac}  →  {name}")
