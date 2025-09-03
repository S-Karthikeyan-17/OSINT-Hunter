import sys
import os

# Start from the outer spiderfoot folder
OUTER_PATH = r"C:\Users\sukar\Desktop\Red Team Recon Automation Toolkit\backend\spiderfoot"

# Search for the inner spiderfoot folder containing __init__.py
inner_path = None
for root, dirs, files in os.walk(OUTER_PATH):
    if "__init__.py" in files and any(f.startswith("sfp_") for f in os.listdir(root)):
        inner_path = root
        break

if not inner_path:
    print(f"❌ Could not find the inner SpiderFoot folder inside {OUTER_PATH}")
    sys.exit(1)

sys.path.insert(0, inner_path)

try:
    import sfp_dns
    import sfp_google
    print("✅ SpiderFoot modules are accessible!")
except ImportError as e:
    print("❌ SpiderFoot modules not accessible")
    print("Error:", e)
