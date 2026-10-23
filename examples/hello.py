"""A tiny successful workload for the BlackBoxJail demo."""
import json
import os
import time

result = {
    "message": "hello from inside the BlackBoxJail workspace",
    "pid": os.getpid(),
    "python": os.sys.version.split()[0],
}
print(json.dumps(result, sort_keys=True))
time.sleep(0.25)
print("completed successfully")
