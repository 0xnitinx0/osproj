from pathlib import Path

Path("blackboxjail-example.txt").write_text(
    "This file was created by a process running inside BlackBoxJail.\n",
    encoding="utf-8",
)
print("Created blackboxjail-example.txt in the selected workspace")
