#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "BlackBoxJail's enforcement backend requires Linux. You can edit code elsewhere, but run it on Linux." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is missing. Install it with your distribution's package manager." >&2
  exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)'; then
  echo "Python 3.10+ is required." >&2
  exit 1
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "Bubblewrap is required; attempting to install it on Debian/Ubuntu..."
  if command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y bubblewrap
  elif [[ "$(id -u)" == "0" ]] && command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y bubblewrap
  else
    echo "Please install Bubblewrap manually. Ubuntu/Debian: sudo apt install python3 bubblewrap" >&2
    exit 1
  fi
fi

chmod +x "$ROOT/bbj"
cd "$ROOT"
echo "Running unit and pure-Python tests..."
python3 -m unittest discover -s "$ROOT/tests" -v

echo
echo "Checking the actual Linux sandbox..."
"$ROOT/bbj" doctor --self-test

echo
echo "Setup complete. For a bounded behavior demo, run: ./bbj benchmark"
