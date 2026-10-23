"""Intentional failure fixture: prints diagnostics and exits with code 23."""
import sys
print("fixture: simulated application failure", file=sys.stderr)
print("fixture: expected_exit_code=23", file=sys.stderr)
sys.exit(23)
