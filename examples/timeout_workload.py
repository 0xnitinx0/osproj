"""Intentional timeout fixture: loop forever until BlackBoxJail stops it."""
import time
print("fixture: starting deliberate timeout", flush=True)
while True:
    time.sleep(0.05)
