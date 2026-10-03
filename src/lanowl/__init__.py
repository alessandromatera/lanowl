"""lanowl: a watchful, read-only caretaker for home and small-office networks.

A deterministic sweep owns up/down detection and the immediate critical alerts, so it keeps
working when the model is slow, wrong or switched off. On top of it, a read-only, tool-calling
model (the owl) correlates, diagnoses and writes the human-readable report. Nothing here
changes a device by itself: a change runs only when the owner approves it.
"""

__version__ = "0.1.0.dev0"
