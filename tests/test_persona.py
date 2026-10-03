"""The persona and the network description: run with `python -m tests.test_persona`.

  1. the owl is the default voice; "" (or a name nobody defined) means none;
  2. the owner's `network.description` reaches every system prompt, as context, before the
     memory's notes, and nothing about a particular network is written into the prompts.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl import prompts as P
from lanowl.agent import LlmAgent

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def test_voice():
    print("\n-- the voice --")
    check(P.DEFAULT_PERSONA == "owl" and "the owl that keeps watch" in P.persona_block(),
          "the owl, by default")
    check(P.persona_block("") == "" and P.persona_block("nobody") == "", "\"\" or an unknown name: no voice")
    owl = P.persona_block("owl")
    check("Never change, soften or inflate a severity" in owl and "Do not add emoji" in owl,
          "the voice never touches a severity, and leaves the 🦉 to the code")


def test_network():
    print("\n-- the network, in the owner's words --")
    check(P.network_block({}) == "" and P.network_block({"network": {"description": "  "}}) == "",
          "no description: nothing added")
    nb = P.network_block({"network": {"description": "A LAN behind one router.\nTwo sites."}})
    check(nb.startswith("THE NETWORK, in its owner's words") and "Two sites." in nb,
          "a description is passed on as it is written")
    a = LlmAgent({"ollama": {"persona": ""}, "network": {"description": "A LAN behind one router."}}, None)
    s = a._with_memory("PROMPT")
    check(s == "PROMPT\n\n" + P.network_block({"network": {"description": "A LAN behind one router."}}),
          "every system prompt carries it, right after the prompt itself")
    b = LlmAgent({}, None)._with_memory("PROMPT")
    check(b.startswith("PROMPT\n\n\nVOICE — you are the owl") and "THE NETWORK" not in b,
          "no config: the owl's voice and no description")
    flat = " ".join(P.SYSTEM_PROMPT.split()) + " ".join(P.QA_SYSTEM_CHAT.split())
    check(not any(w in flat.lower() for w in ("fiber", "antenna", "vps at", "the network lan", "subnet 192")),
          "the prompts themselves describe no particular network")


def test_the_owls_mark():
    print("\n-- 🦉 marks the model's words, never the monitor's --")
    import time as _t
    from lanowl import weekly
    from lanowl.report import format_digest
    rep = {"overall_health": "ok", "counts": {"up": 3, "total": 3, "down": 0}, "wan_ok": True,
           "issues": [], "devices": [], "ts": _t.time()}
    by_model = format_digest({**rep, "summary": "Quiet night.", "summary_by_model": True})
    by_monitor = format_digest({**rep, "summary": "All 3 devices are up."})
    check("🦉 Quiet night." in by_model, "the model's summary carries the owl")
    check("🦉" not in by_monitor, "the monitor's own summary does not")
    check("🦉 A quiet week." in weekly.format_weekly({}, "A quiet week.")
          and "🦉" not in weekly.format_weekly({}, None), "the weekly note: the owl only on the model's words")


if __name__ == "__main__":
    test_voice()
    test_network()
    test_the_owls_mark()
    print(f"\n{len(_fails)} FAILED" if _fails else "\nall passed")
    sys.exit(1 if _fails else 0)
