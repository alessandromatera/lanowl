"""The model's settings: run with `python -m tests.test_model_config`.

  1. config.yaml's `model:` section reaches the agent, the dashboard and the report; without
     one, the defaults; LANOWL_MODEL_URL wins over the file;
  2. `lanowl --check` flags what it would not read: a leftover `ollama:` section, the old
     `model.model` key, a provider that is not built yet — each a silent fall back to the
     defaults otherwise.
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from lanowl.agent import LlmAgent
from lanowl.model import DEFAULT_MODEL, load_config, model_name, model_report

_fails = []


def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        _fails.append(msg)


def _load(text: str) -> dict:
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "config.yaml")
        with open(p, "w") as f:
            f.write(text)
        return load_config(p)


def test_section():
    print("\n-- the `model:` section --")
    os.environ.pop("LANOWL_MODEL_URL", None)
    cfg = _load("model:\n  url: http://192.168.88.6:11434/\n  name: llama3.3\n  num_ctx: 8192\n"
                "  persona: ''\n")
    ag = LlmAgent(cfg, None)
    check(ag.url == "http://192.168.88.6:11434" and ag.model == "llama3.3",
          f"the agent asks the configured server and model (got {ag.url}, {ag.model})")
    check(ag.options["num_ctx"] == 8192 and ag.voice == "", "its other settings come along")
    check(model_name(cfg) == "llama3.3", "the dashboard and the report name it")

    bare = LlmAgent(_load("network: {}\n"), None)
    check(bare.url == "http://127.0.0.1:11434" and bare.model == DEFAULT_MODEL
          and model_name({}) == DEFAULT_MODEL, "no section: the defaults, named the same everywhere")

    os.environ["LANOWL_MODEL_URL"] = "http://198.51.100.7:11434"
    try:
        check(_load("model:\n  url: http://127.0.0.1:11434\n")["model"]["url"] == "http://198.51.100.7:11434",
              "LANOWL_MODEL_URL wins over the file")
        check(_load("model:\n")["model"] == {"url": "http://198.51.100.7:11434"},
              "...also over an empty section")
        check(_load("model: llama3\n")["model"] == "llama3",
              "...and leaves a section that is not one for --check to report")
    finally:
        os.environ.pop("LANOWL_MODEL_URL", None)


def test_check():
    print("\n-- lanowl --check --")
    text, bad = model_report({"model": {"provider": "ollama", "url": "http://192.168.88.6:11434",
                                        "name": "llama3.3"}})
    check(bad == 0 and "Model: ollama · llama3.3 at http://192.168.88.6:11434" in text,
          "a good section: which model, where, nothing wrong")

    text, bad = model_report({"ollama": {"url": "http://192.168.88.6:11434", "model": "llama3.3"}})
    check(bad == 1 and "`ollama:` is not read any more" in text and DEFAULT_MODEL in text,
          "a leftover `ollama:` is ✗, and the line shows the defaults it would get")

    text, bad = model_report({"model": {"model": "llama3.3"}})
    check(bad == 1 and "is `model.name` now" in text, "the old `model.model` key is ✗")

    text, bad = model_report({"model": {"provider": "anthropic"}})
    check(bad == 1 and "only ollama for now" in text, "a provider not built yet is ✗")

    text, bad = model_report({"model": "llama3"})
    check(bad == 1 and "should be a section" in text, "a value instead of a section is ✗")

    text, bad = model_report({})
    check(bad == 0 and f"Model: ollama · {DEFAULT_MODEL} at http://127.0.0.1:11434" in text,
          "no section at all is fine: the defaults")


if __name__ == "__main__":
    test_section()
    test_check()
    print(f"\n{len(_fails)} FAILED" if _fails else "\nall passed")
    sys.exit(1 if _fails else 0)
