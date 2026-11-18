"""Consistency tests for the deliverable registry.

Two copies of the filename map exist (the importable one in
``src/types/deliverables.py`` and an inlined copy in ``scripts/save_deliverable.py``
so the CLI works on PATH without imports). These drift silently — this test
fails loudly if they diverge. It also checks the registry covers every type
the engine's prompts register.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.types.deliverables import DELIVERABLE_FILENAMES  # noqa: E402


def _load_save_deliverable():
    spec = importlib.util.spec_from_file_location(
        "save_deliverable", ROOT / "scripts" / "save_deliverable.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_cli_filename_map_matches_types_module():
    cli = _load_save_deliverable()
    assert cli.DELIVERABLE_FILENAMES == DELIVERABLE_FILENAMES, (
        "scripts/save_deliverable.py inlined map has drifted from "
        "src/types/deliverables.py"
    )


def test_prompt_deliverable_types_are_registered():
    """Every ``save-deliverable --type X`` in a prompt the engine uses is known."""
    import re

    types = set()
    for path in (ROOT / "prompts").rglob("*.txt"):
        if "greybox" in path.parts:
            continue
        types.update(re.findall(r"save-deliverable --type ([A-Z_]+)", path.read_text()))
    assert types, "expected prompts to register deliverables"
    assert types <= set(DELIVERABLE_FILENAMES), types - set(DELIVERABLE_FILENAMES)


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
