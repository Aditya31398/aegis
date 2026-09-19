"""`aegis init`: a working starting point, not an empty one.

The templates are the project's own policy, scenario suite and baseline --
`test_templates_match_repo` fails if they drift -- so a freshly scaffolded
directory passes ratify, verify and audit before the user changes anything.
Starting green matters: the first failure a user sees should be one they
caused, which tells them the checks work.
"""
from __future__ import annotations

from importlib import resources
from pathlib import Path

from .. import __version__

# template name -> destination relative to the target directory
LAYOUT = {
    "policy.yaml": "policies/base.yaml",
    "restricted.yaml": "policies/restricted.yaml",
    "suite.yaml": "suites/core.yaml",
    "baseline.yaml": "loopholes.baseline.yaml",
}
CI_LAYOUT = {"workflow.yml": ".github/workflows/aegis.yml"}


def template(name: str) -> str:
    return (resources.files("aegis") / "templates" / name).read_text(encoding="utf-8")


def scaffold(target: Path, *, ci: bool = False, force: bool = False) -> list[Path]:
    layout = {**LAYOUT, **(CI_LAYOUT if ci else {})}
    dests = {name: target / rel for name, rel in layout.items()}
    if not force:
        for d in dests.values():
            if d.exists():
                raise FileExistsError(str(d))
    written = []
    for name, dest in dests.items():
        text = template(name)
        if name == "workflow.yml":
            text = text.replace("{version}", __version__)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")
        written.append(dest)
    return written
