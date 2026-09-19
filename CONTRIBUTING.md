# Contributing

## Setup

```bash
pip install -e ".[dev]"
pytest -q
```

## Before you open a PR

```bash
pytest -q
python -m conformance.cli verify --suites suites --policy policies/base.yaml --require-coverage
python -m conformance.cli audit  --policy policies/base.yaml --baseline loopholes.baseline.yaml
```

## Rules that are not negotiable

- A new tool in a policy needs at least one allow scenario and one deny
  scenario per constraint, in `suites/`.
- A new loophole check needs a negative control proving it does not fire on a
  well-formed input.
- Do not widen a policy to make a test pass. If a scenario fails, the scenario
  is usually right.
- If the loophole audit surfaces something you are not closing, add it to
  `loopholes.baseline.yaml` with a written reason and an owner. "It is noisy"
  is not a reason.
- Rule ids (`capability.not_granted`, `spawn.max_depth_exceeded`, …) are a
  public contract. Reword `reason` prose freely; renaming a rule id is a
  breaking change and the suites must change in the same commit.

See `CLAUDE.md` for the architectural invariants and why they exist.
