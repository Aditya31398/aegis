# CLAUDE.md

Context for Claude Code working in this repo. Read this before changing
anything under `aegis/`.

## What this is

Two halves that must stay separable:

- `aegis/` — a kernel that mediates every effect an agent can cause. Policies
  are YAML data, grants attenuate on spawn, guards fail closed, every decision
  lands in a hash-chained audit log.
- `aegis/conformance/` — the regression framework. Adversarial scenarios, property
  fuzzing, privilege-drift detection, and a loophole hunter that attacks our
  own policies. This half is the differentiated part of the project.

`aegis/adapters/mcp.py` points the hunter at MCP servers we did not write,
which is what makes the tooling usable as a service.

## Commands

```bash
pip install -e ".[dev]"

ruff check .
pytest -q                                                    # 213 tests, all must pass
aegis ratify  --policy policies/base.yaml
aegis verify  --suites suites --policy policies/base.yaml --require-coverage
aegis fuzz    --policy policies/base.yaml --iterations 20
aegis fuzz    --policy policies/base.yaml --iterations 20 --async
aegis audit   --policy policies/base.yaml --baseline loopholes.baseline.yaml
aegis drift   --baseline old.yaml --candidate policies/base.yaml
aegis mcp     --manifest examples/sample_mcp_manifest.json --out audit-out
aegis mcp     --server https://host/mcp --bearer-env MCP_TOKEN --out audit-out

python examples/demo.py
python examples/quickstart.py
python -m build            # then see the `package` CI job for the wheel smoke test
```

## Invariants — do not break these

These are load-bearing. Each has a test that fails loudly; if one starts
failing, the fix is the code, not the test.

1. **`Kernel._execute` and `Kernel._aexecute` are the only places a tool
   implementation is touched.** `test_kernel_is_the_only_execution_path` parses
   the AST of every file under `aegis/` and fails on *any* `.fn` attribute
   access outside those two functions — a call, a `to_thread(spec.fn)`, a
   `partial(spec.fn)`. `invoke` and `ainvoke` share `_admit` (pre-guards,
   budget) and `_release` (post-guards); never give the async path its own
   copy of either. The whole "every effect is mediated" claim rests on this.
2. **Agents never hold a callable.** They hold a `ToolProxy` bound to
   `(kernel, grant, tool_name)`. Do not add an attribute to `Agent` that
   exposes a registered implementation.
3. **Guards fail closed.** A guard that raises becomes `guard.internal_error`
   DENY, never an allow. Do not add a `try/except: pass` anywhere in
   `Kernel.decide`.
4. **Grants only attenuate.** `Grant.attenuate()` raises on any request for
   authority the parent lacks. Budgets are hierarchical; a child's spend debits
   every ancestor.
5. **Rule ids are the public contract.** Tests pin `verdict.rule`, never the
   prose in `verdict.reason`. Reword reasons freely; renaming a rule id is a
   breaking change and needs the suites updated in the same commit.
6. **The live MCP client never calls a tool.** `mcp_client._ALLOWED_METHODS`
   is `initialize`, `notifications/initialized`, `tools/list` and nothing
   else. Do not add `tools/call` "just to probe" — auditing a server by
   running its destructive tools is an incident, not an audit.
7. **Exit codes are a contract.** `0` pass, `1` findings, `2` bad input,
   `3` internal error. Never let an exception escape as exit 1: a pipeline
   that cannot tell a hole from a crash learns to ignore both. Malformed
   policies must raise `PolicyError`.
8. **The wheel must work outside the repo.** Anything read at runtime lives
   under `aegis/` and is listed in `package-data`. The `package` CI job
   installs the wheel into a clean venv and runs from another directory.
9. **Constitutional clauses have no waiver.** If a clause is inconvenient, the
   fix is to amend `aegis/constitution.yaml` in a visible diff, never to add a
   bypass flag.

## Working agreements

- **Every new tool needs two scenarios**: at least one allow and one deny per
  constraint, in `suites/`. `--require-coverage` fails the build otherwise.
- **Every new check needs a negative control.** A check that cannot produce a
  false positive on a well-formed input has not been tested. See
  `test_omnibus_requires_two_signals`.
- **Findings need a witness or two independent signals.** Published MCP
  scanners run ~78% false positives because they flag descriptions of normal
  functionality. Low noise is the product differentiator; protect it.
- **Never widen a policy to make a test pass.** If a scenario fails, the
  scenario is usually right.
- **New loopholes go in the baseline only with a reason and an owner.**
  `test_baseline_entries_all_have_reasons_and_still_apply` enforces both, and
  also fails on stale entries so a closed hole cannot sit there looking open.
- Keep `aegis/` dependency-free apart from PyYAML. The kernel is meant to be
  vendorable into someone else's codebase.

## Layout

```
aegis/
  kernel.py       the sole mediation point; read this first
  grant.py        capability attenuation + hierarchical budget ledger
  policy.py       YAML policy model, `extends` may only tighten
  constitution.py seven unwaivable clauses, checked at ratification
  guards/         capability, spawn, budget, data (PII + taint)
  observe.py      context providers + audit subscribers; may add correlation data, never change a verdict
  adapters/mcp.py ingest → synthesize → harden
  adapters/mcp_client.py  live handshake (HTTP/stdio), listing-only
  constitution.yaml   shipped in the wheel
  templates/      what `aegis init` scaffolds; must equal the repo copies
aegis/conformance/
  cli.py          the `aegis` command; exit codes defined here
  export.py       JSON (aegis.audit/v1) and SARIF 2.1.0
  scaffold.py     `aegis init`
  runner.py       scenario execution; asserts denials produced no side effect
  invariants.py   seven properties re-checked after every fuzzed operation
  drift.py        privilege-widening detector
  loopholes.py    static + payload probe + metamorphic mutation
  mcp_checks.py   omnibus, shadowing, description injection, secrets
  report.py       the client-facing deliverable
```

## Known-weak areas, ranked

Honest list. Do not paper over these.

1. **Taint does not cross agents.** One child reads sensitive data, a sibling
   holds a sink, and the orchestration hands one's output to the other. The
   kernel cannot see that. Needs a mediated message bus. Accepted in the
   baseline as `54ef34904237b006`.
2. **Effect inference still guesses.** Schema shape and annotations come
   first now, but a tool with an opaque name, an opaque schema and no
   annotations falls back to keywords and then to READ. A wrong effect means
   a wrong severity. Never let an annotation *narrow* the inferred effects:
   it is a claim by the party being audited.
3. **`sample_from_pattern` handles only simple anchored regexes.** It returns
   `None` rather than guessing, which is correct, but means exotic schemas skip
   probing silently.
4. **`ArgConstraint.intersect` composes regexes with lookahead.** Correct but
   unreadable; a proper intersection would be better.
5. **Async fuzzing is single-loop.** `afuzz` interleaves coroutines and runs
   blocking tools in threads, but every ledger charge still happens on the
   loop thread. Multiple loops or threads calling one kernel concurrently are
   covered only by the ledger's lock, not by a fuzzer.

## What not to build yet

- No dashboard, no web UI, no hosted service. The CLI, the GitHub Action, the
  container and SARIF (which plugs into dashboards people already have) are
  the distribution surface until someone is paying.
- No new payload categories before the existing ones have negative controls.
