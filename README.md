# Aegis — constraint enforcement for agent systems

[![CI](https://github.com/Aditya31398/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/Aditya31398/aegis/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aegis-guard)](https://pypi.org/project/aegis-guard/)
[![Python](https://img.shields.io/pypi/pyversions/aegis-guard)](https://pypi.org/project/aegis-guard/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Aegis does two jobs:

1. **Runtime enforcement.** A kernel mediates every tool call an agent makes
   against a declarative YAML policy: capability allowlists, argument
   constraints, spend and time budgets, PII/taint egress rules, and bounded
   agent spawning. Denied calls never execute.
2. **Regression and audit.** A conformance framework proves the constraints
   still hold after a change, detects when a policy is quietly weakened, hunts
   for loopholes in your own policies, and audits third-party MCP servers.

## Install

```bash
pip install aegis-guard          # Python 3.10+, one dependency (PyYAML)
aegis --version
```

Or run the container, no Python needed:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/aditya31398/aegis --help
```

## Quickstart: audit an MCP server

```bash
# a live server (only initialize + tools/list are ever sent; no tool is called)
aegis mcp --server https://mcp.example.com/mcp --bearer-env MCP_TOKEN --out audit-out

# or a saved manifest / claude_desktop_config.json
aegis mcp --manifest claude_desktop_config.json --out audit-out
```

`audit-out/` gets a Markdown report, `audit.json`, `audit.sarif`, and a
`hardened-policy.yaml` you can adopt.

## Quickstart: enforce a policy on your own agents

```bash
aegis init . --ci        # policy, adversarial scenarios, baseline, GitHub workflow
aegis ratify --policy policies/base.yaml
aegis verify --suites suites --policy policies/base.yaml --require-coverage
aegis audit  --policy policies/base.yaml
```

The scaffold passes every check out of the box, so the first failure you see
is one you caused. Then, in code:

```python
from aegis import Agent, PolicyViolation, ToolRegistry, build_kernel, load_policy

registry = ToolRegistry()

@registry.tool("fs.read", effects={"read"}, classification="internal")
def read_file(path: str) -> str:
    return open(path).read()

kernel, root = build_kernel(load_policy("quickstart-policy.yaml"), registry)
agent = Agent(root, kernel)

agent.tools.fs__read(path="/workspace/notes.md")        # allowed
agent.tools.fs__read(path="/etc/passwd")                # PolicyViolation: never executed
await agent.atools.fs__read(path="/workspace/a.md")     # async runtimes too
```

Runnable version: [`examples/quickstart.py`](examples/quickstart.py) with its
one-tool [policy](examples/quickstart-policy.yaml). `build_kernel` refuses to
start an unconstitutional policy — including one that grants a tool you never
registered — and every decision, allowed or denied, lands in a hash-chained
audit log (`kernel.audit`).

## Using it in CI

**GitHub Actions** — pin to a release tag:

```yaml
permissions:
  contents: read
  security-events: write     # only if upload-sarif is on

steps:
  - uses: actions/checkout@v7
  - uses: Aditya31398/aegis@v0.3.0
    with:
      manifest: mcp-servers.json          # and/or  server: https://…/mcp
      baseline: aegis-baseline.yaml
      fail-on: high
      upload-sarif: "true"                # findings appear in the Security tab
      comment-on-pr: "true"
```

**Anywhere else** — `aegis` is a normal CLI with a stable contract:

| | |
|---|---|
| Exit codes | `0` pass · `1` findings/violations at or above `--fail-on` · `2` bad input or usage · `3` internal error |
| Formats | `--format text\|json\|sarif`, `--output FILE` (text stays on stdout for the log) |
| JSON schema | `aegis.audit/v1`; fields are only ever added |
| Fingerprints | stable per finding; SARIF `partialFingerprints` so dashboards dedupe across runs |
| Accepted risk | baselined findings stay in the output as SARIF *suppressions* with the written reason |

A broken policy file is always exit `2`, never `1`, so a pipeline can tell
"your policy has holes" from "your policy file is malformed".

```bash
aegis ratify --policy policies/base.yaml
aegis verify --suites suites --policy policies/base.yaml --require-coverage
aegis fuzz   --policy policies/base.yaml --iterations 20 --async
aegis audit  --policy policies/base.yaml --format sarif --output aegis.sarif
aegis drift  --baseline main-base.yaml --candidate policies/base.yaml
```

## Observability: pairing with an APM

Aegis decides what an agent *may* do; it deliberately ships no dashboard. Two hooks
let an observability tool see every decision without being able to influence one:

```python
from aegis.observe import register_context_provider

register_context_provider(lambda: {"run_id": current_run_id()})   # -> details.ctx on every record
kernel.audit.subscribe(lambda rec: ship(rec))                       # after the record is chained
```

Model calls are not tools, but they spend the same budget. Reserve before the
request and settle after it, and the ledger becomes a hard gate on model spend:

```python
r = kernel.reserve_spend(grant, usd=estimate, tokens=max_tokens)    # BudgetExhausted -> call never made
kernel.settle_spend(r, usd=actual_cost, tokens=actual_tokens)
```

[AgentDynamics](https://github.com/Aditya31398/agentdynamics) uses exactly these
hooks (`agentdynamics.integrations.aegis`): denials land in the task they happened
in, model calls are gated by the Aegis budget, a watchdog revokes grants that keep
probing a boundary, and observed behaviour is turned back into a tighter policy
that `aegis ratify` and `aegis drift` verify.

## Supply chain

Releases are built once in CI from a tag, published to PyPI through trusted
publishing (no long-lived token exists), and carry signed build provenance:

```bash
gh attestation verify aegis_guard-0.3.0-py3-none-any.whl --repo Aditya31398/aegis
gh attestation verify oci://ghcr.io/aditya31398/aegis:0.3.0 --repo Aditya31398/aegis
```

The container runs as a non-root user and ships an SBOM. The kernel has one
runtime dependency (PyYAML) and is small enough to vendor.

---

The rest of this document explains how it works and why it is built this way.

## The load-bearing idea

**Prompt rules are advisory. Only a mediating kernel is enforceable.**

An agent never receives a callable. It receives a `ToolProxy` bound to
`(kernel, grant, tool_name)`. The only code path from an agent to a real
implementation runs through `Kernel.invoke`, which runs the guard chain first.
`tests/test_conformance.py::test_kernel_is_the_only_execution_path` parses the
AST of every file in `aegis/` and fails the build if a second call site to a
tool implementation ever appears.

The same holds for async runtimes. `await kernel.ainvoke(grant, tool, **args)`
(or `await agent.atools.fs__read(path=...)`) goes through the identical guard
chain, ledger and audit log; coroutine tools are awaited, blocking tools run
off the event loop, and calling a coroutine tool through the sync `invoke` is
denied as `kernel.async_tool_requires_ainvoke` rather than leaking an
unmediated awaitable.

So the guarantee is scoped honestly: **an agent can attempt anything; it cannot
*cause* anything outside its grant.** No framework can stop a model from
generating a bad tool call. This one stops the call from executing.

```
Agent ──> ToolProxy ──> Kernel.invoke
                             │
                             ├─ guards (fail-closed, first DENY wins)
                             │    capability → spawn → budget → data
                             ├─ budget charge (reserved before execution)
                             ├─ _execute / _aexecute ← THE ONLY CALL SITES
                             ├─ post-guards (classification ceiling, taint)
                             └─ audit record (hash-chained)
```

## Grants and attenuation

A `Grant` is the only thing that authorises an effect. It can only ever be
*attenuated*. `Grant.attenuate()` raises on any request for authority the
parent doesn't hold, so "a spawned agent can never exceed its parent" is a
structural property, not a convention:

```
child.tools  ⊆ parent.tools ∩ policy.spawn.allow_tools
child.budget ≤ parent.remaining × min(requested, child_budget_fraction)
child.depth  = parent.depth + 1  ≤  max_depth
```

Budgets are **hierarchical** — a child's spend debits every ancestor's ledger,
so N children cannot collectively outspend the root even though each is
individually within its own limit.

Revocation is total: revoking a grant disables its entire subtree immediately.

## The four constraint classes

| Class | Mechanism | Example rule ids |
|---|---|---|
| Tool / side effect | default-deny allowlist + per-argument regex, prefix, enum, length, forbidden-pattern | `capability.not_granted`, `capability.arg_prefix`, `capability.unexpected_arg` |
| Spend / time | hierarchical ledger, pre-flight admission | `budget.usd_exceeded`, `budget.tool_calls_exceeded`, `budget.deadline_exceeded` |
| Data / PII egress | classification ceiling on reads, taint propagation, PII scan at declared sinks | `data.classification_exceeded`, `data.taint_egress_blocked`, `data.pii_egress_blocked` |
| Spawning | depth, fan-out, whole-tree descendant cap, delegable-tool list | `spawn.max_depth_exceeded`, `spawn.max_fanout_exceeded`, `spawn.privilege_escalation` |

Rule ids are the stable contract. Tests pin the id, never the prose, so
reworded messages don't break the suite but a rule that stops firing does.

## Policy

Policies are YAML data, never code — so they can be diffed, signed, pinned, and
cannot be authored at runtime by an agent. `extends:` derives a tighter profile;
the loader rejects a derived policy that raises a budget.

```yaml
tools:
  allow:
    - name: db.query
      require_args: [sql]
      args:
        sql:
          matches: "(?is)^\\s*select\\b.*"
          forbid_matches: "(?i)\\b(drop|delete|update|insert|alter)\\b"
spawn:
  max_depth: 2
  max_fanout: 3
  child_budget_fraction: 0.4
  allow_tools: [kb.search, fs.read, http.get, db.query, agent.spawn]
```

---

# The regression framework

Four independent layers. All four are required CI checks.

### 1. Scenario conformance (`suites/*.yaml`)

Adversarial cases — path traversal, SSRF, SQL mutation, argument smuggling, PII
exfiltration, spawn bombs, privilege escalation, budget exhaustion. Each step
pins the expected verdict *and* the rule id.

Each denial asserts the **strong** form: the tool implementation was never
entered. Fixtures record every execution, so a test proves "nothing happened",
not merely "an error was returned".

```yaml
- id: deny-path-traversal
  steps:
    - invoke: {tool: fs.read, args: {path: "/etc/passwd"}}
      expect: deny
      rule: capability.arg_prefix
```

### 2. Invariants under fuzz (`aegis/conformance/invariants.py`)

A random workload generator drives the kernel with thousands of arbitrary
call/spawn/revoke sequences, half hostile payloads and half well-formed calls
the policy admits. Seven invariants are re-checked after *every* operation:

`attenuation` · `depth_bound` · `budget_conservation` · `no_effect_on_deny` ·
`every_effect_was_charged` · `audit_chain` · `revocation_is_total`

`fuzz --async` drives the same invariants through `ainvoke`/`aspawn`: each
round launches a batch concurrently, cancels some calls mid-flight, and a
watcher task re-checks every invariant at each scheduling point, so the kernel
is observed *during* calls, not only between them. Its negative control is a
planted kernel that checks the budget, awaits the tool, then charges — a
check-then-act race the fuzzer must catch.

Writing that control exposed a weakness in the fuzzer itself: the workload was
almost entirely hostile, so nearly every call died at the guards, budgets were
never exhausted, and the budget invariants were green because the ledger barely
moved. The planted race was caught on 1 seed in 4. Adding well-formed calls
raised that to 4 in 6, and `test_fuzz_workload_reaches_budget_exhaustion` now
fails if the workload ever stops reaching an exhausted budget.

Any exception that isn't a `PolicyViolation` is a framework bug and fails the
run. This layer found a real one during development: `agent.spawn` routed
through the tool path crashed rather than denying.

### 3. Privilege drift (`aegis/conformance/drift.py`)

The subtle regression isn't broken enforcement — the suite catches that. It's
someone quietly *loosening the policy*, after which every test still passes
because the tests now agree with the weaker rules.

So the policy is diffed against the pinned baseline and any widening fails the
build unless explicitly waived by code:

```
+ [tools.constraint_relaxed]  fs.read.path: prefix '/workspace/' -> '/'
+ [budget.usd_raised]         usd 5.0 -> 50.0
+ [spawn.max_depth_raised]    max_depth 2 -> 6
RESULT: FAIL — policy widens agent authority.
```

The differ is deliberately conservative: a regex change it can't *prove* is a
tightening counts as widening.

### 4. Structural and fail-closed checks

- AST check that the kernel remains the sole execution path
- crashing guard → `guard.internal_error` DENY, never an allow
- policy-allowed but unregistered tool → `registry.unknown_tool` DENY
- tampering with an audit record breaks `verify()`
- a sibling swarm with `budget_fraction: 1.0` each still can't outspend the root
- coverage: every granted tool must be exercised by some scenario

## Adding a tool — the checklist

1. `registry.register(...)` with its `effects`, `classification`, `cost_usd`
2. add it to `policies/base.yaml` with the *tightest* argument constraints
3. decide whether it is an egress sink and whether it is delegable to children
4. write at least one allow case and one deny case per constraint in `suites/`
5. run `drift` — the new grant shows as `tools.added`, waive it in the PR

Step 5 is the point: widening authority is always a deliberate, reviewed act.

## What this does not do

- It can't stop the model from *trying*. It stops attempts from having effects.
- Constraints are only as good as the policy. A tool registered with loose
  regexes is a hole the kernel will faithfully honour.
- The PII scanner is a backstop, not the primary control — the primary control
  is that the agent never holds the raw callable.
- Prompt injection is out of scope as an *input* problem; it is in scope as an
  *effect* problem, since an injected instruction still has to pass the guards.

---

# Law, not just locks

The framework is layered the way a legal system is, because the failure modes
are the same ones legal systems evolved to handle.

| Layer | File | Amended by | Waivable? |
|---|---|---|---|
| **Constitution** | `aegis/constitution.yaml` | editing the document | **no** — no flag, no config, no override |
| **Statute** | `policies/*.yaml` | a PR that widens | yes, `--waive <code>` with review |
| **Case law** | `suites/*.yaml` | adding scenarios | n/a — precedents accumulate |
| **Accepted holes** | `loopholes.baseline.yaml` | adding a fingerprint | yes, with a written reason and an owner |

### Constitution

Seven clauses that every policy must satisfy to be **ratified**. `build_kernel`
ratifies before it returns, so an unconstitutional policy cannot start:

```
C1  Bounded authority          — no budget axis may be unbounded
C2  Every egress path screened — an outward-capable tool must be a declared sink
C3  No unconstrained argument  — effectful args carry at least one constraint
C4  Delegation attenuates      — child fraction < 1.0, depth bounded
C5  Reading is not exporting   — egress ceiling strictly below read ceiling
C6  Rules must be enforceable  — every named PII kind has a working detector
C7  No phantom grants          — a granted tool must actually exist
```

There is deliberately no waiver path. The only route past a clause is to edit
`aegis/constitution.yaml`, which is a loud diff in review rather than a flag buried
in a CI invocation. `tests/test_governance.py` asserts every clause can
actually fire — a clause that cannot fail is decoration.

```
aegis ratify --policy policies/base.yaml
```

### Loophole hunting

The conformance suite answers *"do the rules I wrote still work?"*. The hunter
answers *"what gets through that I never thought to test?"* — three techniques:

1. **Static** — structural analysis of policy and registry *together*: rules
   that cannot fire, exits nobody screens, delegation shapes that recombine
   authority, unanchored or wildcard-bearing patterns.
2. **Probe** — pushes a corpus of known-dangerous payloads (traversal,
   SSRF, metadata endpoints, host-suffix confusion, file-reading SELECTs,
   encoded PII) through the real guard chain in decision-only mode. Anything
   ALLOWED is reported with the exact witness string.
3. **Metamorphic** — takes every step the suite expects to be DENIED, mutates
   the arguments in meaning-preserving ways (case, percent-encoding,
   zero-width joiners, SQL comments, null bytes, doubled separators) and
   re-runs. A mutation that flips DENY to ALLOW is a bypass.

```
aegis audit --policy policies/base.yaml --fail-on high
```

**On the first run against the policy shipped in this repo it found 23 holes**
— 7 critical, 9 high — including:

- `SELECT pg_read_file('/etc/passwd')` and `SELECT … INTO OUTFILE` passed the
  read-only SQL guard, because "starts with SELECT and contains no DROP" does
  not mean "cannot write or read files"
- `SELECT dblink_exec(…)` opened an outbound connection from inside a
  "read-only" tool
- `/workspace/%2e%2e/etc/passwd` and a null-byte path defeated the traversal check
- every PII pattern fell to zero-width joiners, homoglyph separators and base64
- taint does not cross agents, so a reader child's output can reach a sink sibling

Fixes: Unicode normalisation (NFKC + invisible-character stripping +
confusables) and base64 decoding in the scanner, a much broader SQL denylist,
and encoded-traversal patterns on paths. **23 → 6.** The remaining six are
architectural, and they live in `loopholes.baseline.yaml` with a written reason
and an owner rather than being quietly dropped.

### The regression property

Findings carry a stable fingerprint. Accepted ones sit in the baseline; anything
new at high or above fails CI. So **the known-hole set can shrink silently but
never grow silently** — and a baseline entry whose finding has disappeared also
fails, so stale acceptances can't hide a hole that was already closed.

The three checks catch different directions of failure and none subsumes
another:

- `ratify` — is the policy *structurally* sound? (a constraint exists)
- `audit` — is the policy *substantively* sound? (the constraint holds)
- `drift` — is the policy moving in the *wrong direction*? (it got weaker)

A weakened `fs.read` prefix still ratifies, still passes every scenario, and is
caught by `audit` and `drift`. That is the point of having all three.

## Prior art

This overlaps with real work; see the chat discussion for the comparison. In
short: NeMo Guardrails, Guardrails AI and Fiddler sit at the content layer;
OPA/Rego, Cedar, Oso, Cerbos and OpenFGA are mature policy engines but are not
tool-call-shaped; AgentSpec (ICSE '26) is the closest academic relative for
runtime enforcement. The part that is genuinely thin in all of them is the
*regression* half — adversarial conformance, privilege-drift detection and
automated loophole discovery. If you adopt an existing engine, port
`aegis/conformance/` onto it rather than rebuilding it.

---

# Auditing somebody else's agents

Everything above points at policies you wrote. `aegis/adapters/mcp.py` points
the same machinery at an MCP server you did not write, which is what makes this
usable as a service rather than a library.

```
aegis mcp --manifest server-manifest.json \
                              --out audit-out --client "Acme"
```

Accepts a `tools/list` response, a `claude_desktop_config.json`, or a bundle of
several servers. Or skip the export and point it at the live server:

```
aegis mcp --server https://mcp.example.com/mcp                               --bearer-env MCP_TOKEN --out audit-out
aegis mcp --server-cmd "npx -y @modelcontextprotocol/server-filesystem /tmp"                               --out audit-out
```

The live client performs the real MCP handshake (Streamable HTTP with JSON or
SSE replies, or stdio) and follows `tools/list` pagination. It is structurally
incapable of calling a tool: any method other than `initialize`,
`notifications/initialized` and `tools/list` raises before reaching the wire.
What it fetched is saved to `audit-out/manifest.json` (env values redacted) so
the audit can be replayed and baselined offline with identical fingerprints.

Auth becomes evidence rather than a guess: a remote server that answers
`tools/list` with no credential is reported as a **critical** with a witness,
and a server that demands and receives a token is not flagged at all.
`--server-cmd` runs the given command on your machine; only use it on servers
you would run anyway. Three moves:

1. **Ingest** — normalise the manifest.
2. **Synthesise** — derive a policy from the declared JSON Schemas. This is
   what the server *currently* permits. Every schema field with no `enum`,
   `pattern` or `maxLength` becomes a door the probe engine walks through.
3. **Harden** — emit a tightened policy the customer can adopt.

Nothing in the audit executes a tool. The registry is built from inert doubles
that raise if called.

## MCP-specific checks

### Effects are inferred from the surface, not the name

A tool called `sync_workspace` tells you nothing; a `path` argument beside a
`content` argument tells you it writes files. Effects come from the schema
shape first (a `url` plus a body is egress; a `command` argument is compute; a
`confirm` boolean implies something worth braking), then the declared MCP
annotations, and only then tool-name keywords. `EffectInference.sources`
records which signal decided, so a severity can be traced back.

Annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) are claims
made by the party being audited, so they may only ever *widen* the inferred
effects. Honouring a narrowing claim would let any server opt out of scrutiny
by asserting its own innocence — and clients that auto-approve tools marked
read-only would run it unattended. A read-only claim on a surface that
demonstrably mutates is reported as `annotation_contradicts_surface`, with
both signals in the witness.

Beyond that: **omnibus tools** (one handler taking a free-form
string and dispatching many operations), **tool-name shadowing** across
servers, **description injection** (model-directed imperatives and invisible
Unicode in tool descriptions, which the model reads verbatim and a reviewer
does not), **irreversible tools with no `confirm`/`dry_run`**, **plaintext
credentials** in client config, and **unauthenticated remote transports**.

### On false positives

Published YARA-based MCP scanners run around a **78% false-positive rate**,
because they flag tool descriptions that merely describe normal functionality.
Two design rules here:

- Every check either produces a **reproducing witness** or requires **two
  independent signals** before firing. `test_omnibus_requires_two_signals`
  asserts a well-scoped tool with one free-form argument is *not* flagged.
- Findings are **consolidated**. Twelve traversal payloads across three
  filesystem tools is not twelve problems, it is three unconstrained path
  arguments. On the sample manifest this takes **101 raw findings down to 32**.
  It also keeps fingerprints stable as the payload corpus grows, which matters
  because the baseline file is keyed on them.

## What a run looks like

On `examples/sample_mcp_manifest.json` (3 servers, 8 tools):

```
32 findings — 8 critical, 16 high, 8 medium
  critical  description_injection          helpdesk.escalate     "you must always"
  critical  payload_admitted               analytics.query.sql   SELECT pg_read_file('/etc/passwd')
  critical  payload_admitted               filesystem.*.path     /workspace/sub/../../etc/passwd
  high      tool_shadowing                 read_file             filesystem, helpdesk
  high      omnibus_tool                   analytics.query.sql   "Accepts raw SQL"
  high      irreversible_no_brake          filesystem.delete_file
  high      annotation_contradicts_surface filesystem.sync_workspace  readOnlyHint vs schema:path+content
```

Apply the generated `hardened-policy.yaml` and re-probe: **0 critical, 1 high**
— and the residual is `taint_laundering`, which is architectural and cannot be
fixed by a policy file. `test_hardened_policy_closes_the_critical_findings`
asserts exactly this, so the claim the report makes to a customer is itself
under regression test.

Writing this found a bug in the hardener: its generated SQL denylist covered
`pg_read_file` and `dblink` but not `pg_shadow`, so `SeLeCt 1 FROM pg_shadow`
survived hardening.

## Deliverables

`audit-out/audit-report.md` — severity summary, surface inventory, every
finding with where, what, a reproducing input and a fix, then a prioritised
top-five.

`audit-out/hardened-policy.yaml` — an adoptable policy. Placeholders are
shouted in capitals on purpose; a generated policy that looks finished is more
dangerous than one that obviously needs a human.

Findings carry stable fingerprints, so `--baseline` plus `--fail-on high` turns
a one-off audit into a CI gate the customer keeps running after you leave.
