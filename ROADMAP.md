# Roadmap

Ordered by whether it unblocks a user, not by how interesting it is.

## Next (pick up here)

- [x] **Async kernel.** `Kernel.ainvoke` / `aspawn`, `agent.atools`. Coroutine
      tools are awaited, blocking tools run in a worker thread, and a coroutine
      tool called through sync `invoke` is denied
      (`kernel.async_tool_requires_ainvoke`) before any budget is charged.
- [x] **Async fuzzing.** `fuzz --async` runs batches under `asyncio.gather`,
      cancels some mid-flight, and re-checks every invariant at each yield
      point. A planted check-then-charge race is a negative control.
- [x] **Live MCP ingest.** `mcp --server URL` (Streamable HTTP, JSON or SSE)
      and `mcp --server-cmd CMD` (stdio). The client can only send
      `initialize`/`tools/list`; anonymous listing is a witnessed critical.
- [x] **Effect inference from schema, not keywords.** Schema shape first, then
      MCP annotations, then name keywords, with the deciding signal recorded in
      `EffectInference.sources`. Annotations may only widen; a narrowing claim
      becomes an `annotation_contradicts_surface` finding.
- [x] **HTML report.** `audit-out/audit-report.html`: one self-contained file,
      no scripts or remote loads, everything escaped under a restrictive CSP.

## Soon

- [x] **Payload corpus as a versioned data file.** `aegis/corpus/payloads.yaml`
      (`schema: aegis.corpus/v1`), swappable with `--corpus` or `$AEGIS_CORPUS`.
      Payload findings are fingerprinted on the (tool, argument) pair, so a
      corpus refresh can reveal a hole but never invalidates a baseline.
- [x] **Per-finding confidence score.** `confirmed` / `likely` / `possible`,
      graded by the evidence the check produces, in every output format
      (SARIF carries it as `rank`, separate from security-severity).
      `--min-confidence` gates what may fail a build; nothing is suppressed.
- [x] **LangChain / OpenAI tool-schema adapters.** `aegis tools --schema
      tools.json` ingests OpenAI (chat and Responses), Anthropic and LangChain
      declarations into the same normalised surface, so synthesis, probing and
      hardening are unchanged. Adds `hosted_tool_unbounded` and
      `provider_validation_off`.
- [ ] **Message-bus mediation** to close the cross-agent taint hole
      (`54ef34904237b006`). The kernel would have to mediate agent-to-agent
      messages, not only tool calls. This is a real design change, not a patch.

## Later

- [ ] Signed policies. A policy file is currently trusted because it is on disk.
- [ ] Cedar / OPA backends, so the kernel can delegate decisions to an existing
      engine while keeping this project's regression half.
- [ ] Rate limiting and concurrency limits as a fifth constraint class.

## Deliberately not doing

- A dashboard or hosted service before anyone is paying. (Observability is
  delegated instead: `aegis.observe` feeds tools such as AgentDynamics.)
- Runtime content filtering of model outputs. Different problem, crowded field,
  and it would dilute what this repo is about.
