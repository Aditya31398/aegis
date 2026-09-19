# Roadmap

Ordered by whether it unblocks a user, not by how interesting it is.

## Next (pick up here)

- [x] **Async kernel.** `Kernel.ainvoke` / `aspawn`, `agent.atools`. Coroutine
      tools are awaited, blocking tools run in a worker thread, and a coroutine
      tool called through sync `invoke` is denied
      (`kernel.async_tool_requires_ainvoke`) before any budget is charged.
- [ ] **Async fuzzing.** Extend `conformance/invariants.py` to run workloads
      under `asyncio.gather` so interleavings are checked, not just parity.
- [ ] **Live MCP ingest.** `--server http://host/mcp` that performs a real
      `tools/list` handshake instead of requiring a saved manifest. This is the
      difference between "send me your config" and "paste your URL", which is
      most of the friction in an audit.
- [ ] **Effect inference from schema, not keywords.** Current inference reads
      tool names. Use the JSON Schema shape and the MCP annotations
      (`readOnlyHint`, `destructiveHint`, `idempotentHint`) where servers
      publish them; fall back to keywords.
- [ ] **HTML report.** Same content as the Markdown, styled, single file.
      Markdown is fine for engineers; the person who approves the invoice
      wants something that opens in a browser.

## Soon

- [ ] **Payload corpus as a versioned data file.** Move `_PAYLOADS` out of
      `loopholes.py` into `corpus/*.yaml` with a schema and a version field.
      This is the thing that would eventually be subscribed to, so it needs to
      be updatable without a code release.
- [ ] **Per-finding confidence score.** Severity answers "how bad"; it does not
      answer "how sure". A low-confidence finding should be reported
      differently, not suppressed.
- [ ] **LangChain / OpenAI tool-schema adapters.** Same three moves as the MCP
      adapter: ingest, synthesize, harden. Most of `adapters/mcp.py` generalises.
- [ ] **Message-bus mediation** to close the cross-agent taint hole
      (`54ef34904237b006`). The kernel would have to mediate agent-to-agent
      messages, not only tool calls. This is a real design change, not a patch.

## Later

- [ ] Signed policies. A policy file is currently trusted because it is on disk.
- [ ] Cedar / OPA backends, so the kernel can delegate decisions to an existing
      engine while keeping this project's regression half.
- [ ] Rate limiting and concurrency limits as a fifth constraint class.

## Deliberately not doing

- A dashboard or hosted service before anyone is paying.
- Runtime content filtering of model outputs. Different problem, crowded field,
  and it would dilute what this repo is about.
