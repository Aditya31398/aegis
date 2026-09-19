"""CLI -- wire this into CI as a required check.

    python -m conformance.cli verify --suites suites/ --policy policies/base.yaml
    python -m conformance.cli drift  --baseline policies/base.yaml \
                                     --candidate policies/base.yaml \
                                     --waive budget.usd_raised
    python -m conformance.cli fuzz   --policy policies/base.yaml --iterations 8
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis.constitution import Constitution, default_constitution
from aegis.policy import load_policy

from .drift import check_drift
from .fixtures import build_fixture_registry
from .loopholes import AuditReport, consolidate, format_audit, hunt
from .invariants import afuzz, fuzz
from .runner import ConformanceRunner, format_report
from .spec import load_suite


def _verify(args) -> int:
    runner = ConformanceRunner(root=args.root)
    failed = 0
    covered_tools: set[str] = set()
    for path in sorted(Path(args.suites).glob("*.yaml")):
        result = runner.run_file(path)
        print(format_report(result))
        covered_tools |= result.exercised_tools
        if not result.ok:
            failed += len(result.failed)

    if args.policy:
        policy = load_policy(args.policy)
        gaps = sorted(policy.tool_names - covered_tools - {"agent.spawn"})
        if gaps:
            print(f"\nCOVERAGE GAP: no scenario exercises {gaps}")
            if args.require_coverage:
                failed += len(gaps)

    print("\nRESULT:", "PASS" if failed == 0 else f"FAIL ({failed} problems)")
    return 0 if failed == 0 else 1


def _drift(args) -> int:
    ok, deltas = check_drift(args.baseline, args.candidate, set(args.waive or []))
    if not deltas:
        print("no policy change detected")
        return 0
    print("policy delta:")
    for d in deltas:
        print("  ", d)
    if ok:
        print("\nRESULT: PASS (no unwaived privilege widening)")
        return 0
    print("\nRESULT: FAIL -- policy widens agent authority. "
          "Re-review, then waive explicitly with --waive <code>.")
    return 1


def _fuzz(args) -> int:
    policy = load_policy(args.policy)
    bad = 0
    for seed in range(args.iterations):
        if args.concurrent:
            vs = afuzz(policy, rounds=max(1, args.steps // args.batch),
                       batch=args.batch, seed=seed)
        else:
            vs = fuzz(policy, steps=args.steps, seed=seed)
        if vs:
            bad += len(vs)
            print(f"seed {seed}: {len(vs)} invariant violation(s)")
            for v in vs[:5]:
                print(f"   {v.invariant}: {v.detail}")
    print("\nRESULT:", "PASS" if bad == 0 else f"FAIL ({bad} violations)")
    return 0 if bad == 0 else 1


def _audit(args) -> int:
    policy = load_policy(args.policy)
    suites = sorted(Path(args.suites).glob("*.yaml")) if args.suites else []
    report = hunt(policy, suite_paths=suites, baseline=args.baseline)
    print(format_audit(report))
    blocking = report.blocking(args.fail_on)
    if blocking:
        print(f"\nRESULT: FAIL -- {len(blocking)} unaccepted finding(s) at "
              f"{args.fail_on} or above.")
        print("Close them, or add the fingerprint to "
              f"{args.baseline} with a written reason.")
        return 1
    print("\nRESULT: PASS (no new loopholes at "
          f"{args.fail_on} or above)")
    return 0


def _ratify(args) -> int:
    policy = load_policy(args.policy)
    registry, _ = build_fixture_registry(policy)
    con = (Constitution.load(args.constitution) if args.constitution
           else default_constitution())
    violations = con.review(policy, registry)
    if not violations:
        print(f"RESULT: PASS -- '{policy.name}' is ratified under "
              f"constitution v{con.version}")
        return 0
    print(f"'{policy.name}' fails ratification:")
    for v in violations:
        print("  ", v)
    print("\nRESULT: FAIL -- constitutional clauses have no waiver. "
          "Fix the policy, or amend constitution.yaml under review.")
    return 1


def _mcp(args) -> int:
    from aegis.adapters.mcp import (build_registry, load_servers,
                                    synthesize_policy, write_hardened)
    from .loopholes import load_baseline, probe_findings, static_findings
    from .mcp_checks import mcp_findings
    from .report import write_report

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    try:
        servers = _mcp_servers(args, outdir)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not any(s.tools for s in servers):
        print("error: no tools discovered; nothing to audit", file=sys.stderr)
        return 2
    policy = synthesize_policy(servers)
    registry = build_registry(servers)

    findings = (mcp_findings(servers)
                + static_findings(policy, registry)
                + probe_findings(policy, registry))
    report = AuditReport(findings=consolidate(findings),
                         accepted=load_baseline(args.baseline) if args.baseline else {})

    hardened = write_hardened(servers, outdir / "hardened-policy.yaml")
    written = write_report(report, servers, outdir / "audit-report.md",
                           client=args.client, hardened_path=hardened.name)

    print(format_audit(report))
    print(f"\nreport:   {written}")
    print(f"hardened: {hardened}")

    blocking = report.blocking(args.fail_on)
    if blocking:
        print(f"\nRESULT: FAIL -- {len(blocking)} finding(s) at {args.fail_on} or above")
        return 1
    print(f"\nRESULT: PASS")
    return 0


def _mcp_servers(args, outdir: Path):
    """Servers from a saved manifest and/or live endpoints. Live results are
    written to <out>/manifest.json so the audit can be replayed offline and
    baselined without reconnecting."""
    import json
    import os

    from aegis.adapters.mcp import load_servers
    from aegis.adapters.mcp_client import (McpClientError, dedupe_names,
                                           dump_manifest, fetch_http, fetch_stdio)

    servers = list(load_servers(args.manifest)) if args.manifest else []
    headers: dict[str, str] = {}
    for h in args.header or []:
        key, sep, value = h.partition(":")
        if not sep:
            raise ValueError(f"--header expects 'Name: value', got {h!r}")
        headers[key.strip()] = value.strip()
    if args.bearer_env:
        token = os.environ.get(args.bearer_env)
        if not token:
            raise ValueError(f"--bearer-env: ${args.bearer_env} is not set")
        headers["Authorization"] = f"Bearer {token}"

    live = []
    try:
        for url in args.server or []:
            print(f"connecting to {url} ...")
            live.append(fetch_http(url, headers=headers, timeout=args.timeout))
        for cmd in args.server_cmd or []:
            print(f"launching {cmd} ...")
            live.append(fetch_stdio(cmd, timeout=args.timeout))
    except McpClientError as exc:
        raise ValueError(f"live ingest failed: {exc}") from exc

    if live:
        for s in live:
            print(f"  {s.name}: {len(s.tools)} tool(s) via {s.transport}")
        path = outdir / "manifest.json"
        path.write_text(json.dumps(dump_manifest(live), indent=2), encoding="utf-8")
        print(f"  saved {path} (replay with --manifest)")
    if not servers and not live:
        raise ValueError("give --manifest, --server or --server-cmd")
    return dedupe_names(servers + live)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="conformance")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="run conformance scenarios")
    v.add_argument("--suites", default="suites")
    v.add_argument("--root", default=".")
    v.add_argument("--policy", default=None)
    v.add_argument("--require-coverage", action="store_true")
    v.set_defaults(fn=_verify)

    d = sub.add_parser("drift", help="detect privilege widening")
    d.add_argument("--baseline", required=True)
    d.add_argument("--candidate", required=True)
    d.add_argument("--waive", nargs="*", default=[])
    d.set_defaults(fn=_drift)

    f = sub.add_parser("fuzz", help="property-based invariant check")
    f.add_argument("--policy", required=True)
    f.add_argument("--iterations", type=int, default=10)
    f.add_argument("--steps", type=int, default=300)
    f.add_argument("--async", dest="concurrent", action="store_true",
                   help="drive ainvoke/aspawn in concurrent batches, checking "
                        "invariants while calls are in flight")
    f.add_argument("--batch", type=int, default=12,
                   help="operations launched together per round (with --async)")
    f.set_defaults(fn=_fuzz)

    a = sub.add_parser("audit", help="hunt for loopholes")
    a.add_argument("--policy", required=True)
    a.add_argument("--suites", default="suites")
    a.add_argument("--baseline", default="loopholes.baseline.yaml")
    a.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "info"])
    a.set_defaults(fn=_audit)

    r = sub.add_parser("ratify", help="check a policy against the constitution")
    r.add_argument("--policy", required=True)
    r.add_argument("--constitution", default=None)
    r.set_defaults(fn=_ratify)

    m = sub.add_parser("mcp", help="audit MCP servers from a manifest or live endpoint")
    m.add_argument("--manifest", default=None,
                   help="tools/list response, client config, or audit bundle")
    m.add_argument("--server", action="append",
                   help="Streamable HTTP endpoint to handshake with (repeatable)")
    m.add_argument("--server-cmd", action="append",
                   help="stdio server command to launch and handshake with "
                        "(repeatable). This RUNS the command locally.")
    m.add_argument("--header", action="append",
                   help="extra HTTP header for --server, 'Name: value' (repeatable)")
    m.add_argument("--bearer-env", default=None,
                   help="env var holding a bearer token for --server; keeps "
                        "the secret out of shell history")
    m.add_argument("--timeout", type=float, default=15.0)
    m.add_argument("--out", default="audit-out")
    m.add_argument("--client", default="")
    m.add_argument("--baseline", default=None)
    m.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "info"])
    m.set_defaults(fn=_mcp)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
