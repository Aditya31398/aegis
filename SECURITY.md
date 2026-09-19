# Security

## Supported versions

Security fixes land on the latest minor release. Pin an exact version in CI
(`aegis-guard==X.Y.Z`, or the action at `@vX.Y.Z`) and let Dependabot propose
upgrades, so a new check arrives in a reviewed PR.

| Version | Supported |
|---|---|
| 0.2.x | yes |
| < 0.2 | no |

## Verifying what you install

Every release artifact carries signed build provenance from the release
workflow. Verify before deploying:

```bash
gh attestation verify aegis_guard-*.whl --repo Aditya31398/aegis
gh attestation verify oci://ghcr.io/aditya31398/aegis:<version> --repo Aditya31398/aegis
```

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability"
button on the Security tab. Please do not open a public issue first.

If you have found a way to make the kernel execute a tool that the guard chain
denied, that is the highest-severity class of bug in this project and I would
like to hear about it quickly.

## Scope and limits

This project is honest about what it cannot do:

- It cannot stop a model from *attempting* an action. It stops the attempt from
  having an effect.
- Constraints are only as strong as the policy. A tool registered with a loose
  pattern is a hole the kernel will faithfully honour. That is what
  `aegis/conformance/loopholes.py` exists to surface.
- Taint is tracked per grant, not across agents. See the known-weak list in
  `CLAUDE.md`.
- The PII scanner is a backstop, not the primary control. The primary control
  is that an agent never holds the raw callable.

The live MCP client sends only `initialize`, `notifications/initialized` and
`tools/list`; this is enforced in code (`ForbiddenMethod`) and tested. A way to
make it send anything else is in scope and high severity. `--server-cmd`
executes the command you give it, by design.

Findings from the audit tool describe what a *schema* permits. They are not a
penetration test of a running service, and nothing in the audit path executes a
tool against real infrastructure.
