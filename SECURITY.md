# Security

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
  `conformance/loopholes.py` exists to surface.
- Taint is tracked per grant, not across agents. See the known-weak list in
  `CLAUDE.md`.
- The PII scanner is a backstop, not the primary control. The primary control
  is that an agent never holds the raw callable.

Findings from the audit tool describe what a *schema* permits. They are not a
penetration test of a running service, and nothing in the audit path executes a
tool against real infrastructure.
