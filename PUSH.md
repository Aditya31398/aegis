# Publishing this repo

The repo is initialised with one commit on `main`. To put it on GitHub:

```bash
# with the GitHub CLI (easiest)
gh auth login
gh repo create aegis --public --source=. --remote=origin \
   --description "Capability-based constraint enforcement for AI agents, with a regression suite that hunts its own loopholes" \
   --push

# or manually: create an empty public repo on github.com, then
git remote add origin git@github.com:<you>/aegis.git
git push -u origin main
```

Then, in this order:

1. Replace `OWNER` with your GitHub handle in `pyproject.toml` (two URLs) and
   `action.yml` (the pip install line). Both are placeholders.
2. Settings → General → enable Issues and Discussions.
3. Settings → Branches → protect `main`, require the `gate` check.
4. Add topics: `ai-agents`, `mcp`, `ai-security`, `guardrails`, `llm-security`,
   `model-context-protocol`. Topics are most of how people find a repo like this.
5. Paste `ROADMAP.md` items in as issues and label the first four
   `good first issue`.
6. Push a `v0.1.0` tag so the composite action can be pinned:
   `git tag v0.1.0 && git push --tags`

## Before you publish the audit report as a sales asset

`examples/sample-audit-output/audit-report.md` is generated from a fictional
manifest, so it is safe to publish as-is. If you run an audit against a real
company's servers, do not publish it without written permission, and strip the
`--client` name and any witness strings containing their data.
