# Releasing

Releases are cut by pushing a tag. Nothing is published from a laptop.

```bash
# 1. bump aegis/__init__.py __version__, move CHANGELOG "Unreleased" under the new version
# 2. merge to main with CI green
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/release.yml` then:

1. checks the tag equals `aegis.__version__` and that `CHANGELOG.md` has an
   entry for it (the entry becomes the GitHub Release notes);
2. builds the sdist and wheel once, runs `twine check`, and runs the **whole
   test suite against the installed wheel** rather than the source tree;
3. signs build provenance for the artifacts;
4. publishes to PyPI via trusted publishing;
5. creates the GitHub Release with the artifacts attached;
6. builds and pushes `ghcr.io/aditya31398/aegis:{X.Y.Z, X.Y, latest}` for
   amd64 and arm64, with an SBOM and signed provenance.

## One-time setup (repository owner)

These need an account holder and cannot be done from CI.

**PyPI trusted publisher.** On https://pypi.org/manage/account/publishing/ add a
*pending* publisher:

| Field | Value |
|---|---|
| PyPI project name | `aegis-guard` |
| Owner | `Aditya31398` |
| Repository | `aegis` |
| Workflow | `release.yml` |
| Environment | `pypi` |

**GitHub environment.** Settings → Environments → New environment `pypi`. Adding
yourself as a required reviewer means every PyPI publish waits for a click,
which is the recommended setting.

**Container visibility.** After the first release, set the `aegis` package on
the GHCR packages page to public so `docker pull` works unauthenticated.

## What counts as breaking

See the preamble of `CHANGELOG.md`. In short: renaming a rule id, changing an
exit code, removing or renaming a JSON field, changing a finding fingerprint,
or removing an export from `aegis/__init__.py`. Before 1.0 these bump the minor
version; after 1.0, the major.
