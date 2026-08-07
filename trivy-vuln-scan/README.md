# trivy-vuln-scan

Proactive Trivy vulnerability scanning across three independent sources, run by
[`trivy-vuln-scan.yml`](../.github/workflows/trivy-vuln-scan.yml):

- **`distribution`** - what ships, built from the `ballerina-lang` release branch per configured
  version line (see [`versions.json`](versions.json)).
- **`central`** - what's published on Ballerina Central (including connectors), latest version
  compatible with each configured line.
- **`vscode-extension`** - the `ballerina-platform/ballerina-vscode` extension, scanned by branch
  (see [`vscode-targets.json`](vscode-targets.json)) rather than by Ballerina version line, since
  its release cadence is independent. Adopts the same two Trivy scans that repo's own pipeline
  runs (an `fs` scan of its npm/pnpm dependencies, an `sbom` scan of its bundled Java language
  server) rather than inventing a new one.

`distribution` and `central` are kept as separate sources - never merged - so a CVE already fixed
on Central but not yet in the next distribution release stays visible as such.

## How it fits together

- [`scripts/central_resolve.py`](scripts/central_resolve.py) / [`bala_scan.py`](scripts/bala_scan.py) -
  resolve and scan Central packages compatible with a given version line.
- [`scripts/combine.py`](scripts/combine.py) - merges every source's per-line/per-branch Trivy
  JSON into one `combined.json`, the contract documented in its module docstring.
- [`scripts/issue_sync.py`](scripts/issue_sync.py) - syncs `combined.json` findings to one GitHub
  issue per package/plugin (see its module docstring for the full lifecycle: closing an issue is
  always a human decision, never auto-reopened).
- [`fixtures/combined.sample.json`](fixtures/combined.sample.json) - a hand-assembled sample
  conforming to that contract, used to develop/test `../dashboard-backend/` independently of a
  real pipeline run (see [`fixtures/README.md`](fixtures/README.md)).

`combined.json` is published as a workflow artifact (`combined-results`) for
[`../dashboard-backend/`](../dashboard-backend/) to pull and serve to
[`../dashboard/`](../dashboard/).

To add a new Ballerina version line or `ballerina-vscode` branch: edit `versions.json` or
`vscode-targets.json` - no workflow changes needed.
