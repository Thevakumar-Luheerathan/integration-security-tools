# integration-security-tools

Internal security-tooling projects for the Ballerina ecosystem. Each project is its own
top-level folder with its own GitHub Actions workflow (workflows must live at the repo root's
`.github/workflows/` - a GitHub Actions platform constraint, not a per-project choice), and can
reuse the shared dashboard components below rather than building its own.

## Shared components

- **[`dashboard-backend/`](dashboard-backend/)** - Ballerina API service. Pulls a project's
  `combined.json` result artifact from its GitHub Actions workflow, aggregates it, and serves it
  as JSON (`/api/summary`). Stateless - GitHub Issues are the state store, not a database.
  Reused by redeploying it (its own `Config.toml`/Choreo env vars point it at whichever project's
  workflow/artifact it should track) rather than writing a new backend per project.
- **[`dashboard/`](dashboard/)** - React (Vite) frontend consuming `dashboard-backend`'s API.
  Renders findings as a package/plugin tree (name -> version/branch -> CVE), with severity
  counts, tracking-issue links, and a filter. Same reuse model as the backend.

## Projects

- **[`trivy-vuln-scan/`](trivy-vuln-scan/)** - Trivy-based dependency vulnerability scanning
  across the Ballerina distribution, Ballerina Central packages, and the `ballerina-vscode`
  extension. Workflow: [`.github/workflows/trivy-vuln-scan.yml`](.github/workflows/trivy-vuln-scan.yml).

Adding a new project: create its top-level folder, add its workflow under `.github/workflows/`,
and either redeploy `dashboard-backend`/`dashboard` pointed at it, or extend them if the new
project's findings need a different shape than `combined.json` already supports.
