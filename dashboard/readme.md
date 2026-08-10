# Security Findings Dashboard (React)

A React frontend for the proactive Ballerina vulnerability scan pipeline (Phase 1 - see
[wso2-enterprise/integration-engineering#2164](https://github.com/wso2-enterprise/integration-engineering/issues/2164)).
It renders the same views the pipeline used to serve as static HTML - summary by version and
source, "fixed on Central, pending in distribution", per-repo breakdown, and a filterable list
of every finding - by consuming the JSON API exposed by the separate `dashboard-backend`
Ballerina service (`../dashboard-backend`). Built for the `trivy-vuln-scan` pipeline's data today,
but structured to be reused by future security-tool projects in this repo that produce the same
`combined.json`/summary contract.

Built with [Vite](https://vitejs.dev/) rather than Create React App: same React code the
[wso2/choreo-samples `react-single-page-app`](https://github.com/wso2/choreo-samples/tree/main/react-single-page-app)
reference uses, but CRA's `react-scripts` toolchain is unmaintained and pulled in 28 known
vulnerabilities (14 high) at `npm install` time - Vite's equivalent toolchain has 2 (both
dev-server-only, not present in the production build). Choreo's React buildpack only needs
`npm run build` to produce a static output directory; it doesn't require CRA specifically.

## Deploy in Choreo

- Fork this repository (or point Choreo at your own copy).
- Create a **Web Application** component in Choreo, using:

| Setting | Value |
|---|---|
| Build Pack | React |
| Project Directory | `dashboard` |
| Build Command | `npm run build` |
| Build output directory | `dist` |
| Node Version | `20` |

- Add a **File Mount** on the component (Deploy page, per environment), at the path where the
  built `index.html` expects to find it - i.e. alongside `index.html` in the build output
  (`dist/config.js`). Content:
  ```js
  window.config = {
    apiUrl: "https://<the deployed dashboard-backend service URL>",
  };
  ```
  This isn't a build-time env var - Choreo doesn't support baking in env vars for SPAs, since the
  same built artifact is meant to be promoted dev -> staging -> prod. `public/config.js` (copied
  verbatim into the build output by Vite) ships a localhost placeholder; the File Mount overwrites
  it per environment at deploy time, without a rebuild. See `public/config.js` and `index.html`
  for how it's wired in, and note it's visible to anyone opening browser devtools - fine for a
  base URL, not for secrets.
- On the `dashboard-backend` Service component, set its `allowOrigins` configurable (in
  `Config.toml` or Choreo's environment variable equivalent) to this web app's actual deployed
  origin once known, narrowing it from the permissive `["*"]` default. Set its endpoint
  **visibility to `Project`** (not `Organization`/`Public`) - this is what actually keeps it
  unreachable from the public internet; login below only gates this web app, not the API's
  network reachability.

### Restricting access to your team (Managed Authentication + Asgardeo)

This dashboard is meant to be login-gated, not public. One-time setup, outside this repo:

1. **Asgardeo** (asgardeo.io console): register a Standard-Based OIDC application, set its
   authorized redirect URLs to `https://<this-app's-deployed-url>/auth/login/callback` and
   `.../auth/logout/callback`, grant types `Code` + `Refresh Token`, access token type `JWT`.
   Create a group for your team (e.g. `security-dashboard-users`), add members, and apply the
   **Group-Based Access Control** conditional-auth template so login only *completes* for group
   members - not just anyone with an Asgardeo account.
2. **Choreo org settings** (one-time, applies to every project in the org): Settings ->
   Organization -> Application Security -> Identity Providers -> + Identity Provider -> Asgardeo
   -> paste the application's well-known/discovery URL from step 1.
3. **This component's Deploy page**: enable "Managed Authentication with Choreo", select the
   Asgardeo identity provider, set Post Login/Logout/Error paths and session expiry.

Once enabled, Choreo injects `/auth/login`, `/auth/logout`, and `/auth/userinfo` into the deployed
app - `src/hooks/useAuth.js` is what calls `/auth/userinfo` to decide whether to render the
dashboard or a sign-in prompt. No token handling happens in this app's own code: Choreo's
managed-auth layer keeps tokens out of browser JS entirely (HTTP-only session cookies), and the
existing Connection to `dashboard-backend` gets the cookie swapped for a real token server-side -
nothing in `src/api.js` needs to change for this.

## Local development

```bash
npm install
# edit public/config.js if your local dashboard-backend isn't on the default localhost:9090
npm run dev                  # dev server with hot reload
npm run build                # production build -> dist/
```

`/auth/*` doesn't exist under `vite dev` (it's a layer Choreo injects only once deployed) -
`public/config.js`'s `authEnabled: false` bypasses the login check locally. Never set that to
`false` in a deployed environment's File Mount.
