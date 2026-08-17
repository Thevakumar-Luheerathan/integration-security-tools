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

- Add a **Connection** from this component to `dashboard-backend` (Deploy page ->
  Dependencies/Connections -> Create Connection -> select the `dashboard-backend` service).
  Choreo generates and injects a `config.js` for you, containing a relative path proxied through
  to the backend:
  ```js
  window.configs = {
    apiUrl: "/choreo-apis/default/dashboard-backend/v1",
  };
  ```
  **The global is `window.configs` (plural)** - that's Choreo's own naming for this feature, not
  ours; `src/api.js` and `src/hooks/useAuth.js` read that exact name. This relative-path form is
  what actually makes a `Project`-visibility backend (see below) reachable from the browser at
  all - the browser calls this app's own origin, and Choreo's edge proxies it through internally;
  a `dashboard-backend` with `Project` visibility has no publicly-resolvable URL of its own to put
  in a plain File Mount instead.
  - If you set this up manually as a File Mount rather than via Connections, the content must
    still assign to `window.configs`, at the path where the built `index.html` expects to find it
    (alongside `index.html` in the build output - `dist/config.js`). This isn't a build-time env
    var either way - Choreo doesn't support baking in env vars for SPAs, since the same built
    artifact is meant to be promoted dev -> staging -> prod. `public/config.js` (copied verbatim
    into the build output by Vite) ships a localhost placeholder that gets overwritten at deploy
    time, without a rebuild - see `public/config.js` and `index.html` for how it's wired in, and
    note its content is visible to anyone opening browser devtools - fine for a URL, not secrets.
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

### Sign-in provider: Google (WSO2 Workspace accounts), curated to specific users

The "Sign in with WSO2" button signs in via Google - specifically, real `@wso2.com` Google
Workspace accounts - rather than Asgardeo's own local username/password form. This is entirely an
Asgardeo/Google Cloud console configuration; nothing in `useAuth.js`'s parameterless
`/auth/login` redirect needs to know which upstream provider is involved.

**Google Cloud Console** (one-time): create an OAuth client (Web application type), set its
consent screen's User type to **Internal** if the Cloud project belongs to the wso2.com Workspace
- this makes Google itself refuse the consent screen for any non-wso2.com account, a real
restriction enforced by Google before Asgardeo is even involved.

**Asgardeo Console** (one-time, on the org this app's application lives in):
1. **Connections -> New Connection -> Google**: paste the Client ID/Secret from the Google Cloud
   client above. Asgardeo shows its own redirect URI (a single per-organization
   `https://api.asgardeo.io/t/<org>/commonauth`) - paste that back into the Google Cloud client.
2. **Applications -> (this dashboard's app) -> Login Flow**: add the Google connection as the
   sole sign-in step (remove/don't add Asgardeo's local username/password option alongside it,
   since the button now explicitly promises "WSO2").
3. **User Management -> Users**: create (or reuse) a local Asgardeo user for each specific person
   who should have access, with their email attribute set to their real `@wso2.com` Google
   address - this exact match is what step 5 below links against.
4. **User Management -> Groups**, **Roles**, and **conditional-authentication scripting** were the
   originally-planned mechanism for restricting to a specific group, but conditional-auth
   scripting turned out to be gated behind Asgardeo's **Enterprise** plan - not available on a
   Growth trial. The actual working mechanism ended up being step 5 instead, which needs no paid
   upgrade.
5. **Connections -> Google -> Advanced tab**: check **"Just-in-Time (JIT) User Provisioning"**,
   then check **"Enable local account linking"**, then check the sub-option **"Skip user
   provisioning when no local account is found"** (this is the actual gate - leave the "Link
   account if" rule unset, since Asgardeo's own inline text confirms email is the default match
   rule when no explicit rule is set). Net effect: a Google login whose email matches one of the
   local users from step 3 gets linked to that existing account and lets them in; anyone else -
   `@wso2.com` or not - has no local account to link to and is skipped entirely, no new account
   auto-created. That's the actual "only a specific set of users" gate, confirmed via the
   console's own UI copy - **not** the group/role-based approach originally assumed, which needs
   Enterprise. (A tempting-looking alternative - "just turn JIT off, keep linking on" - does
   **not** work: the "Enable local account linking" option itself disappears from the console
   entirely when JIT is off, and Asgardeo's own AI assistant confirmed JIT+linking-without-the-
   skip-option still auto-creates an account for any non-matching login.)

## Local development

```bash
npm install
# edit public/config.js if your local dashboard-backend isn't on the default localhost:9090
npm run dev                  # dev server with hot reload
npm run build                # production build -> dist/
```

`/auth/*` doesn't exist under `vite dev` (it's a layer Choreo injects only once deployed) -
`public/config.js`'s `authEnabled: false` bypasses the login check locally. Never set that to
`false` in a deployed environment - a Connection-generated `config.js` won't include the key at
all (which already means "enforced"), so this only matters if you're hand-writing a File Mount.
