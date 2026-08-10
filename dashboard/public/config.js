// Runtime configuration, read by src/api.js via `window.configs`. The name is plural - that's not
// a typo, it's the exact global Choreo's own Connections feature writes (see its "Add Connection
// Configuration" docs: `window.configs = { apiUrl: '...' }`), so this app has to read the same
// name Choreo actually injects, not an arbitrary one of our own choosing.
//
// Deliberately NOT baked in by Vite at build time - Choreo Web Application (SPA) components
// don't support build-time environment variables (the same built artifact is promoted
// dev -> staging -> prod), so this file is instead overwritten at deploy time, per environment -
// either by a Connection (Choreo generates the content, see ../readme.md) or a manual File Mount.
// Vite copies files under public/ verbatim into the build output, so this ships as a plain,
// unbundled /config.js next to index.html - see index.html's <script src="/config.js"> (loaded
// before the app bundle).
//
// This checked-in copy is only the local-dev default, pointing at dashboard-backend's default port
// (see ../../dashboard-backend/main.bal's `configurable int port = 9090`).
//
// authEnabled: false is also local-dev-only. Choreo's Managed Authentication
// (/auth/login, /auth/logout, /auth/userinfo) is a layer Choreo injects only once deployed - it
// doesn't exist under `vite dev`, so src/hooks/useAuth.js reads this flag to bypass the login
// check entirely rather than trying to detect a missing route. Never set this to false in a
// deployed environment's config - a Connection-generated config.js won't include it at all
// (which already means "enforced"), and a manual File Mount should likewise omit it.
window.configs = {
  apiUrl: "http://localhost:9090",
  authEnabled: false,
};
