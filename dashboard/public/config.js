// Runtime configuration, read by src/api.js via `window.config`. Deliberately NOT baked in by
// Vite at build time - Choreo Web Application (SPA) components don't support build-time
// environment variables (the same built artifact is promoted dev -> staging -> prod), so this
// file is instead overwritten by a Choreo File Mount at deploy time, per environment. Vite copies
// files under public/ verbatim into the build output, so this ships as a plain, unbundled
// /config.js next to index.html - see index.html's <script src="/config.js"> (loaded before the
// app bundle) and ../readme.md's "Deploy in Choreo" section.
//
// This checked-in copy is only the local-dev default, pointing at dashboard-backend's default port
// (see ../../dashboard-backend/main.bal's `configurable int port = 9090`).
window.config = {
  apiUrl: "http://localhost:9090",
};
