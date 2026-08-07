// Talks to the Ballerina dashboard API (a separate Choreo Service component - see
// ../dashboard-backend/main.bal's GET /api/summary). The base URL comes from
// window.config (see public/config.js), a plain unbundled file loaded before this module -
// Choreo Web Application (SPA) components don't support build-time environment variables (the
// same built artifact is promoted across environments), so the URL is instead injected at deploy
// time via a Choreo File Mount overwriting that file, per environment.
const API_BASE_URL = window.config?.apiUrl || "";

export async function fetchSummary() {
  if (!API_BASE_URL) {
    throw new Error(
      "window.config.apiUrl is not set - see public/config.js. In Choreo, this is set via a " +
        "File Mount pointing at the deployed dashboard-backend service's URL."
    );
  }
  const response = await fetch(`${API_BASE_URL}/api/summary`);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`API returned ${response.status}: ${body || response.statusText}`);
  }
  return response.json();
}

export async function triggerRefresh() {
  const response = await fetch(`${API_BASE_URL}/refresh`, {method: "POST"});
  if (!response.ok) {
    throw new Error(`Refresh request returned ${response.status}`);
  }
  return response.json();
}
