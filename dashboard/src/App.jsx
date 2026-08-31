import React, {useCallback, useEffect, useState} from "react";
import "./App.css";
import {fetchSummary, triggerRefresh} from "./api";
import AcceptedRiskSummary from "./components/AcceptedRiskSummary";
import PackageTable from "./components/PackageTable";
import ThemeToggle from "./components/ThemeToggle";
import useAuth, {login, logout} from "./hooks/useAuth";

// The exact shape of Choreo's /auth/userinfo claims isn't documented beyond "user claims" - try
// the common OIDC/Asgardeo field names and fall back to nothing rather than assume one.
function displayName(user) {
  return user?.username || user?.email || user?.given_name || user?.name || null;
}

// Tab list is data-driven rather than a ternary so adding a source is one entry, not a branch.
// Each entry maps 1:1 onto a dashboard-backend /api/summary field, all four of which are the
// SAME PackageSummary[] shape (see aggregate.bal) - so one PackageTable renders all of them: a
// core language finding, a package, a tool, and a plugin are each structurally the same thing,
// one row sub-grouped by build variant with CVEs nested under that. Order here is the order the
// tabs render in, left to right.
const TABS = [
  {key: "language-core", label: "Language Core", dataKey: "byLanguageCore"},
  {key: "packages", label: "Packages", dataKey: "byPackage"},
  {key: "tools", label: "Tools", dataKey: "byTool"},
  {key: "plugins", label: "Plugins", dataKey: "byPlugin"},
];

function formatTimestamp(iso) {
  if (!iso) return "unknown";
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch {
    return iso;
  }
}

function App() {
  const auth = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState("packages");
  const activeTabDef = TABS.find((t) => t.key === activeTab) ?? TABS[0];

  const load = useCallback(async () => {
    try {
      const summary = await fetchSummary();
      setData(summary);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // No point calling dashboard-backend before we know the visitor is actually logged in -
    // avoids a flash of "loading scan data" behind the sign-in screen.
    if (auth.authenticated) {
      load();
    }
  }, [auth.authenticated, load]);

  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await triggerRefresh();
      // The backend's refresh is itself async (it re-fetches from GitHub), so give it a
      // moment before re-pulling the summary rather than racing it.
      await new Promise((resolve) => setTimeout(resolve, 2000));
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-title">
          <h1>Vulnerability Scan</h1>
          <span className="topbar-sub">Ballerina dependency triage</span>
        </div>
        <div className="topbar-actions">
          <ThemeToggle />
          {auth.authenticated && (
            <>
              {displayName(auth.user) && <span className="user-badge">{displayName(auth.user)}</span>}
              <button className="btn-refresh" onClick={handleRefresh} disabled={refreshing || loading}>
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
              {/* No real session to sign out of in local dev (auth.user is null there - see
                  useAuth's authEnabled bypass), so only show this once there's an actual one. */}
              {auth.user && <button className="btn-signout" onClick={logout}>Sign out</button>}
            </>
          )}
        </div>
      </header>

      {auth.loading && (
        <div className="state-panel">
          <div className="spinner" aria-hidden="true" />
          <p>Checking your session…</p>
        </div>
      )}

      {!auth.loading && !auth.authenticated && (
        <div className="state-panel state-login">
          <p className="state-title">Sign in required</p>
          <p>Sign in with your WSO2 Google Workspace account. Access is limited to the security team.</p>
          <button className="btn-refresh" onClick={login}>Sign in with WSO2</button>
        </div>
      )}

      {!auth.loading && auth.authenticated && loading && (
        <div className="state-panel">
          <div className="spinner" aria-hidden="true" />
          <p>Loading the latest scan…</p>
        </div>
      )}

      {!auth.loading && auth.authenticated && !loading && error && (
        <div className="state-panel state-error">
          <p className="state-title">Couldn't load scan data</p>
          <p>{error}</p>
          <button className="btn-refresh" onClick={load}>Try again</button>
        </div>
      )}

      {!auth.loading && auth.authenticated && !loading && !error && data && (
        <>
          <p className="meta-line">
            Generated {formatTimestamp(data.generatedAt)} &middot; fetched {formatTimestamp(data.fetchedAt)} &middot;{" "}
            <a href={data.runUrl} target="_blank" rel="noreferrer">view pipeline run</a>
          </p>

          {data.stale && (
            <div className="banner stale">
              <strong>This data is stale.</strong> The scan pipeline hasn't refreshed recently -
              it may have failed or not fired. Check the{" "}
              <a href={data.runUrl} target="_blank" rel="noreferrer">last known-good run</a>.
            </div>
          )}

          <AcceptedRiskSummary byLine={data.acceptedRiskByLine} />

          <section className="findings">
            <div className="findings-tabs" role="tablist">
              {TABS.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === t.key}
                  className={`findings-tab${activeTab === t.key ? " active" : ""}`}
                  onClick={() => setActiveTab(t.key)}
                >
                  {t.label} <span className="findings-tab-count">{(data[t.dataKey] ?? []).length}</span>
                </button>
              ))}
            </div>
            {/* ?? [] is load-bearing, not defensive noise: the dashboard and dashboard-backend
                are separate Choreo components deployed independently, so this frontend can and
                will run for a while against a backend whose /api/summary has no byTool field
                yet. Without the fallback that's a hard crash of the whole findings section, not
                a missing tab. */}
            <PackageTable byPackage={data[activeTabDef.dataKey] ?? []} heading={activeTabDef.label} />
          </section>
        </>
      )}
    </div>
  );
}

export default App;
