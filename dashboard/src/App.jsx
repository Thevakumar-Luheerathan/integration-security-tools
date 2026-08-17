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
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === "packages"}
                className={`findings-tab${activeTab === "packages" ? " active" : ""}`}
                onClick={() => setActiveTab("packages")}
              >
                Packages <span className="findings-tab-count">{data.byPackage.length}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === "plugins"}
                className={`findings-tab${activeTab === "plugins" ? " active" : ""}`}
                onClick={() => setActiveTab("plugins")}
              >
                Plugins <span className="findings-tab-count">{data.byPlugin.length}</span>
              </button>
            </div>
            {activeTab === "packages" ? (
              <PackageTable byPackage={data.byPackage} heading="Packages" />
            ) : (
              <PackageTable byPackage={data.byPlugin} heading="Plugins" />
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default App;
