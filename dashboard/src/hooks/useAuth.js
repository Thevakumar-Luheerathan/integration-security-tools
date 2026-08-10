import {useEffect, useState} from "react";

// Choreo's Managed Authentication injects /auth/login, /auth/login/callback, /auth/logout, and
// /auth/userinfo into the DEPLOYED app - none of these exist when running the Vite dev server
// locally. Rather than trying to sniff "does /auth/userinfo exist at all" (a missing route and a
// real "not logged in" response can look similar depending on the dev server's fallback
// behavior - not worth relying on), local dev opts out explicitly via public/config.js's
// authEnabled flag instead. See that file and ../readme.md's "Deploy in Choreo" section.
export default function useAuth() {
  const [state, setState] = useState({loading: true, authenticated: false, user: null});

  useEffect(() => {
    if (window.config?.authEnabled === false) {
      setState({loading: false, authenticated: true, user: null});
      return;
    }

    let cancelled = false;
    fetch("/auth/userinfo")
      .then((res) => (res.ok ? res.json() : Promise.reject(res.status)))
      .then((user) => {
        if (!cancelled) setState({loading: false, authenticated: true, user});
      })
      .catch(() => {
        // Covers both a real 401 (not logged in) and any network-level failure - either way,
        // the safe default is "treat as logged out", never "assume logged in on ambiguity".
        if (!cancelled) setState({loading: false, authenticated: false, user: null});
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}

function readCookie(name) {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

// Full-page redirects to Choreo's injected endpoints - not API calls. Login/logout are
// necessarily whole-page flows (they hand off to the IdP and back), not something to fetch().
export function login() {
  window.location.href = "/auth/login";
}

export function logout() {
  // Choreo's docs are explicit that /auth/logout must be called WITH the session_hint cookie's
  // value as a query param - without it, the IdP's end-session request Choreo forwards is
  // incomplete and gets rejected (observed for real: Asgardeo returned "Sign Out Failure -
  // unauthorized_request - access denied due to invalid request details" when this was missing).
  const sessionHint = readCookie("session_hint");
  window.location.href = sessionHint
    ? `/auth/logout?session_hint=${encodeURIComponent(sessionHint)}`
    : "/auth/logout";
}
