import React, {useEffect, useState} from "react";

const STORAGE_KEY = "vuln-dashboard-theme";

function getInitialTheme() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return null; // follow system preference
}

export default function ThemeToggle() {
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    if (theme) {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem(STORAGE_KEY, theme);
    } else {
      document.documentElement.removeAttribute("data-theme");
      localStorage.removeItem(STORAGE_KEY);
    }
  }, [theme]);

  const systemDark = window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  const effective = theme ?? (systemDark ? "dark" : "light");

  return (
    <button
      className="theme-toggle"
      onClick={() => setTheme(effective === "dark" ? "light" : "dark")}
      title={theme ? `Following manual ${theme} theme - click to switch` : "Following system theme - click to override"}
      aria-label="Toggle color theme"
    >
      {effective === "dark" ? "☾" : "☀"}
    </button>
  );
}
