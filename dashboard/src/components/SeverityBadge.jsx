import React from "react";

const KNOWN = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function SeverityBadge({severity}) {
  const s = (severity || "UNKNOWN").toUpperCase();
  const key = KNOWN.includes(s) ? s.toLowerCase() : "unknown";

  return (
    <span className={`sev sev-${key}`}>
      <span className="sev-dot" aria-hidden="true" />
      {s}
    </span>
  );
}
