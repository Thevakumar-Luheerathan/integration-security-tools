import React from "react";

const LEVELS = [
  ["critical", "C"],
  ["high", "H"],
  ["medium", "M"],
  ["low", "L"],
  ["unknown", "U"],
];

// A compact segmented bar: width of each segment is proportional to its share of the total, so
// the shape of a package's risk is visible before reading a single number. Falls back to counts
// alone when everything is zero (an empty bar reads as "nothing", not as a rendering bug).
export default function SeverityBar({counts, compact}) {
  const c = counts || {};
  const total = LEVELS.reduce((sum, [key]) => sum + (c[key] ?? 0), 0);

  return (
    <div className={`sev-bar-wrap${compact ? " compact" : ""}`}>
      {total > 0 && (
        <div className="sev-bar" role="img" aria-label={`${total} findings`}>
          {LEVELS.map(([key, _]) =>
            c[key] ? (
              <span
                key={key}
                className={`sev-bar-seg sev-bar-${key}`}
                style={{flexGrow: c[key]}}
                title={`${c[key]} ${key}`}
              />
            ) : null
          )}
        </div>
      )}
      <span className="sev-bar-counts">
        {LEVELS.filter(([key]) => c[key]).map(([key, label]) => (
          <span key={key} className={`sev-bar-count sev-bar-count-${key}`}>
            {label}:{c[key]}
          </span>
        ))}
        {total === 0 && <span className="sev-bar-count-zero">clean</span>}
      </span>
    </div>
  );
}
