import React from "react";

// "Accepted vulnerabilities in each Distribution" - per the reference design doc, a small
// at-a-glance rollup distinct from the inline per-package/per-CVE display (see PackageTable's
// FindingStateBadge/PackageIssueRollup) - lets you see how much accepted risk exists per line
// without expanding a single package.
export default function AcceptedRiskSummary({byLine}) {
  if (!byLine || byLine.length === 0) {
    return null;
  }

  return (
    <section className="accepted-risk-summary">
      <span className="accepted-risk-summary-label">Accepted risk</span>
      {byLine.map((line) => (
        <span key={line.ballerina_version} className="accepted-risk-summary-item">
          <span className="accepted-risk-summary-count">{line.count}</span>
          <span className="accepted-risk-summary-version">{line.ballerina_version}</span>
        </span>
      ))}
    </section>
  );
}
