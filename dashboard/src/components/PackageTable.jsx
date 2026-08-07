import React, {useMemo, useState} from "react";
import SeverityBadge from "./SeverityBadge";
import SeverityBar from "./SeverityBar";

const SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4};
const SEVERITY_RANK = ["critical", "high", "medium", "low"];

function packageDisplayName(pkg) {
  // No org (ballerina-lang, ballerina-vscode) -> name alone; otherwise org/name.
  return pkg.package_org ? `${pkg.package_org}/${pkg.package_name}` : pkg.package_name;
}

function worstSeverity(counts) {
  return SEVERITY_RANK.find((key) => counts?.[key] > 0) ?? null;
}

// Tree connector guides, e.g. "│  │  ├─ " - one segment per ancestor level (a continuing line
// if that ancestor still has siblings below it, blank space if not), then this node's own elbow.
function Guides({ancestorsLast, isLast}) {
  return (
    <span className="guides" aria-hidden="true">
      {ancestorsLast.map((last, i) => (
        <span key={i} className="guide-seg">{last ? "   " : "│  "}</span>
      ))}
      <span className="guide-elbow">{isLast ? "└─ " : "├─ "}</span>
    </span>
  );
}

function matches(term, ...values) {
  return values.filter(Boolean).some((v) => String(v).toLowerCase().includes(term));
}

function findingMatches(term, finding) {
  return matches(term, finding.cve, finding.jar, finding.library_name, finding.severity);
}

function versionMatches(term, version) {
  return matches(term, version.label) || version.findings.some((f) => findingMatches(term, f));
}

function packageMatches(term, pkg) {
  return matches(term, packageDisplayName(pkg)) || pkg.versions.some((v) => versionMatches(term, v));
}

function CveRow({finding, ancestorsLast, isLast}) {
  return (
    <div className="tree-row cve-row" style={{"--spine": `var(--${finding.severity?.toLowerCase() || "unknown"})`}}>
      <div className="tree-cell tree-cell-name">
        <Guides ancestorsLast={ancestorsLast} isLast={isLast} />
        <span className="cve-jar">
          {finding.jar}
          {finding.also_seen_in_jars?.length ? (
            <span className="cve-also"> +{finding.also_seen_in_jars.length} more</span>
          ) : null}
        </span>
      </div>
      <div className="tree-cell tree-cell-detail">
        <span className="cve-id">{finding.cve}</span>
        <SeverityBadge severity={finding.severity} />
        <span className="cve-versions">
          <span className="cve-installed">{finding.installed_version}</span>
          <span className="cve-arrow">&rarr;</span>
          <span className="cve-fixed">{finding.fixed_version || "no fix yet"}</span>
        </span>
      </div>
      <div className="tree-cell tree-cell-issue" />
    </div>
  );
}

function VersionNode({version, ancestorsLast, isLast, forceExpanded, term}) {
  const [expanded, setExpanded] = useState(false);
  const isExpanded = forceExpanded || expanded;

  const directMatches = term ? version.findings.filter((f) => findingMatches(term, f)) : version.findings;
  const displayFindings = term && directMatches.length === 0 ? version.findings : directMatches;
  const rows = [...displayFindings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  const spine = worstSeverity(version.counts);

  return (
    <>
      <div
        className="tree-row version-row"
        style={spine ? {"--spine": `var(--${spine})`} : undefined}
        onClick={() => setExpanded((e) => !e)}
      >
        <div className="tree-cell tree-cell-name">
          <Guides ancestorsLast={ancestorsLast} isLast={isLast} />
          <span className={`chevron${isExpanded ? " chevron-open" : ""}`} aria-hidden="true" />
          <span className="version-label">{version.label}</span>
        </div>
        <div className="tree-cell tree-cell-detail">
          <SeverityBar counts={version.counts} compact />
          <span className="version-cve-count">
            {rows.length === version.findings.length ? `${version.findings.length} CVE${version.findings.length === 1 ? "" : "s"}` : `${rows.length} / ${version.findings.length} match`}
          </span>
        </div>
        <div className="tree-cell tree-cell-issue" />
      </div>
      {isExpanded &&
        rows.map((f, i) => (
          <CveRow
            key={`${f.cve}|${f.jar}|${i}`}
            finding={f}
            ancestorsLast={[...ancestorsLast, isLast]}
            isLast={i === rows.length - 1}
          />
        ))}
    </>
  );
}

function PackageNode({pkg, isLast, forceExpanded, term}) {
  const [expanded, setExpanded] = useState(false);
  const isExpanded = forceExpanded || expanded;
  const versions = [...pkg.versions].sort((a, b) => a.label.localeCompare(b.label));
  const spine = worstSeverity(pkg.counts);

  return (
    <div className="tree-package">
      <div
        className="tree-row package-row"
        style={spine ? {"--spine": `var(--${spine})`} : undefined}
        onClick={() => setExpanded((e) => !e)}
      >
        <div className="tree-cell tree-cell-name">
          <span className={`chevron${isExpanded ? " chevron-open" : ""}`} aria-hidden="true" />
          <span className="package-name">{packageDisplayName(pkg)}</span>
        </div>
        <div className="tree-cell tree-cell-detail">
          <SeverityBar counts={pkg.counts} />
        </div>
        <div className="tree-cell tree-cell-issue">
          {pkg.issue && pkg.issue.url ? (
            <a href={pkg.issue.url} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()} className={`issue-pill issue-${pkg.issue.state}`}>
              #{pkg.issue.number} &middot; {pkg.issue.state}
            </a>
          ) : (
            <span className="issue-pill issue-none">no issue yet</span>
          )}
        </div>
      </div>
      {isExpanded &&
        versions.map((v, i) => (
          <VersionNode
            key={v.label}
            version={v}
            ancestorsLast={[]}
            isLast={i === versions.length - 1}
            forceExpanded={forceExpanded}
            term={term}
          />
        ))}
    </div>
  );
}

export default function PackageTable({byPackage, heading = "Packages"}) {
  const [filter, setFilter] = useState("");
  const term = filter.trim().toLowerCase();
  const headingLower = heading.toLowerCase();

  const rows = useMemo(() => {
    const filtered = term ? byPackage.filter((p) => packageMatches(term, p)) : byPackage;
    return [...filtered].sort((a, b) => {
      const rankA = SEVERITY_RANK.indexOf(worstSeverity(a.counts) ?? "zzz");
      const rankB = SEVERITY_RANK.indexOf(worstSeverity(b.counts) ?? "zzz");
      const normA = rankA === -1 ? 99 : rankA;
      const normB = rankB === -1 ? 99 : rankB;
      if (normA !== normB) return normA - normB;
      return (b.counts.critical + b.counts.high) - (a.counts.critical + a.counts.high);
    });
  }, [byPackage, term]);

  return (
    <section className="tree-section">
      <input
        type="text"
        placeholder="Filter by name, version, CVE, or jar…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="filter-input"
      />
      {rows.length === 0 ? (
        <p className="empty-note">No {headingLower} match &ldquo;{filter}&rdquo;. Try a name, CVE ID, or jar filename.</p>
      ) : (
        <div className="tree" role="table">
          <div className="tree-header" role="row">
            <div className="tree-cell tree-cell-name">{heading.replace(/s$/, "")}</div>
            <div className="tree-cell tree-cell-detail">Severity</div>
            <div className="tree-cell tree-cell-issue">Issue</div>
          </div>
          {rows.map((p, i) => (
            <PackageNode
              key={`${p.package_org ?? ""}|${p.package_name}`}
              pkg={p}
              isLast={i === rows.length - 1}
              forceExpanded={!!term}
              term={term}
            />
          ))}
        </div>
      )}
    </section>
  );
}
