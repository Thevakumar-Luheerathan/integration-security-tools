// Derived view models, aggregated in aggregate.bal and rendered by the React dashboard - built
// FROM the shared combined.json contract types in modules/model (IssueRef, Finding, ScanStatus,
// CombinedReport, AcceptedRisk), imported below as `model`. Kept in the root module rather than
// modules/model since these are dashboard-rendering-specific and have no reason to be visible to
// the alerting module - see modules/model/types.bal's header comment for why the split exists.
import integration_security_tools/dashboard_backend.model;

// Package summaries use a three-level hierarchy: package -> version -> CVE. A package is one
// row/issue (identity = package_org + package_name, e.g. "ballerinax"/"redis", or package_name
// "ballerina-lang" alone). Each distinct version the package appears at gets its own VersionGroup
// - two versions of the same package can have genuinely different CVE sets (different build
// artifacts), so a version's findings must never be merged into a shared package-level list.

public type SeverityCounts record {|
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
    int unknown = 0;
|};

public type VersionSourceSummary record {|
    string ballerina_version;
    string 'source;
    SeverityCounts counts;
    boolean ok;
    string? statusError;
|};

public type VersionGroup record {|
    string label; // e.g. "2.16.6 (2201.12.x, 2201.13.x)" for a central package, "2201.12.x" for
                  // ballerina-lang, or a branch name (e.g. "main") for ballerina-vscode
    string[] ballerina_versions; // empty for ballerina-vscode - it has no Ballerina version concept
    string? package_version; // null for ballerina-lang and ballerina-vscode
    SeverityCounts counts;
    model:Finding[] findings; // ONLY the findings belonging to THIS version - never merged across versions
|};

// A package can legitimately span MORE than one issue over its life (some CVEs closed in one
// issue, a genuinely new CVE opened in another - see issue_sync.py's lifecycle), so the
// package-level summary is a rollup of counts, not one ambiguous issue link. `openIssue` is
// still surfaced directly since there's realistically at most one open issue per package at a
// time, and it's the one thing worth linking straight to.
public type IssueRollup record {|
    int openCount = 0;
    int closedCount = 0;
    int acceptedRiskCount = 0;
    model:IssueRef? openIssue = ();
|};

// Reused as-is for the "Plugins" view (see summarizeByPlugin) - a plugin (e.g. ballerina-vscode)
// is structurally identical to a package: one row/issue, sub-grouped by build variant (a branch
// instead of a package version), CVEs nested under that. summarizeByPackage and summarizeByPlugin
// partition report.findings by source so a finding is never double-counted into both views.
public type PackageSummary record {|
    string? package_org;
    string package_name;
    string 'source;
    IssueRollup issueSummary;
    SeverityCounts counts; // aggregate across all of this package's versions
    VersionGroup[] versions;
|};

// One row per Ballerina version line, for the dashboard's "Accepted vulnerabilities in each
// Distribution" summary (per the reference design doc) - at-a-glance visibility into how much
// accepted risk exists per line without expanding every package. vscode-extension's accepted-risk
// findings (no ballerina_version) are intentionally excluded - this summary is specifically
// per-Ballerina-line, matching the doc's wording.
public type AcceptedRiskLineSummary record {|
    string ballerina_version;
    int count;
|};
