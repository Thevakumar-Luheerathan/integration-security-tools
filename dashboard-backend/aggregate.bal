import integration_security_tools/dashboard_backend.model;

// Pure aggregation logic over a CombinedReport - no I/O, so this is the easiest part of the
// service to unit-test directly (see tests/aggregate_test.bal).

function bumpSeverity(SeverityCounts counts, string severity) returns SeverityCounts {
    SeverityCounts updated = counts.clone();
    string s = severity.toUpperAscii();
    if s == "CRITICAL" {
        updated.critical += 1;
    } else if s == "HIGH" {
        updated.high += 1;
    } else if s == "MEDIUM" {
        updated.medium += 1;
    } else if s == "LOW" {
        updated.low += 1;
    } else {
        updated.unknown += 1;
    }
    return updated;
}

public function summarizeByVersionAndSource(model:CombinedReport report) returns VersionSourceSummary[] {
    map<VersionSourceSummary> byKey = {};

    // Seed every (version, source) pair from scan_status FIRST, so a source that scanned
    // clean (zero findings) still appears - the whole point of surfacing scan_status is that
    // "no findings" and "didn't run" must never look identical.
    // "vscode-extension" entries are skipped here - they have no ballerina_version (branch-scoped
    // instead, see plugin_branch), so they don't fit this Ballerina-version-and-source view at
    // all. They're a package/plugin-level concern, not surfaced as a top-level scan lane.
    foreach model:ScanStatus status in report.scan_status {
        string? line = status.ballerina_version;
        if line is () {
            continue;
        }
        string key = line + "|" + status.'source;
        byKey[key] = {
            ballerina_version: line,
            'source: status.'source,
            counts: {},
            ok: status.ok,
            statusError: status.'error
        };
    }

    foreach model:Finding f in report.findings {
        string? line = f.ballerina_version;
        if line is () {
            continue;
        }
        string key = line + "|" + f.'source;
        VersionSourceSummary? existing = byKey[key];
        VersionSourceSummary current = existing ?: {
            ballerina_version: line,
            'source: f.'source,
            counts: {},
            ok: true,
            statusError: ()
        };
        current.counts = bumpSeverity(current.counts, f.severity);
        byKey[key] = current;
    }

    VersionSourceSummary[] result = byKey.toArray();
    result = from var s in result
        order by s.ballerina_version descending, s.'source ascending
        select s;
    return result;
}

function packageKey(model:Finding f) returns string {
    return (f.package_org ?: "") + "|" + f.package_name;
}

// Groups a package's findings into VersionGroups per the package -> version -> CVE hierarchy.
// Each version's findings list belongs ONLY to that version - two versions of the same package
// can have genuinely different CVE sets (different build artifacts), so merging them would
// misattribute which CVE applies to which version. Mirrors issue_sync.py's version_groups().
function buildVersionGroups(string packageName, model:Finding[] findings) returns VersionGroup[] {
    map<model:Finding[]> byVersionKey = {};
    map<string[]> linesByPkgVersion = {};

    if packageName == "ballerina-lang" {
        foreach model:Finding f in findings {
            string line = f.ballerina_version ?: "";
            model:Finding[] existing = byVersionKey[line] ?: [];
            existing.push(f);
            byVersionKey[line] = existing;
        }
        VersionGroup[] groups = [];
        foreach string line in byVersionKey.keys() {
            model:Finding[] groupFindings = byVersionKey[line] ?: [];
            SeverityCounts counts = {};
            foreach model:Finding f in groupFindings {
                counts = bumpSeverity(counts, f.severity);
            }
            groups.push({
                label: line,
                ballerina_versions: [line],
                package_version: (),
                counts,
                findings: groupFindings
            });
        }
        return from var g in groups order by g.label ascending select g;
    }

    if packageName == "ballerina-vscode" {
        // No Ballerina version concept at all here - grouped by the scanned branch instead
        // (plugin_branch), one VersionGroup per branch, same "never merge across variants"
        // discipline as the ballerina-lang/central cases above.
        foreach model:Finding f in findings {
            string branch = f.plugin_branch ?: "";
            model:Finding[] existing = byVersionKey[branch] ?: [];
            existing.push(f);
            byVersionKey[branch] = existing;
        }
        VersionGroup[] groups = [];
        foreach string branch in byVersionKey.keys() {
            model:Finding[] groupFindings = byVersionKey[branch] ?: [];
            SeverityCounts counts = {};
            foreach model:Finding f in groupFindings {
                counts = bumpSeverity(counts, f.severity);
            }
            groups.push({
                label: branch,
                ballerina_versions: [],
                package_version: (),
                counts,
                findings: groupFindings
            });
        }
        return from var g in groups order by g.label ascending select g;
    }

    foreach model:Finding f in findings {
        string pkgVersion = f.package_version ?: "";
        model:Finding[] existing = byVersionKey[pkgVersion] ?: [];
        existing.push(f);
        byVersionKey[pkgVersion] = existing;

        // Central-package findings always carry ballerina_version - only vscode-extension
        // findings omit it, and those never reach this branch (handled above).
        string line = f.ballerina_version ?: "";
        string[] lines = linesByPkgVersion[pkgVersion] ?: [];
        if lines.indexOf(line) is () {
            lines.push(line);
        }
        linesByPkgVersion[pkgVersion] = lines;
    }

    VersionGroup[] groups = [];
    foreach string pkgVersion in byVersionKey.keys() {
        model:Finding[] groupFindings = byVersionKey[pkgVersion] ?: [];
        string[] lines = linesByPkgVersion[pkgVersion] ?: [];
        string[] sortedLines = from var l in lines order by l ascending select l;
        SeverityCounts counts = {};
        foreach model:Finding f in groupFindings {
            counts = bumpSeverity(counts, f.severity);
        }
        groups.push({
            label: string `${pkgVersion} (${string:'join(", ", ...sortedLines)})`,
            ballerina_versions: sortedLines,
            package_version: pkgVersion,
            counts,
            findings: groupFindings
        });
    }
    return from var g in groups order by g.label ascending select g;
}

// A package can legitimately span more than one issue over its life (see issue_sync.py's
// lifecycle - a closed issue's CVEs never get reopened, but a genuinely new CVE for the same
// package gets its own fresh issue), so this counts per FINDING (per CVE), not per distinct
// issue number - matching how severity counts already work. `openIssue` still surfaces the one
// open issue directly (realistically at most one per package at a time) for a direct link.
function computeIssueRollup(model:Finding[] findings) returns IssueRollup {
    IssueRollup rollup = {};
    foreach model:Finding f in findings {
        if f.accepted_risk is model:AcceptedRisk {
            rollup.acceptedRiskCount += 1;
            continue;
        }
        model:IssueRef? issue = f.issue;
        if issue is model:IssueRef {
            if issue.state == "open" {
                rollup.openCount += 1;
                rollup.openIssue = issue;
            } else if issue.state == "closed" {
                rollup.closedCount += 1;
            }
        }
    }
    return rollup;
}

// Shared by summarizeByPackage (excludes "vscode-extension") and summarizeByPlugin (keeps ONLY
// "vscode-extension") - the two views partition report.findings by source so nothing is ever
// double-counted into both the Packages and Plugins tables.
function groupIntoSummaries(model:Finding[] findings) returns PackageSummary[] {
    map<model:Finding[]> byPackage = {};
    foreach model:Finding f in findings {
        string key = packageKey(f);
        model:Finding[] existing = byPackage[key] ?: [];
        existing.push(f);
        byPackage[key] = existing;
    }

    PackageSummary[] result = [];
    foreach string key in byPackage.keys() {
        model:Finding[] groupFindings = byPackage[key] ?: [];
        if groupFindings.length() == 0 {
            continue;
        }
        model:Finding first = groupFindings[0];
        VersionGroup[] versions = buildVersionGroups(first.package_name, groupFindings);
        SeverityCounts groupCounts = {};
        foreach model:Finding f in groupFindings {
            groupCounts = bumpSeverity(groupCounts, f.severity);
        }
        result.push({
            package_org: first.package_org,
            package_name: first.package_name,
            'source: first.'source,
            issueSummary: computeIssueRollup(groupFindings),
            counts: groupCounts,
            versions
        });
    }

    return from var p in result
        order by p.counts.critical descending, p.counts.high descending
        select p;
}

public function summarizeByPackage(model:CombinedReport report) returns PackageSummary[] {
    model:Finding[] packageFindings = from var f in report.findings where f.'source != "vscode-extension" select f;
    return groupIntoSummaries(packageFindings);
}

// Plugins (currently just ballerina-vscode) get their own top-level view, structurally identical
// to Packages but keyed on the "vscode-extension" source and sub-grouped by scanned branch
// instead of package version - see buildVersionGroups' "ballerina-vscode" branch.
public function summarizeByPlugin(model:CombinedReport report) returns PackageSummary[] {
    model:Finding[] pluginFindings = from var f in report.findings where f.'source == "vscode-extension" select f;
    return groupIntoSummaries(pluginFindings);
}

// "Accepted vulnerabilities in each Distribution" - the reference design doc's explicit ask for
// a per-line rollup, distinct from the inline per-package/per-CVE display (see PackageSummary's
// issueSummary.acceptedRiskCount and each Finding's own accepted_risk). Scoped to Ballerina
// version lines only - vscode-extension's accepted-risk findings have no ballerina_version and
// are intentionally excluded here, matching the doc's per-Distribution wording.
public function summarizeAcceptedRiskByLine(model:CombinedReport report) returns AcceptedRiskLineSummary[] {
    map<int> countByLine = {};
    foreach model:Finding f in report.findings {
        string? line = f.ballerina_version;
        if f.accepted_risk is model:AcceptedRisk && line is string {
            countByLine[line] = (countByLine[line] ?: 0) + 1;
        }
    }
    AcceptedRiskLineSummary[] result = [];
    foreach string line in countByLine.keys() {
        result.push({ballerina_version: line, count: countByLine[line] ?: 0});
    }
    return from var s in result order by s.ballerina_version ascending select s;
}

