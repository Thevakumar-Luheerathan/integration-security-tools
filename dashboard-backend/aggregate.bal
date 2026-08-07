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

public function summarizeByVersionAndSource(CombinedReport report) returns VersionSourceSummary[] {
    map<VersionSourceSummary> byKey = {};

    // Seed every (version, source) pair from scan_status FIRST, so a source that scanned
    // clean (zero findings) still appears - the whole point of surfacing scan_status is that
    // "no findings" and "didn't run" must never look identical.
    // "vscode-extension" entries are skipped here - they have no ballerina_version (branch-scoped
    // instead, see plugin_branch), so they don't fit this Ballerina-version-and-source view at
    // all. They're a package/plugin-level concern, not surfaced as a top-level scan lane.
    foreach ScanStatus status in report.scan_status {
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

    foreach Finding f in report.findings {
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

function packageKey(Finding f) returns string {
    return (f.package_org ?: "") + "|" + f.package_name;
}

// Groups a package's findings into VersionGroups per the package -> version -> CVE hierarchy.
// Each version's findings list belongs ONLY to that version - two versions of the same package
// can have genuinely different CVE sets (different build artifacts), so merging them would
// misattribute which CVE applies to which version. Mirrors issue_sync.py's version_groups().
function buildVersionGroups(string packageName, Finding[] findings) returns VersionGroup[] {
    map<Finding[]> byVersionKey = {};
    map<string[]> linesByPkgVersion = {};

    if packageName == "ballerina-lang" {
        foreach Finding f in findings {
            string line = f.ballerina_version ?: "";
            Finding[] existing = byVersionKey[line] ?: [];
            existing.push(f);
            byVersionKey[line] = existing;
        }
        VersionGroup[] groups = [];
        foreach string line in byVersionKey.keys() {
            Finding[] groupFindings = byVersionKey[line] ?: [];
            SeverityCounts counts = {};
            foreach Finding f in groupFindings {
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
        foreach Finding f in findings {
            string branch = f.plugin_branch ?: "";
            Finding[] existing = byVersionKey[branch] ?: [];
            existing.push(f);
            byVersionKey[branch] = existing;
        }
        VersionGroup[] groups = [];
        foreach string branch in byVersionKey.keys() {
            Finding[] groupFindings = byVersionKey[branch] ?: [];
            SeverityCounts counts = {};
            foreach Finding f in groupFindings {
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

    foreach Finding f in findings {
        string pkgVersion = f.package_version ?: "";
        Finding[] existing = byVersionKey[pkgVersion] ?: [];
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
        Finding[] groupFindings = byVersionKey[pkgVersion] ?: [];
        string[] lines = linesByPkgVersion[pkgVersion] ?: [];
        string[] sortedLines = from var l in lines order by l ascending select l;
        SeverityCounts counts = {};
        foreach Finding f in groupFindings {
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

// Shared by summarizeByPackage (excludes "vscode-extension") and summarizeByPlugin (keeps ONLY
// "vscode-extension") - the two views partition report.findings by source so nothing is ever
// double-counted into both the Packages and Plugins tables.
function groupIntoSummaries(Finding[] findings) returns PackageSummary[] {
    map<Finding[]> byPackage = {};
    map<IssueRef?> issueByPackage = {};
    foreach Finding f in findings {
        string key = packageKey(f);
        Finding[] existing = byPackage[key] ?: [];
        existing.push(f);
        byPackage[key] = existing;
        if !issueByPackage.hasKey(key) {
            issueByPackage[key] = f.issue;
        }
    }

    PackageSummary[] result = [];
    foreach string key in byPackage.keys() {
        Finding[] groupFindings = byPackage[key] ?: [];
        if groupFindings.length() == 0 {
            continue;
        }
        Finding first = groupFindings[0];
        VersionGroup[] versions = buildVersionGroups(first.package_name, groupFindings);
        SeverityCounts groupCounts = {};
        foreach Finding f in groupFindings {
            groupCounts = bumpSeverity(groupCounts, f.severity);
        }
        result.push({
            package_org: first.package_org,
            package_name: first.package_name,
            'source: first.'source,
            issue: issueByPackage[key] ?: (),
            counts: groupCounts,
            versions
        });
    }

    return from var p in result
        order by p.counts.critical descending, p.counts.high descending
        select p;
}

public function summarizeByPackage(CombinedReport report) returns PackageSummary[] {
    Finding[] packageFindings = from var f in report.findings where f.'source != "vscode-extension" select f;
    return groupIntoSummaries(packageFindings);
}

// Plugins (currently just ballerina-vscode) get their own top-level view, structurally identical
// to Packages but keyed on the "vscode-extension" source and sub-grouped by scanned branch
// instead of package version - see buildVersionGroups' "ballerina-vscode" branch.
public function summarizeByPlugin(CombinedReport report) returns PackageSummary[] {
    Finding[] pluginFindings = from var f in report.findings where f.'source == "vscode-extension" select f;
    return groupIntoSummaries(pluginFindings);
}

