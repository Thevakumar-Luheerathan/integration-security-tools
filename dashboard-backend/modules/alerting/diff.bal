// Pure diff logic between two CombinedReport snapshots - no I/O, easy to unit test directly (see
// tests/diff_test.bal). This keeps alerting stateless (per the approved plan: "no database - all
// state lives in GitHub Issues or is derived by diffing consecutive artifacts"): comparing this
// refresh's cached snapshot against the previous one, both already held in dashboard-backend's
// own in-memory cache (see ../../ingest.bal), needs nothing persisted anywhere beyond that.
//
// Moved from the standalone choreo-alerting Choreo component into dashboard-backend as a module
// (per the approved plan's "Alerting merge" section) - reuses dashboard-backend's own Finding/
// CombinedReport/ScanStatus types directly (see the `db` import) instead of choreo-alerting's
// separate duplicated copies, since they now live in the same package.

import integration_security_tools/dashboard_backend.model as db;
import ballerina/time;

// Identity key for "is this the same underlying vulnerability" across two runs. Deliberately
// excludes package_version and jar: if ballerina/http bumps from 2.14.13 to 2.14.14 between runs
// but the same CVE is still open against it, that's the SAME open finding continuing, not a new
// one - re-alerting on every routine version bump would train people to ignore alerts, exactly
// the failure mode this whole project exists to fix. Keys on package identity (package_org,
// package_name) rather than a resolved repo, matching combine.py - there is no repo-resolution
// step in this pipeline at all.
function findingKey(db:Finding f) returns string {
    return string `${f.ballerina_version ?: ""}|${f.'source}|${f.package_org ?: ""}|${f.package_name}|${f.cve}`;
}

public type Transition record {|
    db:Finding finding;
    // "new" - didn't exist in the previous snapshot at all. Kept as a distinct tag (rather than
    // just returning Finding[]) for when/if a longer history than 2 snapshots is ever compared.
    string kind;
|};

public function diffFindings(db:Finding[] previous, db:Finding[] current) returns Transition[] {
    map<boolean> previousKeys = {};
    foreach db:Finding f in previous {
        previousKeys[findingKey(f)] = true;
    }

    Transition[] result = [];
    foreach db:Finding f in current {
        if !previousKeys.hasKey(findingKey(f)) {
            result.push({finding: f, kind: "new"});
        }
    }
    return result;
}

// Excludes accepted_risk findings - those are pre-triaged at scan time (a documented .trivyignore
// decision, see combine.py), so a "new" one appearing is never an unattended surprise the way a
// new untriaged CRITICAL/HIGH is. Alerting on them would just be noise about a decision that was
// already made deliberately upstream.
public function newCriticalOrHigh(Transition[] transitions) returns db:Finding[] {
    db:Finding[] result = [];
    foreach var t in transitions {
        if t.finding.accepted_risk is db:AcceptedRisk {
            continue;
        }
        string s = t.finding.severity.toUpperAscii();
        if s == "CRITICAL" || s == "HIGH" {
            result.push(t.finding);
        }
    }
    return result;
}

// ALL currently-failing scans, not just newly-failing ones - used by the weekly digest, which
// intentionally reports full standing state regardless of what changed since last time.
public function failedScanStatuses(db:CombinedReport report) returns db:ScanStatus[] {
    return from var s in report.scan_status
        where !s.ok
        select s;
}

function scanStatusKey(db:ScanStatus s) returns string {
    return string `${s.ballerina_version ?: ""}|${s.plugin_branch ?: ""}|${s.'source}`;
}

// Only scans that transitioned from ok to failing since the previous snapshot - a scan that was
// ALREADY failing last cycle must not re-alert every subsequent cycle it stays broken (per the
// approved plan: immediate alerts fire "only on the transition into that state, never on every
// cycle it persists"). The weekly digest is what surfaces a standing failure long-term.
public function newlyFailedScanStatuses(db:CombinedReport previous, db:CombinedReport current) returns db:ScanStatus[] {
    map<boolean> previousFailedKeys = {};
    foreach var s in previous.scan_status {
        if !s.ok {
            previousFailedKeys[scanStatusKey(s)] = true;
        }
    }
    db:ScanStatus[] result = [];
    foreach var s in current.scan_status {
        if !s.ok && !previousFailedKeys.hasKey(scanStatusKey(s)) {
            result.push(s);
        }
    }
    return result;
}

// "Not attended" = an open GitHub issue containing at least one CRITICAL/HIGH finding, open
// longer than the threshold. All findings sharing the same issue carry the identical
// issue.created_at (it's the issue's own creation time, not per-CVE), so grouping by issue number
// and keeping the first CRITICAL/HIGH match is enough - no need to hunt for an "earliest" one.
public type UnattendedIssue record {|
    int issueNumber;
    string? issueUrl;
    string packageDisplay; // e.g. "ballerinax/redis", "ballerina-lang", or "ballerina-vscode"
    string severity; // the worst of this issue's CRITICAL/HIGH findings encountered
    string createdAt;
    decimal ageDays;
|};

const decimal SEVERE_UNATTENDED_THRESHOLD_SECONDS = 604800; // 7 days

function packageDisplayName(db:Finding f) returns string {
    if f.'source == "vscode-extension" {
        return f.package_name;
    }
    return f.package_org is string ? string `${f.package_org ?: ""}/${f.package_name}` : f.package_name;
}

// Every open CRITICAL/HIGH-carrying issue whose age, AS OF `asOfIso` (the snapshot's own
// generated_at - not wall-clock "now"), already exceeds the threshold. Evaluating against each
// snapshot's own timestamp (rather than "now" at check-time) is what makes comparing this map
// across two snapshots a genuine crossing-detector: see newlyUnattendedSevereIssues below.
function severeUnattendedIssues(db:Finding[] findings, string asOfIso) returns map<UnattendedIssue>|error {
    map<UnattendedIssue> result = {};
    time:Utc asOfUtc = check time:utcFromString(asOfIso);

    foreach db:Finding f in findings {
        db:IssueRef? issue = f.issue;
        if issue is () || issue.state != "open" || issue.number is () {
            continue;
        }
        string sev = f.severity.toUpperAscii();
        if sev != "CRITICAL" && sev != "HIGH" {
            continue;
        }
        string? createdAt = issue.created_at;
        if createdAt is () {
            // No created_at on this issue ref (e.g. a very old combined.json, see IssueRef's
            // comment) - can't compute an age, so skip rather than guess one.
            continue;
        }
        time:Utc createdUtc = check time:utcFromString(createdAt);
        decimal ageSeconds = time:utcDiffSeconds(asOfUtc, createdUtc);
        if ageSeconds < SEVERE_UNATTENDED_THRESHOLD_SECONDS {
            continue;
        }

        int issueNumber = <int>issue.number;
        string key = issueNumber.toString();
        UnattendedIssue candidate = {
            issueNumber,
            issueUrl: issue.url,
            packageDisplay: packageDisplayName(f),
            severity: sev,
            createdAt,
            ageDays: ageSeconds / 86400
        };
        UnattendedIssue? existing = result[key];
        // Same issue can show up via more than one CRITICAL/HIGH finding - keep whichever is
        // CRITICAL if there's a choice, since that's the more urgent label to alert with.
        if existing is () || (existing.severity == "HIGH" && sev == "CRITICAL") {
            result[key] = candidate;
        }
    }
    return result;
}

// Fires only for issues that just crossed the threshold between the previous and current
// snapshot - an issue already over-threshold last cycle is excluded, so this never re-alerts on
// every cycle a stale issue continues to sit unattended (same transition-only pattern as
// newCriticalOrHigh/newlyFailedScanStatuses).
public function newlyUnattendedSevereIssues(db:Finding[] previous, string previousAsOf, db:Finding[] current, string currentAsOf) returns UnattendedIssue[]|error {
    map<UnattendedIssue> previousOver = check severeUnattendedIssues(previous, previousAsOf);
    map<UnattendedIssue> currentOver = check severeUnattendedIssues(current, currentAsOf);

    UnattendedIssue[] result = [];
    foreach var [key, issue] in currentOver.entries() {
        if !previousOver.hasKey(key) {
            result.push(issue);
        }
    }
    return result;
}
