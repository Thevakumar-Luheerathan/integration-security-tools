// Orchestration - wires diff.bal's pure transition logic, messages.bal's pure formatting, and
// chat.bal's I/O together. Two entry points, matching the approved plan's two trigger shapes:
//
//   - checkImmediateAlerts: called from ../main.bal's existing RefreshJob after every scheduled
//     refresh (piggybacking on the existing ~30min cache-refresh loop, per the plan - safe to
//     re-run every cycle since every condition it checks is diff-based against the previous
//     cached snapshot, firing only on the transition INTO a bad state, never on every cycle that
//     state persists).
//   - sendWeeklyDigest: called from a separate, externally-triggered `POST /alerts/weekly-digest`
//     resource (see ../main.bal) - NOT polled from inside the refresh loop, which would fire it
//     ~48 times on the digest day with no database-backed "already sent today" guard.
//
// Moved from the standalone choreo-alerting Choreo Scheduled Task into this module - see
// diff.bal's header comment for why. fetch.bal/unzip_util.bal were dropped entirely: this module
// reuses dashboard-backend's own cached snapshot (../ingest.bal) instead of fetching its own
// separate copy of the same artifact.

import integration_security_tools/dashboard_backend.model as db;
import ballerina/log;
import ballerina/time;

// How stale a snapshot's own generated_at must be (relative to wall-clock now) before it counts
// as "the pipeline may be failing silently" - deliberately looser than dashboard-backend's own
// ~1hr API-cache staleness banner (main.bal's staleAfterSeconds), which is about "is our cached
// copy due for a refresh soon", a much lower bar than "is the pipeline actually stuck".
configurable decimal pipelineStaleAfterSeconds = 90000; // 25h - one missed daily run plus slack
configurable int digestDayOfWeek = 1; // time:MONDAY

// Tracks only whether the LAST checked snapshot was stale - not the snapshot itself, just enough
// to detect the transition into staleness without re-alerting every subsequent cycle it persists.
// Same isolated-variable-plus-lock pattern as ../ingest.bal's snapshot cache.
isolated boolean previouslyStale = false;

isolated function wasStale() returns boolean {
    lock {
        return previouslyStale;
    }
}

isolated function setStale(boolean stale) {
    lock {
        previouslyStale = stale;
    }
}

function isReportStale(db:CombinedReport report) returns boolean {
    time:Utc|error generatedAtUtc = time:utcFromString(report.generated_at);
    if generatedAtUtc is error {
        log:printWarn("could not parse generated_at on the current snapshot - treating as stale", 'error = generatedAtUtc);
        return true;
    }
    decimal age = time:utcDiffSeconds(time:utcNow(), generatedAtUtc);
    return age > pipelineStaleAfterSeconds;
}

// Called after every scheduled refresh with the snapshot from just before it and the freshly
// refreshed one. A no-op (not an error) when there's no previous snapshot yet (e.g. right after
// service startup) - nothing to diff against, and alerting on a cold start's "everything is new"
// would be pure noise.
public function checkImmediateAlerts(db:CombinedReport previous, db:CombinedReport current) returns error? {
    Transition[] transitions = diffFindings(previous.findings, current.findings);
    db:Finding[] newImportant = newCriticalOrHigh(transitions);
    db:ScanStatus[] newlyFailed = newlyFailedScanStatuses(previous, current);
    UnattendedIssue[] newlyUnattended = check newlyUnattendedSevereIssues(
            previous.findings, previous.generated_at, current.findings, current.generated_at);

    boolean currentStale = isReportStale(current);
    boolean staleTransition = currentStale && !wasStale();
    setStale(currentStale);

    string? message = formatImmediateAlert(newImportant, newlyFailed, staleTransition, newlyUnattended);
    if message is () {
        log:printInfo("no immediate-alert conditions this refresh");
        return;
    }

    check sendChatMessage(message);
    log:printInfo(string `immediate alert sent: ${newImportant.length()} new critical/high, ` +
            string `${newlyFailed.length()} newly-failed scan(s), stale-transition=${staleTransition}, ` +
            string `${newlyUnattended.length()} newly-unattended severe issue(s)`);
}

// Only actually sends when called on `digestDayOfWeek` - the resource calling this (see
// ../main.bal) is expected to be triggered by an external once-a-week schedule, but this check is
// kept as a defense-in-depth guard against a misconfigured trigger firing more often than
// intended, since there's still no database to record "already sent this week".
public function sendWeeklyDigest(db:CombinedReport current) returns error? {
    time:Civil nowCivil = time:utcToCivil(time:utcNow());
    int todayDow = time:dayOfWeek({year: nowCivil.year, month: nowCivil.month, day: nowCivil.day});
    if todayDow != digestDayOfWeek {
        log:printInfo(string `weekly digest skipped - today (dow=${todayDow}) is not the configured digest day (dow=${digestDayOfWeek})`);
        return;
    }

    int totalOpen = 0;
    int criticalCount = 0;
    int highCount = 0;
    int acceptedRiskCount = 0;
    foreach db:Finding f in current.findings {
        if f.accepted_risk is db:AcceptedRisk {
            acceptedRiskCount += 1;
            continue;
        }
        totalOpen += 1;
        string s = f.severity.toUpperAscii();
        if s == "CRITICAL" {
            criticalCount += 1;
        } else if s == "HIGH" {
            highCount += 1;
        }
    }

    string digest = formatWeeklyDigest(current, totalOpen, criticalCount, highCount, acceptedRiskCount);
    check sendChatMessage(digest);
    log:printInfo("weekly digest sent");
}
