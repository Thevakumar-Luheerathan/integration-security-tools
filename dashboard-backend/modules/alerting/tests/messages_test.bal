import integration_security_tools/dashboard_backend.model as db;
import ballerina/test;

@test:Config {}
function testFormatImmediateAlertReturnsNilWhenNothingWorthAlertingOn() {
    // The single most important behavior here: a quiet, healthy run must produce NO message, not
    // an empty/near-empty one. An "everything's fine!" ping every cycle is exactly the kind of
    // noise that trains people to ignore the channel - the documented failure mode of the
    // pre-this-project setup.
    string? result = formatImmediateAlert([], [], false, []);
    test:assertTrue(result is (), msg = "a clean run with nothing new/failed/stale/unattended must not page anyone");
}

@test:Config {}
function testFormatImmediateAlertFiresOnNewCritical() {
    db:Finding f = mkFinding("2201.12.x", "central", "ballerinax", "redis", "CVE-X", "CRITICAL");
    string? result = formatImmediateAlert([f], [], false, []);
    test:assertTrue(result is string);
    string message = <string>result;
    test:assertTrue(message.includes("CVE-X"));
    test:assertTrue(message.includes("CRITICAL"));
}

@test:Config {}
function testFormatImmediateAlertFiresOnNewlyFailedScanAloneEvenWithNoNewFindings() {
    db:ScanStatus failure = {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "central", ok: false, 'error: "timed out"};
    string? result = formatImmediateAlert([], [failure], false, []);
    test:assertTrue(result is string,
            msg = "a newly-failed scan must alert even with zero new findings - silence when the scanner itself breaks is the original failure mode this project fixes");
    test:assertTrue((<string>result).includes("timed out"));
}

@test:Config {}
function testFormatImmediateAlertFiresOnStaleTransitionAlone() {
    string? result = formatImmediateAlert([], [], true, []);
    test:assertTrue(result is string);
    test:assertTrue((<string>result).includes("hasn't produced fresh results"));
}

@test:Config {}
function testFormatImmediateAlertFiresOnNewlyUnattendedIssueAlone() {
    UnattendedIssue u = {issueNumber: 5, issueUrl: "https://example.com/5", packageDisplay: "ballerinax/redis", severity: "CRITICAL", createdAt: "2026-01-01T00:00:00Z", ageDays: 8.2};
    string? result = formatImmediateAlert([], [], false, [u]);
    test:assertTrue(result is string);
    string message = <string>result;
    test:assertTrue(message.includes("#5"));
    test:assertTrue(message.includes("unattended"));
}

@test:Config {}
function testFormatWeeklyDigestIncludesCounts() {
    db:CombinedReport report = {
        generated_at: "2026-08-03T00:00:00Z",
        pipeline_run_url: (),
        versions: ["2201.12.x", "2201.13.x"],
        scan_status: [],
        findings: []
    };
    string digest = formatWeeklyDigest(report, 42, 3, 10, 5);
    test:assertTrue(digest.includes("42"));
    test:assertTrue(digest.includes("3"));
    test:assertTrue(digest.includes("10"));
    test:assertTrue(digest.includes("5"));
    test:assertTrue(digest.includes("accepted risk"));
    test:assertTrue(digest.includes("weekly digest"));
}

@test:Config {}
function testFormatWeeklyDigestOmitsAcceptedRiskLineWhenZero() {
    db:CombinedReport report = {
        generated_at: "2026-08-03T00:00:00Z",
        pipeline_run_url: (),
        versions: ["2201.12.x"],
        scan_status: [],
        findings: []
    };
    string digest = formatWeeklyDigest(report, 10, 1, 2, 0);
    test:assertTrue(!digest.includes("accepted risk"),
            msg = "no accepted-risk findings this run - the digest shouldn't mention a zero count");
}
