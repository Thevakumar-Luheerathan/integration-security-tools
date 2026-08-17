import integration_security_tools/dashboard_backend.model as db;
import ballerina/test;

function mkFinding(string? version, string 'source, string? packageOrg, string packageName, string cve, string severity,
        string? packageVersion = (), string libraryName = "test:library", db:IssueRef? issue = (),
        db:AcceptedRisk? acceptedRisk = ()) returns db:Finding => {
    ballerina_version: version,
    'source,
    package_org: packageOrg,
    package_name: packageName,
    package_version: packageVersion,
    library_name: libraryName,
    jar: "irrelevant.jar",
    cve,
    severity,
    installed_version: "1.0",
    fixed_version: "",
    issue,
    accepted_risk: acceptedRisk
};

@test:Config {}
function testDiffFindsGenuinelyNewFinding() {
    db:Finding[] previous = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH")
    ];
    db:Finding[] current = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH"),
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-2", "CRITICAL")
    ];

    Transition[] transitions = diffFindings(previous, current);
    test:assertEquals(transitions.length(), 1);
    test:assertEquals(transitions[0].finding.cve, "CVE-2");
    test:assertEquals(transitions[0].kind, "new");
}

@test:Config {}
function testDiffDoesNotReAlertOnRoutineVersionBump() {
    db:Finding[] previous = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH", packageVersion = "2.14.13")
    ];
    db:Finding[] current = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH", packageVersion = "2.14.14")
    ];

    Transition[] transitions = diffFindings(previous, current);
    test:assertEquals(transitions.length(), 0,
            msg = "a routine package version bump with the same still-open CVE must not be reported as a new finding");
}

@test:Config {}
function testDiffTreatsDifferentVersionLinesIndependently() {
    db:Finding[] previous = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH")
    ];
    db:Finding[] current = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH"),
        mkFinding("2201.13.x", "central", "ballerina", "http", "CVE-1", "HIGH")
    ];

    Transition[] transitions = diffFindings(previous, current);
    test:assertEquals(transitions.length(), 1);
    test:assertEquals(transitions[0].finding.ballerina_version, "2201.13.x");
}

@test:Config {}
function testDiffTreatsDistributionAndCentralIndependently() {
    db:Finding[] previous = [
        mkFinding("2201.12.x", "distribution", (), "ballerina-lang", "CVE-1", "HIGH")
    ];
    db:Finding[] current = [
        mkFinding("2201.12.x", "distribution", (), "ballerina-lang", "CVE-1", "HIGH"),
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH")
    ];

    Transition[] transitions = diffFindings(previous, current);
    test:assertEquals(transitions.length(), 1);
    test:assertEquals(transitions[0].finding.'source, "central");
}

@test:Config {}
function testDiffTreatsDifferentPackagesIndependently() {
    db:Finding[] previous = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH")
    ];
    db:Finding[] current = [
        mkFinding("2201.12.x", "central", "ballerina", "http", "CVE-1", "HIGH"),
        mkFinding("2201.12.x", "central", "ballerinax", "redis", "CVE-1", "HIGH")
    ];

    Transition[] transitions = diffFindings(previous, current);
    test:assertEquals(transitions.length(), 1);
    test:assertEquals(transitions[0].finding.package_name, "redis");
}

@test:Config {}
function testNewCriticalOrHighFiltersOutLowerSeverities() {
    Transition[] transitions = [
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-1", "CRITICAL"), kind: "new"},
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-2", "HIGH"), kind: "new"},
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-3", "MEDIUM"), kind: "new"},
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-4", "LOW"), kind: "new"}
    ];
    db:Finding[] important = newCriticalOrHigh(transitions);
    test:assertEquals(important.length(), 2);
}

@test:Config {}
function testNewCriticalOrHighExcludesAcceptedRisk() {
    // A new CRITICAL that's ALREADY tagged accepted_risk (a .trivyignore match at scan time) was
    // never an unattended surprise - it was pre-triaged upstream. Must not alert on it.
    Transition[] transitions = [
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-1", "CRITICAL",
                acceptedRisk = {reason: "known, fix pending", 'source: "ballerina-distribution:.trivyignore@2201.12.x"}), kind: "new"},
        {finding: mkFinding("2201.12.x", "central", (), "r", "CVE-2", "HIGH"), kind: "new"}
    ];
    db:Finding[] important = newCriticalOrHigh(transitions);
    test:assertEquals(important.length(), 1);
    test:assertEquals(important[0].cve, "CVE-2");
}

@test:Config {}
function testFailedScanStatusesFiltersCorrectly() {
    db:CombinedReport report = {
        generated_at: "2026-08-03T00:00:00Z",
        pipeline_run_url: (),
        versions: ["2201.12.x"],
        scan_status: [
            {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "central", ok: true, 'error: ()},
            {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "distribution", ok: false, 'error: "build failed"}
        ],
        findings: []
    };
    db:ScanStatus[] failing = failedScanStatuses(report);
    test:assertEquals(failing.length(), 1);
    test:assertEquals(failing[0].'source, "distribution");
}

function mkReport(db:ScanStatus[] statuses) returns db:CombinedReport => {
    generated_at: "2026-08-03T00:00:00Z",
    pipeline_run_url: (),
    versions: ["2201.12.x"],
    scan_status: statuses,
    findings: []
};

@test:Config {}
function testNewlyFailedScanStatusesExcludesAlreadyFailing() {
    db:CombinedReport previous = mkReport([
        {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "central", ok: false, 'error: "timed out"},
        {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "distribution", ok: true, 'error: ()}
    ]);
    db:CombinedReport current = mkReport([
        {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "central", ok: false, 'error: "timed out"},
        {ballerina_version: "2201.12.x", plugin_branch: (), 'source: "distribution", ok: false, 'error: "build failed"}
    ]);

    db:ScanStatus[] newlyFailed = newlyFailedScanStatuses(previous, current);
    test:assertEquals(newlyFailed.length(), 1,
            msg = "a scan that was ALREADY failing last cycle must not be reported as newly failed");
    test:assertEquals(newlyFailed[0].'source, "distribution");
}

@test:Config {}
function testNewlyUnattendedSevereIssuesFiresOnlyOnCrossing() returns error? {
    // Issue #1 created exactly 8 days before the CURRENT snapshot, so at the PREVIOUS snapshot's
    // own timestamp (7.5 days before current) it was only ~... let's make previous timestamp
    // close enough to created_at that it's still under threshold there, but over by current.
    db:IssueRef openIssue = {number: 1, url: "https://example.com/1", state: "open", created_at: "2026-01-01T00:00:00Z"};
    db:Finding[] findings = [
        mkFinding("2201.12.x", "central", "ballerinax", "redis", "CVE-1", "CRITICAL", issue = openIssue)
    ];

    // previousAsOf: 6 days after creation - under the 7-day threshold, not yet unattended.
    string previousAsOf = "2026-01-07T00:00:00Z";
    // currentAsOf: 8 days after creation - over the threshold, now unattended.
    string currentAsOf = "2026-01-09T00:00:00Z";

    UnattendedIssue[] result = check newlyUnattendedSevereIssues(findings, previousAsOf, findings, currentAsOf);
    test:assertEquals(result.length(), 1);
    test:assertEquals(result[0].issueNumber, 1);

    // Simulate the NEXT cycle: both previous and current are now past the threshold - must NOT
    // fire again for the same issue.
    string stillCurrentAsOf = "2026-01-16T00:00:00Z";
    UnattendedIssue[] secondCheck = check newlyUnattendedSevereIssues(findings, currentAsOf, findings, stillCurrentAsOf);
    test:assertEquals(secondCheck.length(), 0,
            msg = "an issue already over-threshold last cycle must not re-fire every subsequent cycle");
}

@test:Config {}
function testNewlyUnattendedSevereIssuesIgnoresClosedAndLowSeverity() returns error? {
    db:IssueRef closedIssue = {number: 2, url: (), state: "closed", created_at: "2026-01-01T00:00:00Z"};
    db:IssueRef openLowSevIssue = {number: 3, url: (), state: "open", created_at: "2026-01-01T00:00:00Z"};
    db:Finding[] findings = [
        mkFinding("2201.12.x", "central", (), "closed-pkg", "CVE-1", "CRITICAL", issue = closedIssue),
        mkFinding("2201.12.x", "central", (), "low-sev-pkg", "CVE-2", "MEDIUM", issue = openLowSevIssue)
    ];

    UnattendedIssue[] result = check newlyUnattendedSevereIssues([], "2026-01-01T00:00:00Z", findings, "2026-02-01T00:00:00Z");
    test:assertEquals(result.length(), 0,
            msg = "a closed issue or one with no CRITICAL/HIGH finding must never be reported as unattended");
}
