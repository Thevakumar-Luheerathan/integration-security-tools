// Exercises aggregate.bal against the shared sample fixture (trivy-vuln-scan/fixtures/
// combined.sample.json, copied here since Ballerina test resources must live under the
// package). This is the concrete implementation of the plan's Verification step: "Track B can
// be verified independently of Track A by committing a hand-written sample combined.json ...
// and pointing the Choreo service at a fixture." Presentation-layer tests (HTML rendering) were
// removed when the dashboard UI moved to the separate React app - see ../../dashboard/.

import ballerina/io;
import ballerina/test;

function loadFixture() returns CombinedReport|error {
    json j = check io:fileReadJson("tests/combined.sample.json");
    return j.cloneWithType();
}

function findPackage(PackageSummary[] packages, string? packageOrg, string packageName) returns PackageSummary? {
    foreach var p in packages {
        if p.package_org == packageOrg && p.package_name == packageName {
            return p;
        }
    }
    return ();
}

@test:Config {}
function testSummarizeByVersionAndSourceCoversEveryScanStatus() returns error? {
    CombinedReport report = check loadFixture();
    VersionSourceSummary[] summaries = summarizeByVersionAndSource(report);

    // The fixture's scan_status lists 4 (version, source) pairs, including one with ok=false
    // and zero findings for it. Every one of those 4 must appear - a failed/empty scan must
    // never be indistinguishable from "not run at all".
    test:assertEquals(summaries.length(), 4);

    VersionSourceSummary? failedOne = ();
    foreach var s in summaries {
        if s.ballerina_version == "2201.12.x" && s.'source == "central" {
            failedOne = s;
        }
    }
    test:assertTrue(failedOne is VersionSourceSummary, msg = "expected the failed central/2201.12.x entry to be present");
    VersionSourceSummary failed = <VersionSourceSummary>failedOne;
    test:assertFalse(failed.ok);
    test:assertTrue(failed.statusError is string);
    // The fixture models a PARTIAL failure: some packages resolved and scanned fine (producing
    // real findings) while 4 others timed out. The failure flag and the findings that WERE
    // captured must both surface - neither should suppress the other.
    int totalCaptured = failed.counts.critical + failed.counts.high + failed.counts.medium + failed.counts.low;
    test:assertTrue(totalCaptured > 0,
            msg = "findings captured before a partial failure must still be shown, not suppressed by ok=false");
}

@test:Config {}
function testSeverityCountsMatchFixture() returns error? {
    CombinedReport report = check loadFixture();
    VersionSourceSummary[] summaries = summarizeByVersionAndSource(report);

    // 2201.12.x/central in the fixture: netty-codec (HIGH) + netty-codec-http (HIGH) +
    // bcprov/redis (CRITICAL) + rocketmq (MEDIUM) = 2 HIGH, 1 CRITICAL.
    foreach var s in summaries {
        if s.ballerina_version == "2201.12.x" && s.'source == "central" {
            test:assertEquals(s.counts.high, 2);
            test:assertEquals(s.counts.critical, 1);
        }
    }
}

@test:Config {}
function testSummarizeByPackageGroupsOnePackageAcrossVersionLines() returns error? {
    CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // ballerina/http has findings on BOTH 2201.12.x (package_version 2.13.0) and 2201.13.x
    // (package_version 2.16.6) - per the confirmed design ("one entry per package, all lines
    // combined"), this MUST be exactly one PackageSummary, not two.
    PackageSummary? http = findPackage(packages, "ballerina", "http");
    test:assertTrue(http is PackageSummary, msg = "expected exactly one ballerina/http package entry");
    PackageSummary httpPkg = <PackageSummary>http;

    // Two distinct package_versions (2.13.0, 2.16.6) => two VersionGroups, each carrying only
    // the findings that actually belong to that version - never a merged list.
    test:assertEquals(httpPkg.versions.length(), 2,
            msg = "http spans two distinct package_versions across the two lines - expected two VersionGroups");

    foreach var v in httpPkg.versions {
        if v.package_version == "2.13.0" {
            test:assertEquals(v.findings.length(), 2, msg = "2.13.0 should carry only its own 2 CVEs (netty-codec, netty-codec-http)");
            test:assertEquals(v.ballerina_versions, ["2201.12.x"]);
        } else if v.package_version == "2.16.6" {
            test:assertEquals(v.findings.length(), 1, msg = "2.16.6 should carry only its own 1 CVE (netty-common)");
            test:assertEquals(v.ballerina_versions, ["2201.13.x"]);
        } else {
            test:assertFail(string `unexpected package_version ${v.package_version ?: "()"}`);
        }
    }

    // Package-level counts aggregate across both versions: 2 HIGH + 1 LOW.
    test:assertEquals(httpPkg.counts.high, 2);
    test:assertEquals(httpPkg.counts.low, 1);
}

@test:Config {}
function testSummarizeByPackageGroupsBallerinaLangByLineNotByJar() returns error? {
    CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // ballerina-lang (package_org == ()) has findings on both 2201.12.x (commons-beanutils) and
    // 2201.13.x (netty-codec-http, jackson-databind) - still exactly ONE package entry, and for
    // ballerina-lang specifically each Ballerina line is its own VersionGroup (no package_version
    // concept there).
    PackageSummary? lang = findPackage(packages, (), "ballerina-lang");
    test:assertTrue(lang is PackageSummary, msg = "expected exactly one ballerina-lang package entry");
    PackageSummary langPkg = <PackageSummary>lang;
    test:assertEquals(langPkg.versions.length(), 2, msg = "expected one VersionGroup per Ballerina line (2201.12.x, 2201.13.x)");

    foreach var v in langPkg.versions {
        test:assertEquals(v.package_version, (), msg = "ballerina-lang has no package_version concept");
        if v.label == "2201.12.x" {
            test:assertEquals(v.findings.length(), 1);
            test:assertEquals(v.findings[0].cve, "CVE-2025-48734",
                    msg = "commons-beanutils must be scoped to its own 2201.12.x version group, not mixed with 2201.13.x findings");
        } else if v.label == "2201.13.x" {
            test:assertEquals(v.findings.length(), 2, msg = "netty-codec-http and jackson-databind both belong to 2201.13.x");
        } else {
            test:assertFail(string `unexpected version group label ${v.label}`);
        }
    }
}

@test:Config {}
function testSummarizeByPackageNeverProducesAnUnresolvedBucket() returns error? {
    CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // There is no repo-resolution step left to fail (confirmed design decision) - every finding
    // has a real package_org/package_name by construction, so no package summary should ever
    // need an "(unresolved)" placeholder the way the old repo-keyed view did.
    test:assertEquals(packages.length(), 4, msg = "expected exactly 4 distinct packages in the fixture");
    foreach var p in packages {
        test:assertTrue(p.package_name.length() > 0, msg = "package_name must never be empty/placeholder");
        test:assertFalse(p.package_name == "(unresolved)");
    }

    // The package with no synced issue yet (rocketmq driver) still surfaces with issue = () -
    // "no issue yet" is a legitimate, visible state, not a silent drop.
    PackageSummary? rocketmq = findPackage(packages, "ballerinax", "cdc.schema.rocketmq.driver");
    test:assertTrue(rocketmq is PackageSummary);
    test:assertTrue((<PackageSummary>rocketmq).issue is (), msg = "rocketmq driver has no issue synced yet in the fixture - should show as absent, not crash");
}

@test:Config {}
function testSummarizeByPackageExcludesVscodeExtension() returns error? {
    CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // The fixture's 2 vscode-extension findings must never appear in the Packages view - they
    // belong exclusively to summarizeByPlugin (see below). Package count stays at 4 regardless
    // of the vscode-extension findings added to the fixture.
    test:assertEquals(packages.length(), 4);
    PackageSummary? vscode = findPackage(packages, (), "ballerina-vscode");
    test:assertTrue(vscode is (), msg = "ballerina-vscode must not appear in the Packages view");
}

@test:Config {}
function testSummarizeByPluginGroupsByBranchNotVersion() returns error? {
    CombinedReport report = check loadFixture();
    PackageSummary[] plugins = summarizeByPlugin(report);

    // Exactly one plugin (ballerina-vscode), never mixed into the Packages count.
    test:assertEquals(plugins.length(), 1);
    PackageSummary vscode = plugins[0];
    test:assertEquals(vscode.package_org, ());
    test:assertEquals(vscode.package_name, "ballerina-vscode");

    // Both fixture findings (one npm CVE from the fs scan, one Maven CVE from the LS sbom scan)
    // are scanned from the same branch ("main"), so they collapse into ONE VersionGroup - never
    // split by which of the two real upstream scans produced them.
    test:assertEquals(vscode.versions.length(), 1, msg = "both findings are on branch 'main' - expected exactly one VersionGroup");
    VersionGroup mainGroup = vscode.versions[0];
    test:assertEquals(mainGroup.label, "main");
    test:assertEquals(mainGroup.ballerina_versions, [], msg = "ballerina-vscode has no Ballerina version concept");
    test:assertEquals(mainGroup.findings.length(), 2, msg = "expected both the npm (axios) and Maven (jackson-databind) CVEs under branch main");

    // Package-level counts aggregate across the (here, single) branch: 1 HIGH + 1 CRITICAL.
    test:assertEquals(vscode.counts.high, 1);
    test:assertEquals(vscode.counts.critical, 1);

    // The issue synced for this package is visible exactly like a real package's.
    test:assertTrue(vscode.issue is IssueRef, msg = "expected the fixture's synced issue to surface");
}

