// Exercises aggregate.bal against the shared sample fixture (trivy-vuln-scan/fixtures/
// combined.sample.json, copied here since Ballerina test resources must live under the
// package). This is the concrete implementation of the plan's Verification step: "Track B can
// be verified independently of Track A by committing a hand-written sample combined.json ...
// and pointing the Choreo service at a fixture." Presentation-layer tests (HTML rendering) were
// removed when the dashboard UI moved to the separate React app - see ../../dashboard/.

import integration_security_tools/dashboard_backend.model;
import ballerina/io;
import ballerina/test;

function loadFixture() returns model:CombinedReport|error {
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
    model:CombinedReport report = check loadFixture();
    VersionSourceSummary[] summaries = summarizeByVersionAndSource(report);

    // The fixture's scan_status lists 6 (version, source) pairs (distribution x2, central x2,
    // tools x2 - the vscode-extension row is skipped, it has no ballerina_version), including
    // one with ok=false and zero findings for it. Every one of those 6 must appear - a
    // failed/empty scan must never be indistinguishable from "not run at all".
    test:assertEquals(summaries.length(), 6);

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
    model:CombinedReport report = check loadFixture();
    VersionSourceSummary[] summaries = summarizeByVersionAndSource(report);

    // 2201.12.x/central in the fixture: netty-codec (HIGH) + netty-codec-http (HIGH) +
    // aws.s3 closed-but-still-detected (HIGH) + bcprov/redis (CRITICAL) + rocketmq (MEDIUM)
    // = 3 HIGH, 1 CRITICAL.
    foreach var s in summaries {
        if s.ballerina_version == "2201.12.x" && s.'source == "central" {
            test:assertEquals(s.counts.high, 3);
            test:assertEquals(s.counts.critical, 1);
        }
    }
}

@test:Config {}
function testSummarizeByPackageGroupsOnePackageAcrossVersionLines() returns error? {
    model:CombinedReport report = check loadFixture();
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
function testSummarizeByLanguageCoreGroupsBallerinaLangByLineNotByJar() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] core = summarizeByLanguageCore(report);

    // ballerina-lang (package_org == ()) has findings on both 2201.12.x (commons-beanutils) and
    // 2201.13.x (netty-codec-http, jackson-databind) - still exactly ONE entry, and for
    // ballerina-lang specifically each Ballerina line is its own VersionGroup (no package_version
    // concept there).
    PackageSummary? lang = findPackage(core, (), "ballerina-lang");
    test:assertTrue(lang is PackageSummary, msg = "expected exactly one ballerina-lang Language Core entry");
    PackageSummary langPkg = <PackageSummary>lang;
    test:assertEquals(langPkg.versions.length(), 2, msg = "expected one VersionGroup per Ballerina line (2201.12.x, 2201.13.x)");

    foreach var v in langPkg.versions {
        test:assertEquals(v.package_version, (), msg = "ballerina-lang has no package_version concept");
        if v.label == "2201.12.x" {
            test:assertEquals(v.findings.length(), 1);
            test:assertEquals(v.findings[0].cve, "CVE-2025-48734",
                    msg = "commons-beanutils must be scoped to its own 2201.12.x version group, not mixed with 2201.13.x findings");
        } else if v.label == "2201.13.x" {
            // netty-codec-http, jackson-databind CVE-2026-54512, and the accepted-risk
            // CVE-2025-48924 - accepted_risk findings are never dropped, just tagged (see
            // testAcceptedRiskFindingsAreNeverDroppedFromTheTree below), so they still count here.
            test:assertEquals(v.findings.length(), 3, msg = "netty-codec-http, jackson-databind, and the accepted-risk finding all belong to 2201.13.x");
        } else {
            test:assertFail(string `unexpected version group label ${v.label}`);
        }
    }
}

@test:Config {}
function testSummarizeByPackageNeverProducesAnUnresolvedBucket() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // There is no repo-resolution step left to fail (confirmed design decision) - every finding
    // has a real package_org/package_name by construction, so no package summary should ever
    // need an "(unresolved)" placeholder the way the old repo-keyed view did. 4, not 5: ballerina
    // -lang now belongs exclusively to Language Core (see summarizeByLanguageCore), not Packages.
    test:assertEquals(packages.length(), 4, msg = "expected exactly 4 distinct Central packages in the fixture");
    foreach var p in packages {
        test:assertTrue(p.package_name.length() > 0, msg = "package_name must never be empty/placeholder");
        test:assertFalse(p.package_name == "(unresolved)");
    }

    // The package with no synced issue yet (rocketmq driver) still surfaces with an all-zero
    // rollup and no open issue - "no issue yet" is a legitimate, visible state, not a silent drop.
    PackageSummary? rocketmq = findPackage(packages, "ballerinax", "cdc.schema.rocketmq.driver");
    test:assertTrue(rocketmq is PackageSummary);
    test:assertTrue((<PackageSummary>rocketmq).issueSummary.openIssue is (), msg = "rocketmq driver has no issue synced yet in the fixture - should show as absent, not crash");
}

@test:Config {}
function testSummarizeByPackageExcludesVscodeExtension() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    // Packages is now an explicit allowlist of exactly "central" (see summarizeByPackage) - none
    // of vscode-extension, tools, or distribution (ballerina-lang) may appear here. Count stays
    // at 4 regardless of how many other-source findings the fixture carries - this is the
    // allowlist fix's real regression guard (a plain negative filter would have silently swept
    // "tools" in here, and previously did also include ballerina-lang) - see
    // testEverySourceBelongsToExactlyOneView below for the general form of this check.
    test:assertEquals(packages.length(), 4);
    PackageSummary? vscode = findPackage(packages, (), "ballerina-vscode");
    test:assertTrue(vscode is (), msg = "ballerina-vscode must not appear in the Packages view");
    PackageSummary? tool = findPackage(packages, "ballerina", "tool_scan");
    test:assertTrue(tool is (), msg = "a \"tools\"-source finding must not appear in the Packages view");
    PackageSummary? lang = findPackage(packages, (), "ballerina-lang");
    test:assertTrue(lang is (), msg = "ballerina-lang must not appear in the Packages view - it belongs to Language Core");
}

@test:Config {}
function testSummarizeByPluginGroupsByBranchNotVersion() returns error? {
    model:CombinedReport report = check loadFixture();
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
    test:assertTrue(vscode.issueSummary.openIssue is model:IssueRef, msg = "expected the fixture's synced issue to surface");
}

@test:Config {}
function testAcceptedRiskFindingsAreNeverDroppedFromTheTree() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] core = summarizeByLanguageCore(report);

    // ballerina-lang's fixture accepted-risk finding (CVE-2025-48924, .trivyignore@2201.13.x)
    // must still be present in its VersionGroup, carrying its accepted_risk reason verbatim -
    // never dropped just because it's not an active/tracked finding.
    PackageSummary? lang = findPackage(core, (), "ballerina-lang");
    test:assertTrue(lang is PackageSummary);
    PackageSummary langPkg = <PackageSummary>lang;

    model:Finding? acceptedFinding = ();
    foreach var v in langPkg.versions {
        foreach var f in v.findings {
            if f.cve == "CVE-2025-48924" {
                acceptedFinding = f;
            }
        }
    }
    test:assertTrue(acceptedFinding is model:Finding, msg = "accepted-risk finding must still appear in the version tree");
    model:AcceptedRisk? risk = (<model:Finding>acceptedFinding).accepted_risk;
    test:assertTrue(risk is model:AcceptedRisk);
    test:assertEquals((<model:AcceptedRisk>risk).reason, "Need to be fixed");
    test:assertTrue((<model:Finding>acceptedFinding).issue is (), msg = "accepted-risk findings are never issue-tracked - issue_sync.py skips them entirely");

    // Package-level rollup: this package has 3 open findings (CVE-2026-42587, CVE-2026-54512
    // on 2201.13.x, and CVE-2025-48734 on 2201.12.x - all issue #2) plus this 1 accepted-risk one.
    test:assertEquals(langPkg.issueSummary.acceptedRiskCount, 1);
    test:assertEquals(langPkg.issueSummary.openCount, 3);
}

@test:Config {}
function testClosedButStillDetectedFindingStaysVisibleAndIsNeverCountedAsOpen() returns error? {
    // ballerinax/aws.s3's fixture finding (CVE-2024-99999) models the scenario this whole
    // project exists to make visible: a human closed issue #5 believing the fix was already
    // shipped, but the SAME CVE is still being detected by this run (fix not yet published, or
    // won't-fix). issue_sync.py's suppress-on-recurrence logic (see its sync_package()) never
    // reopens the issue or creates a new one for it - it just re-attaches the closed issue ref
    // so the dashboard can show it as "closed" rather than silently vanishing or looking active.
    model:CombinedReport report = check loadFixture();
    PackageSummary[] packages = summarizeByPackage(report);

    PackageSummary? aws = findPackage(packages, "ballerinax", "aws.s3");
    test:assertTrue(aws is PackageSummary, msg = "expected the closed-but-still-detected fixture package to appear");
    PackageSummary awsPkg = <PackageSummary>aws;

    model:Finding? closedFinding = ();
    foreach var v in awsPkg.versions {
        foreach var f in v.findings {
            if f.cve == "CVE-2024-99999" {
                closedFinding = f;
            }
        }
    }
    test:assertTrue(closedFinding is model:Finding,
            msg = "a finding matching a closed issue must still appear in the version tree, never dropped");
    model:IssueRef? issue = (<model:Finding>closedFinding).issue;
    test:assertTrue(issue is model:IssueRef);
    test:assertEquals((<model:IssueRef>issue).state, "closed");
    test:assertEquals((<model:IssueRef>issue).number, 5);

    // The whole point: this must count as CLOSED, never as open (a human already made the call
    // that this issue is resolved/acknowledged) and never as accepted-risk (that's a distinct,
    // .trivyignore-driven state - this finding has no accepted_risk tag at all).
    test:assertEquals(awsPkg.issueSummary.closedCount, 1);
    test:assertEquals(awsPkg.issueSummary.openCount, 0);
    test:assertEquals(awsPkg.issueSummary.acceptedRiskCount, 0);
}

@test:Config {}
function testSummarizeAcceptedRiskByLine() returns error? {
    model:CombinedReport report = check loadFixture();
    AcceptedRiskLineSummary[] byLine = summarizeAcceptedRiskByLine(report);

    // Fixture has exactly one accepted-risk finding per line (2201.13.x: ballerina-lang's
    // jackson-databind; 2201.12.x: ballerinax/redis's commons-compress) - two distinct lines,
    // one each, sorted ascending.
    test:assertEquals(byLine.length(), 2);
    test:assertEquals(byLine[0].ballerina_version, "2201.12.x");
    test:assertEquals(byLine[0].count, 1);
    test:assertEquals(byLine[1].ballerina_version, "2201.13.x");
    test:assertEquals(byLine[1].count, 1);
}

@test:Config {}
function testSummarizeByToolIsSeparateFromPackagesAndPlugins() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] tools = summarizeByTool(report);

    // Fixture has 2 distinct tools: ballerina/tool_scan (2 versions) and wso2/tool_migrate_tibco
    // (1 version) - neither may leak into summarizeByPackage/summarizeByPlugin (see
    // testSummarizeByPackageExcludesVscodeExtension's companion assertion, and
    // testEverySourceBelongsToExactlyOneView below for the general partition check).
    test:assertEquals(tools.length(), 2);
    PackageSummary? scanTool = findPackage(tools, "ballerina", "tool_scan");
    test:assertTrue(scanTool is PackageSummary, msg = "expected ballerina/tool_scan in the Tools view");

    test:assertTrue(findPackage(summarizeByPackage(report), "ballerina", "tool_scan") is (),
            msg = "a tool must never appear in the Packages view");
    test:assertTrue(findPackage(summarizeByPlugin(report), "ballerina", "tool_scan") is (),
            msg = "a tool must never appear in the Plugins view");
}

@test:Config {}
function testSummarizeByToolGroupsByPackageVersionLikeACentralPackage() returns error? {
    model:CombinedReport report = check loadFixture();
    PackageSummary[] tools = summarizeByTool(report);

    // ballerina/tool_scan has findings on 0.11.0 (2201.13.x) and 0.10.0 (2201.12.x) - buildVersionGroups
    // needs NO special case for "tools": it already falls into the same default branch a Central
    // package uses, since tools carry package_version/ballerina_version identically.
    PackageSummary? scanTool = findPackage(tools, "ballerina", "tool_scan");
    test:assertTrue(scanTool is PackageSummary);
    PackageSummary scanToolPkg = <PackageSummary>scanTool;
    test:assertEquals(scanToolPkg.versions.length(), 2, msg = "expected two VersionGroups, one per package_version");

    foreach var v in scanToolPkg.versions {
        test:assertTrue(v.package_version is string, msg = "a tool's VersionGroup must carry package_version just like a Central package's");
        if v.package_version == "0.11.0" {
            test:assertEquals(v.ballerina_versions, ["2201.13.x"]);
        } else if v.package_version == "0.10.0" {
            test:assertEquals(v.ballerina_versions, ["2201.12.x"]);
        } else {
            test:assertFail(string `unexpected package_version ${v.package_version ?: "()"}`);
        }
        // tool_id lives on each Finding (model:Finding), not on VersionGroup/PackageSummary -
        // spot-check it survived cloneWithType() and is carried through to the leaf findings.
        foreach var f in v.findings {
            test:assertEquals(f.tool_id, "scan");
        }
    }
}

@test:Config {}
function testEverySourceBelongsToExactlyOneView() returns error? {
    // The general form of the allowlist-fix regression guard: whatever distinct `source` values
    // exist in the fixture, each one's findings must appear in EXACTLY one of the four views -
    // never zero (silently dropped) and never two (double-counted). This is what makes adding a
    // future fifth source safe: this test fails loudly instead of a source silently landing in
    // the wrong tab, the way "tools" would have under the old `!= "vscode-extension"` filter,
    // and the way "distribution" used to double up with "central" in Packages before the
    // Language Core split.
    model:CombinedReport report = check loadFixture();
    PackageSummary[] core = summarizeByLanguageCore(report);
    PackageSummary[] packages = summarizeByPackage(report);
    PackageSummary[] plugins = summarizeByPlugin(report);
    PackageSummary[] tools = summarizeByTool(report);

    string[] sources = [];
    foreach var f in report.findings {
        if sources.indexOf(f.'source) is () {
            sources.push(f.'source);
        }
    }
    test:assertTrue(sources.length() >= 4, msg = "fixture should exercise all of distribution/central/tools/vscode-extension");

    PackageSummary[][] views = [core, packages, plugins, tools];
    foreach var 'source in sources {
        int count = 0;
        foreach var view in views {
            foreach var p in view {
                if p.'source == 'source {
                    count += 1;
                    break;
                }
            }
        }
        test:assertEquals(count, 1, msg = string `source "${'source}" must appear in exactly one view, found in ${count}`);
    }
}

