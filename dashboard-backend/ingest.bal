// Pulls the latest combined.json out of the pipeline's GitHub Actions artifact:
//   1. GET /repos/{owner}/{repo}/actions/workflows/{workflow}/runs?status=completed&per_page=10
//   2. For each run (newest first): GET .../runs/{run_id}/artifacts, looking for artifactName
//   3. First one that has it: GET .../artifacts/{artifact_id}/zip -> 302, ~1min-lived URL
//
// Deliberately queries status=completed (any conclusion), NOT status=success, and then checks
// each candidate run's artifact list directly - a run's overall conclusion is "failure" if ANY
// job failed, even when `combine` (the only job that actually produces artifactName) succeeded.
// The proactive-vuln-scan pipeline's combine job is intentionally allowed to run and upload even
// when distribution-scan/etc. fail (see that workflow's `if: always()` on the combine job), so
// filtering on the run's overall status would skip runs that have perfectly good data. What
// actually matters is "does this run have the artifact", checked directly per run below - not
// whether the whole workflow succeeded. Verified against a real run (Thevakumar-Luheerathan/
// integration-security-tools run 31168496007): distribution-scan failed, combine succeeded and
// uploaded combined-results, but the run's own overall conclusion was still "failure" - the
// original status=success query found zero runs and the dashboard showed "no successful
// pipeline runs found yet" indefinitely despite real, usable data existing.
//
// Stateless by design (per the approved plan): this service holds no database. All real state
// lives in GitHub Issues (written by issue_sync.py) and in the source-of-truth artifact itself.
// The only "state" here is an in-memory cache of the last successfully parsed snapshot, purely
// so a transient GitHub API hiccup doesn't blank the dashboard - falling back to stale-but-known
// data (with a visible staleness banner, see render.bal) beats showing an error page.

import integration_security_tools/dashboard_backend.model;
import ballerina/http;
import ballerina/io;
import ballerina/log;
import ballerina/os;
import ballerina/time;

configurable string ghToken = os:getEnv("GH_TOKEN");
configurable string pipelineOwner = "Thevakumar-Luheerathan";
configurable string pipelineRepo = "integration-security-tools";
configurable string workflowFile = "trivy-vuln-scan.yml";
configurable string artifactName = "combined-results";

final http:Client ghApi = check new ("https://api.github.com", {
    auth: {token: ghToken},
    httpVersion: http:HTTP_1_1
});

// A second client, unauthenticated redirect-follower, dedicated to the artifact download step -
// the redirect target is a pre-signed Azure blob URL that must NOT be sent the GitHub auth
// header (and doesn't need it).
final http:Client redirectFollower = check new ("https://api.github.com", {
    followRedirects: {enabled: true, maxCount: 5},
    httpVersion: http:HTTP_1_1
});

type CachedSnapshot record {|
    model:CombinedReport report;
    string fetchedAt;
    string runUrl;
|};

// isolated root so concurrent HTTP requests can safely read the cache while a background
// refresh is in flight (Ballerina requires explicit isolation reasoning for shared mutable
// state accessed from multiple service calls / strands).
isolated CachedSnapshot? cache = ();

isolated function getCached() returns CachedSnapshot? {
    lock {
        // Clone on the way out - a value can't be transferred out of a `lock` block still
        // aliasing the shared isolated variable, since callers could then mutate it and
        // silently corrupt the cache for every other concurrent request.
        return cache.clone();
    }
}

isolated function setCached(CachedSnapshot snapshot) {
    lock {
        cache = snapshot.clone();
    }
}

// Downloads and parses one run's artifactName artifact into a CachedSnapshot. Split out of
// refreshSnapshot so a malformed/partial artifact on the newest candidate run doesn't stop the
// caller from falling back to the next older run.
function downloadAndParseArtifact(json target, string runHtmlUrl) returns CachedSnapshot|error {
    int artifactId = check (check target.id).ensureType();

    // The zip download. Not caching or reusing this URL - it's documented to expire ~1 minute
    // after issuance, so we follow the redirect and read the body immediately.
    http:Response|http:ClientError zipResp = redirectFollower->/repos/[pipelineOwner]/[pipelineRepo]/actions/artifacts/[artifactId]/zip(
        headers = {"Authorization": "Bearer " + ghToken}
    );
    if zipResp is http:ClientError {
        return error("artifact download failed", zipResp);
    }
    byte[] zipBytes = check zipResp.getBinaryPayload();

    // ballerina/io has no temp-directory helper - shell out to `mktemp -d`, same pragmatic
    // approach as the `unzip` call below.
    os:Process|os:Error mktempProc = os:exec({value: "mktemp", arguments: ["-d"]});
    if mktempProc is os:Error {
        return error("failed to create a temp directory", mktempProc);
    }
    int mktempExit = check mktempProc.waitForExit();
    if mktempExit != 0 {
        return error("mktemp -d exited non-zero");
    }
    byte[] mktempOut = check mktempProc.output();
    string workDir = (check string:fromBytes(mktempOut)).trim();

    string zipPath = workDir + "/artifact.zip";
    check io:fileWriteBytes(zipPath, zipBytes);

    // Shelling out to `unzip` (verified via os:exec) rather than relying on an unconfirmed
    // stdlib archive-extraction API - `unzip` is a safe, universally-available assumption on
    // the Linux containers Choreo runs services on.
    os:Process|os:Error proc = os:exec({
        value: "unzip",
        arguments: ["-o", "-q", zipPath, "-d", workDir]
    });
    if proc is os:Error {
        return error("failed to invoke unzip", proc);
    }
    int exitCode = check proc.waitForExit();
    if exitCode != 0 {
        return error(string `unzip exited ${exitCode} for artifact ${artifactId}`);
    }

    json combinedJson = check io:fileReadJson(workDir + "/combined.json");
    model:CombinedReport report = check combinedJson.cloneWithType();

    return {
        report,
        fetchedAt: time:utcToString(time:utcNow()),
        runUrl: runHtmlUrl
    };
}

public function refreshSnapshot() returns CachedSnapshot|error {
    json runsResp = check ghApi->/repos/[pipelineOwner]/[pipelineRepo]/actions/workflows/[workflowFile]/runs
        (status = "completed", per_page = 10);
    json[] runs = check (check runsResp.workflow_runs).ensureType();
    if runs.length() == 0 {
        return error("no completed pipeline runs found yet");
    }

    // Runs are returned newest-first. The first one whose artifact list actually contains
    // artifactName wins - regardless of that run's own overall conclusion (see the module
    // docstring for why checking the run-level status isn't the right signal here).
    foreach json run in runs {
        int runId = check (check run.id).ensureType();
        string runHtmlUrl = check (check run.html_url).ensureType();

        json artifactsResp = check ghApi->/repos/[pipelineOwner]/[pipelineRepo]/actions/runs/[runId]/artifacts;
        json[] artifacts = check (check artifactsResp.artifacts).ensureType();
        json? target = ();
        foreach json a in artifacts {
            string name = check (check a.name).ensureType();
            if name == artifactName {
                target = a;
                break;
            }
        }
        if target is () {
            continue;
        }

        CachedSnapshot|error snapshot = downloadAndParseArtifact(<json>target, runHtmlUrl);
        if snapshot is CachedSnapshot {
            return snapshot;
        }
        // This run's artifact exists but failed to download/parse - fall back to an older run
        // rather than surfacing a hard error when a good candidate might exist right below it.
        log:printWarn(string `run ${runId}'s "${artifactName}" artifact failed to parse, trying an older run`, 'error = snapshot);
    }

    return error(string `none of the last ${runs.length()} completed runs have a usable "${artifactName}" artifact`);
}

// Called on service startup and then on a timer (see main.bal). Never lets a failed refresh
// clobber a good cached snapshot - logs loudly instead, and the dashboard keeps serving the
// last-known-good data with a staleness indicator (see render.bal:isStale).
public function refreshSnapshotSafely() {
    CachedSnapshot|error result = refreshSnapshot();
    if result is error {
        log:printError("snapshot refresh failed - serving last known good data if any", 'error = result);
        return;
    }
    setCached(result);
    log:printInfo(string `snapshot refreshed: ${result.report.findings.length()} findings, run ${result.runUrl}`);
}

public function getSnapshotOrRefresh() returns CachedSnapshot|error {
    CachedSnapshot? existing = getCached();
    if existing is CachedSnapshot {
        return existing;
    }
    // Cold start with nothing cached yet - block once so the first request isn't an error page.
    refreshSnapshotSafely();
    existing = getCached();
    if existing is CachedSnapshot {
        return existing;
    }
    return error("no snapshot available yet and the initial refresh failed - check service logs");
}
