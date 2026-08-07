// Pulls the latest combined.json out of the pipeline's GitHub Actions artifact, per the
// 3-call REST sequence verified during this project's design phase:
//   1. GET /repos/{owner}/{repo}/actions/workflows/{workflow}/runs?status=success&per_page=1
//   2. GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts
//   3. GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip  -> 302, ~1min-lived URL
//
// Stateless by design (per the approved plan): this service holds no database. All real state
// lives in GitHub Issues (written by issue_sync.py) and in the source-of-truth artifact itself.
// The only "state" here is an in-memory cache of the last successfully parsed snapshot, purely
// so a transient GitHub API hiccup doesn't blank the dashboard - falling back to stale-but-known
// data (with a visible staleness banner, see render.bal) beats showing an error page.

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
    CombinedReport report;
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

public function refreshSnapshot() returns CachedSnapshot|error {
    json runsResp = check ghApi->/repos/[pipelineOwner]/[pipelineRepo]/actions/workflows/[workflowFile]/runs
        (status = "success", per_page = 1);
    json[] runs = check (check runsResp.workflow_runs).ensureType();
    if runs.length() == 0 {
        return error("no successful pipeline runs found yet");
    }
    int runId = check (check runs[0].id).ensureType();
    string runHtmlUrl = check (check runs[0].html_url).ensureType();

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
        return error(string `run ${runId} has no "${artifactName}" artifact (yet?)`);
    }
    int artifactId = check (check target.id).ensureType();

    // Step 3: the zip download. Not caching or reusing this URL - it's documented to expire
    // ~1 minute after issuance, so we follow the redirect and read the body immediately.
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
    CombinedReport report = check combinedJson.cloneWithType();

    return {
        report,
        fetchedAt: time:utcToString(time:utcNow()),
        runUrl: runHtmlUrl
    };
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
