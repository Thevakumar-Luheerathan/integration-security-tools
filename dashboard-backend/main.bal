import integration_security_tools/dashboard_backend.alerting;
import ballerina/http;
import ballerina/log;
import ballerina/task;
import ballerina/time;

configurable int port = 9090;
configurable decimal refreshIntervalSeconds = 1800; // 30 min, aligned to slightly after the pipeline's own cadence
configurable decimal staleAfterSeconds = 2 * refreshIntervalSeconds;
// The React dashboard (a separate Choreo Web Application component) calls this API cross-origin
// from the browser. Defaults to "*" since the frontend's deployed Choreo URL isn't known until
// that component is created - tighten this to the real origin once it is.
configurable string[] allowOrigins = ["*"];

isolated class RefreshJob {
    *task:Job;

    public function execute() {
        // Captured BEFORE this cycle's refresh overwrites the cache - this is the "previous
        // snapshot" alerting.checkImmediateAlerts diffs against. () on a cold start (nothing
        // cached yet) or the very first refresh ever - checkImmediateAlerts is skipped in that
        // case below, since there's nothing meaningful to diff a first snapshot against.
        CachedSnapshot? previous = getCached();

        refreshSnapshotSafely();

        CachedSnapshot? current = getCached();
        if previous is CachedSnapshot && current is CachedSnapshot {
            error? alertResult = alerting:checkImmediateAlerts(previous.report, current.report);
            if alertResult is error {
                log:printError("immediate alert check failed", 'error = alertResult);
            }
        }
    }
}

function decimalSecondsBetween(string isoA, string isoB) returns decimal|error {
    time:Utc a = check time:utcFromString(isoA);
    time:Utc b = check time:utcFromString(isoB);
    return time:utcDiffSeconds(b, a);
}

@http:ServiceConfig {
    cors: {
        allowOrigins,
        allowMethods: ["GET", "POST"]
    }
}
service / on new http:Listener(port) {

    // The dashboard UI itself is the separate React app (a Choreo Web Application component) -
    // this service is a pure JSON API. Four structurally-identical views, each keyed to its own
    // pipeline source so nothing is ever double-counted (see aggregate.bal's SOURCE_* constants):
    // byLanguageCore is what ships with ballerina-lang itself (source "distribution"); byPackage
    // is Central packages/connectors (source "central"); byTool is Central bal tools, its own
    // pipeline track (source "tools" - see combine.py's process_central_tool_dir); byPlugin is
    // everything with no Ballerina-version concept (currently just ballerina-vscode, grouped by
    // scanned branch instead of package version). All four feed the same React PackageTable.
    resource function get api/summary() returns json|http:Response {
        CachedSnapshot|error snapshot = getSnapshotOrRefresh();
        if snapshot is error {
            http:Response response = new;
            response.statusCode = 503;
            response.setJsonPayload({'error: snapshot.message()});
            return response;
        }

        string nowIso = time:utcToString(time:utcNow());
        decimal|error age = decimalSecondsBetween(snapshot.fetchedAt, nowIso);
        boolean stale = age is decimal && age > staleAfterSeconds;

        return {
            generatedAt: snapshot.report.generated_at,
            fetchedAt: snapshot.fetchedAt,
            runUrl: snapshot.runUrl,
            stale,
            byVersionAndSource: summarizeByVersionAndSource(snapshot.report).toJson(),
            byLanguageCore: summarizeByLanguageCore(snapshot.report).toJson(),
            byPackage: summarizeByPackage(snapshot.report).toJson(),
            byPlugin: summarizeByPlugin(snapshot.report).toJson(),
            byTool: summarizeByTool(snapshot.report).toJson(),
            // "Accepted vulnerabilities in each Distribution" - per the reference design doc,
            // a per-line rollup distinct from the inline per-package/per-CVE display above.
            acceptedRiskByLine: summarizeAcceptedRiskByLine(snapshot.report).toJson(),
            findings: snapshot.report.findings.toJson()
        };
    }

    resource function get healthz() returns json {
        return {status: "ok"};
    }

    // Forces an immediate re-fetch, bypassing the scheduled interval - useful right after a
    // pipeline run finishes, or for manually clearing a stale/error state.
    resource function post refresh() returns json {
        refreshSnapshotSafely();
        return {status: "refresh triggered"};
    }

    // Deliberately a SEPARATE, externally-triggered endpoint rather than something checked on
    // every internal refresh cycle (see alerting.alert.bal's header comment) - a once-a-week
    // external schedule (e.g. a Choreo cron trigger) should call this, not the ~30min refresh
    // loop, which would otherwise fire it ~48 times on the digest day with no database-backed
    // "already sent today" guard. alert.bal itself also re-checks the configured digest day as a
    // defense-in-depth guard against a misconfigured trigger.
    resource function post alerts/weekly\-digest() returns json|http:Response {
        CachedSnapshot|error snapshot = getSnapshotOrRefresh();
        if snapshot is error {
            http:Response response = new;
            response.statusCode = 503;
            response.setJsonPayload({'error: snapshot.message()});
            return response;
        }

        error? result = alerting:sendWeeklyDigest(snapshot.report);
        if result is error {
            http:Response response = new;
            response.statusCode = 502;
            response.setJsonPayload({'error: result.message()});
            return response;
        }
        return {status: "weekly digest sent"};
    }
}

public function main() returns error? {
    log:printInfo("Ballerina vulnerability scan dashboard starting up");
    // Populate the cache once at startup so the very first request isn't a cold-start error.
    refreshSnapshotSafely();

    task:JobId _ = check task:scheduleJobRecurByFrequency(new RefreshJob(), refreshIntervalSeconds);

    // IMPORTANT: main() must RETURN here, not block forever. Ballerina's execution model is:
    // module init (registers listeners) -> main() runs -> ONLY AFTER main() returns does the
    // "listening phase" begin, which is when listener.start() actually gets called. An earlier
    // version of this function had `while true { runtime:sleep(3600) }` here, added under the
    // mistaken belief that returning from main() would kill the service - it's the opposite:
    // that loop prevented the listening phase from ever starting, so the HTTP listener never
    // bound to any port at all (verified: confirmed via lsof/nc/curl all showing zero listening
    // sockets on the process, while outbound calls from refreshSnapshotSafely() worked fine).
    // The runtime keeps the process alive on its own once real listeners are registered.
}
