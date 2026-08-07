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
        refreshSnapshotSafely();
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
    // this service is a pure JSON API. byPackage groups findings into the package -> version ->
    // CVE hierarchy (see aggregate.bal:summarizeByPackage) that the React PackageTable renders.
    // byPlugin is the structurally-identical view for non-Ballerina-versioned sources (currently
    // just the ballerina-vscode extension, grouped by scanned branch instead of package version).
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
            byPackage: summarizeByPackage(snapshot.report).toJson(),
            byPlugin: summarizeByPlugin(snapshot.report).toJson(),
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
