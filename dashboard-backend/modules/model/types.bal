// Types mirroring combined.json, produced by the pipeline in
// Thevakumar-Luheerathan/integration-security-tools/trivy-vuln-scan/scripts/combine.py.
// Keep this in sync with that script's output shape - it is the single contract between
// Track A (the scan pipeline) and Track B (this dashboard).
//
// Lives in its own submodule (rather than the root module) purely so the alerting module
// (../alerting) can import it too: Ballerina disallows a submodule importing its own root
// package (that's a cyclic import), so the shared combined.json contract types have to live
// somewhere both the root module (aggregate.bal/ingest.bal/main.bal) and alerting can reach -
// this module, imported by both. The root module's own types.bal holds everything derived FROM
// these (PackageSummary, IssueRollup, etc.) - those are dashboard-rendering-specific and have no
// reason to be visible to alerting, so they stay put.

public type IssueRef record {|
    int? number;
    string? url;
    string state; // "open" | "closed"
    // Absent for very old combined.json produced before this field existed - null-safe, not
    // required, since alerting (the only consumer) already treats "unknown age" as "not stale".
    string? created_at = ();
|};

// A .trivyignore match - the finding is deliberately, permanently accepted as a known risk
// (upstream's decision, not a pipeline guess), never touched by issue_sync.py at all: no issue
// is ever created/updated/referenced for it (see issue_sync.py's main()). Distinct from a closed
// GitHub issue, which represents "believed fixed in source, maybe not yet published" - this is
// "won't be fixed / can't be fixed yet, and that's a documented decision", so it needs its own
// state in the UI rather than being conflated with either "active" or "closed".
public type AcceptedRisk record {|
    string reason; // the .trivyignore comment text verbatim, e.g. "Axiom version is not released yet"
    string 'source; // which ignorefile, e.g. "ballerina-distribution:.trivyignore@2201.13.x"
|};

public type Finding record {|
    // Absent for "vscode-extension" findings - that source has no Ballerina version concept at
    // all (it's scanned by branch, see plugin_branch below), so this can't be required for
    // every finding the way it used to be when only distribution/central sources existed.
    string? ballerina_version;
    string 'source; // "distribution" | "central" | "vscode-extension" - NEVER merge across these when aggregating
    string? package_org;
    string package_name; // always populated: "ballerina-lang"/"ballerina-vscode" for those sources, real name for central
    string? package_version;
    // Only populated for source "vscode-extension": the ballerina-vscode branch this was
    // scanned from (e.g. "main"), configurable per trivy-vuln-scan/vscode-targets.json.
    // Plays the same "which specific build variant" role package_version plays for central
    // packages - kept as a separate field rather than overloading package_version because a
    // branch name isn't a version and conflating them would be misleading.
    string? plugin_branch = ();
    // Raw underlying dependency coordinate trivy reports (e.g. "io.netty:netty-codec",
    // "axios"), independent of which Ballerina package/plugin wraps it. Version-independent, so
    // it's the only reliable way to check "is this library used by anything on Central at all" -
    // needed by findPendingDistributionFixes to avoid falsely claiming a lang-only/tooling
    // dependency (e.g. commons-beanutils) is "already fixed on Central" when it was never
    // published there.
    string library_name;
    string jar;
    string cve;
    string severity; // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    string installed_version;
    string fixed_version; // "" means no upstream fix exists yet
    // Other jar targets within the SAME package/distribution scan that reported the identical
    // CVE, collapsed into this one finding by combine.py's within-source dedup. Defaults to []
    // so a producer that omits the key (rather than sending an empty array) doesn't break
    // parsing - belt-and-suspenders, since combine.py always sets it today.
    string[] also_seen_in_jars = [];
    // Defaults to nil, not just nullable - a finding whose repo never resolved never gets this
    // key touched by issue_sync.py at all (verified: this broke parsing of every such finding
    // on this pipeline's first real end-to-end run against a live-generated report).
    IssueRef? issue = ();
    // Set by combine.py when this CVE matches a .trivyignore entry - mutually exclusive with
    // `issue` in practice (issue_sync.py skips accepted_risk findings entirely, so this stays
    // populated and `issue` stays null for them), but not enforced at the type level since
    // combine.py and issue_sync.py run as separate steps against the same JSON.
    AcceptedRisk? accepted_risk = ();
|};

public type ScanStatus record {|
    string? ballerina_version;
    string? plugin_branch = (); // populated instead of ballerina_version for "vscode-extension"
    string 'source;
    boolean ok;
    string? 'error;
|};

public type CombinedReport record {|
    string generated_at;
    // Optional with a default (not just nullable) - combine.py's output is the only producer
    // of this field, and a future version of it omitting the key entirely (as happened once
    // already - see git history) must not break parsing for everything else in the report.
    string? pipeline_run_url = ();
    string[] versions;
    ScanStatus[] scan_status;
    Finding[] findings;
|};
