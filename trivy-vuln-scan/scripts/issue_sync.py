#!/usr/bin/env python3
"""
Sync combined.json findings to GitHub issues, one issue per PACKAGE (not per repo, not per CVE),
in a tracking repo (currently Thevakumar-Luheerathan/integration-engineering - the user's fork;
migrating to the upstream wso2-enterprise/integration-engineering later is a --tracking-repo +
token swap only).

Design (confirmed with user):
  - One issue per package, keyed on (package_org, package_name) - e.g. "ballerinax"/"redis", or
    package_name="ballerina-lang" for the distribution source. There is deliberately no
    repo-resolution step (see combine.py's docstring) - library owners already know which repo
    their package lives in, so the issue TITLE uses a purely cosmetic, unverified naming
    convention (module-{org}-{name}, or "ballerina-lang" verbatim) for human readability only.
    Nothing links or routes on that string - the real identity used for grouping/dedup is
    (package_org, package_name) from the finding data itself.
  - The issue body is organized package -> version -> CVE: each distinct package version (or,
    for ballerina-lang, each Ballerina release line) gets its own subsection, listing only the
    CVEs that belong to THAT version - never a flat merged list, since two versions of the same
    package can have genuinely different vulnerable dependencies.
  - No assignee (confirmed with user - CODEOWNERS is unreliable for this: one individual
    appears on 67% of repos, so auto-assignment would spam them).
  - Closing an issue is a HUMAN judgment call ("already processed", "waiting on a release",
    "won't fix yet") - the pipeline never reopens a closed issue and never rewrites its body,
    regardless of what shows up in later scans. If the SAME CVE that was in a closed issue
    reappears, it is suppressed (treated as already-acknowledged, most likely just waiting on a
    Central publish that hasn't happened yet) rather than surfaced again. If a genuinely
    DIFFERENT CVE appears for that same package, a fresh issue is created for it - closing a
    package's issue doesn't blacklist the package forever, only the specific CVEs it covered.
    The pipeline MAY still auto-close an OPEN issue when a package's active findings drop to
    zero (a mechanical "genuinely clean" signal, unambiguous and distinct from reopening).
  - The issue is found by a deterministic label ("trivy-scan") + title convention, NOT by
    reading a cached issue number from a previous combined.json - that field is a DERIVED
    output of this script, never an input to it, re-derived from GitHub itself every run.

This script mutates combined.json IN PLACE, writing {"number", "url", "state"} onto every
finding. Every finding gets some package identity now (package_name is never null - see
combine.py), so there is no "unresolved" bucket left to handle here.

Requires: `gh` CLI authenticated with a token that has issue read/write on --tracking-repo.
"""
import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

LABEL = "trivy-scan"
CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)


def gh(args, input_text=None):
    proc = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, input=input_text, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def ensure_label_exists(tracking_repo):
    existing = gh(["label", "list", "--repo", tracking_repo, "--json", "name"])
    names = {item["name"] for item in json.loads(existing)}
    if LABEL not in names:
        gh([
            "label", "create", LABEL, "--repo", tracking_repo,
            "--color", "B60205", "--description", "Auto-filed by the Ballerina vulnerability scan pipeline",
        ])


def display_name(package_org, package_name):
    """
    Cosmetic-only string for the issue title - never verified against GitHub, never looked up,
    no exceptions file. A human reading the title will recognize their own package regardless of
    an occasional naming-convention mismatch; nothing routes or links on this string.
    """
    if package_name in ("ballerina-lang", "ballerina-vscode"):
        return package_name
    return f"module-{package_org}-{package_name}"


def issue_title(package_org, package_name):
    return f"[Trivy] Vulnerabilities found in {display_name(package_org, package_name)}"


def find_package_issues(tracking_repo, title):
    """Returns (open_issue_or_None, [closed_issues]), each a dict with number/title/state/url/body.

    createdAt is requested alongside the rest so it can be threaded onto the Finding.issue ref
    written at the bottom of this script - the alerting module (dashboard-backend) needs "how
    long has this been open" to detect a severe issue crossing the not-attended threshold, without
    a second GitHub API round-trip of its own.
    """
    result = gh([
        "issue", "list", "--repo", tracking_repo, "--label", LABEL,
        "--state", "all", "--search", f'"{title}" in:title',
        "--json", "number,title,state,url,body,updatedAt,createdAt",
    ])
    matches = [item for item in json.loads(result) if item["title"] == title]

    open_issues = [i for i in matches if i["state"].lower() == "open"]
    closed_issues = [i for i in matches if i["state"].lower() == "closed"]

    open_issue = None
    if open_issues:
        # Expected at most one; if somehow more, the most recently updated is authoritative.
        open_issue = max(open_issues, key=lambda i: i["updatedAt"])

    return open_issue, closed_issues


def extract_cve_ids(text):
    if not text:
        return set()
    return {m.group(1) for m in CVE_ID_RE.finditer(text)}


def fetch_issue_comment_bodies(tracking_repo, issue_number):
    result = gh(["issue", "view", str(issue_number), "--repo", tracking_repo, "--json", "comments"])
    return [c["body"] for c in json.loads(result).get("comments", [])]


def known_cve_ids(tracking_repo, issue):
    """
    Every CVE already surfaced for this issue - from its body (only ever written at creation time
    now, see render_body/create_issue) UNION every comment posted on it since (new-finding
    comments from comment_new_findings, the close comment from close_issue, etc.).

    Needed because the body is no longer kept in sync after creation - it used to be the single
    source of truth for "what's already been reported here", rewritten in full on every run. Now
    that ongoing updates are comments instead, a CVE that only ever arrived via a comment (never
    in the body) still has to count as "already known" - both for the open issue (so a routine
    re-run doesn't re-comment about a finding that's still there) and for a CLOSED issue (so
    suppress-on-recurrence in sync_package still recognizes it if the same CVE reappears later -
    otherwise it would incorrectly look "new" and get its own fresh issue instead of being
    suppressed as already-acknowledged).
    """
    ids = extract_cve_ids(issue.get("body"))
    for comment_body in fetch_issue_comment_bodies(tracking_repo, issue["number"]):
        ids |= extract_cve_ids(comment_body)
    return ids


def version_groups(package_name, findings):
    """
    Groups a package's findings into (label, findings) pairs per the package -> version -> CVE
    hierarchy - each version's CVE list belongs only to that version, never merged across
    versions. Returns groups sorted by label for stable rendering.
    """
    groups = defaultdict(list)
    if package_name == "ballerina-lang":
        for f in findings:
            groups[f["ballerina_version"]].append(f)
        return sorted(groups.items())

    if package_name == "ballerina-vscode":
        # No Ballerina version concept at all - grouped by the scanned branch instead.
        for f in findings:
            groups[f["plugin_branch"]].append(f)
        return sorted(groups.items())

    # Central package: group by distinct package_version, label with every Ballerina line that
    # version was resolved for (a version can legitimately serve >1 line - Central always
    # returns the single latest version, which often satisfies more than one line's floor check).
    versions_by_pkg_version = defaultdict(set)
    for f in findings:
        groups[f["package_version"]].append(f)
        versions_by_pkg_version[f["package_version"]].add(f["ballerina_version"])

    labeled = []
    for pkg_version, group_findings in groups.items():
        lines = ", ".join(sorted(versions_by_pkg_version[pkg_version]))
        labeled.append((f"{pkg_version} ({lines})", group_findings))
    return sorted(labeled)


def render_finding_row(f):
    also = f.get("also_seen_in_jars") or []
    jar = f["jar"] + (f" (+{len(also)} more)" if also else "")
    fixed = f["fixed_version"] or "_no fix available yet_"
    return f"| {jar} | {f['cve']} | {f['severity']} | {f['installed_version']} | {fixed} |"


def render_body(package_org, package_name, findings, suppressed_count):
    """
    Only ever called once, by create_issue() - an already-open issue's body is never rewritten
    again (see comment_new_findings for how ongoing updates work instead). This snapshot reflects
    the findings active at creation time only; it will not stay in sync as the issue evolves.
    """
    name = display_name(package_org, package_name)
    lines = [
        f"Automatically tracked vulnerabilities for `{name}`, across all scanned versions/"
        f"branches. This issue's body reflects the findings active when it was CREATED - it is "
        f"never rewritten after that. New findings while this issue stays open are posted as "
        f"comments instead (see below), not edits to this body.",
        "",
        "Closing this issue is a judgment call for a human to make (already fixed upstream but "
        "not yet published, won't-fix, tracked elsewhere, etc.) - the pipeline never reopens a "
        "closed issue and never rewrites its body. If the same CVE reappears in a later scan "
        "after this issue is closed, it will be suppressed (not re-surfaced) rather than "
        "reopening this issue, since a closed issue implies it's already been acknowledged - "
        "most likely just waiting on a new package release. A genuinely different/new CVE for "
        "this package will get its own fresh issue instead.",
    ]
    if suppressed_count:
        lines.append(
            f"\n_{suppressed_count} finding(s) for this package matched a CVE already covered "
            f"by a previously closed issue and are intentionally omitted below._"
        )
    lines.append("")

    for label, group_findings in version_groups(package_name, findings):
        lines.append(f"### {label}")
        lines.append("")
        lines.append("| Jar | CVE | Severity | Installed | Fixed |")
        lines.append("|---|---|---|---|---|")
        for f in sorted(group_findings, key=lambda f: (f["severity"], f["cve"] or "")):
            lines.append(render_finding_row(f))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def create_issue(tracking_repo, package_org, package_name, active_findings, dry_run):
    title = issue_title(package_org, package_name)
    body = render_body(package_org, package_name, active_findings, suppressed_count=0)
    # Approximated as "now" rather than a follow-up `gh issue view` round-trip - a few seconds of
    # drift from the real creation timestamp is irrelevant for a "been open more than a week"
    # staleness check.
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if dry_run:
        print(f"[dry-run] would CREATE issue '{title}' ({len(active_findings)} active finding(s))", file=sys.stderr)
        return {"number": None, "url": None, "state": "open", "created_at": created_at}
    out = gh([
        "issue", "create", "--repo", tracking_repo, "--title", title,
        "--body", body, "--label", LABEL,
    ])
    # `gh issue create` prints the created issue's URL as its only stdout line.
    url = out.strip().splitlines()[-1]
    number = int(url.rstrip("/").rsplit("/", 1)[-1])
    return {"number": number, "url": url, "state": "open", "created_at": created_at}


def render_new_findings_comment(new_findings, suppressed_count):
    lines = [f"**{len(new_findings)} new finding(s) detected in this scan:**", ""]
    lines.append("| Jar | CVE | Severity | Installed | Fixed |")
    lines.append("|---|---|---|---|---|")
    for f in sorted(new_findings, key=lambda f: (f["severity"], f["cve"] or "")):
        lines.append(render_finding_row(f))
    if suppressed_count:
        lines.append("")
        lines.append(
            f"_{suppressed_count} other finding(s) for this package matched a CVE already "
            f"covered by a previously closed issue and are intentionally omitted._"
        )
    return "\n".join(lines)


def issue_ref(issue):
    return {"number": issue["number"], "url": issue["url"], "state": "open", "created_at": issue.get("createdAt")}


def comment_new_findings(tracking_repo, issue, new_findings, suppressed_count, dry_run):
    """
    Replaces the old update_issue()'s full-body rewrite: an already-open issue's body is now
    written ONLY at creation time (see create_issue/render_body) and never touched again -
    ongoing updates while it stays open are comments instead, one per sync run, listing only the
    genuinely new finding(s) that triggered it. A run with no new findings for this issue (e.g. a
    routine package_version bump with the same CVEs, or simply nothing changed) posts nothing at
    all - this is the whole point of the switch: don't ping the issue on every single run the way
    a full body rewrite implicitly did.
    """
    if dry_run:
        print(f"[dry-run] would COMMENT on issue #{issue['number']} ({len(new_findings)} new finding(s))", file=sys.stderr)
    else:
        body = render_new_findings_comment(new_findings, suppressed_count)
        gh(["issue", "comment", str(issue["number"]), "--repo", tracking_repo, "--body", body])
    return issue_ref(issue)


def close_issue(tracking_repo, issue, dry_run):
    if dry_run:
        print(f"[dry-run] would CLOSE issue #{issue['number']} (no active findings remain)", file=sys.stderr)
        return
    gh([
        "issue", "comment", str(issue["number"]), "--repo", tracking_repo,
        "--body", "No active findings remain for this package as of the latest scan. Closing.",
    ])
    gh(["issue", "close", str(issue["number"]), "--repo", tracking_repo])


def sync_package(tracking_repo, package_org, package_name, findings, dry_run):
    """
    Returns a dict mapping each finding's id(finding) -> issue ref, per the lifecycle described
    in the module docstring. Never reopens or rewrites a closed issue.
    """
    title = issue_title(package_org, package_name)
    open_issue, closed_issues = find_package_issues(tracking_repo, title)

    # Union of CVEs already covered by ANY closed issue for this package, plus a per-CVE map to
    # the most recent closed issue that mentioned it (for attaching a reference onto suppressed
    # findings below). known_cve_ids (not extract_cve_ids(body) alone) is required here: a CVE
    # may have only ever been surfaced via a comment on this issue while it was still open (see
    # comment_new_findings), never written into the body itself - missing that would make a
    # recurring CVE look "new" instead of being correctly suppressed as already-acknowledged.
    closed_cve_to_issue = {}
    for issue in sorted(closed_issues, key=lambda i: i["updatedAt"]):
        for cve in known_cve_ids(tracking_repo, issue):
            closed_cve_to_issue[cve] = issue  # later (more recent) closed issues win on conflict
    closed_cves = set(closed_cve_to_issue.keys())

    active = [f for f in findings if f["cve"] not in closed_cves]
    suppressed = [f for f in findings if f["cve"] in closed_cves]

    issue_refs = {}

    if active:
        if open_issue:
            already_known = known_cve_ids(tracking_repo, open_issue)
            new_findings = [f for f in active if f["cve"] not in already_known]
            if new_findings:
                ref = comment_new_findings(tracking_repo, open_issue, new_findings, len(suppressed), dry_run)
            else:
                ref = issue_ref(open_issue)
        else:
            ref = create_issue(tracking_repo, package_org, package_name, active, dry_run)
        for f in active:
            issue_refs[id(f)] = ref
    elif open_issue:
        close_issue(tracking_repo, open_issue, dry_run)

    for f in suppressed:
        closed_issue = closed_cve_to_issue[f["cve"]]
        issue_refs[id(f)] = {
            "number": closed_issue["number"], "url": closed_issue["url"], "state": "closed",
            "created_at": closed_issue.get("createdAt"),
        }

    return issue_refs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--combined", required=True, help="combined.json to read AND update in place")
    ap.add_argument("--tracking-repo", default="Thevakumar-Luheerathan/integration-engineering")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.combined) as f:
        combined = json.load(f)

    ensure_label_exists(args.tracking_repo)

    for finding in combined["findings"]:
        finding.setdefault("issue", None)

    # Every package that had ANY finding this run still gets grouped here - including ones whose
    # findings are entirely accepted_risk - so sync_package still gets called for it below and
    # can auto-close a previously-open issue if nothing trackable remains. accepted_risk findings
    # themselves are filtered out before being handed to sync_package: they're pre-accepted at
    # scan time (via .trivyignore), so they never influence issue creation/update/closing and
    # never get an issue reference written (stays None from the setdefault above) - tracked via
    # their accepted_risk field instead, not a GitHub issue.
    by_package = defaultdict(list)
    for finding in combined["findings"]:
        by_package[(finding["package_org"], finding["package_name"])].append(finding)

    for (package_org, package_name), all_findings in by_package.items():
        trackable = [f for f in all_findings if not f.get("accepted_risk")]
        accepted_count = len(all_findings) - len(trackable)

        issue_refs = sync_package(args.tracking_repo, package_org, package_name, trackable, args.dry_run)
        active_count = sum(1 for f in trackable if issue_refs.get(id(f), {}).get("state") == "open")
        suppressed_count = len(trackable) - active_count
        for f in trackable:
            f["issue"] = issue_refs.get(id(f))
        name = display_name(package_org, package_name)
        active_ref = next((r for r in issue_refs.values() if r["state"] == "open"), None)
        print(
            f"{name}: {active_count} active, {suppressed_count} suppressed, {accepted_count} "
            f"accepted-risk -> issue {active_ref.get('url') if active_ref else '(none open)'}",
            file=sys.stderr,
        )

    with open(args.combined, "w") as f:
        json.dump(combined, f, indent=2)


if __name__ == "__main__":
    main()
