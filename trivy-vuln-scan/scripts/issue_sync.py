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
    """Returns (open_issue_or_None, [closed_issues]), each a dict with number/title/state/url/body."""
    result = gh([
        "issue", "list", "--repo", tracking_repo, "--label", LABEL,
        "--state", "all", "--search", f'"{title}" in:title',
        "--json", "number,title,state,url,body,updatedAt",
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
    name = display_name(package_org, package_name)
    lines = [
        f"Automatically tracked vulnerabilities for `{name}`, across all scanned versions/"
        f"branches. This issue's body is fully rewritten on every pipeline run to reflect "
        f"current ACTIVE findings - manual edits here will be overwritten.",
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
    if dry_run:
        print(f"[dry-run] would CREATE issue '{title}' ({len(active_findings)} active finding(s))", file=sys.stderr)
        return {"number": None, "url": None, "state": "open"}
    out = gh([
        "issue", "create", "--repo", tracking_repo, "--title", title,
        "--body", body, "--label", LABEL,
    ])
    # `gh issue create` prints the created issue's URL as its only stdout line.
    url = out.strip().splitlines()[-1]
    number = int(url.rstrip("/").rsplit("/", 1)[-1])
    return {"number": number, "url": url, "state": "open"}


def update_issue(tracking_repo, issue, package_org, package_name, active_findings, suppressed_count, dry_run):
    body = render_body(package_org, package_name, active_findings, suppressed_count)
    if dry_run:
        print(f"[dry-run] would UPDATE issue #{issue['number']} ({len(active_findings)} active finding(s))", file=sys.stderr)
    else:
        gh(["issue", "edit", str(issue["number"]), "--repo", tracking_repo, "--body", body])
    return {"number": issue["number"], "url": issue["url"], "state": "open"}


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
    # findings below).
    closed_cve_to_issue = {}
    for issue in sorted(closed_issues, key=lambda i: i["updatedAt"]):
        for cve in extract_cve_ids(issue.get("body")):
            closed_cve_to_issue[cve] = issue  # later (more recent) closed issues win on conflict
    closed_cves = set(closed_cve_to_issue.keys())

    active = [f for f in findings if f["cve"] not in closed_cves]
    suppressed = [f for f in findings if f["cve"] in closed_cves]

    issue_refs = {}

    if active:
        if open_issue:
            ref = update_issue(tracking_repo, open_issue, package_org, package_name, active, len(suppressed), dry_run)
        else:
            ref = create_issue(tracking_repo, package_org, package_name, active, dry_run)
        for f in active:
            issue_refs[id(f)] = ref
    elif open_issue:
        close_issue(tracking_repo, open_issue, dry_run)

    for f in suppressed:
        closed_issue = closed_cve_to_issue[f["cve"]]
        issue_refs[id(f)] = {"number": closed_issue["number"], "url": closed_issue["url"], "state": "closed"}

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

    by_package = defaultdict(list)
    for finding in combined["findings"]:
        by_package[(finding["package_org"], finding["package_name"])].append(finding)

    for (package_org, package_name), findings in by_package.items():
        issue_refs = sync_package(args.tracking_repo, package_org, package_name, findings, args.dry_run)
        active_count = sum(1 for f in findings if issue_refs.get(id(f), {}).get("state") == "open")
        suppressed_count = len(findings) - active_count
        for f in findings:
            f["issue"] = issue_refs.get(id(f))
        name = display_name(package_org, package_name)
        active_ref = next((r for r in issue_refs.values() if r["state"] == "open"), None)
        print(
            f"{name}: {active_count} active, {suppressed_count} suppressed -> "
            f"issue {active_ref.get('url') if active_ref else '(none open)'}",
            file=sys.stderr,
        )

    with open(args.combined, "w") as f:
        json.dump(combined, f, indent=2)


if __name__ == "__main__":
    main()
