#!/usr/bin/env python3
"""
Sync combined.json findings to GitHub issues, one issue per PACKAGE (not per repo, not per CVE),
in a tracking repo (wso2-enterprise/integration-engineering, the real upstream tracker - it lived
at Thevakumar-Luheerathan/integration-engineering, a personal fork, while this pipeline itself was
being built/tested; migrating was just a --tracking-repo + token-access swap, no redesign).

Design (confirmed with user):
  - One issue per package (or tool), keyed on (source, package_org, package_name) - e.g.
    "central"/"ballerinax"/"redis", or package_name="ballerina-lang" for the distribution
    source. `source` is part of the key (not just package_org/package_name) so a Central "tools"
    finding can never merge into a same-named regular package's group - see main()'s by_package
    comment. There is deliberately no repo-resolution step for regular packages (see combine.py's
    docstring) - library owners already know which repo their package lives in, so the issue
    TITLE uses a purely cosmetic, unverified naming convention (module-{org}-{name}, or
    "ballerina-lang" verbatim) for human readability only - see group_display_name for the
    per-source display rule (tools use their balToolId alone instead, e.g. "scan tool", since
    the module-{org}-{name} convention is confirmed actively misleading for them). Nothing links
    or routes on that string - the real identity used for grouping/dedup is
    (source, package_org, package_name) from the finding data itself.
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
PARENT_LABEL = "trivy-scan-parent"
PARENT_TITLE = "[Trivy] Vulnerability tracking - parent issue"
CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)


def gh(args, input_text=None):
    proc = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, input=input_text, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def ensure_label_exists(tracking_repo, label, color, description):
    # --limit is required, not cosmetic: `gh label list` defaults to a 30-item page, which was
    # invisible on the small personal testing fork (a handful of labels total) but silently
    # broke the very first real run against the actual upstream org repo - it already had 110
    # labels, trivy-scan/trivy-scan-parent existed but sorted outside the default page, so this
    # wrongly concluded they didn't exist and then failed trying to (re)create them. 1000 is
    # comfortably above any repo's real label count.
    existing = gh(["label", "list", "--repo", tracking_repo, "--json", "name", "--limit", "1000"])
    names = {item["name"] for item in json.loads(existing)}
    if label not in names:
        gh([
            "label", "create", label, "--repo", tracking_repo,
            "--color", color, "--description", description,
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


def group_display_name(findings):
    """
    THE one place that decides what a finding group is called. Computed once per group in
    main() and threaded down through sync_package/create_issue/issue_title/render_body -
    deliberately never re-derived at a lower layer. The title IS the lookup key
    (find_package_issues matches on exact title text), so a layer deriving it even slightly
    differently would miss the existing issue and file a duplicate on every single run.

    `findings` is never empty here: main() computes this from a group's FULL finding list, not
    the trackable subset, which can legitimately be empty (all-accepted-risk auto-close).
    """
    first = findings[0]
    if first.get("source") == "tools":
        # balToolId ALONE (e.g. "scan" for ballerina/tool_scan), read naturally as "...found in
        # scan tool". NOT module-{org}-{name}: that convention is confirmed actively MISLEADING
        # for tools (ballerina/tool_scan actually lives in
        # ballerina-platform/static-code-analysis-tool). NOT {org}/{name} either - the tool id is
        # what its users and maintainers actually call it (`bal tool pull scan`).
        return f"{first.get('tool_id') or first['package_name']} tool"
    return display_name(first["package_org"], first["package_name"])


def issue_title(display):
    return f"[Trivy] Vulnerabilities found in {display}"


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
        "--json", "number,title,state,url,body,updatedAt,createdAt", "--limit", "1000",
    ])
    matches = [item for item in json.loads(result) if item["title"] == title]

    open_issues = [i for i in matches if i["state"].lower() == "open"]
    closed_issues = [i for i in matches if i["state"].lower() == "closed"]

    open_issue = None
    if open_issues:
        # Expected at most one; if somehow more, the most recently updated is authoritative.
        open_issue = max(open_issues, key=lambda i: i["updatedAt"])

    return open_issue, closed_issues


def find_or_create_parent_issue(tracking_repo, dry_run):
    """
    The single, ongoing parent issue every newly-created package issue gets attached to as a
    real GitHub sub-issue (see add_sub_issue) - found by its dedicated PARENT_LABEL, not by
    title text matching (unlike find_package_issues), since there's only ever meant to be one
    of these and a distinct label is a more robust lookup than a title search. Returns its issue
    number, or None in dry-run mode (nothing was actually created/found to attach to).
    """
    result = gh([
        "issue", "list", "--repo", tracking_repo, "--label", PARENT_LABEL,
        "--state", "open", "--json", "number,title", "--limit", "1000",
    ])
    matches = [i for i in json.loads(result) if i["title"] == PARENT_TITLE]
    if matches:
        return matches[0]["number"]

    if dry_run:
        print("[dry-run] would CREATE the parent tracking issue", file=sys.stderr)
        return None

    body = (
        "Parent tracking issue for the Ballerina proactive vulnerability scan pipeline - every "
        "per-package issue the pipeline creates is linked below as a sub-issue.\n\n"
        "- Each sub-issue is independently created, updated, and closed by the pipeline exactly "
        "as described in its own body - this parent doesn't change any of that, it exists "
        "purely to give one place to see everything at a glance (GitHub tracks the open/closed "
        "sub-issue count and progress bar automatically once they're linked).\n"
        "- Closing a sub-issue acknowledges that package's findings, per its own body - it has "
        "no effect on this parent, which stays open indefinitely.\n"
        "- New package issues the pipeline creates going forward are linked here automatically "
        "as they're created."
    )
    out = gh([
        "issue", "create", "--repo", tracking_repo, "--title", PARENT_TITLE,
        "--body", body, "--label", LABEL, "--label", PARENT_LABEL,
    ])
    url = out.strip().splitlines()[-1]
    return int(url.rstrip("/").rsplit("/", 1)[-1])


def add_sub_issue(tracking_repo, parent_number, child_number, dry_run):
    """
    Attaches child_number as a real GitHub sub-issue of parent_number - only ever called right
    after create_issue() for a BRAND NEW package issue (not on every sync of an already-existing
    one, and not for closed/suppressed findings). GitHub's sub-issue API is asymmetric: the
    parent is addressed by its issue NUMBER (repo-scoped) in the URL path, but the child must be
    given by its internal database ID (globally unique, NOT the same as its issue number) in the
    request body - hence the extra lookup below.

    Failure here is logged and swallowed, never raised: the child issue itself was already
    created successfully by this point and is fully valid/tracked on its own - losing just the
    visual sub-issue grouping is a cosmetic degradation, not a reason to fail the whole sync run.
    """
    if dry_run or parent_number is None:
        print(f"[dry-run] would attach issue #{child_number} as a sub-issue of parent #{parent_number}", file=sys.stderr)
        return
    try:
        child_id = int(gh(["api", f"repos/{tracking_repo}/issues/{child_number}", "--jq", ".id"]).strip())
        gh(["api", "--method", "POST", f"repos/{tracking_repo}/issues/{parent_number}/sub_issues", "-F", f"sub_issue_id={child_id}"])
    except RuntimeError as e:
        print(f"WARNING: failed to attach issue #{child_number} as a sub-issue of parent #{parent_number}: {e}", file=sys.stderr)


def extract_cve_ids(text):
    if not text:
        return set()
    return {m.group(1) for m in CVE_ID_RE.finditer(text)}


def fetch_issue_comment_bodies(tracking_repo, issue_number):
    result = gh(["issue", "view", str(issue_number), "--repo", tracking_repo, "--json", "comments"])
    return [c["body"] for c in json.loads(result).get("comments", [])]


def finding_scope(f):
    """
    The identity dimension a finding belongs to within its package - "which variant of this
    package/version-line does this finding belong to". Reused by version_groups() (grouping) AND
    known_finding_keys()/sync_package() (dedup identity) so the two can never drift apart: once a
    package can resolve to multiple simultaneous versions (see the multi-version Central scan),
    a bare CVE is no longer a unique identity - the same CVE can legitimately be new for one
    version and already-known for another.
    """
    if f["package_name"] == "ballerina-lang":
        return f["ballerina_version"]
    if f["package_name"] == "ballerina-vscode":
        return f["plugin_branch"]
    return f["package_version"]


KEYS_MARKER_RE = re.compile(r"<!--\s*trivy-scan-keys:\s*(\{.*?\})\s*-->", re.DOTALL)


def build_keys_marker(scope_to_cves):
    """
    Low-level marker builder taking a plain {scope: [cve, ...]} map - split out from
    render_keys_marker so the standalone backfill script (which works from parsed GitHub text,
    not Finding dicts) can build the identical marker format without duplicating this logic.
    """
    payload = {scope: sorted(set(cves)) for scope, cves in sorted(scope_to_cves.items())}
    return f"<!-- trivy-scan-keys: {json.dumps(payload)} -->"


def render_keys_marker(findings):
    """
    Hidden HTML-comment marker embedding a body/comment's exact (scope, cve) keys as structured
    JSON - GitHub renders HTML comments as nothing visible, but `gh issue view --json
    comments/body` returns the raw markdown source, so known_finding_keys can read this back out
    exactly rather than re-deriving it from the visible table. Grouped by scope so a single
    comment covering multiple versions at once doesn't collapse into an ambiguous flat CVE list.
    """
    by_scope = defaultdict(list)
    for f in findings:
        by_scope[finding_scope(f)].append(f["cve"])
    return build_keys_marker(by_scope)


def parse_keys_marker(text):
    """Returns {(scope, cve), ...} from a trivy-scan-keys marker in text, or None if absent/unparseable."""
    if not text:
        return None
    m = KEYS_MARKER_RE.search(text)
    if not m:
        return None
    try:
        payload = json.loads(m.group(1))
    except (json.JSONDecodeError, TypeError):
        return None
    keys = set()
    for scope, cves in payload.items():
        for cve in cves:
            keys.add((scope, cve))
    return keys


def parse_body_scopes(text):
    """
    Fallback for bodies/comments that predate the trivy-scan-keys marker: recovers scope from
    the "### <scope> (...)" section headers render_body already emits (see version_groups) -
    scope is the text before " (" (a no-op split for distribution/vscode labels, which carry no
    parenthetical). Returns {scope: set(cve)} by scanning each section's own text for CVE-shaped
    tokens, so a CVE only ever attaches to the section it actually appeared under. Returns {} if
    no "### " header is found at all (comments never have one - only render_body writes them).
    """
    if not text:
        return {}
    sections = re.split(r"^### (.+)$", text, flags=re.MULTILINE)
    # re.split with a capturing group interleaves: [preamble, header1, body1, header2, body2, ...]
    scopes = {}
    for i in range(1, len(sections), 2):
        header = sections[i]
        section_text = sections[i + 1] if i + 1 < len(sections) else ""
        scope = header.split(" (", 1)[0].strip()
        scopes[scope] = extract_cve_ids(section_text)
    return scopes


def known_finding_keys(tracking_repo, issue):
    """
    Every (scope, cve) pair already surfaced for this issue - successor to the old CVE-only
    known_cve_ids now that identity is scope-aware (see finding_scope): once a package can
    resolve to multiple versions at once, a bare CVE match is no longer enough - a CVE already
    reported for version 2.16.6 must not suppress that SAME CVE showing up for a different
    version, 2.15.7, that was never actually reported.

    Prefers the hidden trivy-scan-keys marker (present on every body/comment this script writes
    going forward - see render_keys_marker) - exact, unambiguous. Falls back to parsing the
    "### <scope> (...)" section headers already written by render_body, for older bodies/
    comments that predate this change and carry no marker (verified: the 13 real open issues at
    the time of this change each have exactly one such section, so their scope is unambiguous
    even without a marker - see backfill_comment_versions.py for the one-off migration of their
    comments). A comment with neither a marker nor a recognizable header contributes its bare
    CVEs as known for EVERY scope this issue has otherwise established - conservative
    (suppresses rather than double-posts) - and logs a warning naming the issue, so a missed
    backfill is visible rather than silently wrong.
    """
    keys = set()
    unscoped_cves = set()
    all_scopes_seen = set()

    def _consume(text):
        marker_keys = parse_keys_marker(text)
        if marker_keys is not None:
            keys.update(marker_keys)
            all_scopes_seen.update(scope for scope, _ in marker_keys)
            return
        scoped = parse_body_scopes(text)
        if scoped:
            for scope, cves in scoped.items():
                all_scopes_seen.add(scope)
                for cve in cves:
                    keys.add((scope, cve))
            return
        bare = extract_cve_ids(text)
        if bare:
            unscoped_cves.update(bare)

    _consume(issue.get("body"))
    for comment_body in fetch_issue_comment_bodies(tracking_repo, issue["number"]):
        _consume(comment_body)

    if unscoped_cves:
        print(
            f"WARNING: issue #{issue['number']} has a comment/body with no trivy-scan-keys "
            f"marker and no '### <scope>' header - treating {sorted(unscoped_cves)} as known "
            f"for every scope this issue has ({sorted(all_scopes_seen) or 'none seen yet'}).",
            file=sys.stderr,
        )
        for scope in all_scopes_seen:
            for cve in unscoped_cves:
                keys.add((scope, cve))

    return keys


def version_groups(package_name, findings):
    """
    Groups a package's findings into (label, findings) pairs per the package -> version -> CVE
    hierarchy - each version's CVE list belongs only to that version, never merged across
    versions. Returns groups sorted by label for stable rendering. Grouping key is finding_scope
    (see there) so this can never drift out of sync with the dedup identity used elsewhere.
    """
    groups = defaultdict(list)
    if package_name == "ballerina-lang":
        for f in findings:
            groups[finding_scope(f)].append(f)
        return sorted(groups.items())

    if package_name == "ballerina-vscode":
        # No Ballerina version concept at all - grouped by the scanned branch instead.
        for f in findings:
            groups[finding_scope(f)].append(f)
        return sorted(groups.items())

    # Central package: group by distinct package_version, label with every Ballerina line that
    # version was resolved for (a version can legitimately serve >1 line - see the multi-version
    # selection rule in central_resolve.py, which can also fill a line's slot from a lower one).
    versions_by_pkg_version = defaultdict(set)
    for f in findings:
        scope = finding_scope(f)
        groups[scope].append(f)
        versions_by_pkg_version[scope].add(f["ballerina_version"])

    labeled = []
    for pkg_version, group_findings in groups.items():
        lines = ", ".join(sorted(versions_by_pkg_version[pkg_version]))
        labeled.append((f"{pkg_version} ({lines})", group_findings))
    return sorted(labeled)


def dedupe_for_display(findings):
    """
    Collapses Finding objects that share the same (scope, cve) into one representative, for
    DISPLAY purposes only - never mutates or drops anything from combined.json itself. This
    happens for real: a Central package version resolved under more than one configured line
    (see central_resolve.py's multi-version selection) gets scanned once per line, and
    combine.py's dedup is per-line (process_central_dir resets its "seen" map for each line's
    own run) - so the exact same (package_version, cve) fact legitimately ends up as two
    separate Finding objects, identical except for ballerina_version. Nothing distinguishes them
    in a rendered row (which never shows ballerina_version - see render_finding_row/version_groups'
    label, which already carries the "(2201.12.x, 2201.13.x)" line info at the header level), so
    printing both is pure noise that reads as a data bug to anyone reading the issue.

    Deliberately NOT done in combine.py / the Finding schema: dashboard-backend's
    summarizeByVersionAndSource needs one Finding object per line to attribute severity counts
    to each line correctly - collapsing at the data layer would silently under-count one line's
    dashboard view. sync_package's issue-ref assignment also still iterates the full, undeduped
    findings list, so every original object (including the one dropped here) still gets its
    issue reference written back onto combined.json exactly as before.
    """
    seen = {}
    for f in findings:
        key = (finding_scope(f), f["cve"])
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def render_finding_row(f):
    also = f.get("also_seen_in_jars") or []
    jar = f["jar"] + (f" (+{len(also)} more)" if also else "")
    fixed = f["fixed_version"] or "_no fix available yet_"
    return f"| {finding_scope(f)} | {jar} | {f['cve']} | {f['severity']} | {f['installed_version']} | {fixed} |"


def render_body(display, package_name, findings, suppressed_count):
    """
    Only ever called once, by create_issue() - an already-open issue's body is never rewritten
    again (see comment_new_findings for how ongoing updates work instead). This snapshot reflects
    the findings active at creation time only; it will not stay in sync as the issue evolves.
    """
    source = findings[0].get("source")
    # `source` is derived locally here rather than threaded like `display` - a display-name
    # mismatch is catastrophic (duplicate issues, see group_display_name), a prose mismatch here
    # is merely cosmetic, so it doesn't need the same single-source-of-truth discipline.
    if source == "tools":
        tool_id = findings[0].get("tool_id") or display
        acknowledgement_lines = [
            "- Acknowledging a finding means **closing this issue** - there's no separate flag or "
            "label, closing this issue is the acknowledgment.",
            "- Close this issue once you've made a call on it: already fixed upstream (release "
            "pending), won't-fix, tracked elsewhere, accepted risk, etc.",
            # TODO(tools-trivyignore): no .trivyignore/accepted-risk path exists for tools yet
            # (see combine.py's process_central_tool_dir) - this must NOT tell a tool owner to
            # add a CVE to a file nothing reads. Restore the standard wording (pointed at the
            # tool's own repo) once that work resumes.
            "- **There is no `.trivyignore`-based accepted-risk path for Ballerina tools yet** - "
            "if a CVE will not actually be fixed, say so in a comment before closing; closing "
            "this issue is currently the only acknowledgement mechanism available for tools.",
            "- Once closed, every CVE mentioned in this issue (body + comments) is treated as "
            "acknowledged - if the exact same CVE shows up again in a future scan, it is silently "
            "suppressed, not reopened and not re-surfaced as a new issue.",
            "- A genuinely **different** CVE for this same tool always gets its own fresh issue - "
            "closing this one does not block future issues for this tool.",
            "- Once closed, this issue is never reopened and its body is never edited again by "
            "the pipeline.",
        ]
        lines = [
            f"Automatically tracked vulnerabilities for the Ballerina tool `{tool_id}` "
            f"(published on Ballerina Central as `{findings[0]['package_org']}/{findings[0]['package_name']}`).",
            "",
            f"- This issue's body reflects the findings active when it was **created** - it is "
            f"never rewritten after that.",
            f"- New findings detected while this issue stays open are posted as **comments below**, "
            f"not edits to this body.",
            "",
            "**How acknowledgement works:**",
            "",
            *acknowledgement_lines,
        ]
    else:
        # Where an unfixed CVE should be documented via .trivyignore before closing. Drive-by fix
        # (unrelated to tools): this used to read "ballerina-distribution's branch" for Central
        # findings too, which went stale the moment Phase 2 moved Central to a per-package repo
        # lookup (see combine.py's "Central accepted-risk handling") - still correct for
        # distribution findings, which do still share that one file.
        if package_name == "ballerina-vscode":
            trivyignore_target = "ballerina-vscode's own branch"
        elif source == "central":
            trivyignore_target = "your package's own repo"
        else:
            trivyignore_target = "ballerina-distribution's branch for this Ballerina version line"
        lines = [
            f"Automatically tracked vulnerabilities for `{display}`.",
            "",
            f"- This issue's body reflects the findings active when it was **created** - it is "
            f"never rewritten after that.",
            f"- New findings detected while this issue stays open are posted as **comments below**, "
            f"not edits to this body.",
            "",
            "**How acknowledgement works:**",
            "",
            "- Acknowledging a finding means **closing this issue** - there's no separate flag or "
            "label, closing this issue is the acknowledgment.",
            "- Close this issue once you've made a call on it: already fixed upstream (release "
            "pending), won't-fix, tracked elsewhere, accepted risk, etc.",
            f"- **If a CVE will not actually be fixed** (or won't be fixed soon), also add it to "
            f"`.trivyignore` (with a reason) in {trivyignore_target} before closing - that documents "
            f"it as a deliberate, accepted risk instead of silently suppressing it with no paper "
            f"trail. Once it's in `.trivyignore`, future scans will tag it `accepted_risk` directly "
            f"and it will stop appearing in issues/comments at all.",
            "- Once closed, every CVE mentioned in this issue (body + comments) is treated as "
            "acknowledged - if the exact same CVE shows up again in a future scan, it is silently "
            "suppressed, not reopened and not re-surfaced as a new issue.",
            "- A genuinely **different** CVE for this same package always gets its own fresh issue - "
            "closing this one does not block future issues for this package.",
            "- Once closed, this issue is never reopened and its body is never edited again by the "
            "pipeline.",
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
        lines.append("| Version | Jar | CVE | Severity | Installed | Fixed |")
        lines.append("|---|---|---|---|---|---|")
        for f in sorted(dedupe_for_display(group_findings), key=lambda f: (f["severity"], f["cve"] or "")):
            lines.append(render_finding_row(f))
        lines.append("")

    lines.append(render_keys_marker(findings))
    return "\n".join(lines).rstrip() + "\n"


def create_issue(tracking_repo, display, package_name, active_findings, dry_run):
    title = issue_title(display)
    body = render_body(display, package_name, active_findings, suppressed_count=0)
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
    display_findings = dedupe_for_display(new_findings)
    lines = [f"**{len(display_findings)} new finding(s) detected in this scan:**", ""]
    lines.append("| Version | Jar | CVE | Severity | Installed | Fixed |")
    lines.append("|---|---|---|---|---|---|")
    for f in sorted(display_findings, key=lambda f: (f["severity"], f["cve"] or "")):
        lines.append(render_finding_row(f))
    if suppressed_count:
        lines.append("")
        lines.append(
            f"_{suppressed_count} other finding(s) for this package matched a CVE already "
            f"covered by a previously closed issue and are intentionally omitted._"
        )
    lines.append("")
    lines.append(render_keys_marker(new_findings))
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


def sync_package(tracking_repo, display, package_name, findings, dry_run, parent_number):
    """
    Returns a dict mapping each finding's id(finding) -> issue ref, per the lifecycle described
    in the module docstring. Never reopens or rewrites a closed issue.

    `display` is the pre-computed group_display_name(...) - see its docstring for why this is
    threaded rather than re-derived here (the title is the lookup key; re-deriving it at this
    layer risks it drifting from what create_issue used, which would file a duplicate issue on
    every run).

    parent_number is the ongoing parent tracking issue (see find_or_create_parent_issue) - only
    ever used right below, when this package's issue is BRAND NEW (create_issue branch). An
    already-existing open issue was already attached to the parent the run it was created, so
    re-attaching it every subsequent sync would be redundant (and GitHub would just reject the
    duplicate sub-issue link anyway).
    """
    title = issue_title(display)
    open_issue, closed_issues = find_package_issues(tracking_repo, title)

    def finding_key(f):
        return (finding_scope(f), f["cve"])

    # Union of (scope, cve) keys already covered by ANY closed issue for this package, plus a
    # per-key map to the most recent closed issue that mentioned it (for attaching a reference
    # onto suppressed findings below). known_finding_keys (not extract_cve_ids(body) alone) is
    # required here: a key may have only ever been surfaced via a comment on this issue while it
    # was still open (see comment_new_findings), never written into the body itself - missing
    # that would make a recurring finding look "new" instead of being correctly suppressed as
    # already-acknowledged. Scope-aware (not CVE-only) so a CVE already acknowledged for one
    # version doesn't wrongly suppress the SAME CVE newly appearing on a different version.
    closed_key_to_issue = {}
    for issue in sorted(closed_issues, key=lambda i: i["updatedAt"]):
        for key in known_finding_keys(tracking_repo, issue):
            closed_key_to_issue[key] = issue  # later (more recent) closed issues win on conflict
    closed_keys = set(closed_key_to_issue.keys())

    active = [f for f in findings if finding_key(f) not in closed_keys]
    suppressed = [f for f in findings if finding_key(f) in closed_keys]

    issue_refs = {}

    if active:
        if open_issue:
            already_known = known_finding_keys(tracking_repo, open_issue)
            new_findings = [f for f in active if finding_key(f) not in already_known]
            if new_findings:
                ref = comment_new_findings(tracking_repo, open_issue, new_findings, len(dedupe_for_display(suppressed)), dry_run)
            else:
                ref = issue_ref(open_issue)
        else:
            ref = create_issue(tracking_repo, display, package_name, active, dry_run)
            add_sub_issue(tracking_repo, parent_number, ref["number"], dry_run)
        for f in active:
            issue_refs[id(f)] = ref
    elif open_issue:
        close_issue(tracking_repo, open_issue, dry_run)

    for f in suppressed:
        closed_issue = closed_key_to_issue[finding_key(f)]
        issue_refs[id(f)] = {
            "number": closed_issue["number"], "url": closed_issue["url"], "state": "closed",
            "created_at": closed_issue.get("createdAt"),
        }

    return issue_refs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--combined", required=True, help="combined.json to read AND update in place")
    ap.add_argument("--tracking-repo", default="wso2-enterprise/integration-engineering")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.combined) as f:
        combined = json.load(f)

    ensure_label_exists(args.tracking_repo, LABEL, "B60205", "Auto-filed by the Ballerina vulnerability scan pipeline")
    ensure_label_exists(args.tracking_repo, PARENT_LABEL, "5319E7", "The parent tracking issue linking all trivy-scan sub-issues")
    # Found/created ONCE per run, not per package - every brand-new package issue this run
    # attaches to this same parent (see sync_package's create_issue branch).
    parent_number = find_or_create_parent_issue(args.tracking_repo, args.dry_run)

    for finding in combined["findings"]:
        finding.setdefault("issue", None)

    # Every package that had ANY finding this run still gets grouped here - including ones whose
    # findings are entirely accepted_risk - so sync_package still gets called for it below and
    # can auto-close a previously-open issue if nothing trackable remains. accepted_risk findings
    # themselves are filtered out before being handed to sync_package: they're pre-accepted at
    # scan time (via .trivyignore), so they never influence issue creation/update/closing and
    # never get an issue reference written (stays None from the setdefault above) - tracked via
    # their accepted_risk field instead, not a GitHub issue.
    # Keyed on (source, package_org, package_name), not just (package_org, package_name) -
    # provably a no-op for today's data (no existing (org,name) pair spans two sources), but
    # closes a real future footgun: a tool is a real Central package, invisible to the package
    # track today only because that track's enumeration filters on the latest version's
    # `platform`. If a tool ever ships a platform.java21 block, it becomes independently
    # enumerable by BOTH tracks, and an un-sourced key would nondeterministically merge them into
    # one group whose title flips between runs depending on findings[0] - exactly the cross-track
    # bleed the separate-tools-track decision exists to prevent.
    by_package = defaultdict(list)
    for finding in combined["findings"]:
        by_package[(finding["source"], finding["package_org"], finding["package_name"])].append(finding)

    for (finding_source, package_org, package_name), all_findings in by_package.items():
        trackable = [f for f in all_findings if not f.get("accepted_risk")]
        accepted_count = len(all_findings) - len(trackable)
        # From all_findings, not trackable: trackable can be legitimately empty (an all-accepted
        # -risk package/tool still gets synced so a previously-open issue can auto-close), and
        # group_display_name needs at least one finding regardless.
        display = group_display_name(all_findings)

        issue_refs = sync_package(args.tracking_repo, display, package_name, trackable, args.dry_run, parent_number)
        active_count = sum(1 for f in trackable if issue_refs.get(id(f), {}).get("state") == "open")
        suppressed_count = len(trackable) - active_count
        for f in trackable:
            f["issue"] = issue_refs.get(id(f))
        active_ref = next((r for r in issue_refs.values() if r["state"] == "open"), None)
        print(
            f"{display}: {active_count} active, {suppressed_count} suppressed, {accepted_count} "
            f"accepted-risk -> issue {active_ref.get('url') if active_ref else '(none open)'}",
            file=sys.stderr,
        )

    with open(args.combined, "w") as f:
        json.dump(combined, f, indent=2)


if __name__ == "__main__":
    main()
