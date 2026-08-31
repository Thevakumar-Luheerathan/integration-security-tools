#!/usr/bin/env python3
"""
One-off migration: rewrites existing new-findings comments (posted by comment_new_findings,
issue_sync.py) that predate scope-aware (version, CVE) identity to add a Version column and a
hidden trivy-scan-keys marker, so known_finding_keys() can recover their scope exactly instead of
falling back to "known for every scope this issue has" (see known_finding_keys' docstring).

Must run BEFORE issue_sync.py's scope-aware identity change is deployed for real - see the vuln-
scan plan's sequencing section. Scope is derived from each issue's OWN body, which must have
exactly one "### <scope> (...)" version group at backfill time (verified: true for every open
trivy-scan issue as of this migration - a package can only have accumulated multiple simultaneous
scopes once the multi-version Central scan ships, which this backfill runs ahead of).

Usage:
  python3 backfill_comment_versions.py --tracking-repo wso2-enterprise/integration-engineering \
      --backup backfill-backup.json [--dry-run | --apply]

--dry-run (the default) prints every comment it would rewrite, in full, without touching GitHub.
--apply actually PATCHes the comments - requires --backup, and writes the original body of every
comment it touches there BEFORE issuing the PATCH, so this can be reversed by hand if needed
(GitHub comment edits are not git-revertable, unlike everything else in this repo).
"""
import argparse
import json
import re
import sys

import issue_sync

TABLE_HEADER_RE = re.compile(r"^\|\s*Jar\s*\|\s*CVE\s*\|\s*Severity\s*\|\s*Installed\s*\|\s*Fixed\s*\|\s*$")
TABLE_SEP_RE = re.compile(r"^\|(?:\s*-+\s*\|)+\s*$")
TABLE_ROW_RE = re.compile(r"^\|(.+)\|\s*$")


def find_backfillable_issues(tracking_repo):
    """
    Every open trivy-scan issue with at least one comment, excluding the parent tracking issue
    (which has no version-group body at all - it would just noisily "skip" every time otherwise).
    """
    result = issue_sync.gh([
        "issue", "list", "--repo", tracking_repo, "--label", issue_sync.LABEL,
        "--state", "open", "--json", "number,title,body,comments", "--limit", "1000",
    ])
    issues = json.loads(result)
    return [
        i for i in issues
        if i["title"] != issue_sync.PARENT_TITLE and i.get("comments")
    ]


def add_version_column(comment_body, scope):
    """
    Rewrites one legacy new-findings comment (created before scope-aware identity shipped) to
    insert a Version column as the new first column of its table - both the header/separator
    rows and every data row. Returns (new_body_without_marker, cves_found), or (None, None) if
    this comment doesn't look like a findings table at all (defensive - skip rather than mangle
    anything unexpected, e.g. the close_issue comment, which has no table).
    """
    lines = comment_body.splitlines()
    out = []
    cves = set()
    touched = False
    for line in lines:
        stripped = line.strip()
        if TABLE_HEADER_RE.match(stripped):
            out.append("| Version | Jar | CVE | Severity | Installed | Fixed |")
            touched = True
            continue
        if touched and TABLE_SEP_RE.match(stripped) and out and out[-1].startswith("| Version"):
            out.append("|---|---|---|---|---|---|")
            continue
        m = TABLE_ROW_RE.match(stripped)
        if touched and m:
            cells = [c.strip() for c in m.group(1).split("|")]
            if len(cells) == 5:  # Jar | CVE | Severity | Installed | Fixed
                out.append(f"| {scope} | " + " | ".join(cells) + " |")
                cves.add(cells[1])
                continue
        out.append(line)
    if not touched:
        return None, None
    return "\n".join(out), cves


def backfill_issue(tracking_repo, issue, dry_run, backup):
    scopes = issue_sync.parse_body_scopes(issue.get("body"))
    if len(scopes) != 1:
        print(
            f"SKIP #{issue['number']} ({issue['title']}): body has {len(scopes)} version "
            f"group(s), expected exactly 1 - ambiguous, not backfilling automatically.",
            file=sys.stderr,
        )
        return

    scope = next(iter(scopes))
    touched_any = False

    for c in issue["comments"]:
        comment_id = c["url"].rsplit("#issuecomment-", 1)[-1]
        if issue_sync.parse_keys_marker(c["body"]) is not None:
            continue  # already backfilled (or already scope-aware) - nothing to do

        new_body, cves = add_version_column(c["body"], scope)
        if new_body is None:
            print(
                f"SKIP #{issue['number']} comment {comment_id}: doesn't look like a findings "
                f"table (e.g. the close-issue comment) - leaving untouched.",
                file=sys.stderr,
            )
            continue

        marker = issue_sync.build_keys_marker({scope: cves})
        new_body = new_body.rstrip("\n") + "\n\n" + marker
        touched_any = True

        if dry_run:
            print(f"[dry-run] would PATCH comment {comment_id} on issue #{issue['number']} (scope={scope}, {len(cves)} CVE(s)):", file=sys.stderr)
            print("---8<---", file=sys.stderr)
            print(new_body, file=sys.stderr)
            print("---8<---\n", file=sys.stderr)
        else:
            backup.append({
                "issue": issue["number"], "comment_id": comment_id,
                "original_body": c["body"],
            })
            issue_sync.gh([
                "api", "--method", "PATCH", f"repos/{tracking_repo}/issues/comments/{comment_id}",
                "-f", f"body={new_body}",
            ])
            print(f"PATCHED comment {comment_id} on issue #{issue['number']} (scope={scope}, {len(cves)} CVE(s))", file=sys.stderr)

    if not touched_any:
        print(f"#{issue['number']}: nothing to backfill (all comments already scope-aware or non-table)", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--tracking-repo", default="wso2-enterprise/integration-engineering")
    ap.add_argument("--backup", default="backfill-backup.json", help="where original comment bodies are saved before any --apply PATCH")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="default: print what would change, touch nothing")
    mode.add_argument("--apply", action="store_true", help="actually PATCH comments on GitHub")
    args = ap.parse_args()

    dry_run = not args.apply

    issues = find_backfillable_issues(args.tracking_repo)
    print(f"{len(issues)} open trivy-scan issue(s) with comments to check.", file=sys.stderr)

    backup = []
    for issue in issues:
        backfill_issue(args.tracking_repo, issue, dry_run, backup)

    if not dry_run:
        with open(args.backup, "w") as f:
            json.dump(backup, f, indent=2)
        print(f"\nBacked up {len(backup)} original comment bod{'y' if len(backup) == 1 else 'ies'} to {args.backup} before patching.", file=sys.stderr)


if __name__ == "__main__":
    main()
