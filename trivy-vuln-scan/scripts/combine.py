#!/usr/bin/env python3
"""
Combine per-version-line, per-source trivy JSON reports into one combined.json matching the
pipeline's contract (see the repo's vuln-scan plan for the full schema).

Inputs, per configured version line:
  --distribution-report <line>=<path>   a single trivy JSON report from scanning the built
                                         distribution (source "distribution"). Repeatable.
  --central-dir <line>=<path>           a directory produced by bala_scan.py: manifest.json +
                                         one trivy JSON report per package (source "central").
                                         Repeatable.
  --distribution-status <line>=ok|<error message>   whether the distribution build/scan for
                                         that line succeeded. Repeatable; if omitted for a line
                                         that has a --distribution-report, assumed ok.
  --vscode-report <branch>=<path>       a trivy JSON report from scanning ballerina-vscode at a
                                         configured branch (source "vscode-extension"). A branch
                                         can appear more than once (the fs scan and the language
                                         server's sbom scan both feed the same branch) - all
                                         reports for a branch are combined. Repeatable.
  --vscode-status <branch>=ok|<error message>   whether ballerina-vscode's scan for that branch
                                         succeeded. Repeatable; if omitted for a branch that has
                                         a --vscode-report, assumed ok.
  --dist-trivyignore <line>=<path>      ballerina-distribution's OWN per-branch .trivyignore for
                                         that line (fetched from the real, actively-maintained
                                         file in ballerina-platform/ballerina-distribution@<line>).
                                         Applied ONLY to distribution findings for that line -
                                         Central findings no longer consult this file at all (see
                                         "Central accepted-risk handling" below). Repeatable.
  --vscode-trivyignore <branch>=<path>  ballerina-vscode's own .trivyignore file(s) for that
                                         branch (the fs scan's repo+submodule files, the ls scan's
                                         language-server one) - merged per branch. Repeatable.
  --central-tool-dir <line>=<path>      a directory produced by bala_scan.py run against
                                         central_resolve.py's --kind tools output (source
                                         "tools") - same manifest.json + per-tool trivy report
                                         shape as --central-dir, but a DELIBERATELY SEPARATE
                                         processing path (see process_central_tool_dir) so a bug
                                         in tool handling is structurally incapable of touching
                                         the package path. Repeatable.
  --central-tool-status <line>=ok|<error message>   mirrors --central-status for the tools track.

Accepted-risk handling: a finding whose CVE appears in the relevant .trivyignore is NEVER
dropped - it's tagged with `accepted_risk: {reason, source}` (reason = the comment text above
that CVE in the file) and still flows through to combined.json like any other finding, so the
dashboard can render it distinctly rather than it silently vanishing. This mirrors exactly how a
closed GitHub issue works (see issue_sync.py) - a decision that's already been made and
documented, not something to hide. Trivy's own `--ignorefile`/`--show-suppressed` are NOT used
for this (verified: `--show-suppressed` does not actually restore suppressed entries to JSON
output in the installed trivy version) - every scan runs with no ignorefile at all, and this
script does the suppression/classification itself in one place for every source.

Central accepted-risk handling (per-package, NOT the shared distribution file): Central findings
check ONLY their own package's repo .trivyignore (see load_package_trivyignore), fetched live
from that repo's default branch using the `repo` field central_resolve.py/bala_scan.py attach to
each manifest entry. This replaced an earlier design where Central findings shared
ballerina-distribution's file with distribution findings - that was both indiscriminate (one CVE
excluded for a line suppressed it for every package on that line) and line-scoped rather than
version-scoped (once a package's same version could be resolved under multiple lines, an
exclusion added to only one line's branch left it active under the other). A package with no
resolved repo, or whose repo has no .trivyignore, simply gets no accepted_risk tag for that CVE -
there is NO fallback to ballerina-distribution's file for Central findings anymore.

Tools accepted-risk handling: TODO(tools-trivyignore) - Central bal TOOLS (source "tools", see
process_central_tool_dir) have NO accepted-risk/.trivyignore path at all yet. Deliberately
deferred, not an oversight - grep "tools-trivyignore" for every spot that needs to change
together when this resumes.

Package identity is (package_org, package_name) - "ballerina-lang" (package_org=None) for
distribution-source findings, or the actual Central org/name (e.g. "ballerinax"/"redis") for
central-source findings. There is deliberately NO repo-resolution step: an earlier version of
this script guessed a GitHub repo per package (naming convention + a `gh api` existence check +
a hand-maintained exception file) and still left 36 of 738 real findings unresolved - mostly
`ballerina/lang.*` submodules, which aren't separate repos at all. Library owners already know
which repo their package lives in; this pipeline only needs to identify the package itself.

Each finding also carries `library_name` - the raw underlying dependency coordinate trivy
reports (e.g. "commons-beanutils:commons-beanutils", "io.netty:netty-codec"), independent of
which Ballerina package wraps it. This is what `package_name` used to hold for distribution
findings before package_name became the Ballerina-level identity; it's kept because it's the
only version-independent way to check "is this library used by anything on Central at all",
which downstream consumers need for the distribution-vs-central pending-fix comparison.

Output: combined.json with top-level generated_at/versions/scan_status/findings, per the
pipeline contract. Findings are deduped WITHIN a source (a single package or the distribution
build re-reporting the same CVE against multiple shaded/fat jars collapses to one finding with
a note of how many jar targets it appeared in) and NEVER across sources - the whole point of
keeping "distribution" and "central" separate is to preserve the "already fixed on Central,
still pending in the distribution" signal, which a cross-source merge would destroy.
"""
import argparse
import json
import os
import subprocess
import sys
import time

DISTRIBUTION_PACKAGE_NAME = "ballerina-lang"


def _fetch_raw_github(url):
    """
    Fetch a raw file from GitHub, returning its text content, or None on 404/any failure. Same
    minimal, no-retry shape as central_resolve.py's own helper of the same name (this script has
    no prior curl dependency of its own, deliberately not sharing a module with central_resolve.py
    across these standalone scripts - matches this codebase's existing convention of small
    per-script duplication, e.g. bala_scan.py/central_resolve.py each already have their own
    near-identical curl helpers rather than a shared one).
    """
    cmd = ["curl", "-sS", "-L", "--max-time", "15", "-w", "\n%{http_code}", url]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    body, _, status = proc.stdout.rpartition("\n")
    if status.strip().startswith("2"):
        return body
    return None


def parse_trivy_report(path):
    """
    Yields (jar_path, cve, severity, trivy_pkg_name, installed_version, fixed_version).

    Verified against real trivy 0.64.1 `rootfs` JSON output: when a rootfs scan finds multiple
    jars, `Results[].Target` is an aggregate label like "Java" or "Node.js" - NOT a jar path.
    The actual per-finding jar lives on each vulnerability entry as `PkgPath`
    (e.g. "platform/java21/netty-codec-4.1.115.Final.jar"). We fall back to `Target` only if
    `PkgPath` is absent, since some rootfs scan modes (observed in ballerina-lang's own
    distribution scan) DO report one Target per jar directly.
    """
    with open(path) as f:
        data = json.load(f)
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            jar_path = vuln.get("PkgPath") or target
            yield (
                jar_path,
                vuln.get("VulnerabilityID"),
                vuln.get("Severity"),
                vuln.get("PkgName"),
                vuln.get("InstalledVersion"),
                vuln.get("FixedVersion", ""),
            )


def parse_trivyignore(text):
    """
    Parses Trivy's plain one-ID-per-line .trivyignore format into {cve_or_ghsa_id: reason}.
    A '# comment' line sets the reason for every bare ID line that follows, until the next
    comment line resets it - matches the real format observed in ballerina-distribution's and
    ballerina-vscode's actual files (one comment block, then one or more IDs, e.g.:
    "# Axiom version is not released yet\nCVE-2024-21742"). Blank lines are just separators.
    """
    reasons = {}
    current_reason = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            current_reason = line.lstrip("#").strip()
            continue
        vuln_id = line.split()[0]  # defensive: ignore any trailing content on an ID line
        reasons[vuln_id] = current_reason or "(no reason given in .trivyignore)"
    return reasons


def load_trivyignore(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return parse_trivyignore(f.read())


def load_merged_trivyignore(paths):
    """Merges multiple .trivyignore files (e.g. a repo's own + its submodule's) into one map."""
    merged = {}
    for path in paths or []:
        merged.update(load_trivyignore(path))
    return merged


# Cached per repo within this run - central_resolve.py's multi-version selection can produce many
# manifest entries sharing one repo (e.g. ballerina/ai resolves to 15 versions in real production
# data), and a repo's .trivyignore doesn't vary by package version - re-fetching it per version
# would be wasteful.
_PACKAGE_TRIVYIGNORE_CACHE = {}


def _repo_raw_url(repo, branch, path):
    """'https://github.com/{owner}/{name}' -> 'https://raw.githubusercontent.com/{owner}/{name}/{branch}/{path}'"""
    owner_repo = repo.rstrip("/")
    if owner_repo.startswith("https://github.com/"):
        owner_repo = owner_repo[len("https://github.com/"):]
    return f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{path}"


def load_package_trivyignore(repo):
    """
    Fetches <repo>@<default branch>/.trivyignore for a Central package's own repo (see
    central_resolve.py's resolve_package_repo) - the per-package replacement for the old shared
    ballerina-distribution ignorefile (see module docstring's "Central accepted-risk handling").
    Tries master then main (every real module repo checked during design uses master, but that's
    not asserted to hold for every repo Central might ever resolve to - e.g. wso2/xlibb-hosted
    repos). Returns ({}, None) if repo is falsy, or if neither branch has a .trivyignore -
    correctly means "no accepted-risk tags for this package", not a fallback to any other file.
    """
    if not repo:
        return {}, None
    if repo in _PACKAGE_TRIVYIGNORE_CACHE:
        return _PACKAGE_TRIVYIGNORE_CACHE[repo]

    result = ({}, None)
    for branch in ("master", "main"):
        text = _fetch_raw_github(_repo_raw_url(repo, branch, ".trivyignore"))
        if text is not None:
            result = (parse_trivyignore(text), f"{repo}:.trivyignore@{branch}")
            break

    _PACKAGE_TRIVYIGNORE_CACHE[repo] = result
    return result


def dedupe_within_source(raw_findings, dedupe_key_fn):
    """
    raw_findings: list of dicts already carrying all schema fields except dedup bookkeeping.
    Collapses entries whose dedupe_key_fn(...) matches, keeping the first jar seen and
    recording how many distinct jar targets reported the same CVE.
    """
    by_key = {}
    order = []
    for finding in raw_findings:
        key = dedupe_key_fn(finding)
        if key not in by_key:
            by_key[key] = finding
            finding["also_seen_in_jars"] = []
            order.append(key)
        else:
            existing = by_key[key]
            if finding["jar"] != existing["jar"]:
                existing["also_seen_in_jars"].append(finding["jar"])
    return [by_key[k] for k in order]


def _apply_accepted_risk(finding, ignore_map, ignore_source):
    if ignore_map and finding["cve"] in ignore_map:
        finding["accepted_risk"] = {"reason": ignore_map[finding["cve"]], "source": ignore_source}


def process_distribution_report(line, report_path, ignore_map, ignore_source, findings_out):
    raw = []
    for target, cve, severity, trivy_pkg_name, installed, fixed in parse_trivy_report(report_path):
        jar = os.path.basename(target)
        finding = {
            "ballerina_version": line,
            "source": "distribution",
            "package_org": None,
            "package_name": DISTRIBUTION_PACKAGE_NAME,
            "package_version": None,
            "library_name": trivy_pkg_name,
            "jar": jar,
            "cve": cve,
            "severity": severity,
            "installed_version": installed,
            "fixed_version": fixed,
        }
        _apply_accepted_risk(finding, ignore_map, ignore_source)
        raw.append(finding)
    deduped = dedupe_within_source(raw, lambda f: (f["cve"], f["library_name"], f["installed_version"]))
    findings_out.extend(deduped)


def process_vscode_report(branch, report_paths, ignore_map, ignore_source, findings_out):
    """
    ballerina-vscode findings have NO Ballerina version at all - they're scanned by branch
    (configurable via trivy-vuln-scan/vscode-targets.json), independent of the 2201.x lines.
    Two real upstream Trivy scans feed into this same source ("vscode-extension"), mirroring
    ballerina-vscode's OWN pipeline exactly rather than inventing a new one: an `fs` scan of the
    whole checked-out repo (catches the extension's npm/pnpm dependencies, same flags upstream's
    reusable-build.yml uses) and an `sbom` scan of the bundled Java language server (same as
    upstream's schedule.yml `ls-trivy` job, via a CycloneDX SBOM). Both report shapes are the
    same trivy JSON, so this just reads both paths the same way and dedupes across them.
    """
    raw = []
    for report_path in report_paths:
        for target, cve, severity, trivy_pkg_name, installed, fixed in parse_trivy_report(report_path):
            finding = {
                "ballerina_version": None,
                "source": "vscode-extension",
                "package_org": None,
                "package_name": "ballerina-vscode",
                "package_version": None,
                "plugin_branch": branch,
                "library_name": trivy_pkg_name,
                "jar": trivy_pkg_name,
                "cve": cve,
                "severity": severity,
                "installed_version": installed,
                "fixed_version": fixed,
            }
            _apply_accepted_risk(finding, ignore_map, ignore_source)
            raw.append(finding)
    deduped = dedupe_within_source(raw, lambda f: (f["cve"], f["library_name"], f["installed_version"]))
    findings_out.extend(deduped)


def process_central_dir(line, central_dir, findings_out):
    """
    Unlike process_distribution_report/process_vscode_report, this does NOT take a shared
    ignore_map/ignore_source - each package resolves its OWN accepted-risk map from its own repo
    (see load_package_trivyignore), per the module docstring's "Central accepted-risk handling".
    """
    manifest_path = os.path.join(central_dir, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    for pkg in manifest.get("scanned", []):
        report_path = os.path.join(central_dir, pkg["report"])
        if not os.path.exists(report_path):
            continue
        ignore_map, ignore_source = load_package_trivyignore(pkg.get("repo"))
        raw = []
        for target, cve, severity, trivy_pkg_name, installed, fixed in parse_trivy_report(report_path):
            jar = os.path.basename(target)
            finding = {
                "ballerina_version": line,
                "source": "central",
                "package_org": pkg["org"],
                "package_name": pkg["name"],
                "package_version": pkg["version"],
                "library_name": trivy_pkg_name,
                "jar": jar,
                "cve": cve,
                "severity": severity,
                "installed_version": installed,
                "fixed_version": fixed,
            }
            _apply_accepted_risk(finding, ignore_map, ignore_source)
            raw.append(finding)
        deduped = dedupe_within_source(raw, lambda f: f["cve"])
        findings_out.extend(deduped)


def process_central_tool_dir(line, tool_dir, findings_out):
    """
    Central bal TOOLS - a DELIBERATELY SEPARATE track from process_central_dir above, not a
    parameterization of it: tools are discovered through a completely different registry endpoint
    (see central_resolve.py's list_candidate_tools) and are a much smaller, less-exercised
    population, so a bug here must be structurally incapable of touching the package path that
    already runs in production. Keep the two in sync by hand if their shared shape ever changes.

    Divergences from process_central_dir, all intentional:
      - source is "tools", never "central" - never merged with packages when aggregating.
      - tool_id carries balToolId (e.g. "scan"), threaded from central_resolve.py via
        bala_scan.py's manifest. It is NOT derivable from package_name ("tool_scan") and has no
        naming convention - issue_sync.py titles a tool's issue with this alone.
      - No accepted-risk lookup at all - see TODO(tools-trivyignore) in the module docstring.
        `repo` is still carried through on the manifest entry (sourceCodeLocation only - the
        module-{org}-{name} guess is useless for tools) so the data is already there once that
        work resumes; the fix then is to call load_package_trivyignore(pkg.get("repo")) here
        exactly as process_central_dir already does.
    """
    manifest_path = os.path.join(tool_dir, "manifest.json")
    with open(manifest_path) as f:
        manifest = json.load(f)

    for tool in manifest.get("scanned", []):
        report_path = os.path.join(tool_dir, tool["report"])
        if not os.path.exists(report_path):
            continue
        raw = []
        for target, cve, severity, trivy_pkg_name, installed, fixed in parse_trivy_report(report_path):
            raw.append({
                "ballerina_version": line,
                "source": "tools",
                "package_org": tool["org"],
                "package_name": tool["name"],
                "package_version": tool["version"],
                "tool_id": tool.get("balToolId"),
                "library_name": trivy_pkg_name,
                "jar": os.path.basename(target),
                "cve": cve,
                "severity": severity,
                "installed_version": installed,
                "fixed_version": fixed,
            })
        # Same key as process_central_dir: within ONE tool's ONE version's scan, a CVE reported
        # against several bundled jars (tool/libs/*.jar) is one finding.
        findings_out.extend(dedupe_within_source(raw, lambda f: f["cve"]))


def _current_run_url():
    """
    The GitHub Actions run URL for this pipeline execution, built from the standard env vars
    every Actions job gets automatically. None when run outside Actions (e.g. local testing) -
    the field is genuinely optional in that case, not a bug to work around.
    """
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return None


def parse_kv_args(items):
    """'2201.12.x=/path/to/file' -> {'2201.12.x': '/path/to/file'}"""
    out = {}
    for item in items or []:
        line, _, value = item.partition("=")
        out[line] = value
    return out


def parse_kv_list_args(items):
    """'main=/path/a.json' repeated -> {'main': ['/path/a.json', '/path/b.json']}"""
    out = {}
    for item in items or []:
        key, _, value = item.partition("=")
        out.setdefault(key, []).append(value)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--distribution-report", action="append", default=[])
    ap.add_argument("--central-dir", action="append", default=[])
    ap.add_argument("--distribution-status", action="append", default=[])
    ap.add_argument("--central-status", action="append", default=[])
    ap.add_argument("--vscode-report", action="append", default=[])
    ap.add_argument("--vscode-status", action="append", default=[])
    ap.add_argument("--dist-trivyignore", action="append", default=[])
    ap.add_argument("--vscode-trivyignore", action="append", default=[])
    ap.add_argument("--central-tool-dir", action="append", default=[])
    ap.add_argument("--central-tool-status", action="append", default=[])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    dist_reports = parse_kv_args(args.distribution_report)
    central_dirs = parse_kv_args(args.central_dir)
    dist_status = parse_kv_args(args.distribution_status)
    central_status = parse_kv_args(args.central_status)
    vscode_reports = parse_kv_list_args(args.vscode_report)
    vscode_status = parse_kv_args(args.vscode_status)
    dist_trivyignore_paths = parse_kv_args(args.dist_trivyignore)
    vscode_trivyignore_paths = parse_kv_list_args(args.vscode_trivyignore)
    central_tool_dirs = parse_kv_args(args.central_tool_dir)
    central_tool_status = parse_kv_args(args.central_tool_status)

    findings = []
    scan_status = []
    versions = sorted(set(list(dist_reports) + list(central_dirs) + list(central_tool_dirs)))

    for line in versions:
        # ballerina-distribution's file - distribution findings ONLY. Central findings resolve
        # their own per-package ignorefile inside process_central_dir instead (see module
        # docstring's "Central accepted-risk handling").
        line_ignore_map = load_trivyignore(dist_trivyignore_paths.get(line))
        line_ignore_source = f"ballerina-distribution:.trivyignore@{line}"

        if line in dist_reports:
            try:
                process_distribution_report(line, dist_reports[line], line_ignore_map, line_ignore_source, findings)
                ok = dist_status.get(line, "ok") == "ok"
                scan_status.append({
                    "ballerina_version": line, "source": "distribution",
                    "ok": ok, "error": None if ok else dist_status.get(line),
                })
            except Exception as e:  # noqa: BLE001
                scan_status.append({
                    "ballerina_version": line, "source": "distribution",
                    "ok": False, "error": str(e),
                })
        else:
            scan_status.append({
                "ballerina_version": line, "source": "distribution",
                "ok": False, "error": "no report produced",
            })

        if line in central_dirs:
            try:
                process_central_dir(line, central_dirs[line], findings)
                ok = central_status.get(line, "ok") == "ok"
                scan_status.append({
                    "ballerina_version": line, "source": "central",
                    "ok": ok, "error": None if ok else central_status.get(line),
                })
            except Exception as e:  # noqa: BLE001
                scan_status.append({
                    "ballerina_version": line, "source": "central",
                    "ok": False, "error": str(e),
                })
        else:
            scan_status.append({
                "ballerina_version": line, "source": "central",
                "ok": False, "error": "no report produced",
            })

        if line in central_tool_dirs:
            try:
                process_central_tool_dir(line, central_tool_dirs[line], findings)
                ok = central_tool_status.get(line, "ok") == "ok"
                scan_status.append({
                    "ballerina_version": line, "source": "tools",
                    "ok": ok, "error": None if ok else central_tool_status.get(line),
                })
            except Exception as e:  # noqa: BLE001
                scan_status.append({
                    "ballerina_version": line, "source": "tools",
                    "ok": False, "error": str(e),
                })
        else:
            # A failed/missing tools job must never be indistinguishable from a clean one - same
            # discipline as the distribution/central "no report produced" branches above.
            scan_status.append({
                "ballerina_version": line, "source": "tools",
                "ok": False, "error": "no report produced",
            })

    # ballerina-vscode is scanned by branch, independent of the Ballerina version lines above -
    # not added to `versions` (that field is specifically Ballerina release lines).
    for branch in sorted(vscode_reports):
        branch_ignore_map = load_merged_trivyignore(vscode_trivyignore_paths.get(branch))
        branch_ignore_source = f"ballerina-vscode:.trivyignore@{branch}"
        try:
            process_vscode_report(branch, vscode_reports[branch], branch_ignore_map, branch_ignore_source, findings)
            ok = vscode_status.get(branch, "ok") == "ok"
            scan_status.append({
                "ballerina_version": None, "plugin_branch": branch, "source": "vscode-extension",
                "ok": ok, "error": None if ok else vscode_status.get(branch),
            })
        except Exception as e:  # noqa: BLE001
            scan_status.append({
                "ballerina_version": None, "plugin_branch": branch, "source": "vscode-extension",
                "ok": False, "error": str(e),
            })

    combined = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline_run_url": _current_run_url(),
        "versions": versions,
        "scan_status": scan_status,
        "findings": findings,
    }

    with open(args.out, "w") as f:
        json.dump(combined, f, indent=2)

    print(
        f"Wrote {len(findings)} findings across {len(versions)} version line(s) to {args.out}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
