#!/usr/bin/env python3
"""
Resolve the set of Ballerina Central Java-platform package VERSIONS compatible with a given
Ballerina distribution release line (e.g. "2201.12.x").

Background (verified during design, see the repo's vuln-scan plan for full evidence):
  - The registry API field `ballerinaVersion` on a package version record is identical to
    that package's `Ballerina.toml` `distribution` field and the bala's `package.json`
    `ballerina_version`. It records the MINIMUM distribution the package version targets
    (a floor, not an exact match) - a package declaring 2201.12.0 also runs on 2201.13.x.
  - No registry API query parameter filters by distribution version. `ballerinaVersion` must
    be read per-version.
  - `ballerinaVersion` was verified monotonic (non-decreasing) across a package's version
    history for `ballerina/http` (38 versions checked). This is assumed to hold generally
    (that's how the Ballerina release process works - a package version is built against a
    specific distribution and later versions target later distributions) but was NOT
    exhaustively verified for every package. We binary-search on that assumption for speed,
    and fall back to a linear scan for any package where the assumption is observed to break,
    logging a warning so the anomaly is visible rather than silently wrong.
  - `platform=java21` (etc.) as a query param filters on a package's LATEST version only. A
    package whose latest version is "any" but had an older java21 version is invisible to this
    approach. This is a known, documented approximation - see the plan's "Known gaps" section.

Selection rule (confirmed with user, replaces the old "newest compatible version only" behavior):
  Order the configured distributions descending. Under each, place the library versions built
  FOR that distribution. A distribution left empty for a given library is filled from the most
  recent distribution that DOES have versions for it. Then keep only the latest patch of each
  (major, minor) combination - applied uniformly, not differently per case.

  As an algorithm, per target line D: consider only versions with floor <= D; let F be the
  highest floor present in that set; take every version whose floor == F (the "F run" - versions
  are newest-first and, under the monotonicity assumption above, same-floor versions are
  contiguous); reduce to the latest patch of each (major, minor). See _resolve_version_pool.

  Pre-GA ballerinaVersion labels are real in production (observed: "slalpha5", "slbeta2",
  "slbeta3", "slbeta6" on ballerinax/choreo, ballerinax/azure_cosmosdb, ballerinax/trigger.asb) -
  version_to_tuple sentinels these below every real 2201.x floor explicitly (see its docstring).

Output: a JSON array of objects:
  {"org": ..., "name": ..., "version": ..., "ballerinaVersion": ..., "platform": ...,
   "balaURL": ..., "digest": ..., "repo": ...}
one entry per SELECTED version - a package can now contribute more than one entry per line (see
the selection rule above). `repo` is the resolved GitHub repo backing this package (see
resolve_package_repo), or null if it couldn't be resolved - used downstream by combine.py to
read that package's OWN .trivyignore instead of the shared distribution-wide one (see combine.py's
docstring). Also writes a small sidecar of packages that could NOT be resolved (network errors,
monotonicity anomalies needing a fallback that also failed) so failures are visible instead of
silently dropped.
"""
import argparse
import concurrent.futures
import json
import subprocess
import sys
import time

API_BASE = "https://api.central.ballerina.io/2.0/registry"
# Recognized "official" orgs to enumerate. Community/personal orgs also publish java-platform
# packages (observed: thushani, heshanp, and ~25 others) but are deliberately excluded here -
# they are not part of what this org ships or supports. Adjust via --orgs if that's wrong.
DEFAULT_ORGS = ["ballerina", "ballerinax", "wso2", "xlibb"]
PLATFORMS = ["java21", "java17", "java11"]
MAX_RETRIES = 4
RETRY_BACKOFF_SECS = 2


def _get(url, headers=None, retries=MAX_RETRIES):
    """
    Shell out to curl rather than use urllib/requests. This sidesteps environments (observed:
    local dev machines behind a corporate TLS-inspecting proxy) where Python's bundled CA store
    doesn't trust a locally-injected root cert but the OS/curl trust store does - curl worked
    reliably in every manual check during this pipeline's design. Also avoids needing a pip
    dependency (requests) in the GitHub Actions runner.
    """
    cmd = ["curl", "-sS", "-L", "--max-time", "30", "-w", "\n%{http_code}"]
    for k, v in (headers or {}).items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)

    last_err = None
    for attempt in range(retries):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
            if proc.returncode != 0:
                last_err = f"curl exit {proc.returncode}: {proc.stderr.strip()}"
            else:
                body, _, status = proc.stdout.rpartition("\n")
                status = status.strip()
                if status == "404":
                    return None
                if status.startswith("2"):
                    return body
                last_err = f"HTTP {status}: {body[:200]}"
        except subprocess.TimeoutExpired:
            last_err = "curl timed out"
        time.sleep(RETRY_BACKOFF_SECS * (attempt + 1))
    raise RuntimeError(f"GET {url} failed after {retries} attempts: {last_err}")


def _json(url, headers=None):
    body = _get(url, headers=headers)
    if body is None:
        return None
    # Registry API responses can contain raw control characters in the `readme` field
    # (verified during research) - json.loads needs strict=False to tolerate that.
    return json.loads(body, strict=False)


def line_to_tuple(line):
    """'2201.12.x' -> (2201, 12). Used for floor-comparison against ballerinaVersion."""
    parts = line.replace(".x", "").split(".")
    return int(parts[0]), int(parts[1])


def version_to_tuple(v):
    """
    '2201.12.0' -> (2201, 12, 0). Tolerates missing patch component.

    Pre-GA labels are real in production ballerinaVersion values (observed: "slalpha5",
    "slbeta2", "slbeta3", "slbeta6" on ballerinax/choreo, ballerinax/azure_cosmosdb,
    ballerinax/trigger.asb) - never a real distribution version. Explicitly sentinel these to
    sort below every real 2201.x floor: the first dot-separated part must be ALL digits for this
    to parse as a genuine version, otherwise return (-1, 0, 0). This used to happen only by
    accident (digit-stripping "slbeta6" silently yielded (6, 0, 0), which happened to still sort
    below 2201.x, but would silently misbehave for a label like "slbeta2201").
    """
    parts = v.split(".")
    if not parts or not parts[0].isdigit():
        return (-1, 0, 0)
    nums = []
    for p in parts:
        digits = "".join(ch for ch in p if ch.isdigit())
        nums.append(int(digits) if digits else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:3])


def list_candidate_packages(orgs, platforms):
    """Enumerate (org, name) candidates via the platform-filtered latest-version listing."""
    seen = set()
    candidates = []
    for org in orgs:
        for platform in platforms:
            url = f"{API_BASE}/packages?org={org}&platform={platform}&limit=1000"
            data = _json(url)
            if not data:
                continue
            for pkg in data.get("packages", []):
                key = (pkg["organization"], pkg["name"])
                if key not in seen:
                    seen.add(key)
                    candidates.append(key)
    return candidates


def resolve_package_for_line(org, name, target_tuple, platforms):
    """
    Resolve every version of org/name selected for target_tuple's line, per the module
    docstring's selection rule. Tries each platform's header (a package may only exist under
    one). Returns a list of resolved dicts - empty if no compatible version exists on any
    platform.
    """
    for platform in platforms:
        headers = {"Ballerina-Platform": platform}
        versions_json = _get(f"{API_BASE}/packages/{org}/{name}", headers=headers)
        if versions_json is None:
            continue
        versions = json.loads(versions_json, strict=False)
        if not versions:
            continue
        # Registry returns newest-first.
        result = _resolve_version_pool(org, name, versions, target_tuple, headers)
        if result:
            return result
    return []


def _fetch_version_meta(org, name, version, headers):
    data = _json(f"{API_BASE}/packages/{org}/{name}/{version}", headers=headers)
    if data is None:
        return None
    bv = data.get("ballerinaVersion")
    return {
        "org": org,
        "name": name,
        "version": data.get("version", version),
        "ballerinaVersion": bv,
        "ballerinaVersionTuple": version_to_tuple(bv) if bv else None,
        "platform": data.get("platform"),
        "balaURL": data.get("balaURL"),
        "digest": data.get("digest"),
        # Already present in this same API response (no extra request) - the repo backing this
        "sourceCodeLocation": data.get("sourceCodeLocation") or None,
    }


# The GitHub org hosting Central's official module-{org}-{name} convention repos - verified
# against real examples (module-ballerinax-kafka, module-ballerina-http, etc). Only used for the
# guess fallback in resolve_package_repo, never for sourceCodeLocation-resolved repos (which
# carry their own full URL, e.g. "wso2"/"xlibb" packages that live under completely different
# GitHub orgs and would never match this convention).
MODULE_REPO_GITHUB_ORG = "ballerina-platform"

# Cached per (org, name) within a run - a single package can now resolve to many simultaneous
# versions (see the multi-version selection rule; e.g. ballerina/ai resolves to 15 versions in
# real production data), and the repo is a property of the PACKAGE, not the version - re-fetching
# it per version would be wasteful and could theoretically give inconsistent answers within one
# run if a single transient fetch happened to fail differently each time.
_REPO_RESOLUTION_CACHE = {}


def _fetch_raw_github(url):
    """
    Fetch a raw file from GitHub, returning its text content, or None on 404/any failure - a
    guess-verification fetch here is EXPECTED to 404 often (most guesses will be wrong), so this
    is deliberately simpler than _get(): no retry backoff, no JSON handling.
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


def _toml_declares_package(toml_text, org, name):
    """
    Cheap, dependency-free check that a Ballerina.toml's [package] org/name match exactly -
    turns an unverified module-{org}-{name} guess into a checked resolution. No TOML library
    needed for this narrow a check, BUT this must only read lines inside the [package] table
    itself, stopping at the next [section] header - a real Ballerina.toml commonly has other
    "name = ..." lines further down (e.g. [[package.modules]], [[platform.java21.dependency]])
    that must not be mistaken for the package's own org/name. Verified: an earlier version of
    this function that scanned the whole file produced a false negative on the real
    ballerina/observe repo, whose [[package.modules]] block declares
    name = "observe.mockextension" AFTER the correct [package] name = "observe" line, silently
    overwriting it.
    """
    declared_org = declared_name = None
    in_package_section = False
    for raw_line in toml_text.splitlines():
        line = raw_line.strip()
        if line.startswith("["):
            in_package_section = (line == "[package]")
            continue
        if not in_package_section:
            continue
        if line.startswith("org") and "=" in line:
            declared_org = line.split("=", 1)[1].strip().strip('"')
        elif line.startswith("name") and "=" in line:
            declared_name = line.split("=", 1)[1].strip().strip('"')
    return declared_org == org and declared_name == name


def resolve_package_repo(org, name, source_code_location):
    """
    Resolve the GitHub repo backing a Central package, per the verified ladder (see the vuln-scan
    plan for full evidence):
      1. sourceCodeLocation from the registry API, if present - authoritative, already fetched
         for free (see _fetch_version_meta). Measured coverage: 56/60 (93%) across a sample
         spanning all 4 configured orgs.
      2. The module-{org}-{name} naming guess under MODULE_REPO_GITHUB_ORG, accepted ONLY if that
         guessed repo's own Ballerina.toml declares matching org/name (see
         _toml_declares_package) - converts an unverified guess into a checked resolution.
         Verified during design: recovers ballerina/observe; correctly 404s rather than resolving
         wrong for ballerina/openapi, ballerina/test, ballerinax/asyncapi.native.handler (none of
         which actually follow this naming convention).
      3. None - no per-package .trivyignore will be consulted for this package; the caller
         records this into the failures/scan-status sidecar rather than silently dropping it.
    """
    cache_key = (org, name)
    if cache_key in _REPO_RESOLUTION_CACHE:
        return _REPO_RESOLUTION_CACHE[cache_key]

    repo = None
    if source_code_location:
        repo = source_code_location.rstrip("/")
    else:
        guessed_repo = f"https://github.com/{MODULE_REPO_GITHUB_ORG}/module-{org}-{name}"
        for toml_path in ("ballerina/Ballerina.toml", "build-config/resources/Ballerina.toml"):
            toml_url = f"https://raw.githubusercontent.com/{MODULE_REPO_GITHUB_ORG}/module-{org}-{name}/master/{toml_path}"
            toml_text = _fetch_raw_github(toml_url)
            if toml_text and _toml_declares_package(toml_text, org, name):
                repo = guessed_repo
                break

    _REPO_RESOLUTION_CACHE[cache_key] = repo
    return repo


def _floor_of(meta):
    return meta["ballerinaVersionTuple"][:2]


def _reduce_to_latest_patch(pool):
    """
    Groups a pool of resolved version metas by (major, minor) parsed from the package's OWN
    version string (not ballerinaVersion - that's the floor already used to build the pool),
    keeping only the newest patch of each - the final cut in the selection rule, applied
    identically whether the pool came from a directly-matched configured line or a lower-floor
    fallback.
    """
    best_by_minor = {}
    for meta in pool:
        major_minor = version_to_tuple(meta["version"])[:2]
        existing = best_by_minor.get(major_minor)
        if existing is None or version_to_tuple(meta["version"]) > version_to_tuple(existing["version"]):
            best_by_minor[major_minor] = meta
    return list(best_by_minor.values())


def _resolve_version_pool(org, name, versions, target_tuple, headers):
    """
    versions: newest-first list of version strings for one platform.

    Binary-searches for the newest version whose ballerinaVersion (major, minor) <= target -
    this newest-qualifying version's floor IS the F in the module docstring's selection rule
    (the highest floor <= target present in this package's history), since versions[] is
    newest-first and floor is assumed monotonic. Then walks forward (older) from it collecting
    every version that shares that exact floor (the contiguous "F run"), and reduces the pool to
    the latest patch of each (major, minor).

    Falls back to a full linear scan if the monotonicity assumption is observed to break for
    this package. Returns [] if nothing qualifies.
    """
    lo, hi = 0, len(versions) - 1
    best = None
    best_index = None
    monotonicity_violated = False
    last_seen = None  # (index, floor) most recently fetched, for a sanity check

    while lo <= hi:
        mid = (lo + hi) // 2
        meta = _fetch_version_meta(org, name, versions[mid], headers)
        if meta is None or meta["ballerinaVersionTuple"] is None:
            hi = mid - 1
            continue
        bv = _floor_of(meta)

        if last_seen is not None:
            prev_idx, prev_bv = last_seen
            # versions[] is newest-first: a SMALLER index is a newer package version and
            # should have a >= floor. If a newer version has a strictly OLDER floor than a
            # version we saw that was older-in-index, monotonicity does not hold for this
            # package (verified to hold for ballerina/http, not exhaustively for every package).
            if (mid < prev_idx and bv < prev_bv) or (mid > prev_idx and bv > prev_bv):
                monotonicity_violated = True
        last_seen = (mid, bv)

        if bv <= target_tuple:
            best, best_index = meta, mid
            hi = mid - 1
        else:
            lo = mid + 1

    if monotonicity_violated:
        print(
            f"WARNING: monotonicity assumption violated for {org}/{name}; "
            f"falling back to a full linear scan ({len(versions)} versions).",
            file=sys.stderr,
        )
        return _linear_scan_pool(org, name, versions, target_tuple, headers)

    if best is None:
        return []

    floor = _floor_of(best)
    pool = [best]
    idx = best_index + 1
    while idx < len(versions):
        meta = _fetch_version_meta(org, name, versions[idx], headers)
        if meta is None or meta["ballerinaVersionTuple"] is None:
            idx += 1
            continue
        if _floor_of(meta) != floor:
            break
        pool.append(meta)
        idx += 1

    return _reduce_to_latest_patch(pool)


def _linear_scan_pool(org, name, versions, target_tuple, headers):
    """
    Exhaustive fallback when monotonicity doesn't hold for this package: fetches every version's
    metadata, finds the true highest floor <= target_tuple (F) among them, collects every
    version sharing that floor, and reduces as usual.
    """
    metas = []
    for v in versions:
        meta = _fetch_version_meta(org, name, v, headers)
        if meta is None or meta["ballerinaVersionTuple"] is None:
            continue
        if _floor_of(meta) <= target_tuple:
            metas.append(meta)
    if not metas:
        return []
    floor = max(_floor_of(m) for m in metas)
    pool = [m for m in metas if _floor_of(m) == floor]
    return _reduce_to_latest_patch(pool)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--line", required=True, help="e.g. 2201.12.x")
    ap.add_argument("--orgs", default=",".join(DEFAULT_ORGS))
    ap.add_argument("--platforms", default=",".join(PLATFORMS))
    ap.add_argument("--out", required=True)
    ap.add_argument("--failures-out", default=None)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    orgs = [o.strip() for o in args.orgs.split(",") if o.strip()]
    platforms = [p.strip() for p in args.platforms.split(",") if p.strip()]
    target_tuple = line_to_tuple(args.line)

    print(f"Enumerating candidates in orgs={orgs} platforms={platforms} ...", file=sys.stderr)
    candidates = list_candidate_packages(orgs, platforms)
    print(f"{len(candidates)} candidate packages found.", file=sys.stderr)

    resolved = []
    failures = []

    def _work(item):
        org, name = item
        try:
            r = resolve_package_for_line(org, name, target_tuple, platforms)
            return (org, name, r, None)
        except Exception as e:  # noqa: BLE001 - want to record and continue, not abort the run
            return (org, name, None, str(e))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for org, name, result, err in pool.map(_work, candidates):
            if err is not None:
                failures.append({"org": org, "name": name, "error": err})
            elif not result:
                # No version of this package targets this line or anything older - not a
                # failure, just not applicable (e.g. package launched after this line's date).
                continue
            else:
                # Stamp when this package's balaURL was actually fetched, so a downstream
                # consumer (bala_scan.py) knows whether it's stale (URLs expire ~5min after
                # the metadata call that produced them) without re-deriving it from file mtimes.
                # resolve_package_repo is cached per (org, name), so this costs nothing extra for
                # a package's 2nd+ selected version (e.g. ballerina/ai's 15 versions).
                for r in result:
                    r["resolved_at"] = time.time()
                    r["repo"] = resolve_package_repo(r["org"], r["name"], r.get("sourceCodeLocation"))
                    resolved.append(r)

    print(
        f"Resolved {len(resolved)} version(s) for line {args.line}; "
        f"{len(failures)} failures.",
        file=sys.stderr,
    )

    with open(args.out, "w") as f:
        json.dump(resolved, f, indent=2)

    if args.failures_out:
        with open(args.failures_out, "w") as f:
            json.dump(failures, f, indent=2)
    elif failures:
        print(f"WARNING: {len(failures)} package resolutions failed:", file=sys.stderr)
        for fail in failures:
            print(f"  {fail['org']}/{fail['name']}: {fail['error']}", file=sys.stderr)


if __name__ == "__main__":
    main()
