#!/usr/bin/env python3
"""
Resolve the set of Ballerina Central Java-platform packages compatible with a given
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

Output: a JSON array of objects:
  {"org": ..., "name": ..., "version": ..., "ballerinaVersion": ..., "platform": ...,
   "balaURL": ..., "digest": ...}
one entry per package that has a version compatible with the target line (the newest such
version). Also writes a small sidecar of packages that could NOT be resolved (network errors,
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
    """'2201.12.0' -> (2201, 12, 0). Tolerates missing patch component."""
    parts = v.split(".")
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
    Find the newest version of org/name whose ballerinaVersion floor is <= target_tuple's
    (major, minor). Tries each platform's header (a package may only exist under one).
    Returns a resolved dict, or None if no compatible version exists on any platform.
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
        result = _binary_search_compatible(org, name, versions, target_tuple, headers)
        if result is not None:
            return result
    return None


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
    }


def _binary_search_compatible(org, name, versions, target_tuple, headers):
    """
    versions: newest-first list of version strings.
    Binary-searches for the newest version whose ballerinaVersion (major, minor) <= target.
    Falls back to a linear scan if the monotonicity assumption appears violated.
    """
    lo, hi = 0, len(versions) - 1
    best = None
    probes = 0
    monotonicity_violated = False
    last_seen = None  # (index, ballerinaVersionTuple) most recently fetched, for a sanity check

    while lo <= hi:
        mid = (lo + hi) // 2
        meta = _fetch_version_meta(org, name, versions[mid], headers)
        probes += 1
        if meta is None or meta["ballerinaVersionTuple"] is None:
            hi = mid - 1
            continue
        bv = meta["ballerinaVersionTuple"][:2]  # compare on (major, minor) only

        if last_seen is not None:
            prev_idx, prev_bv = last_seen
            # versions[] is newest-first: a SMALLER index is a newer package version and
            # should have a >= ballerinaVersion. If a newer version has a strictly OLDER
            # ballerinaVersion than a version we saw that was older-in-index, monotonicity
            # (as verified for ballerina/http) does not hold for this package.
            if (mid < prev_idx and bv < prev_bv) or (mid > prev_idx and bv > prev_bv):
                monotonicity_violated = True
        last_seen = (mid, bv)

        if bv <= target_tuple:
            # This version is old enough to qualify. versions[] is newest-first (index 0 =
            # newest), so try smaller indices to find an even newer qualifying version.
            best = meta
            hi = mid - 1
        else:
            # Too new for the target line - look toward older versions (larger index).
            lo = mid + 1

    if monotonicity_violated:
        print(
            f"WARNING: monotonicity assumption violated for {org}/{name}; "
            f"falling back to a full linear scan ({len(versions)} versions).",
            file=sys.stderr,
        )
        return _linear_scan_compatible(org, name, versions, target_tuple, headers)

    return best


def _linear_scan_compatible(org, name, versions, target_tuple, headers):
    """Exhaustive fallback: newest-first, return the first version that's compatible."""
    for v in versions:
        meta = _fetch_version_meta(org, name, v, headers)
        if meta is None or meta["ballerinaVersionTuple"] is None:
            continue
        if meta["ballerinaVersionTuple"][:2] <= target_tuple:
            return meta
    return None


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
            elif result is None:
                # No version of this package targets this line or anything older - not a
                # failure, just not applicable (e.g. package launched after this line's date).
                continue
            else:
                # Stamp when this package's balaURL was actually fetched, so a downstream
                # consumer (bala_scan.py) knows whether it's stale (URLs expire ~5min after
                # the metadata call that produced them) without re-deriving it from file mtimes.
                result["resolved_at"] = time.time()
                resolved.append(result)

    print(
        f"Resolved {len(resolved)} packages for line {args.line}; "
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
