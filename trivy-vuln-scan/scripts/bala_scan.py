#!/usr/bin/env python3
"""
Download a set of resolved Ballerina Central packages (.bala files) and trivy-scan each one.

Input: the JSON produced by central_resolve.py - a list of
  {"org", "name", "version", "ballerinaVersion", "platform", "balaURL", "digest", "resolved_at",
   "repo"}

A .bala is just a zip archive that bundles every third-party JAR the package ships (verified
during design by extracting a real one - platform/java21/*.jar plus compiler-plugin/libs/*.jar).
No build step is needed; we scan the extracted archive directly with `trivy rootfs`.

Important operational detail (verified): `balaURL` is a CloudFront pre-signed URL that expires
about 5 minutes after the metadata call that produced it. If central_resolve.py's output is more
than a few minutes old by the time we get to a given package (e.g. we're deep into a long
sequential run), we re-fetch that package's metadata to get a fresh URL rather than risk a 403.

Output: for each package, a trivy JSON report at <out-dir>/<org>__<name>__<version>.trivy.json,
plus a manifest.json mapping report files back to package metadata (org/name/version/
ballerinaVersion/repo) so combine.py doesn't have to re-derive it from the filename.
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time

API_BASE = "https://api.central.ballerina.io/2.0/registry"
BALA_URL_TTL_SECS = 240  # refresh if metadata is older than this (real TTL observed ~300s)


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.pop("timeout", 120), **kwargs)


def refresh_bala_url(org, name, version):
    cmd = ["curl", "-sS", "-L", "--max-time", "30", API_BASE + f"/packages/{org}/{name}/{version}"]
    proc = _run(cmd, timeout=35)
    if proc.returncode != 0:
        raise RuntimeError(f"refresh metadata failed for {org}/{name}/{version}: {proc.stderr}")
    data = json.loads(proc.stdout, strict=False)
    return data.get("balaURL")


def download_bala(pkg, dest_path):
    url = pkg["balaURL"]
    age = time.time() - pkg.get("resolved_at", 0)
    if age > BALA_URL_TTL_SECS:
        url = refresh_bala_url(pkg["org"], pkg["name"], pkg["version"])
        if not url:
            raise RuntimeError(f"could not refresh balaURL for {pkg['org']}/{pkg['name']}/{pkg['version']}")

    proc = _run(["curl", "-sS", "-L", "--max-time", "120", "-o", dest_path, "-w", "%{http_code}", url], timeout=130)
    status = proc.stdout.strip()
    if proc.returncode != 0 or not status.startswith("2"):
        # One retry with a freshly-fetched URL, in case it expired mid-run despite the TTL check.
        url = refresh_bala_url(pkg["org"], pkg["name"], pkg["version"])
        proc = _run(["curl", "-sS", "-L", "--max-time", "120", "-o", dest_path, "-w", "%{http_code}", url], timeout=130)
        status = proc.stdout.strip()
        if proc.returncode != 0 or not status.startswith("2"):
            raise RuntimeError(f"download failed for {pkg['org']}/{pkg['name']}/{pkg['version']}: HTTP {status}")


def scan_one(pkg, out_dir, trivy_cache_dir):
    key = f"{pkg['org']}__{pkg['name']}__{pkg['version']}"
    report_path = os.path.join(out_dir, f"{key}.trivy.json")

    with tempfile.TemporaryDirectory(prefix="bala_") as tmp:
        bala_path = os.path.join(tmp, "package.bala")
        download_bala(pkg, bala_path)

        extract_dir = os.path.join(tmp, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        unzip_proc = _run(["unzip", "-q", "-o", bala_path, "-d", extract_dir], timeout=60)
        if unzip_proc.returncode != 0:
            raise RuntimeError(f"unzip failed for {key}: {unzip_proc.stderr}")

        trivy_cmd = [
            "trivy", "rootfs",
            "--format", "json",
            "--output", report_path,
            "--scanners", "vuln",
            "--timeout", "5m",
            # The workflow ensures a fresh DB once before this script runs (potentially
            # hundreds of times, one per package) - skip trivy's own per-invocation staleness
            # check so it can't drift into re-downloading mid-run.
            "--skip-db-update", "--skip-java-db-update",
        ]
        if trivy_cache_dir:
            trivy_cmd += ["--cache-dir", trivy_cache_dir]
        trivy_cmd.append(extract_dir)

        trivy_proc = _run(trivy_cmd, timeout=330)
        # trivy exits non-zero only if --exit-code is set for findings; we don't set it here
        # (this pipeline reports findings, it doesn't gate anything), so non-zero here means a
        # real scan failure, not "vulnerabilities found".
        if trivy_proc.returncode != 0:
            raise RuntimeError(f"trivy scan failed for {key}: {trivy_proc.stderr}")

    return key, report_path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--packages", required=True, help="output of central_resolve.py")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--trivy-cache-dir", default=None)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    with open(args.packages) as f:
        packages = json.load(f)

    manifest = []
    failures = []

    def _work(pkg):
        try:
            key, report_path = scan_one(pkg, args.out_dir, args.trivy_cache_dir)
            return {
                "org": pkg["org"], "name": pkg["name"], "version": pkg["version"],
                "ballerinaVersion": pkg["ballerinaVersion"], "report": os.path.basename(report_path),
                # Passed through from central_resolve.py's output - combine.py uses this to read
                # the package's OWN .trivyignore instead of the shared distribution-wide one.
                # Must be explicitly carried here: this dict is built fresh, not a copy of `pkg`,
                # so any field not named here (this one included, before this fix) is silently
                # dropped before combine.py ever sees it.
                "repo": pkg.get("repo"), "error": None,
            }
        except Exception as e:  # noqa: BLE001 - record and continue; one bad package shouldn't kill the run
            return {
                "org": pkg["org"], "name": pkg["name"], "version": pkg["version"],
                "ballerinaVersion": pkg.get("ballerinaVersion"), "repo": pkg.get("repo"),
                "report": None, "error": str(e),
            }

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for result in pool.map(_work, packages):
            if result["error"]:
                failures.append(result)
                print(f"FAILED {result['org']}/{result['name']}/{result['version']}: {result['error']}", file=sys.stderr)
            else:
                manifest.append(result)

    with open(os.path.join(args.out_dir, "manifest.json"), "w") as f:
        json.dump({"scanned": manifest, "failed": failures}, f, indent=2)

    print(f"Scanned {len(manifest)} packages, {len(failures)} failures.", file=sys.stderr)
    if failures:
        # Non-fatal: a handful of packages failing to download/scan shouldn't blank the whole
        # run. combine.py surfaces these via scan_status so they're visible, not silent.
        print("See manifest.json 'failed' array for details.", file=sys.stderr)


if __name__ == "__main__":
    main()
