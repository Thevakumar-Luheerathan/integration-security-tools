# combined.sample.json

Hand-assembled sample conforming to the pipeline's `combined.json` contract (see
`../scripts/combine.py`'s module docstring for the authoritative schema), used to
develop and test the dashboard-backend (Track B) against a stable contract before Track A's real
pipeline is fully wired end-to-end in CI.

Deliberately kept as **pure contract data with no extra fields** - `dashboard:CombinedReport`
(in `../../dashboard-backend/types.bal`) is a closed record, matching what `combine.py` actually emits.
An earlier version of this fixture included a `$comment` key for self-documentation, which broke
`cloneWithType()` with `field '$comment' cannot be added to the closed record`. That's exactly the
kind of contract drift this fixture exists to catch early, so the explanation lives here instead.

A few of the findings (the netty-codec/netty-codec-http CVEs against `ballerina/http` 2.13.0, and
the bcprov-jdk18on CRITICAL against `ballerinax/redis`) are copied verbatim from this pipeline's
actual design-phase verification runs - real Trivy output against real Ballerina Central packages,
not invented data. The rest are illustrative but structurally identical.

What it's constructed to exercise:
- Both sources (`distribution`, `central`) and both configured version lines.
- Mixed severities, including one CVE with no upstream fix yet (`fixed_version: ""`).
- The **"fixed on Central, pending in distribution"** comparison case: `CVE-2026-42587` appears
  under `source=distribution` for both 2201.12.x and 2201.13.x, but under `source=central` only
  for 2201.12.x - for 2201.13.x, `ballerina/http`'s latest Central version already carries the
  fix. `aggregate.bal:findPendingDistributionFixes` must flag the 2201.13.x case and must NOT
  flag the 2201.12.x one (the fix isn't actually available yet there).
- A `scan_status` entry with `ok: false`, so the dashboard can be tested for showing a failed
  scan distinctly from "scanned clean, zero findings" - conflating the two was one of the
  original failure modes this whole project exists to fix.
- A finding with `issue: null` (the rocketmq driver package, not yet synced to a tracking issue),
  to confirm the dashboard surfaces "no issue yet" as a visible state rather than dropping it.
- The **`library_name`-not-on-Central exclusion**: `commons-beanutils` appears only under
  `source=distribution` (it's a `ballerina-lang`-only tooling dependency, never published to
  Central) - `findPendingDistributionFixes` must exclude it entirely rather than falsely
  claiming it's "already fixed on Central" just because no Central finding shares its CVE. This
  is the real false positive found and fixed during this pipeline's design phase.

Note: there is no `repo` field anywhere in this schema and no "(unresolved)" bucket - every
finding has a real `package_org`/`package_name` by construction (there is deliberately no
repo-resolution step in this pipeline; see `combine.py`'s module docstring).
