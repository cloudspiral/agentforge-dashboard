# AF-A06-EXP-001 - Deployed Guzzle component exposure

## Classification

- Status: Open exposure; application-specific exploitability unverified
- Triage severity: High
- Exploit severity: Not assigned
- Category: OWASP Web A06 - Vulnerable and Outdated Components
- Target build: `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d`
- Component: `guzzlehttp/guzzle 7.12.1`
- Scanner references: `GHSA-94pj-82f3-465w`, `GHSA-f283-ghqc-fg79`,
  `GHSA-g446-98w2-8p5w`, `GHSA-h95v-h523-3mw8`, `GHSA-wm3w-8rrp-j577`

## Description and possible clinical impact

The exact Composer input and running OpenEMR container both reported
`guzzlehttp/guzzle 7.12.1`, and the pinned OSV scan associated that version with five
advisories involving proxy authorization, cookies, and redirect/referrer behavior.
If an affected Guzzle request path accepts attacker-influenced destinations,
redirects, proxies, or cookies, confidentiality or availability of an OpenEMR
workflow could be affected.

This is not evidence of a Clinical Co-Pilot exploit. Read-only source inspection found
that the main Co-Pilot chat proxy uses native PHP cURL, not Guzzle. Other OpenEMR
features do use Guzzle, but no advisory prerequisite or attacker-controlled route was
executed.

## Reproducible verification sequence

1. Resolve the deployed OpenEMR/Co-Pilot target to build
   `fe8268f8953bc7c9bde9b01020b9ddf8b5c5649d`.
2. Verify the Composer lockfile digest recorded in
   `evals/results/submission/controls/AF-SC-001.evidence.json`.
3. Inspect the pinned OSV 2.3.8 result at
   `evals/results/submission/controls/sca/AF-SC-001.osv.json`.
4. Confirm the running OpenEMR container reports
   `guzzlehttp/guzzle 7.12.1`.
5. Inspect `interface/patient_file/clinical_copilot/proxy.php`; the `/agent/chat`
   bridge is created with `curl_init`.
6. Search the Co-Pilot-specific PHP paths for `GuzzleHttp`; no direct reference is
   present in the inspected build.

No exploit payload, proxy credential, redirect chain, persistent write, or
infrastructure change is part of this verification.

## Expected versus observed

- Expected: no affected deployed dependency remains without explicit applicability
  and remediation disposition.
- Observed: the affected version is installed in the deployed runtime; the primary
  Co-Pilot chat bridge does not directly use it; wider OpenEMR reachability remains
  unverified.

## Recommended remediation and validation

1. Upgrade Guzzle to a release outside every applicable advisory range after OpenEMR
   compatibility review.
2. Inventory runtime call sites that configure proxies, redirects, cookies, or
   attacker-influenced URIs.
3. Add focused non-destructive tests for applicable call sites rather than treating
   the package match itself as an exploit.
4. Rebuild the target image, regenerate the SBOM, rerun the pinned scanner, and verify
   the running container version.
5. Replay Co-Pilot security regressions to detect unrelated behavior changes.

## Submission treatment

This exposure report supports A06 triage. It is not a Judge-confirmed exploit, was not
produced by the Documentation Agent, and does not count toward the assignment's
minimum of three distinct vulnerability reports.
