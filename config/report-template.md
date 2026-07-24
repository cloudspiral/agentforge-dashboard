# {{ title }}

**Vulnerability ID:** {{ vulnerability_id }}  
**Status:** {{ status }}  
**Severity:** {{ severity }}  
**Confidence:** {{ confidence }}  
**Category:** {{ category }} / {{ subcategory }}  
**OWASP mappings:** {{ owasp_mappings }}

## Executive summary

{{ description }}

## Clinical and security impact

{{ clinical_impact }}

## Affected target versions

{{ affected_target_versions }}

## Preconditions

{{ prerequisites }}

## Exact confirmed sequence

{{ minimal_reproducible_attack_sequence }}

## Observed behavior

{{ observed_behavior }}

## Expected secure behavior

{{ expected_behavior }}

## Evidence

{{ evidence_references }}

## Exact transcript

{{ exact_transcript }}

## Remediation validation history

{{ current_fix_validation_results }}

## Recommended remediation approach

{{ recommended_remediation_approach }}

## Regression protection

The exact confirmed sequence is saved as a versioned regression case after this
report is persisted.

## Human review lifecycle

The status above is the canonical vulnerability lifecycle state. `pending_review`
means the Judge confirmed evidence that still requires a human decision; `open` and
`in_progress` track remediation; `resolved` requires changed-version secure
regression evidence or a labeled reasoned override; `false_positive` records a
human dismissal. Report publication is not a separate workflow.
