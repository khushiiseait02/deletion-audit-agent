# Evaluation Report

## Measured Results

Public-sample evaluation is performed separately from the 518-request full output. The public sample contains 32 requests.

| Measure | Baseline before this change | Final measured run |
|---|---:|---:|
| Status accuracy | 24/32 (75.0%) at the start of this continuation | 31/32 (96.875%) |
| Exact status-and-steps matches | 1/32 (3.125%) at the start of this continuation | 3/32 (9.375%) |

The final sample run had no missing or unexpected case IDs. A detailed local case-by-case diagnostic was used during development but is not included in this public source-only mirror because it contains dataset-derived evidence excerpts.

Status mismatch: `case_04` expected `COMPLETE`, predicted `INCOMPLETE`. Exact status-and-steps matches: `case_01`, `case_02`, and `case_05`. The other 29 cases are not exact, mostly because step coverage and fields still differ.

## Changes Made

- Request classification now gives affirmative deletion intent precedence over incidental mentions of downloads, exports, and copies, while preserving explicit negation handling and common Spanish deletion forms.
- Added a shared participant-evidence audit path for JSON, SQLite-compatible SQL, and log/text evidence.
- Added current and historical identifier linking, policy-category mapping, resource-level evidence correlation, and audit-time cutoffs for identity events and evidence records.
- Added general treatment handling for profiles, search entries, analytics, support records, exports, connectors, backups, security audit records, and account tombstones.
- Expanded evidence identifier matching across nested/scalar fields and normalized quote-wrapped log values; mapped service-export paths and explicit null/404 readbacks.
- Treat support conversations with cleared direct identifiers as already redacted rather than exposed PII.
- Correlated structured log values only within matching trace IDs and honored row-level `origin_system`, table, and JSON payload metadata in SQL inventory snapshots.
- For account absence, a unique deletion-worker event near `reported_at` is used only to identify a candidate resource; COMPLETE requires an independent pre-`audit_at` SQL snapshot covering the account table and omitting that candidate. Requests explicitly mentioning other unverified categories do not use this shortcut.
- Added the reproducible sample prediction artifact and case-level diagnostic report.

These changes improve the measured status result versus baseline, but the exact-match result remains very low. The solver is not ready to be represented as challenge-correct.

## Full Output Structural Validation

The final run of `code/main.py` generated root `output.csv` with 518 rows. An independent validation passed with zero errors for:

- Exact request coverage, unique case IDs, and sorted order.
- Required header order and allowed status values.
- Valid JSON arrays and exact step object fields.
- Consecutive step numbering, allowed operations, and phase ordering.

Final generated status counts: `COMPLETE` 86, `INCOMPLETE` 426, `NOT_APPLICABLE` 6.

Structural validity is not a measure of decision accuracy. The 518-case output has not been validated against hidden answers, and no hidden-test accuracy is claimed.

## Additional Checks

Three intent-classification checks passed: a non-deletion request, a clear deletion request, and a request that refers to an earlier email address. These are narrow classification checks, not full audit-case tests.

## Remaining Failures And Risks

- Sample status accuracy is 31/32, but exact status-and-step accuracy remains only 3/32.
- The leading remaining step-difference groups are missing/extra steps (68 positions), system ID (68 differences), and operation (63 differences); field differences are positional diagnostics, not independent causal counts.
- `case_04` remains `INCOMPLETE` deliberately: `evidence_56` shows `analytics_901` has null user/email/phone/hash fields, and the nearby `ANONYMIZE_RECORD` activity targets that resource, but that activity is a claim. `evidence_54` contains primary and failover account tables but no identifier or resource row linking this subject to `account_004`; the snapshot omission alone does not prove that account's absence for this subject. No safe COMPLETE fix is justified from current participant-facing evidence.
- Evidence linkage still misses records in a number of sample cases, and evidence correlations can contain ambiguous or shared identifiers.
- Active synchronization, replica drift, retention periods, legal holds, support attachments, and historical identity relationships are not yet comprehensively modeled.
- The generic evidence parser covers only common JSON, SQL, and text/log structures; PDFs and images require specialized extraction and validation.
- Results are limited to the public sample and structural checks; hidden evaluation behavior remains unverified.

No final ZIP was created.
