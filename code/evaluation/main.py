
import csv
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"
SAMPLE_PREDICTIONS = Path(__file__).resolve().parent / "sample_predictions.csv"
ERROR_REPORT = Path(__file__).resolve().parent / "sample_error_analysis.md"


def load_project_main():
    module_path = ROOT / "code" / "main.py"
    spec = importlib.util.spec_from_file_location("project_main", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_csv(filename):
    path = DATASET / filename
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def normalize_steps(value):
    try:
        parsed = json.loads(value)
    except Exception:
        return None
    if not isinstance(parsed, list):
        return None
    return parsed


def read_evidence_manifest():
    return {row["file_id"]: row for row in read_csv("evidence_files.csv")}


def evidence_context(evidence_ids, resources, user_ids, aliases, cutoff, manifest):
    contexts = []
    for evidence_id in evidence_ids:
        item = manifest.get(evidence_id)
        if not item:
            continue
        if item["captured_at"] > cutoff:
            contexts.append(f"{evidence_id} ({item['file_path']}) is after audit_at and excluded")
            continue
        path = DATASET / item["file_path"]
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            content = ""
        needles = [*resources, *user_ids, *aliases]
        lines = [
            line.strip() for line in content.splitlines()
            if any(value and value.lower() in line.lower() for value in needles)
        ]
        excerpt = " | ".join(lines[:3])[:700]
        if not excerpt:
            excerpt = "No direct text match; the manifest identifies a non-text or indirect evidence item."
        contexts.append(
            f"{evidence_id} ({item['file_path']}, captured {item['captured_at']}): {excerpt}"
        )
    return contexts


def sample_identity_context(request, identities, audit_log):
    email = request.get("email", "").strip().lower()
    matched = set()
    for user in identities:
        if (user.get("email") or "").strip().lower() == email:
            matched.add(user["user_id"])
    for audit in audit_log:
        if audit.get("field_name") == "email" and email in {
            (audit.get("old_value") or "").strip().lower(),
            (audit.get("new_value") or "").strip().lower(),
        }:
            matched.add(audit["user_id"])
    relevant_audits = [
        row for row in audit_log
        if row.get("user_id") in matched and row.get("field_name") in {"email", "phone", "email_hash"}
    ]
    aliases = {email}
    for row in relevant_audits:
        for field in ("old_value", "new_value"):
            if row.get(field):
                aliases.add(row[field].strip().lower())
    identity_text = ", ".join(sorted(matched)) or "no identity match"
    audit_text = "; ".join(
        f"{row.get('field_name')} {row.get('old_value')} -> {row.get('new_value')}"
        for row in relevant_audits
    ) or "no matching email/phone/hash audit changes"
    return sorted(matched), sorted(aliases), identity_text, audit_text


def relevant_activity(resources, user_ids, aliases, cutoff):
    activity = read_csv("system_activity.csv")
    needles = [*resources, *user_ids, *aliases]
    matched = []
    for row in activity:
        if row.get("event_time", "") > cutoff:
            continue
        searchable = " ".join(row.values()).lower()
        if any(value and value.lower() in searchable for value in needles):
            matched.append(row)
    return [
        f"{row['activity_id']} {row['event_time']} {row['event_type']} "
        f"{row['source_system']} -> {row['target_system']} {row['resource_id']} "
        f"reported_result={row['reported_result']}: {row['details']}"
        for row in matched[:5]
    ]


def root_causes(request, expected_steps, predicted_steps, expected_status, predicted_status):
    text = (request.get("request_text") or "").lower()
    causes = set()
    project_main = load_project_main()
    intent = project_main.classify_request(request.get("request_text", ""))
    if expected_status != predicted_status and (
        (intent == "NOT_APPLICABLE") != (expected_status == "NOT_APPLICABLE")
        or (intent == "NOT_APPLICABLE") != (predicted_status == "NOT_APPLICABLE")
    ):
        causes.add("request classification")
    if expected_status != predicted_status and intent != "NOT_APPLICABLE":
        causes.add("evidence matching")
    if len(expected_steps) != len(predicted_steps):
        causes.add("evidence matching")
    expected_evidence = {step.get("evidence_id") for step in expected_steps if step.get("evidence_id")}
    predicted_evidence = {step.get("evidence_id") for step in predicted_steps if step.get("evidence_id")}
    if expected_evidence != predicted_evidence:
        causes.add("evidence matching")
    fields = ("system_id", "resource_id", "operation", "state")
    if any(
        step.get(field) != predicted_steps[index].get(field)
        for index, step in enumerate(expected_steps[:len(predicted_steps)])
        for field in fields
    ):
        causes.add("identity resolution")
    if any(word in text for word in ("old", "earlier", "previous", "historical", "current")):
        causes.add("audit-time filtering")
    expected_ops = {step.get("operation") for step in expected_steps}
    if expected_ops & {"REDACT_RECORD", "ANONYMIZE_RECORD", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED"}:
        causes.add("retention/redaction/anonymization policy")
    if expected_ops & {"REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"}:
        causes.add("active data flows")
    if expected_ops & {"REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"}:
        causes.add("restoration risk")
    phases = [step.get("phase") for step in expected_steps]
    if phases != sorted(phases, key={"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}.get):
        causes.add("step ordering")
    if not causes:
        causes.add("evidence matching")
    return causes


def render_sample_error_analysis(requests, predictions, expected_rows):
    identities = read_csv("user_identities.csv")
    audit_log = read_csv("user_audit_log.csv")
    rules = read_csv("deletion_rules.csv")
    manifest = read_evidence_manifest()
    prediction_map = {row["case_id"]: row for row in predictions}
    expected_map = {row["case_id"]: row for row in expected_rows}
    cause_counts = Counter()
    report = [
        "# Public Sample Error Analysis",
        "",
        "Generated by comparing the current solver predictions with the public sample output by `case_id`.",
        "The expected output is used only as an evaluation reference; it is not used to construct predictions.",
        "",
        "## Most Frequent Root Causes",
    ]
    case_data = []
    for request in sorted(requests, key=lambda row: row["case_id"]):
        case_id = request["case_id"]
        prediction = prediction_map.get(case_id)
        expected = expected_map.get(case_id)
        if not prediction or not expected:
            continue
        expected_steps = normalize_steps(expected["steps_json"]) or []
        predicted_steps = normalize_steps(prediction["steps_json"]) or []
        causes = root_causes(
            request, expected_steps, predicted_steps,
            expected["deletion_status"], prediction["deletion_status"],
        )
        cause_counts.update(causes)
        case_data.append((request, prediction, expected, expected_steps, predicted_steps, causes))
    report.extend(f"- {cause}: {count} cases" for cause, count in cause_counts.most_common())
    for cause in (
        "request classification", "identity resolution", "evidence matching", "audit-time filtering",
        "retention/redaction/anonymization policy", "active data flows", "restoration risk", "step ordering",
    ):
        if cause not in cause_counts:
            report.append(f"- {cause}: 0 cases")
    report.extend([
        "",
        "The most frequent mechanical differences are step count, resource ID, evidence ID, and operation. The cause counts are diagnostic groupings, not independent causal proof; activity entries are treated as claims and are not sufficient alone to establish resource state.",
        "",
        "## Case-by-Case Diagnostics",
    ])
    for request, prediction, expected, expected_steps, predicted_steps, causes in case_data:
        case_id = request["case_id"]
        user_ids, aliases, identity_text, audit_text = sample_identity_context(request, identities, audit_log)
        resources = sorted({step.get("resource_id", "") for step in expected_steps + predicted_steps if step.get("resource_id")})
        evidence_ids = sorted({step.get("evidence_id", "") for step in expected_steps if step.get("evidence_id")})
        evidence = evidence_context(evidence_ids, resources, user_ids, aliases, request.get("audit_at", ""), manifest)
        activity = relevant_activity(resources, user_ids, aliases, request.get("audit_at", ""))
        categories_by_system = {
            "account_service": {"USER_PROFILE"},
            "search_service": {"SEARCH_INDEX_ENTRY"},
            "analytics_platform": {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"},
            "support_platform": {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"},
            "export_service": {"USER_EXPORT"},
            "backup_service": {"BACKUP_ARCHIVE"},
            "security_service": {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"},
            "identity_service": {"ACCOUNT_TOMBSTONE"},
        }
        expected_ops = {step.get("operation") for step in expected_steps}
        relevant_categories = set().union(*(
            categories_by_system.get(step.get("system_id", ""), set())
            for step in expected_steps
        )) if expected_steps else set()
        if "REDACT_RECORD" in expected_ops:
            relevant_categories |= {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}
        relevant_rules = [
            f"{row['rule_id']} {row['data_category']} ({row['condition']}): {row['required_action']}"
            for row in rules if row["data_category"] in relevant_categories
        ]
        report.extend([
            "",
            f"### {case_id}",
            f"- Request: {request.get('request_text', '').strip()}",
            f"- Status: expected `{expected['deletion_status']}`; predicted `{prediction['deletion_status']}`; match: **{'yes' if expected['deletion_status'] == prediction['deletion_status'] else 'no'}**.",
            f"- Step count: expected {len(expected_steps)}; predicted {len(predicted_steps)}.",
        ])
        max_steps = max(len(expected_steps), len(predicted_steps))
        field_names = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
        step_diffs = []
        for index in range(max_steps):
            exp_step = expected_steps[index] if index < len(expected_steps) else None
            pred_step = predicted_steps[index] if index < len(predicted_steps) else None
            if exp_step is None:
                step_diffs.append(f"step {index + 1}: expected [none]; predicted {pred_step}")
            elif pred_step is None:
                step_diffs.append(f"step {index + 1}: expected {exp_step}; predicted [none]")
            else:
                differences = [
                    f"{name} `{exp_step.get(name, '')}` -> `{pred_step.get(name, '')}`"
                    for name in field_names if exp_step.get(name) != pred_step.get(name)
                ]
                if differences:
                    step_diffs.append(f"step {index + 1}: " + "; ".join(differences))
        report.append("- Field differences: " + ("; ".join(step_diffs) if step_diffs else "none"))
        report.append(f"- Root-cause groups: {', '.join(sorted(causes))}.")
        report.append(f"- Identity/audit context: {identity_text}; {audit_text}.")
        report.append(f"- Applicable policy context: {', '.join(relevant_rules[:8]) or 'no policy row could be associated with the available step labels'}.")
        report.append(f"- Evidence context: {'; '.join(evidence) if evidence else 'no expected evidence citation'}.")
        report.append(f"- Activity context by audit_at: {'; '.join(activity) if activity else 'no matching activity row found for the linked resource or identity before audit_at'}.")
        expected_resources = sorted({step.get("resource_id", "") for step in expected_steps if step.get("resource_id")})
        predicted_resources = sorted({step.get("resource_id", "") for step in predicted_steps if step.get("resource_id")})
        evidence_files = sorted({manifest[eid]["file_path"] for eid in evidence_ids if eid in manifest})
        explanation = (
            f"The request text is classified as {prediction['deletion_status'] if prediction['deletion_status'] == 'NOT_APPLICABLE' else 'an affirmative deletion request'} by the current intent rules. "
            f"The supplied address links to {identity_text}; identifier history available by audit_at is {audit_text}. "
            f"The reference output cites {', '.join(evidence_ids) or 'no evidence IDs'} in {', '.join(evidence_files) or 'no associated evidence files'}, with expected resource IDs {', '.join(expected_resources) or 'none'}; the current solver produced resource IDs {', '.join(predicted_resources) or 'none'}. "
            f"Relevant policy rows and cutoff-eligible evidence excerpts are listed above. Activity entries are corroborating claims only. Where a cited snapshot contains a resource but no subject identifier, it establishes that resource's observed state but does not independently link it to this subject. The observed discrepancy is grouped under {', '.join(sorted(causes))}."
        )
        report.append("- Explanation: " + explanation)
    ERROR_REPORT.write_text("\n".join(report) + "\n", encoding="utf-8")
    return cause_counts


def build_sample_predictions(project_main):
    requests = read_csv("sample_deletion_requests.csv")
    identities = read_csv("user_identities.csv")
    audit_log = read_csv("user_audit_log.csv")
    evidence_records = project_main.load_evidence_records()
    predictions = []
    for request in sorted(requests, key=lambda item: item["case_id"]):
        status, steps = project_main.audit_case(request, identities, audit_log, evidence_records)
        predictions.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
        })
    return predictions


def compare_sample_predictions(predictions, expected_rows):
    status_correct = 0
    exact_match = 0
    mismatches = []
    step_field_errors = []
    step_order_errors = []

    expected_map = {row["case_id"]: row for row in expected_rows}
    for prediction in predictions:
        case_id = prediction["case_id"]
        expected = expected_map.get(case_id)
        if not expected:
            mismatches.append({"case_id": case_id, "reason": "missing in expected sample output"})
            continue

        expected_status = expected["deletion_status"]
        predicted_status = prediction["deletion_status"]
        if predicted_status == expected_status:
            status_correct += 1

        expected_steps = normalize_steps(expected["steps_json"])
        predicted_steps = normalize_steps(prediction["steps_json"])

        if predicted_status == expected_status and predicted_steps == expected_steps:
            exact_match += 1
        else:
            reason = []
            if predicted_status != expected_status:
                reason.append("status mismatch")
            if predicted_steps != expected_steps:
                reason.append("steps mismatch")
            mismatches.append({
                "case_id": case_id,
                "reason": "; ".join(reason) if reason else "unexpected mismatch",
                "expected_status": expected_status,
                "predicted_status": predicted_status,
            })

        if predicted_steps is not None and expected_steps is not None:
            if len(predicted_steps) != len(expected_steps):
                step_field_errors.append({
                    "case_id": case_id,
                    "reason": "step count mismatch",
                    "expected": len(expected_steps),
                    "actual": len(predicted_steps),
                })
            for idx, (pred_step, exp_step) in enumerate(zip(predicted_steps, expected_steps), start=1):
                pred_keys = set(pred_step.keys())
                exp_keys = set(exp_step.keys())
                if pred_keys != exp_keys:
                    step_field_errors.append({
                        "case_id": case_id,
                        "reason": f"field mismatch at step {idx}",
                        "expected_keys": sorted(exp_keys),
                        "actual_keys": sorted(pred_keys),
                    })
                if pred_step.get("step_no") != exp_step.get("step_no"):
                    step_field_errors.append({
                        "case_id": case_id,
                        "reason": f"step_no mismatch at step {idx}",
                        "expected": exp_step.get("step_no"),
                        "actual": pred_step.get("step_no"),
                    })
                if pred_step.get("phase") != exp_step.get("phase"):
                    step_order_errors.append({
                        "case_id": case_id,
                        "reason": f"phase mismatch at step {idx}",
                        "expected": exp_step.get("phase"),
                        "actual": pred_step.get("phase"),
                    })

    return {
        "status_accuracy": status_correct,
        "exact_matches": exact_match,
        "mismatches": mismatches,
        "field_errors": step_field_errors,
        "phase_order_errors": step_order_errors,
    }


def run_additional_checks():
    checks = [
        {
            "name": "non_deletion request",
            "input": "Please do not close my account; I only want a PDF of my data.",
            "expected": "NOT_APPLICABLE",
        },
        {
            "name": "clear deletion request",
            "input": "Please permanently delete my account and remove the associated profile.",
            "expected": "DELETION",
        },
        {
            "name": "historical email alias",
            "input": "I used this old address before; please remove all records linked to it.",
            "expected": "DELETION",
        },
    ]
    results = []
    project_main = load_project_main()
    for item in checks:
        request = {"case_id": "custom_test", "request_text": item["input"], "email": "example@example.com"}
        actual = project_main.classify_request(request["request_text"])
        results.append({
            "name": item["name"],
            "expected": item["expected"],
            "actual": actual,
            "passed": actual == item["expected"],
        })
    return results


def main():
    project_main = load_project_main()
    sample_rows = read_csv("sample_output.csv")
    sample_requests = read_csv("sample_deletion_requests.csv")
    sample_predictions = build_sample_predictions(project_main)
    with SAMPLE_PREDICTIONS.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(sample_predictions)
    root_causes_summary = render_sample_error_analysis(sample_requests, sample_predictions, sample_rows)
    comparison = compare_sample_predictions(sample_predictions, sample_rows)
    expected_ids = {row["case_id"] for row in sample_rows}
    predicted_ids = {row["case_id"] for row in sample_predictions}

    print("=== SAMPLE EVALUATION ===")
    print(f"Saved predictions: {SAMPLE_PREDICTIONS}")
    print(f"Diagnostic report: {ERROR_REPORT}")
    print(f"Status accuracy: {comparison['status_accuracy']}/32")
    print(f"Exact status-and-steps matches: {comparison['exact_matches']}/32")
    print(f"Missing prediction IDs: {sorted(expected_ids - predicted_ids) or 'none'}")
    print(f"Unexpected prediction IDs: {sorted(predicted_ids - expected_ids) or 'none'}")
    print("Most frequent root causes:")
    for cause, count in root_causes_summary.most_common():
        print(f" - {cause}: {count} cases")
    if comparison["mismatches"]:
        print("Per-case mismatches:")
        for item in comparison["mismatches"]:
            print(" -", item)
    else:
        print("Mismatches: none")

    if comparison["field_errors"]:
        print("Field errors:")
        for item in comparison["field_errors"][:10]:
            print(" -", item)
    else:
        print("Field errors: none")

    if comparison["phase_order_errors"]:
        print("Phase-order errors:")
        for item in comparison["phase_order_errors"][:10]:
            print(" -", item)
    else:
        print("Phase-order errors: none")

    print("\n=== ADDITIONAL CUSTOM CHECKS ===")
    for result in run_additional_checks():
        print(f"{result['name']}: expected={result['expected']} actual={result['actual']} passed={result['passed']}")


if __name__ == "__main__":
    main()
