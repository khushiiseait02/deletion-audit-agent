
import csv
import json
import re
import sqlite3
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

FIELDS = ["case_id", "deletion_status", "steps_json"]

NON_DELETION_PATTERNS = [
    r"\bmarketing\b",
    r"\bpromotional\b",
    r"\bopt.?out\b",
    r"\bcorrect(?:ion)?\b",
    r"\brectif\w*",
    r"\bupdate my\b",
    r"\bchange my\b",
    r"\breset (?:my )?(?:password|login)\b",
    r"\bdownload\b",
    r"\bexport\b",
    r"\bcopy of\b",
    r"\binvoices?\b",
    r"\bkeep my account\b",
    r"\bleave my (?:account|profile)\b",
    r"\bmobile number\b",
    r"\bphone number\b",
    r"\breplace it\b",
    r"\bcontinue using\b",
    r"\bchange the email address\b",
    r"\bdo not close\b",
    r"\bdon't close\b",
    r"\bnot delete\b",
    r"\bnot remove\b",
    r"\bresetting the login\b",
]

DELETION_PATTERNS = [
    r"\bdelet\w*",
    r"\beras\w*",
    r"\bremov\w*",
    r"\bclos(?:e|ing|ure)\b.{0,35}\baccount\b",
    r"\bpermanent(?:ly)?\b.{0,35}\baccount\b",
    r"exclus[aã]o",
    r"elimina[cç][aã]o",
    r"\belimin\w*",
    r"supresi[oó]n",
    r"supression",
    r"suppression",
    r"supprimer",
    r"deleted this account",
    r"erase my account",
    r"remove the profile",
    r"remove any remaining copy",
    r"削除",
    r"消去",
    r"삭제",
]

INCOMPLETE_HINTS = [
    r"still recognized",
    r"still appears",
    r"still there",
    r"old profile",
    r"old email",
    r"same email",
    r"search result",
    r"download your data",
    r"export file",
    r"copy(?:ies)? still",
    r"not fully",
    r"partial",
    r"error",
    r"same address is still",
]


def read_csv(filename):
    with (DATASET / filename).open("r", encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def parse_time(value):
    if not value:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def normalize_text(value):
    return re.sub(r"\s+", " ", (value or "")).strip().lower()


def normalize_email(value):
    return normalize_text(value).strip(". ")


def normalize_phone(value):
    digits = re.sub(r"\D+", "", str(value or ""))
    return digits


def classify_request(text):
    text_norm = normalize_text(text)
    negated_deletion = re.compile(
        r"\b(?:do not|don't|dont|never|not)\s+(?:permanently\s+)?"
        r"(?:delete|erase|remove|close|deactivate)\b[^.!?;]*"
    )
    affirmative_text = negated_deletion.sub(" ", text_norm)
    if any(re.search(pattern, affirmative_text) for pattern in DELETION_PATTERNS):
        return "DELETION"
    if negated_deletion.search(text_norm):
        return "NOT_APPLICABLE"
    if any(re.search(pattern, text_norm) for pattern in NON_DELETION_PATTERNS):
        return "NOT_APPLICABLE"
    return "REVIEW"


def build_identity_index(identities, audit_log):
    alias_index = defaultdict(set)
    for user in identities:
        user_id = user.get("user_id")
        for field in ("email", "phone"):
            value = (user.get(field) or "").strip()
            if not value:
                continue
            key = normalize_email(value) if field == "email" else normalize_phone(value)
            if key:
                alias_index[key].add(user_id)

    for audit in audit_log:
        if audit.get("field_name") not in {"email", "phone"}:
            continue
        for value in (audit.get("old_value"), audit.get("new_value")):
            if not value:
                continue
            key = normalize_email(value) if audit.get("field_name") == "email" else normalize_phone(value)
            if key:
                alias_index[key].add(audit.get("user_id"))

    return alias_index


def resolve_subject(request, identity_index):
    candidates = set()
    email = normalize_email(request.get("email"))
    phone = normalize_phone(request.get("email"))
    if email:
        candidates |= identity_index.get(email, set())
    if phone:
        candidates |= identity_index.get(phone, set())
    return sorted(candidates)


SYSTEM_CATEGORIES = {
    "account_service": "USER_PROFILE",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
}


TABLE_CATEGORIES = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
}


def _walk_records(value, context="", metadata=None):
    metadata = metadata or {}
    if isinstance(value, dict):
        inherited = dict(metadata)
        for key in ("data_store", "collection"):
            if value.get(key):
                inherited[key] = value[key]
        yield value, context, inherited
        for key, child in value.items():
            yield from _walk_records(child, f"{context} {key}", inherited)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_records(child, context, metadata)


def _decode_sql_value(value):
    if not isinstance(value, str):
        return value
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value
    return parsed


def load_evidence_records():
    records = []
    for item in read_csv("evidence_files.csv"):
        evidence_path = DATASET / item["file_path"]
        suffix = evidence_path.suffix.lower()
        if suffix == ".json":
            try:
                payload = json.loads(evidence_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                continue
            for record, context, metadata in _walk_records(payload):
                if record.get("resource_id"):
                    context_system = next((system for system in SYSTEM_CATEGORIES if system in context), "")
                    system_id, category = TABLE_CATEGORIES.get(
                        metadata.get("collection", ""),
                        (context_system or metadata.get("data_store", ""), ""),
                    )
                    if not category:
                        category = SYSTEM_CATEGORIES.get(system_id, "")
                    records.append({
                        "evidence_id": item["file_id"],
                        "captured_at": item["captured_at"],
                        "resource_id": str(record["resource_id"]),
                        "system_id": system_id,
                        "category": category,
                        "data": record,
                    })
        elif suffix == ".sql":
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(evidence_path.read_text(encoding="utf-8-sig"))
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                for (table_name,) in tables:
                    if table_name == "snapshot_scope":
                        continue
                    cursor = connection.execute(f'SELECT * FROM "{table_name}"')
                    columns = [column[0] for column in cursor.description]
                    for row in cursor.fetchall():
                        record = {key: _decode_sql_value(value) for key, value in zip(columns, row)}
                        if {"origin_system", "table_name", "record_json"}.issubset(record):
                            system_id = record["origin_system"]
                            category = TABLE_CATEGORIES.get(record["table_name"], (system_id, ""))[1]
                            payload = record["record_json"]
                            if isinstance(payload, dict):
                                record = {**payload, **record}
                        else:
                            system_id, category = TABLE_CATEGORIES.get(table_name, ("", ""))
                        if record.get("resource_id"):
                            records.append({
                                "evidence_id": item["file_id"],
                                "captured_at": item["captured_at"],
                                "resource_id": str(record["resource_id"]),
                                "system_id": system_id,
                                "category": category,
                                "data": record,
                            })
            except sqlite3.Error:
                pass
            finally:
                connection.close()
        elif suffix in {".log", ".txt"}:
            try:
                content = evidence_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            trace_context = defaultdict(dict)
            for line in content.splitlines():
                pairs = re.findall(r'([A-Za-z_]+)="((?:\\.|[^"])*)"|([A-Za-z_]+)=([^\s]+)', line)
                fields = {}
                for quoted_key, quoted_value, plain_key, plain_value in pairs:
                    key = quoted_key or plain_key
                    value = quoted_value if quoted_key else plain_value
                    fields[key] = value.strip("'\"")
                trace = fields.get("trace_id") or fields.get("traceId") or fields.get("requestId")
                if trace:
                    trace_context[trace].update({key: value for key, value in fields.items() if key != "raw"})
                resource_id = fields.get("resource_id")
                if not resource_id:
                    resource = re.search(r"\bresource_id[=\s]+['\"]?([A-Za-z0-9_-]+)", line)
                    resource_id = resource.group(1) if resource else ""
                if not resource_id:
                    continue
                data = dict(trace_context.get(trace, {})) if trace else {}
                data.update(fields)
                data["raw"] = line
                system_id = data.get("service", "") or data.get("logger", "") or data.get("function", "")
                if system_id.startswith("[") and system_id.endswith("]"):
                    system_id = system_id[1:-1]
                records.append({
                    "evidence_id": item["file_id"],
                    "captured_at": item["captured_at"],
                    "resource_id": resource_id,
                    "system_id": system_id,
                    "category": SYSTEM_CATEGORIES.get(system_id, ""),
                    "data": data,
                })
    return records


def _contains_subject(record, user_ids, emails, phones, hashes):
    data = record["data"]
    def scalar_values(value):
        if isinstance(value, dict):
            for child in value.values():
                yield from scalar_values(child)
        elif isinstance(value, list):
            for child in value:
                yield from scalar_values(child)
        elif isinstance(value, (str, int)):
            yield str(value)

    for value in scalar_values(data):
        normalized_value = value.strip().strip("'\".,;:()[]{}")
        lowered = normalized_value.lower()
        if lowered in {item.lower() for item in user_ids if item}:
            return True
        if normalize_email(normalized_value) in emails:
            return True
        digits = normalize_phone(normalized_value)
        if digits and digits in phones:
            return True
        if lowered in hashes:
            return True
    return False


def subject_identifiers(request, identities, audit_log):
    email = normalize_email(request.get("email"))
    cutoff = request.get("audit_at", "")
    subject_ids = set()
    user_by_id = {row.get("user_id"): row for row in identities}
    for user in identities:
        if normalize_email(user.get("email")) == email and user.get("updated_at", "") <= cutoff:
            subject_ids.add(user.get("user_id"))
    for row in audit_log:
        if row.get("event_time", "") > cutoff:
            continue
        if row.get("field_name") == "email" and email in {
            normalize_email(row.get("old_value")), normalize_email(row.get("new_value"))
        }:
            subject_ids.add(row.get("user_id"))
    emails = {email} if email else set()
    phones = set()
    hashes = set()
    for subject_id in subject_ids:
        user = user_by_id.get(subject_id, {})
        if user.get("email"):
            emails.add(normalize_email(user["email"]))
        if user.get("phone"):
            phones.add(normalize_phone(user["phone"]))
        if user.get("email_hash"):
            hashes.add(user["email_hash"].lower())
    for row in audit_log:
        if row.get("user_id") not in subject_ids or row.get("event_time", "") > cutoff:
            continue
        field = row.get("field_name")
        for value in (row.get("old_value"), row.get("new_value")):
            if not value:
                continue
            if field == "email":
                emails.add(normalize_email(value))
            elif field == "phone":
                phones.add(normalize_phone(value))
            elif field == "email_hash":
                hashes.add(value.lower())
    return subject_ids, emails, phones, hashes


def record_state(record):
    data = record["data"]
    values = {str(value).lower() for value in data.values() if isinstance(value, (str, int, bool))}
    raw = str(data.get("raw", "")).lower()
    if record.get("category") == "SUPPORT_MESSAGE":
        direct_fields = ("requester_name", "requester_email", "requester_phone")
        message = str(data.get("message_excerpt", data.get("message_text", "")))
        has_email = re.search(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b", message) is not None
        has_phone = re.search(r"(?:\+?\d[\d\s().-]{7,}\d)", message) is not None
        if not any(data.get(field) for field in direct_fields) and not (has_email or has_phone):
            return "REDACTED"
    if data.get("event", "").endswith("_completed"):
        if "rows" in data and str(data["rows"]) == "0":
            return "ABSENT"
        if str(data.get("result", "")).lower() == "miss":
            return "ABSENT"
        if str(data.get("http_status", "")) == "404":
            return "ABSENT"
        if "rows" in data and str(data["rows"]) not in {"0", ""}:
            return "PRESENT"
        if str(data.get("result", "")).lower() == "hit":
            return "PRESENT"
        if str(data.get("http_status", "")) == "200":
            return "PRESENT"
    if str(data.get("status_code", "")) == "404":
        return "ABSENT"
    if str(data.get("status_code", "")) == "200":
        return "PRESENT"
    if data.get("profile", object()) is None:
        return "ABSENT"
    if "enabled" in data and str(data["enabled"]).lower() in {"true", "1"}:
        return "ACTIVE"
    if "restore_allowed" in data and str(data["restore_allowed"]).lower() in {"true", "1"}:
        return "ACTIVE"
    if "false" in values and "enabled" in data:
        return "DISABLED"
    if "false" in values and "restore_allowed" in data:
        return "BLOCKED"
    if re.search(r"rows=0|total_hits=0|result=miss|http_status=404", raw):
        return "ABSENT"
    if re.search(r"rows=1|total_hits=[1-9]|result=hit|http_status=200", raw):
        return "PRESENT"
    if record.get("category") in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        identifier_fields = ("user_id", "customer_reference", "email", "phone", "email_hash")
        if all(not data.get(field) for field in identifier_fields):
            return "ANONYMIZED"
    return "PRESENT"


def policy_operation(record):
    category = record.get("category", "")
    data = record["data"]
    if category == "USER_PROFILE":
        return ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD")
    if category == "SEARCH_INDEX_ENTRY":
        return ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD")
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        return ("ANONYMIZE_RECORD", "ANONYMIZED", "VERIFY_RECORD_ANONYMIZED", "REPORT_EXPOSED_PII")
    if category == "SUPPORT_MESSAGE":
        if any(data.get(field) for field in ("requester_email", "requester_phone", "requester_name")):
            return ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REPORT_EXPOSED_PII")
        return ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REPORT_EXPOSED_PII")
    if category == "USER_EXPORT":
        return ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD")
    if category == "DATA_FLOW":
        return ("DISABLE_DATA_FLOW", "DISABLED", "VERIFY_DATA_FLOW_DISABLED", "REPORT_ACTIVE_DATA_FLOW")
    if category == "BACKUP_ARCHIVE":
        return ("BLOCK_RESTORE", "BLOCKED", "VERIFY_RESTORE_BLOCKED", "REPORT_RESTORE_RISK")
    if category == "ACCOUNT_TOMBSTONE":
        pii_fields = ("name", "full_name", "email", "phone", "email_hash")
        if any(data.get(field) for field in pii_fields):
            return ("REDACT_RECORD", "REDACTED", "VERIFY_RECORD_REDACTED", "REPORT_EXPOSED_PII")
        return ("VERIFY_RECORD_REDACTED", "REDACTED", "VERIFY_RECORD_REDACTED", "")
    if category == "SECURITY_AUDIT_LOG":
        return ("RETAIN", "PRESENT", "VERIFY_RECORD_PRESENT", "")
    return ("UNKNOWN", "PRESENT", "VERIFY_RECORD_PRESENT", "REPORT_REMAINING_RECORD")


def linked_absent_account(request, evidence_records):
    request_text = normalize_text(request.get("request_text", ""))
    unverified_scope_patterns = (
        r"\bsupport\b", r"\battachments?\b", r"\bdocuments?\b", r"\bintegrations?\b",
        r"\bbackups?\b", r"\barchives?\b", r"\banalytics\b", r"\bsearch(?:\s+result|\s+index)?\b",
        r"\bexports?\b", r"\bmarketing\b", r"\btombstones?\b",
    )
    if any(re.search(pattern, request_text) for pattern in unverified_scope_patterns):
        return []
    reported_at = parse_time(request.get("reported_at"))
    audit_at = request.get("audit_at", "")
    if reported_at is None:
        return []
    activities = read_csv("system_activity.csv")
    candidates = []
    for activity in activities:
        if activity.get("event_type") != "DELETE_RECORD":
            continue
        if activity.get("source_system") != "deletion_worker" or activity.get("target_system") != "account_service":
            continue
        if not activity.get("resource_id", "").startswith("account_"):
            continue
        event_time = parse_time(activity.get("event_time"))
        if event_time is None or event_time > parse_time(audit_at):
            continue
        if abs((event_time - reported_at).total_seconds()) <= 600:
            candidates.append(activity)
    if len(candidates) != 1:
        return []
    resource_id = candidates[0]["resource_id"]

    manifest = read_csv("evidence_files.csv")
    snapshots = []
    for item in manifest:
        if item["captured_at"] > audit_at or not item["file_path"].lower().endswith(".sql"):
            continue
        file_records = [record for record in evidence_records if record["evidence_id"] == item["file_id"]]
        covered = any(
            record.get("category") == "USER_PROFILE" for record in file_records
        )
        if not covered:
            path = DATASET / item["file_path"]
            try:
                sql_text = path.read_text(encoding="utf-8-sig", errors="ignore")
            except OSError:
                continue
            covered = any(
                table in sql_text
                for table, (system, category) in TABLE_CATEGORIES.items()
                if system == "account_service" and category == "USER_PROFILE"
            )
        if covered:
            snapshots.append((item, file_records))
    if not snapshots:
        return []
    latest_item, latest_records = max(snapshots, key=lambda pair: pair[0]["captured_at"])
    if any(record["resource_id"] == resource_id for record in latest_records):
        return []
    path = DATASET / latest_item["file_path"]
    try:
        sql_text = path.read_text(encoding="utf-8-sig", errors="ignore")
    except OSError:
        return []
    account_tables = [
        table for table, (system, category) in TABLE_CATEGORIES.items()
        if system == "account_service" and category == "USER_PROFILE" and re.search(rf"CREATE\s+TABLE\s+[\"`]?{re.escape(table)}[\"`]?\b", sql_text, re.IGNORECASE)
    ]
    if not account_tables:
        return []
    return [{
        "phase": "VERIFICATION",
        "system_id": "account_service",
        "resource_id": resource_id,
        "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT",
        "evidence_id": latest_item["file_id"],
    }]


def audit_case(request, identities, audit_log, evidence_records):
    intent = classify_request(request.get("request_text", ""))
    if intent == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", []
    subject_ids, emails, phones, hashes = subject_identifiers(request, identities, audit_log)
    cutoff = request.get("audit_at", "")
    matched = [
        row for row in evidence_records
        if row["captured_at"] <= cutoff
        and all(
            not isinstance(row["data"].get(field), str)
            or not re.match(r"^\d{4}-\d{2}-\d{2}T", row["data"][field])
            or row["data"][field] <= cutoff
            for field in ("observed_at", "captured_at", "updated_at", "indexed_at", "event_time")
        )
        and _contains_subject(row, subject_ids, emails, phones, hashes)
    ]
    linked_resources = {(row["evidence_id"], row["resource_id"]) for row in matched}
    matched.extend(
        row for row in evidence_records
        if row["captured_at"] <= cutoff
        and all(
            not isinstance(row["data"].get(field), str)
            or not re.match(r"^\d{4}-\d{2}-\d{2}T", row["data"][field])
            or row["data"][field] <= cutoff
            for field in ("observed_at", "captured_at", "updated_at", "indexed_at", "event_time")
        )
        and (row["evidence_id"], row["resource_id"]) in linked_resources
        and row not in matched
    )
    latest = {}
    for row in matched:
        resource_id = row["resource_id"]
        old = latest.get(resource_id)
        completed = str(row["data"].get("event", "")).endswith("_completed")
        old_completed = old and str(old["data"].get("event", "")).endswith("_completed")
        if old is None or (row["captured_at"], completed) >= (old["captured_at"], old_completed):
            latest[resource_id] = row
    records = list(latest.values())
    records.sort(key=lambda row: (row.get("system_id", ""), row["resource_id"]))
    violations = []
    compliant = []
    for row in records:
        state = record_state(row)
        operation, target_state, verification, finding = policy_operation(row)
        if operation == "RETAIN":
            compliant.append((row, verification, target_state))
        elif operation == "REDACT_RECORD" and state == "REDACTED":
            compliant.append((row, verification, target_state))
        elif operation == "VERIFY_RECORD_REDACTED" and not finding:
            compliant.append((row, verification, target_state))
        elif operation == "DISABLE_DATA_FLOW" and state == "DISABLED":
            compliant.append((row, verification, target_state))
        elif operation == "BLOCK_RESTORE" and state == "BLOCKED":
            compliant.append((row, verification, target_state))
        elif state == "ABSENT" and operation in {"DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD"}:
            compliant.append((row, "VERIFY_RECORD_ABSENT", "ABSENT"))
        elif state == "ANONYMIZED" and operation == "ANONYMIZE_RECORD":
            compliant.append((row, verification, "ANONYMIZED"))
        else:
            violations.append((row, state, operation, target_state, verification, finding))
    absent_account_checks = linked_absent_account(request, evidence_records)
    for check in absent_account_checks:
        linked_resource = check["resource_id"]
        if not any(row["resource_id"] == linked_resource for row in records):
            compliant.append((
                {"system_id": check["system_id"], "resource_id": linked_resource, "evidence_id": check["evidence_id"]},
                check["operation"],
                check["state"],
            ))
    if not records:
        if compliant:
            steps = []
            for row, verification, target_state in compliant:
                steps.append({
                    "phase": "VERIFICATION", "system_id": row["system_id"], "resource_id": row["resource_id"],
                    "operation": verification, "state": target_state, "evidence_id": row["evidence_id"],
                })
            for index, step in enumerate(steps, start=1):
                step["step_no"] = index
            return "COMPLETE", steps
        return "INCOMPLETE", []
    if violations:
        steps = []
        for row, state, operation, target_state, verification, finding in violations:
            if finding:
                steps.append({
                    "phase": "FINDING", "system_id": row["system_id"], "resource_id": row["resource_id"],
                    "operation": finding, "state": state, "evidence_id": row["evidence_id"],
                })
        priority = {"DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1, "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4}
        for row, _, operation, target_state, _, _ in sorted(violations, key=lambda item: (priority.get(item[2], 5), item[0]["system_id"], item[0]["resource_id"])):
            if operation != "UNKNOWN":
                steps.append({
                    "phase": "REMEDIATION", "system_id": row["system_id"], "resource_id": row["resource_id"],
                    "operation": operation, "state": target_state, "evidence_id": "",
                })
        verify_rows = [(row, verification, target_state) for row, _, _, target_state, verification, _ in violations]
        verify_rows.extend(compliant)
        for row, verification, target_state in sorted(verify_rows, key=lambda item: (item[0]["system_id"], item[0]["resource_id"])):
            steps.append({
                "phase": "VERIFICATION", "system_id": row["system_id"], "resource_id": row["resource_id"],
                "operation": verification, "state": target_state, "evidence_id": "",
            })
        for index, step in enumerate(steps, start=1):
            step["step_no"] = index
        return "INCOMPLETE", steps
    steps = []
    for row, verification, target_state in compliant:
        steps.append({
            "phase": "VERIFICATION", "system_id": row["system_id"], "resource_id": row["resource_id"],
            "operation": verification, "state": target_state, "evidence_id": row["evidence_id"],
        })
    for index, step in enumerate(steps, start=1):
        step["step_no"] = index
    return ("COMPLETE", steps) if steps else ("INCOMPLETE", [])


def determine_status(request):
    text = normalize_text(request.get("request_text", ""))
    intent = classify_request(text)
    if intent == "NOT_APPLICABLE":
        return "NOT_APPLICABLE"
    return "INCOMPLETE"


def main():
    requests = read_csv("deletion_requests.csv")
    identities = read_csv("user_identities.csv")
    audit_log = read_csv("user_audit_log.csv")
    identity_index = build_identity_index(identities, audit_log)
    evidence_records = load_evidence_records()

    output_rows = []
    for request in sorted(requests, key=lambda row: row["case_id"]):
        status, steps = audit_case(request, identities, audit_log, evidence_records)

        output_rows.append({
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
        })

    with OUTPUT.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(output_rows)

    counts = defaultdict(int)
    for row in output_rows:
        counts[row["deletion_status"]] += 1

    print(f"Created {OUTPUT} with {len(output_rows)} rows.")
    print(dict(sorted(counts.items())))
    print(f"Resolved aliases: {sum(len(v) for v in identity_index.values())}")


if __name__ == "__main__":
    main()
