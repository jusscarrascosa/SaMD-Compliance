"""
Validadores determinísticos. NUNCA usan un LLM.
Cada función recibe el inventario del repo y devuelve evidencia verificable
o None. Esto es la traducción directa del principio de XBOW:
"Creative AI discovers. Deterministic logic decides what's real."
"""
from __future__ import annotations
import re
from pathlib import Path
from datetime import datetime, timezone

from analysis import (
    CODE_CONFIG_EXTENSIONS,
    find_all_pattern_hits,
    find_pattern_in_text,
    iter_repo_files,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evidence(
    repo: Path,
    file_path: Path,
    line: int,
    match: str,
    detail: str,
    evidence_type: str,
    **extra,
) -> dict:
    rel = str(file_path.relative_to(repo))
    return {
        "type": evidence_type,
        "source": rel,
        "file": rel,
        "line": line,
        "match": match,
        "detail": detail,
        "verified_at": _now(),
        **extra,
    }


def _scan_repo(
    repo: Path,
    patterns: list[tuple[re.Pattern[str], str]],
    extensions: frozenset[str],
    evidence_type: str,
    detail_fn,
) -> dict | None:
    """Busca el primer match en el repo y devuelve evidencia con file:line."""
    for path in iter_repo_files(repo, extensions):
        text = path.read_text(errors="ignore")
        hit = find_pattern_in_text(text, patterns)
        if hit:
            return _evidence(
                repo,
                path,
                hit["line"],
                hit["match"],
                detail_fn(hit),
                evidence_type,
            )
    return None


# --- HITRUST 06.d: cifrado en reposo ---

_ENCRYPTION_TF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"storage_encrypted\s*=\s*true", re.I), "storage_encrypted=true"),
    (re.compile(r"encryption_at_rest", re.I), "encryption_at_rest"),
    (re.compile(r"""["']encrypted["']\s*:\s*true""", re.I), '"encrypted": true'),
    (re.compile(r"kms_key_id|aws_kms_key|kms_master_key", re.I), "KMS key"),
    (re.compile(r"server_side_encryption", re.I), "server_side_encryption"),
    (re.compile(r"encrypted\s*=\s*true", re.I), "encrypted=true"),
]

_ENCRYPTION_CODE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"from\s+cryptography|import\s+cryptography", re.I), "cryptography library"),
    (re.compile(r"Fernet\s*\(", re.I), "Fernet (cryptography)"),
    (re.compile(r"AES\.new\s*\(", re.I), "AES"),
    (re.compile(r"from\s+bcrypt|import\s+bcrypt|bcrypt\.", re.I), "bcrypt"),
    (re.compile(r"encryption_at_rest", re.I), "encryption_at_rest"),
    (re.compile(r"""["']encrypted["']\s*:\s*true""", re.I), '"encrypted": true'),
    (re.compile(r"ENCRYPTION_KEY|encryption_key", re.I), "encryption_key"),
    (re.compile(r"\.encrypt\s*\(", re.I), "encrypt()"),
    (re.compile(r"createCipher|createDecipher|crypto\.subtle", re.I), "crypto API"),
]

_TF_EXTENSIONS = frozenset({".tf", ".tfvars"})
_APP_CODE_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})


def validate_encryption_at_rest_terraform(repo: Path) -> dict | None:
    """HITRUST 06.d — fuente primaria: infra Terraform (storage_encrypted, KMS)."""
    return _scan_repo(
        repo,
        _ENCRYPTION_TF_PATTERNS,
        _TF_EXTENSIONS,
        "config_check",
        lambda h: f"cifrado en reposo detectado en infra ({h['label']})",
    )


def validate_encryption_at_rest_python(repo: Path) -> dict | None:
    """HITRUST 06.d — fuente alternativa: cifrado a nivel aplicación."""
    return _scan_repo(
        repo,
        _ENCRYPTION_CODE_PATTERNS,
        _APP_CODE_EXTENSIONS,
        "code_check",
        lambda h: f"cifrado a nivel aplicación detectado ({h['label']})",
    )


# Alias retrocompatible
validate_encryption_at_rest = validate_encryption_at_rest_terraform


# --- HITRUST 01.q: MFA ---

_MFA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"MFA_REQUIRED\s*=\s*True", re.I), "MFA_REQUIRED=True"),
    (re.compile(r"mfa_required\s*[:=]\s*true", re.I), "mfa_required=true"),
    (re.compile(r"requireMfa|require_mfa|MFA_ENABLED\s*=\s*true", re.I), "MFA enabled flag"),
    (re.compile(r"multifactor|multi_factor|multi-factor", re.I), "multifactor config"),
    (re.compile(r"\b(totp|webauthn|2fa|two_factor)\b", re.I), "2FA method"),
    (re.compile(r"ResourceServerPolicy.*mfa|enforceMfa", re.I), "MFA enforcement"),
]


def validate_mfa(repo: Path) -> dict | None:
    """HITRUST 01.q / HIPAA 164.312(d): autenticación multifactor."""
    return _scan_repo(
        repo,
        _MFA_PATTERNS,
        CODE_CONFIG_EXTENSIONS,
        "config_check",
        lambda h: f"MFA detectado ({h['label']})",
    )


# --- HITRUST 09.aa: audit logging ---

_AUDIT_LOGGING_RE = re.compile(
    r"(audit_log|audit\.log|logger\.(info|warning|error|debug)|"
    r"logging\.(info|warning|error|debug)|_audit\s*\(|\.append\s*\(\s*\{)",
    re.IGNORECASE,
)

_AUDIT_SUB_REQ_PATTERNS: dict[str, re.Pattern[str]] = {
    "user_identifier": re.compile(
        r"\b(user_id|userid|userId|actor|principal|username|client_id|client)\b|"
        r"['\"]user['\"]",
        re.IGNORECASE,
    ),
    "timestamp": re.compile(
        r"\b(timestamp|time_stamp|datetime|logged_at|created_at|"
        r"event_time|fecha|date_time|isoformat)\b|['\"]ts['\"]",
        re.IGNORECASE,
    ),
    "action": re.compile(
        r"\b(action|event_type|operation|activity|event_name|"
        r"audit_event|function_name)\b|['\"]action['\"]",
        re.IGNORECASE,
    ),
    "retention_policy": re.compile(
        r"\b(retention|retain|retention_days|retention_policy|"
        r"log_retention|ttl|expire|expiry|purge|archive_after)\b",
        re.IGNORECASE,
    ),
}

_AUDIT_SUB_REQ_LABELS = {
    "user_identifier": "identificador de usuario",
    "timestamp": "timestamp / fecha-hora",
    "action": "función o acción realizada",
    "retention_policy": "política de retención",
}

_ESSENTIAL_AUDIT_FIELDS = ("user_identifier", "timestamp", "action")

_AUDIT_CODE_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})

_AUDIT_TF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'resource\s+"aws_cloudtrail"', re.I), "AWS CloudTrail"),
    (re.compile(r'resource\s+"aws_cloudwatch_log_group"', re.I), "CloudWatch Log Group"),
    (re.compile(r"enable_logging\s*=\s*true", re.I), "enable_logging=true"),
    (re.compile(r"audit_log|cloudtrail", re.I), "audit infra"),
]


def _scan_audit_sub_requirements(text: str) -> dict[str, dict]:
    breakdown: dict[str, dict] = {}
    for key, pattern in _AUDIT_SUB_REQ_PATTERNS.items():
        signals: list[dict] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            m = pattern.search(line)
            if m:
                signals.append({"line": line_no, "match": m.group(0)})
        breakdown[key] = {
            "label": _AUDIT_SUB_REQ_LABELS[key],
            "met": bool(signals),
            "signals": signals[:5],
        }
    return breakdown


def validate_audit_logging_python(repo: Path) -> dict | None:
    """HITRUST 09.aa — fuente primaria: audit logging en código.
    None -> sin logging (GAP). validation_status 'partial' -> logging incompleto."""
    logging_locations: list[dict] = []
    audit_text_parts: list[str] = []

    for path in iter_repo_files(repo, _AUDIT_CODE_EXTENSIONS):
        text = path.read_text(errors="ignore")
        file_hits = find_all_pattern_hits(
            text,
            [( _AUDIT_LOGGING_RE, "audit logging")],
        )
        if not file_hits:
            continue
        rel = str(path.relative_to(repo))
        for hit in file_hits:
            logging_locations.append({
                "file": rel,
                "line": hit["line"],
                "match": hit["match"],
            })
        audit_text_parts.append(text)

    if not logging_locations:
        return None

    combined = "\n".join(audit_text_parts)
    sub_requirements = _scan_audit_sub_requirements(combined)
    missing_essential = [
        _AUDIT_SUB_REQ_LABELS[key]
        for key in _ESSENTIAL_AUDIT_FIELDS
        if not sub_requirements[key]["met"]
    ]
    essential_met = not missing_essential
    validation_status = "satisfied" if essential_met else "partial"

    met_labels = [s["label"] for s in sub_requirements.values() if s["met"]]
    missing_labels = [s["label"] for s in sub_requirements.values() if not s["met"]]

    primary = logging_locations[0]
    if validation_status == "satisfied":
        detail = (
            "logging con campos esenciales (usuario, timestamp, acción); "
            f"sub-requisitos cumplidos: {', '.join(met_labels)}"
        )
    else:
        detail = (
            "logging detectado pero incompleto; "
            f"faltan esenciales: {', '.join(missing_essential)}"
        )

    return {
        "type": "code_check",
        "source": primary["file"],
        "file": primary["file"],
        "line": primary["line"],
        "match": primary["match"],
        "detail": detail,
        "locations": logging_locations,
        "validation_status": validation_status,
        "sub_requirements": sub_requirements,
        "essential_fields_met": essential_met,
        "missing_essential": missing_essential,
        "sub_requirements_summary": {
            "met": met_labels,
            "missing": missing_labels,
        },
        "verified_at": _now(),
    }


def validate_audit_logging_terraform(repo: Path) -> dict | None:
    """HITRUST 09.aa — fuente alternativa: logging de infra en Terraform."""
    return _scan_repo(
        repo,
        _AUDIT_TF_PATTERNS,
        _TF_EXTENSIONS,
        "infra_check",
        lambda h: f"audit logging infra: {h['label']}",
    )


# Alias retrocompatible
validate_audit_logging = validate_audit_logging_python


# Registro: control_id -> (framework refs, validador, proximidad clínica)
CONTROL_REGISTRY = {
    "HITRUST-06.d": {
        "name": "06.d Data Protection and Privacy of Covered Information",
        "framework_refs": [
            "HIPAA-164.312(a)(2)(iv)",
            "HIPAA-164.310(d)",
            "HIPAA-164.308(a)(1)(ii)(D)",
            "IEC-62304-5.1",
            "ISO-27001-A.8.24",
        ],
        "validator": validate_encryption_at_rest_terraform,
        "primary_validator": validate_encryption_at_rest_terraform,
        "primary_source": {
            "id": "terraform",
            "label": "Infra Terraform (storage_encrypted, KMS)",
        },
        "fallback_validator": validate_encryption_at_rest_python,
        "fallback_source": {
            "id": "python_code",
            "label": "Código de aplicación (cryptography, bcrypt, encrypt)",
        },
        "clinical_proximity": "data_storage",
    },
    "HITRUST-01.q": {
        "name": "01.q User Identification and Authentication",
        "framework_refs": [
            "HIPAA-164.312(a)(2)(i)",
            "ISO/IEC-27799-9.2.1",
        ],
        "validator": validate_mfa,
        "clinical_proximity": "access_control",
    },
    "HITRUST-09.aa": {
        "name": "09.aa Audit Logging",
        "framework_refs": [
            "HIPAA-164.312(b)",
            "HIPAA-164.316(b)(2)",
            "IEC-62304-5.1",
            "ISO-14971-clause7",
        ],
        "validator": validate_audit_logging_python,
        "primary_validator": validate_audit_logging_python,
        "primary_source": {
            "id": "python_code",
            "label": "Código (audit_log, logging)",
        },
        "fallback_validator": validate_audit_logging_terraform,
        "fallback_source": {
            "id": "terraform",
            "label": "Terraform (CloudTrail, aws_cloudwatch_log_group)",
        },
        "clinical_proximity": "diagnostic_decision",
    },
}
