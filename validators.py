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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_encryption_at_rest_terraform(repo: Path) -> dict | None:
    """HITRUST 06.d — fuente primaria: infra Terraform (storage_encrypted, KMS)."""
    for tf in repo.rglob("*.tf"):
        text = tf.read_text(errors="ignore")
        if re.search(r"storage_encrypted\s*=\s*true", text):
            kms = bool(re.search(r"kms_key_id", text))
            return {
                "type": "config_check",
                "source": str(tf.relative_to(repo)),
                "detail": f"storage_encrypted=true{' con KMS' if kms else ''}",
                "verified_at": _now(),
            }
    return None


def validate_encryption_at_rest_python(repo: Path) -> dict | None:
    """HITRUST 06.d — fuente alternativa: cifrado a nivel aplicación en Python."""
    patterns = [
        (r"Fernet\s*\(", "Fernet (cryptography)"),
        (r"AES\.new\s*\(", "AES"),
        (r"\.encrypt\s*\(", "encrypt()"),
        (r"encryption_key|ENCRYPTION_KEY", "encryption_key"),
        (r"from cryptography", "cryptography library"),
    ]
    for py in repo.rglob("*.py"):
        text = py.read_text(errors="ignore")
        for pat, label in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {
                    "type": "code_check",
                    "source": str(py.relative_to(repo)),
                    "detail": f"cifrado a nivel aplicación detectado ({label})",
                    "verified_at": _now(),
                }
    return None


# Alias retrocompatible
validate_encryption_at_rest = validate_encryption_at_rest_terraform


def validate_mfa(repo: Path) -> dict | None:
    """HITRUST 01.q / HIPAA 164.312(d): autenticación multifactor.
    Evidencia real: config que exige MFA."""
    for py in repo.rglob("*.py"):
        text = py.read_text()
        if re.search(r"MFA_REQUIRED\s*=\s*True", text):
            methods = re.search(r"MFA_METHODS\s*=\s*\[([^\]]*)\]", text)
            return {
                "type": "config_check",
                "source": str(py.relative_to(repo)),
                "detail": f"MFA_REQUIRED=True; métodos: {methods.group(1) if methods else 'n/a'}",
                "verified_at": _now(),
            }
    return None


_AUDIT_LOGGING_RE = re.compile(
    r"(audit_log|logger\.(info|warning|error|debug)|logging\.(info|warning|error|debug)|"
    r"_audit\s*\(|\.append\s*\(\s*\{)",
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


def _scan_audit_sub_requirements(text: str) -> dict[str, dict]:
    breakdown: dict[str, dict] = {}
    for key, pattern in _AUDIT_SUB_REQ_PATTERNS.items():
        signals = sorted({m.group(0) for m in pattern.finditer(text)}, key=str.lower)
        breakdown[key] = {
            "label": _AUDIT_SUB_REQ_LABELS[key],
            "met": bool(signals),
            "signals": signals[:5],
        }
    return breakdown


def validate_audit_logging_python(repo: Path) -> dict | None:
    """HITRUST 09.aa — fuente primaria: audit logging en código Python.
    None -> sin logging (GAP). validation_status 'partial' -> logging incompleto."""
    logging_hits: list[str] = []
    audit_text_parts: list[str] = []

    for py in repo.rglob("*.py"):
        text = py.read_text(errors="ignore")
        if _AUDIT_LOGGING_RE.search(text):
            rel = str(py.relative_to(repo))
            logging_hits.append(rel)
            audit_text_parts.append(text)

    if not logging_hits:
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
        "source": ", ".join(logging_hits),
        "detail": detail,
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
    infra_patterns = [
        (r'resource\s+"aws_cloudtrail"', "AWS CloudTrail"),
        (r'resource\s+"aws_cloudwatch_log_group"', "CloudWatch Log Group"),
        (r"enable_logging\s*=\s*true", "enable_logging=true"),
    ]
    for tf in repo.rglob("*.tf"):
        text = tf.read_text(errors="ignore")
        hits = [label for pat, label in infra_patterns if re.search(pat, text, re.IGNORECASE)]
        if hits:
            return {
                "type": "infra_check",
                "source": str(tf.relative_to(repo)),
                "detail": f"audit logging infra: {', '.join(hits)}",
                "verified_at": _now(),
            }
    return None


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
            "label": "Código Python (cifrado en aplicación)",
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
            "label": "Código Python (audit_log, logging)",
        },
        "fallback_validator": validate_audit_logging_terraform,
        "fallback_source": {
            "id": "terraform",
            "label": "Terraform (CloudTrail, aws_cloudwatch_log_group)",
        },
        "clinical_proximity": "diagnostic_decision",
    },
}
