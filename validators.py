"""
Validadores determinísticos. NUNCA usan un LLM.
Cada función recibe el inventario del repo y devuelve evidencia verificable
o None. Esto es la traducción directa del principio de XBOW:
"Creative AI discovers. Deterministic logic decides what's real."
"""
from __future__ import annotations
import re
from collections.abc import Callable
from pathlib import Path
from datetime import datetime, timezone

from analysis import (
    CODE_CONFIG_EXTENSIONS,
    find_all_pattern_hits,
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
    line_skip: Callable[[str], bool] | None = None,
    path_skip: Callable[[Path, Path], bool] | None = None,
) -> dict | None:
    """Busca el primer match en el repo y devuelve evidencia con file:line."""
    for path in iter_repo_files(repo, extensions):
        if path_skip and path_skip(path, repo):
            continue
        text = path.read_text(errors="ignore")
        hit = _find_pattern_in_text(text, patterns, line_skip=line_skip)
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


def _find_pattern_in_text(
    text: str,
    patterns: list[tuple[re.Pattern[str], str]],
    line_skip: Callable[[str], bool] | None = None,
) -> dict | None:
    """Primera coincidencia con número de línea; omite líneas que fallen line_skip."""
    for line_no, line in enumerate(text.splitlines(), start=1):
        if line_skip and line_skip(line):
            continue
        for pattern, label in patterns:
            if pattern.search(line):
                return {
                    "line": line_no,
                    "match": line.strip(),
                    "label": label,
                }
    return None


# Líneas de hash/digest — no son cifrado en reposo (HITRUST 06.d).
_HASH_LINE_RE = re.compile(
    r"\b(digest|\.hash\s*\(|sha[-_]?\d+|md5|bcrypt|scrypt|pbkdf2|hmac|hashlib)\b",
    re.IGNORECASE,
)


def _is_hash_line(line: str) -> bool:
    return bool(_HASH_LINE_RE.search(line))


_TEST_FILE_RE = re.compile(r"\.(test|spec)\.(ts|tsx|js|jsx)$", re.IGNORECASE)
_TEST_DIR_NAMES = frozenset({"__tests__", "test", "tests"})


def _is_test_file(path: Path, repo: Path) -> bool:
    """Excluye archivos y carpetas de test del escaneo de audit logging."""
    if _TEST_FILE_RE.search(path.name):
        return True
    rel_parts = path.relative_to(repo).parts[:-1]
    return any(part in _TEST_DIR_NAMES for part in rel_parts)


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
    (re.compile(r"encryption_at_rest", re.I), "encryption_at_rest"),
    (re.compile(r"""["']encrypted["']\s*:\s*true""", re.I), '"encrypted": true'),
    (re.compile(r"ENCRYPTION_KEY|encryption_key", re.I), "encryption_key"),
    (re.compile(r"\.encrypt\s*\(", re.I), "encrypt()"),
    (re.compile(r"\.decrypt\s*\(", re.I), "decrypt()"),
    (re.compile(r"createCipher(?:iv)?|createDecipher(?:iv)?", re.I), "Node crypto cipher"),
    (re.compile(r"crypto\.subtle\.(?:encrypt|decrypt)", re.I), "Web Crypto encrypt/decrypt"),
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
        line_skip=_is_hash_line,
        path_skip=_is_test_file,
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
    r"(?:audit_log|audit\.log|logAuditEvent|createAuditEvent|"
    r"logger\.(?:info|warning|error|debug)|"
    r"logging\.(?:info|warning|error|debug)|_audit\s*\(|\.append\s*\(\s*\{)",
    re.IGNORECASE,
)

# Valores concretos en campos de log — excluye declaraciones de tipo (p. ej. `who: Reference`).
_TYPE_ONLY_VALUE = r"(?:string|number|boolean|undefined|null|Reference|Date|Record|Partial)\b"
# Tras `:` exige valor real; el lookahead evita backtracking que aceptaba solo el nombre del campo.
_FIELD_VALUE = r"(?=\S)(?!" + _TYPE_ONLY_VALUE + r")"


def _is_audit_definition_file(rel: str, text: str) -> bool:
    """Archivo que define audit events, no solo los importa."""
    if re.search(r"audit", rel, re.IGNORECASE):
        return True
    return bool(re.search(
        r"(?:export\s+)?function\s+(?:createAuditEvent|logAuditEvent)\b",
        text,
    ))


_AUDIT_SUB_REQ_PATTERNS: dict[str, re.Pattern[str]] = {
    "user_identifier": re.compile(
        r"(?:^|[,{[\s])(?:user_id|userid|userId|username|actor_id|actorId|"
        r"principal_id|principalId)\s*:\s*" + _FIELD_VALUE +
        r"|['\"](?:user_id|userId|userid|username|actor|principal|who)['\"]\s*:"
        r"|\bwho\s*:\s*" + _FIELD_VALUE,
        re.IGNORECASE,
    ),
    "timestamp": re.compile(
        r"(?:^|[,{[\s])(?:timestamp|logged_at|event_time|recorded|date_time)\s*:\s*"
        r"(?:new Date|Date\.|['\"`]|`\$\{|\d)"
        r"|['\"](?:timestamp|logged_at|event_time|recorded|ts)['\"]\s*:"
        r"|\.isoformat\s*\(",
        re.IGNORECASE,
    ),
    "action": re.compile(
        r"(?:^|[,{[\s])action\s*:\s*" + _FIELD_VALUE +
        r"|['\"](?:action|event_type|activity)['\"]\s*:",
        re.IGNORECASE,
    ),
    "retention_policy": re.compile(
        r"(?:^|[,{[\s])(?:retention_days|retention_policy|log_retention|retention_period)\s*[:=]"
        r"|\b(?:retention|retain)\s+(?:days|period|policy)\b"
        r"|(?:purge_after|archive_after|expire_after)\s*[:=]\s*\d",
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


def _collect_audit_sub_requirement_text(
    text: str,
    rel: str,
    file_hits: list[dict],
) -> str:
    """Texto acotado para sub-requisitos: contexto de hits + módulos audit reales."""
    lines = text.splitlines()
    chunks: list[str] = []
    seen: set[int] = set()

    for hit in file_hits:
        idx = hit["line"] - 1
        for i in range(max(0, idx - 2), min(len(lines), idx + 3)):
            if i not in seen:
                seen.add(i)
                chunks.append(lines[i])

    if _is_audit_definition_file(rel, text):
        chunks.append(text)

    return "\n".join(chunks)


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
        if _is_test_file(path, repo):
            continue
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
        audit_text_parts.append(_collect_audit_sub_requirement_text(text, rel, file_hits))

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
            "label": "Código de aplicación (cryptography, AES, encrypt/decrypt)",
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
