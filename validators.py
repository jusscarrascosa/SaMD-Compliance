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
    effective_code_line,
    find_all_pattern_hits,
    is_declaration_file,
    iter_repo_files,
    safe_read_text,
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
    skip_declaration_files: bool = True,
    skip_comments: bool = True,
) -> dict | None:
    """Busca el primer match en el repo y devuelve evidencia con file:line."""
    for path in iter_repo_files(repo, extensions):
        if skip_declaration_files and is_declaration_file(path):
            continue
        if path_skip and path_skip(path, repo):
            continue
        text = safe_read_text(path, repo)
        if text is None:
            continue
        hit = _find_pattern_in_text(
            text, patterns, line_skip=line_skip, skip_comments=skip_comments,
        )
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


# Líneas enormes (JSON embebido, base64) — evitan backtracking catastrófico en regex.
_MAX_SCAN_LINE_LENGTH = 2000


def _find_pattern_in_text(
    text: str,
    patterns: list[tuple[re.Pattern[str], str]],
    line_skip: Callable[[str], bool] | None = None,
    skip_comments: bool = True,
) -> dict | None:
    """Primera coincidencia con número de línea; omite comentarios y line_skip."""
    in_block = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > _MAX_SCAN_LINE_LENGTH:
            continue
        search_line = line
        if skip_comments:
            search_line, in_block = effective_code_line(line, in_block)
            if not search_line.strip() or len(search_line) > _MAX_SCAN_LINE_LENGTH:
                continue
        if line_skip and line_skip(search_line):
            continue
        for pattern, label in patterns:
            if pattern.search(search_line):
                return {
                    "line": line_no,
                    "match": line.strip()[:200],
                    "label": label,
                }
    return None


# Valor concreto en asignaciones (número, booleano, string, Duration.days(N)).
_CONCRETE_VALUE = (
    r"(?:\d+(?:\.\d+)?(?:\s*\*\s*\d+)?|\btrue\b|\bfalse\b|"
    r"""['"][^'"]+['"]|Duration\.(?:days|hours|minutes|seconds)\(\s*\d+)"""
)


def _config_key(key: str) -> re.Pattern[str]:
    """Exige key = value o key: value con un valor concreto, no solo el nombre."""
    return re.compile(rf"(?:\b(?:{key}))\s*[:=]\s*{_CONCRETE_VALUE}", re.I)


def _is_function_definition(line: str) -> bool:
    return bool(re.search(
        r"^\s*(?:export\s+)?(?:async\s+)?(?:function\s+\w+|def\s+\w+|"
        r"(?:public|private|protected)\s+\w+\s*\()",
        line,
    ))


def _is_variable_passthrough(line: str) -> bool:
    """Asignación que solo referencia otra variable — no configuración concreta."""
    return bool(re.search(
        r"^\s*[\w.]+\s*=\s*(?:each\.value\.\w+|var\.\w+|local\.\w+|module\.\w+\.\w+)\s*$",
        line,
    ))


def _is_type_schema_line(line: str) -> bool:
    """Declaraciones de tipo (p. ej. retention_period = number) — no config real."""
    return bool(re.search(
        r"=\s*(?:number|string|boolean|object|list\s*\(|optional\s*\(|map\s*\()",
        line,
        re.I,
    ))


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


_EXAMPLE_DOC_DIR_NAMES = frozenset({"examples", "docs", "doc", "documentation", "__mocks__"})


def _is_example_or_docs_file(path: Path, repo: Path) -> bool:
    """Excluye ejemplos, docs y mocks — no son implementación desplegada."""
    rel_parts = path.relative_to(repo).parts[:-1]
    return any(part in _EXAMPLE_DOC_DIR_NAMES for part in rel_parts)


# --- HITRUST 06.d: cifrado en reposo ---

_ENCRYPTION_TF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_config_key(r"storage_encrypted"), "storage_encrypted=true"),
    (_config_key(r"encryption_at_rest"), "encryption_at_rest"),
    (_config_key(r"kms_enabled"), "kms_enabled=true"),
    (_config_key(r"enabled_for_disk_encryption"), "enabled_for_disk_encryption=true"),
    (re.compile(r'resource\s+"aws_kms_key"|resource\s+"azurerm_key_vault_key"', re.I), "KMS key resource"),
    (re.compile(r'resource\s+"azurerm_disk_encryption_set"', re.I), "disk encryption set"),
    (re.compile(r"server_side_encryption\s*\{", re.I), "server_side_encryption block"),
    (re.compile(r"kms_key_id\s*=\s*\w+", re.I), "KMS key assignment"),
]

_ENCRYPTION_CODE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"from\s+cryptography|import\s+cryptography", re.I), "cryptography library"),
    (re.compile(r"Fernet\s*\(", re.I), "Fernet (cryptography)"),
    (re.compile(r"AES\.new\s*\(", re.I), "AES"),
    (_config_key(r"encryption_at_rest"), "encryption_at_rest"),
    (_config_key(r"ENCRYPTION_KEY|encryption_key"), "encryption_key"),
    (re.compile(r"createCipher(?:iv)?|createDecipher(?:iv)?", re.I), "Node crypto cipher"),
]


def _is_encryption_false_positive(line: str) -> bool:
    """Excluye hash/digest y .encrypt() de firma/URL — no cifrado en reposo."""
    if _is_hash_line(line):
        return True
    if re.search(r"\.encrypt\s*\(", line) and not re.search(
        r"encryption_at_rest|storage_encrypted|server_side|at_rest|Fernet|AES\.new|createCipher",
        line,
        re.I,
    ):
        return True
    return False


_TF_EXTENSIONS = frozenset({".tf", ".tfvars"})
_APP_CODE_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx"})
_RETENTION_CODE_EXTENSIONS = CODE_CONFIG_EXTENSIONS - _TF_EXTENSIONS


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
        line_skip=_is_encryption_false_positive,
        path_skip=_is_test_file,
    )


# Alias retrocompatible
validate_encryption_at_rest = validate_encryption_at_rest_terraform


# --- HITRUST 01.q: MFA ---

_MFA_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"MFA_REQUIRED\s*=\s*True", re.I), "MFA_REQUIRED=True"),
    (_config_key(r"mfa_required"), "mfa_required=true"),
    (_config_key(r"requireMfa|require_mfa"), "requireMfa=true"),
    (_config_key(r"MFA_ENABLED|mfa_enabled"), "MFA enabled flag"),
    (re.compile(r"""name\s*:\s*['"]mfaRequired['"].{0,80}valueBoolean\s*:\s*true""", re.I), "mfaRequired setting=true"),
    (re.compile(r"""['"]mfaRequired['"].{0,80}valueBoolean\s*:\s*true""", re.I), "mfaRequired project setting"),
    (re.compile(r"ResourceServerPolicy.*enforceMfa|enforceMfa\s*[:=]\s*true", re.I), "MFA enforcement"),
    (re.compile(r"authenticator\.verify\s*\(", re.I), "TOTP verification (authenticator.verify)"),
    (re.compile(r'resource\s+"aws_cognito_user_pool".{0,200}mfa_configuration', re.I), "Cognito MFA config"),
]


def _is_mfa_false_positive(line: str) -> bool:
    """Excluye strings UI, respuestas API y menciones sueltas de totp/webauthn."""
    if re.search(
        r"display\s*:|Invalid MFA|MFA code|Authenticator app|['\"].*totp.*['\"]|"
        r"res\.json\s*\(\s*\{[^}]*mfaRequired",
        line,
        re.I,
    ):
        return True
    if re.search(r"\.body\.mfaRequired|expect\(.*mfaRequired", line, re.I):
        return True
    return False


def validate_mfa(repo: Path) -> dict | None:
    """HITRUST 01.q / HIPAA 164.312(d): autenticación multifactor."""
    return _scan_repo(
        repo,
        _MFA_PATTERNS,
        CODE_CONFIG_EXTENSIONS,
        "config_check",
        lambda h: f"MFA detectado ({h['label']})",
        line_skip=_is_mfa_false_positive,
        path_skip=_is_test_file,
    )


# --- HITRUST 09.aa: audit logging ---

_AUDIT_LOGGING_RE = re.compile(
    r"(?:createAuditEvent\s*\(|logAuditEvent\s*\(|audit_log\s*\(|audit\.log\s*\()",
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
    (_config_key(r"enable_logging"), "enable_logging=true"),
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
        in_block = False
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > _MAX_SCAN_LINE_LENGTH:
                continue
            search_line, in_block = effective_code_line(line, in_block)
            if not search_line.strip() or len(search_line) > _MAX_SCAN_LINE_LENGTH:
                continue
            m = pattern.search(search_line)
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
        if is_declaration_file(path):
            continue
        if _is_test_file(path, repo):
            continue
        text = safe_read_text(path, repo)
        if text is None:
            continue
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


# --- HITRUST 09.l: backup ---

_BACKUP_TF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_config_key(r"backup_retention_period|backup_retention_days"), "backup_retention_period"),
    (re.compile(r'resource\s+"aws_backup', re.I), "aws_backup resource"),
    (re.compile(r'resource\s+"aws_db_instance_snapshot"|resource\s+"aws_db_snapshot"', re.I), "DB snapshot resource"),
    (_config_key(r"retained_backups"), "retained_backups"),
    (_config_key(r"point_in_time_recovery_enabled"), "point_in_time_recovery_enabled"),
    (re.compile(r"deleteAfter\s*:\s*Duration\.(?:days|hours)\(\s*\d+", re.I), "CDK backup deleteAfter"),
    (re.compile(r"new\s+bk\.BackupPlanRule\s*\(", re.I), "AWS CDK BackupPlanRule"),
    (re.compile(r"expiration\s*\{\s*days\s*=\s*\d+", re.I), "lifecycle expiration with days"),
]

_BACKUP_CODE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bpg_dump\b", re.I), "pg_dump"),
    (re.compile(r"\bmysqldump\b", re.I), "mysqldump"),
    (re.compile(r"new\s+DailyBackup\s*\(", re.I), "CDK DailyBackup"),
    (_config_key(r"backup_retention|backup_schedule"), "backup retention/schedule config"),
    (re.compile(r"BackupPlan\s*\(", re.I), "BackupPlan construct"),
]


def _is_dump_false_positive(line: str) -> bool:
    """Excluye dump() genérico de serialización — no es backup de datos."""
    if re.search(r"\bpg_dump\b|\bmysqldump\b|backup.*dump|dump.*backup", line, re.I):
        return False
    return bool(re.search(r"\bdump\s*\(|\.dump\s*\(|json\.dump|yaml\.dump|pickle\.dump", line, re.I))


def _is_backup_false_positive(line: str) -> bool:
    """Excluye referencias a variables, renombrado de tablas y menciones sueltas."""
    if _is_variable_passthrough(line):
        return True
    if re.search(r"lifecycle_rules\s*=\s*each\.value", line, re.I):
        return True
    if re.search(r"RENAME TO.*backup|_backup\d+\s*[`'\"]", line, re.I):
        return True
    if re.search(r"^\s*#.*backup|Backup your data", line, re.I):
        return True
    return False


def validate_backup_terraform(repo: Path) -> dict | None:
    """HITRUST 09.l — fuente primaria: backup/snapshot/lifecycle en Terraform."""
    return _scan_repo(
        repo,
        _BACKUP_TF_PATTERNS,
        _TF_EXTENSIONS,
        "infra_check",
        lambda h: f"configuración de backup en infra ({h['label']})",
        line_skip=_is_backup_false_positive,
    )


def validate_backup_code(repo: Path) -> dict | None:
    """HITRUST 09.l — fuente alternativa: backup programado o dump en código/config."""
    return _scan_repo(
        repo,
        _BACKUP_CODE_PATTERNS,
        CODE_CONFIG_EXTENSIONS,
        "config_check",
        lambda h: f"backup programado detectado ({h['label']})",
        line_skip=lambda line: _is_dump_false_positive(line) or _is_backup_false_positive(line),
        path_skip=_is_test_file,
    )


# --- HITRUST 01.b: session management / timeout ---

_SESSION_TIMEOUT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_config_key(r"session_timeout|SESSION_TIMEOUT"), "session_timeout"),
    (_config_key(r"SESSION_TIMEOUT_MINUTES|session_timeout_minutes"), "session timeout config"),
    (_config_key(r"idle[_\s-]?timeout|IDLE_TIMEOUT"), "idle timeout"),
    (_config_key(r"accessTokenLifetime|refreshTokenLifetime"), "token lifetime config"),
    (_config_key(r"expires_in"), "expires_in config"),
    (re.compile(r"maxAge\s*:\s*\d+(?:\s*\*\s*\d+)?", re.I), "session/cookie maxAge"),
]


def _is_session_timeout_false_positive(line: str) -> bool:
    """Excluye lectores de expiración, timeouts de DB/CORS y MFA — no timeout de sesión."""
    if _is_function_definition(line) and re.search(r"expir|Expir|Jwt|jwt|Token|token", line):
        return True
    if re.search(
        r"tryGetJwtExpiration|getJwtExpiration|parseJWTPayload|getExpiration|"
        r"EMAIL_MFA_CODE_EXPIRATION|idle_in_transaction_session_timeout|statement_timeout",
        line,
        re.I,
    ):
        return True
    if re.search(r"req\.query\.max_age|query\.max_age", line, re.I):
        return True
    if re.search(r"maxAge\s*:", line) and re.search(r"cors|CORS|exposedHeaders", line, re.I):
        return True
    if re.search(r"maxAge:\s*600\b", line):
        return True
    return False


def validate_session_timeout(repo: Path) -> dict | None:
    """HITRUST 01.b / HIPAA 164.312(a)(2)(iii): timeout de sesión o expiración de token."""
    return _scan_repo(
        repo,
        _SESSION_TIMEOUT_PATTERNS,
        CODE_CONFIG_EXTENSIONS,
        "config_check",
        lambda h: f"control de sesión detectado ({h['label']})",
        line_skip=_is_session_timeout_false_positive,
        path_skip=lambda p, r: _is_test_file(p, r) or _is_example_or_docs_file(p, r),
    )


# --- HITRUST 06.h: data retention and disposal ---

_DATA_RETENTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_config_key(r"data_retention"), "data retention policy"),
    (_config_key(r"(?<!backup_)(?<!soft_delete_)(?<!transaction_log_)retention_period"), "retention_period"),
    (_config_key(r"(?<!backup_)(?<!soft_delete_)retention_days|retention_in_days"), "retention_days"),
    (_config_key(r"record_retention|log_retention"), "record/log retention"),
    (_config_key(r"purge_after|data_purge|purge_records"), "data purge"),
    (_config_key(r"delete_after|deletion_after|remove_after|delete_expired"), "delete after"),
    (_config_key(r"expire_after|expiry_days|expiration_days"), "data expiry"),
    (_config_key(r"disposal_policy|data_disposal"), "data disposal policy"),
    (re.compile(r"noncurrent_version_expiration\s*\{", re.I), "noncurrent version expiration"),
    (re.compile(r"expiration\s*\{\s*days\s*=\s*\d+", re.I), "lifecycle expiration with days"),
]

_RETENTION_TF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"noncurrent_version_expiration\s*\{", re.I), "noncurrent version expiration"),
    (re.compile(r"expiration\s*\{\s*days\s*=\s*\d+", re.I), "lifecycle expiration with days"),
    (_config_key(r"deletion_policy"), "data deletion policy"),
]


def _is_data_retention_false_positive(line: str) -> bool:
    """Excluye URLs temporales, tokens, lectores de expiración y esquemas de tipo."""
    if _is_type_schema_line(line):
        return True
    if _is_variable_passthrough(line):
        return True
    if re.search(
        r"expiring_url|expires_at|expiresAt|tryGetJwtExpiration|getJwtExpiration|"
        r"downloadDocumentContent|accessTokenExpires|token.*expir|jwt.*expir",
        line,
        re.I,
    ):
        return True
    if re.search(r"backup_retention|transaction_log_retention|soft_delete_retention", line, re.I):
        return True
    if re.search(r"\bpurge\b", line, re.I) and not re.search(
        r"purge_after|data_purge|purge_policy|purge_records", line, re.I,
    ):
        return True
    return False


def validate_data_retention_code(repo: Path) -> dict | None:
    """HITRUST 06.h — fuente primaria: retención/disposición de datos en código/config."""
    return _scan_repo(
        repo,
        _DATA_RETENTION_PATTERNS,
        _RETENTION_CODE_EXTENSIONS,
        "config_check",
        lambda h: f"retención/disposición de datos detectada ({h['label']})",
        line_skip=_is_data_retention_false_positive,
        path_skip=lambda p, r: _is_test_file(p, r) or _is_example_or_docs_file(p, r),
    )


def validate_data_retention_terraform(repo: Path) -> dict | None:
    """HITRUST 06.h — fuente alternativa: retención/expiración en infra Terraform."""
    return _scan_repo(
        repo,
        _RETENTION_TF_PATTERNS,
        _TF_EXTENSIONS,
        "infra_check",
        lambda h: f"retención de datos en infra ({h['label']})",
        line_skip=_is_data_retention_false_positive,
    )


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
    "HITRUST-09.l": {
        "name": "09.l Backup",
        "framework_refs": [
            "HIPAA-164.308(a)(7)(ii)(A)",
            "ISO-27001-A.12.3",
            "IEC-62304-5.1",
        ],
        "validator": validate_backup_terraform,
        "primary_validator": validate_backup_terraform,
        "primary_source": {
            "id": "terraform",
            "label": "Infra Terraform (backup_retention_period, snapshot, aws_backup, S3 lifecycle)",
        },
        "fallback_validator": validate_backup_code,
        "fallback_source": {
            "id": "code_config",
            "label": "Código/config (pg_dump, backup programado)",
        },
        "clinical_proximity": "data_storage",
    },
    "HITRUST-01.b": {
        "name": "01.b Session Management / Timeout",
        "framework_refs": [
            "HIPAA-164.312(a)(2)(iii)",
            "ISO/IEC-27799-11.5.5",
        ],
        "validator": validate_session_timeout,
        "clinical_proximity": "access_control",
    },
    "HITRUST-06.h": {
        "name": "06.h Data Retention and Disposal",
        "framework_refs": [
            "HIPAA-164.310(d)(2)(i)",
            "ISO-27001-A.8.10",
            "IEC-62304-5.1",
        ],
        "validator": validate_data_retention_code,
        "primary_validator": validate_data_retention_code,
        "primary_source": {
            "id": "code_config",
            "label": "Código/config (retention_period, purge, delete_after, disposal)",
        },
        "fallback_validator": validate_data_retention_terraform,
        "fallback_source": {
            "id": "terraform",
            "label": "Terraform (retention_in_days, lifecycle expiration)",
        },
        "clinical_proximity": "data_storage",
    },
}
