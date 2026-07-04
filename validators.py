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


def validate_encryption_at_rest(repo: Path) -> dict | None:
    """HITRUST 06.d / HIPAA 164.312(a)(2)(iv): cifrado de PHI en reposo.
    Evidencia real: un recurso de storage con storage_encrypted = true."""
    for tf in repo.rglob("*.tf"):
        text = tf.read_text()
        if re.search(r"storage_encrypted\s*=\s*true", text):
            kms = bool(re.search(r"kms_key_id", text))
            return {
                "type": "config_check",
                "source": str(tf.relative_to(repo)),
                "detail": f"storage_encrypted=true{' con KMS' if kms else ''}",
                "verified_at": _now(),
            }
    return None


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


def validate_audit_logging(repo: Path) -> dict | None:
    """HITRUST 09.aa / HIPAA 164.312(b): registro de auditoría de acceso a PHI.
    Evidencia real: llamadas de logging en las capas que tocan datos clínicos.
    Si no hay, devuelve None -> el control queda como GAP."""
    logging_hits = []
    for py in repo.rglob("*.py"):
        text = py.read_text()
        if re.search(r"(audit_log|logger\.(info|warning|error)|logging\.)", text):
            logging_hits.append(str(py.relative_to(repo)))
    if logging_hits:
        return {
            "type": "code_check",
            "source": ", ".join(logging_hits),
            "detail": "se encontraron llamadas de logging",
            "verified_at": _now(),
        }
    return None


# Registro: control_id -> (framework refs, validador, proximidad clínica)
CONTROL_REGISTRY = {
    "HITRUST-06.d": {
        "name": "Encryption of PHI at rest",
        "framework_refs": ["HIPAA-164.312(a)(2)(iv)", "IEC-62304-5.1", "ISO-27001-A.10.1"],
        "validator": validate_encryption_at_rest,
        "clinical_proximity": "data_storage",
    },
    "HITRUST-01.q": {
        "name": "Multi-factor authentication",
        "framework_refs": ["HIPAA-164.312(d)", "ISO-27001-A.9.4"],
        "validator": validate_mfa,
        "clinical_proximity": "access_control",
    },
    "HITRUST-09.aa": {
        "name": "Audit logging of PHI access",
        "framework_refs": ["HIPAA-164.312(b)", "IEC-62304-5.1", "ISO-14971-clause7"],
        "validator": validate_audit_logging,
        "clinical_proximity": "diagnostic_decision",
    },
}
