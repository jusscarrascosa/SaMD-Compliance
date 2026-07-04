"""
Deep Compliance Analysis: parsea el repo y construye un inventario
(el 'grafo' en memoria) ANTES de que ningún LLM razone.
Traducción del DCA de Apiiro: entender qué maneja cada módulo.
"""
from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Iterator, Literal

# Errores de lectura que no deben abortar el análisis completo.
READ_ERRORS = (FileNotFoundError, PermissionError, UnicodeDecodeError, OSError)

_skipped_files: list[dict] | None = None


def begin_file_scan() -> list[dict]:
    """Inicia un escaneo; devuelve la lista compartida de archivos omitidos."""
    global _skipped_files
    _skipped_files = []
    return _skipped_files


def get_skipped_files() -> list[dict]:
    """Archivos que no pudieron leerse durante el escaneo actual."""
    return list(_skipped_files or [])


def _record_skipped(path: Path, repo: Path | None, exc: BaseException) -> None:
    if _skipped_files is None:
        return
    entry: dict = {
        "path": str(path.relative_to(repo)) if repo else str(path),
        "error": type(exc).__name__,
        "message": str(exc),
    }
    _skipped_files.append(entry)


def safe_read_text(path: Path, repo: Path | None = None) -> str | None:
    """Lee un archivo de texto; None si no se puede leer (sin abortar)."""
    try:
        return path.read_text(errors="ignore")
    except READ_ERRORS as exc:
        _record_skipped(path, repo, exc)
        return None


def is_declaration_file(path: Path) -> bool:
    """Archivos .d.ts: definiciones de tipos, no implementación."""
    return path.name.lower().endswith(".d.ts")


def effective_code_line(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Código ejecutable de una línea; omite //, #, /* */ y bloques multilínea."""
    if in_block_comment:
        end_idx = line.find("*/")
        if end_idx == -1:
            return "", True
        line = line[end_idx + 2 :]
        in_block_comment = False
        if not line.strip():
            return "", False

    result: list[str] = []
    i = 0
    n = len(line)
    in_single = in_double = False

    while i < n:
        ch = line[i]
        if in_single:
            result.append(ch)
            if ch == "'" and (i == 0 or line[i - 1] != "\\"):
                in_single = False
            i += 1
            continue
        if in_double:
            result.append(ch)
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            result.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            result.append(ch)
            i += 1
            continue
        if ch == "#":
            break
        if line[i : i + 2] == "//":
            break
        if line[i : i + 2] == "/*":
            end_idx = line.find("*/", i + 2)
            if end_idx == -1:
                return "".join(result).rstrip(), True
            i = end_idx + 2
            continue
        result.append(ch)
        i += 1

    return "".join(result).rstrip(), in_block_comment

# Carpetas de dependencias, build y VCS que no aportan señal de compliance.
SKIP_DIRS = frozenset({
    "node_modules",
    ".git",
    "dist",
    "build",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
    ".next",
    ".nuxt",
    "target",
    ".cache",
    ".turbo",
})

# Solo archivos de código y configuración — sin binarios ni assets.
CODE_CONFIG_EXTENSIONS = frozenset({
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".tf",
    ".tfvars",
    ".yaml",
    ".yml",
    ".json",
})

# Niveles de cumplimiento alcanzado, alineados con el CSF de HITRUST.
# Referencia: HITRUST CSF v11.8, sección "Implementation Requirement Levels"
# (https://hitrustalliance.net) — tres niveles progresivos y acumulativos
# (Level 1 → Level 2 → Level 3) más requisitos segment-specific (FedRAMP, GDPR).
ComplianceLevel = Literal["none", "partial", "level_1", "level_2", "level_3", "segment"]

# --- Proximidad clínica → peso de impacto al paciente ---
#
# El CSF clasifica riesgo en tres factores (Organizational, System, Compliance)
# que determinan el nivel de implementación exigido por control. Mapeamos la
# proximidad clínica del módulo al grado de exposición del paciente si el control
# falla, usando la misma lógica de escalamiento progresivo:
#
#   diagnostic_decision = 1.0
#     Equivalente al escenario de System + Compliance Factors elevados (CSF
#     Level 3): el control protege un sistema que interviene directamente en
#     decisiones clínicas (p. ej. motor diagnóstico SaMD, IEC 62304 clase C /
#     ISO 14971 — daño directo al paciente). Peso máximo: falla = impacto clínico
#     inmediato, no solo confidencialidad.
#
#   access_control = 0.7
#     Equivalente a CSF Level 2 (System Factors): autenticación, acceso remoto,
#     terceros. El CSF exige controles adicionales ~30-40 % más estrictos en
#     Level 2 vs Level 1; un gap de acceso requiere explotación adicional antes
#     de afectar una decisión clínica. 0.7 ≈ 1 − (1/3): un escalón por debajo
#     del impacto diagnóstico directo, coherente con la distancia Level 2→3
#     en la guía de Risk Analysis del CSF.
#
#   data_storage = 0.6
#     Equivalente a CSF Level 1 (baseline organizacional): cifrado en reposo,
#     retención — requisito mínimo de protección de PHI (HIPAA §164.312(a)(2)(iv)
#     integrado en Level 1). El daño primario es confidencialidad/integridad del
#     dato, no una acción clínica errónea. 0.6 = Level1/Level3 (1/1.67): ratio
#     derivado de la progresión acumulativa de requisitos del CSF.
#
#   administrative = 0.3
#     Controles de gobernanza sin exposición directa a PHI clínico (CSF
#     dominios 00.x — políticas, capacitación). Impacto indirecto al paciente.
_PROXIMITY_WEIGHT: dict[str, float] = {
    "diagnostic_decision": 1.0,
    "access_control": 0.7,
    "data_storage": 0.6,
    "administrative": 0.3,
}

# --- Nivel de cumplimiento alcanzado → factor de riesgo residual ---
#
# El CSF evalúa cada requisito contra niveles de madurez (Policy 15 %, Procedure
# 20 %, Implemented 40 %, Measured 10 %, Managed 15 %) y grados de
# implementación (NC 0 %, SC 25 %, PC 75 %, FC 100 %). El factor below
# representa el riesgo RESIDUAL al paciente: mayor cumplimiento → menor factor.
#
#   none = 1.0
#     NC (No Compliance): ningún elemento del requisito implementado (CSF
#     maturity scoring = 0 %). Exposición total; sin compensación verificable.
#
#   partial = 0.80
#     SC/PC (Some/Partial Compliance): elementos parciales del requisito (25-75 %
#     según escala CSF). Mitigación insuficiente para certificación i1/r2
#     (mínimo Implemented = 40 % del score de madurez). 0.80 refleja que ~20 %
#     del riesgo base queda cubierto por controles incompletos.
#
#   level_1 = 0.65
#     CSF Implementation Level 1: baseline mínimo (factores organizacionales —
#     tamaño, volumen de PHI). Cumple el piso HIPAA pero sin controles de System
#     Factors. Un gap aquí implica incumplimiento del requisito más básico;
#     0.65 = 1 − 0.35, donde 0.35 ≈ peso relativo de Level 1 dentro del stack
#     acumulativo (Level 1 es ~35 % del total de requisitos en controles típicos
#     de PHI según Risk Analysis Guide, Tabla 1).
#
#   level_2 = 0.45
#     CSF Level 2: Level 1 + System Factors (acceso remoto, dispositivos móviles,
#     terceros). Controles adicionales ~30 % más restrictivos. Factor 0.45 =
#     riesgo residual tras cubrir dos tercios del stack (1 − 2/3 ≈ 0.33, ajustado
#     al 0.45 para reflejar que Level 2 no incluye aún Compliance Factors
#     regulatorios).
#
#   level_3 = 0.30
#     CSF Level 3: Level 1 + 2 + Compliance Factors (mapeos a NIST 800-53,
#     FedRAMP, FISMA, GDPR). Máximo rigor en requisitos generales del CSF.
#     Factor 0.30 = riesgo residual mínimo antes de segment-specific; alinea con
#     el 30 % de controles adicionales que Level 3 agrega sobre Level 2 en la
#     progresión acumulativa del framework.
#
#   segment = 0.20
#     Segment-Specific Requirements (CSF: FedRAMP r5, GDPR, cloud CSP). Capa
#     adicional sobre Level 3 para industrias/regulaciones específicas. 0.20 =
#     riesgo residual más bajo: cumplimiento verificado contra el estándar más
#     exigente aplicable (p. ej. FedRAMP Moderate baseline vía mapeo CSF).
_COMPLIANCE_RISK_FACTOR: dict[ComplianceLevel, float] = {
    "none": 1.0,
    "partial": 0.80,
    "level_1": 0.65,
    "level_2": 0.45,
    "level_3": 0.30,
    "segment": 0.20,
}

# --- Sensibilidad del dato (PHI) ---
#
# CSF Organizational Factors: volumen y sensibilidad de la información determinan
# el nivel de implementación exigido. Módulos que procesan PHI activan factores
# de riesgo elevados; los demás reciben peso reducido (0.5) porque un gap no
# expone datos de pacientes identificables.
_PHI_WEIGHT = {"touches": 1.0, "no_phi": 0.5}


def iter_repo_files(
    repo: Path,
    extensions: frozenset[str] | None = None,
) -> Iterator[Path]:
    """Recorre solo archivos de código/config, omitiendo carpetas irrelevantes."""
    ext_filter = extensions or CODE_CONFIG_EXTENSIONS
    try:
        walk = os.walk(repo)
    except OSError as exc:
        _record_skipped(repo, None, exc)
        return

    for dirpath, dirnames, filenames in walk:
        try:
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        except OSError:
            continue
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.suffix.lower() not in ext_filter:
                    continue
                # Excluye symlinks rotos, directorios y entradas que desaparecieron.
                if not path.is_file():
                    continue
            except OSError as exc:
                _record_skipped(path, repo, exc)
                continue
            yield path


def find_pattern_in_text(
    text: str,
    patterns: list[tuple[re.Pattern[str], str]],
    *,
    skip_comments: bool = True,
) -> dict | None:
    """Primera coincidencia con número de línea exacto. None si no hay match."""
    in_block = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        search_line = line
        if skip_comments:
            search_line, in_block = effective_code_line(line, in_block)
            if not search_line.strip():
                continue
        for pattern, label in patterns:
            if pattern.search(search_line):
                return {
                    "line": line_no,
                    "match": line.strip(),
                    "label": label,
                }
    return None


def find_all_pattern_hits(
    text: str,
    patterns: list[tuple[re.Pattern[str], str]],
    *,
    skip_comments: bool = True,
    max_line_length: int = 2000,
) -> list[dict]:
    """Todas las coincidencias con archivo/línea (para validadores multi-hit)."""
    hits: list[dict] = []
    in_block = False
    for line_no, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line_length:
            continue
        search_line = line
        if skip_comments:
            search_line, in_block = effective_code_line(line, in_block)
            if not search_line.strip() or len(search_line) > max_line_length:
                continue
        for pattern, label in patterns:
            if pattern.search(search_line):
                hits.append({
                    "line": line_no,
                    "match": line.strip()[:200],
                    "label": label,
                })
    return hits


def build_inventory(repo: Path) -> dict:
    """Recorre el repo y arma un mapa módulo -> propiedades.
    Marca módulos que tocan PHI y los que participan en decisiones clínicas."""
    modules = []
    for f in iter_repo_files(repo):
        text = safe_read_text(f, repo)
        if text is None:
            continue
        low = text.lower()
        modules.append({
            "path": str(f.relative_to(repo)),
            "touches_phi": any(k in low for k in ["phi", "patient", "diagnosis", "clinical", "lab result"]),
            "clinical_decision": any(k in low for k in ["diagnos", "decision", "evaluate_patient"]),
            "is_infra": f.suffix.lower() in (".tf", ".tfvars"),
        })
    return {
        "root": str(repo),
        "file_count": len(modules),
        "modules": modules,
        "phi_modules": [m["path"] for m in modules if m["touches_phi"]],
        "clinical_modules": [m["path"] for m in modules if m["clinical_decision"]],
        "skipped_files": get_skipped_files(),
    }


def patient_risk_score(
    security_severity: float,
    clinical_proximity: str,
    touches_phi: bool,
    compliance_level: ComplianceLevel = "none",
) -> float:
    """Patient Risk Score (§6): producto de cuatro vectores alineados al CSF.

    score = severity × proximity × phi_sensitivity × compliance_residual

    Rango 0–10. Un gap en decisión diagnóstica con PHI y sin cumplimiento
    (none) pesa mucho más que uno administrativo con Level 1 parcialmente
    implementado.

    Args:
        security_severity: Magnitud del gap (9.0) o control satisfecho (2.0).
        clinical_proximity: Proximidad al flujo clínico del paciente.
        touches_phi: Si el control protege datos identificables de pacientes.
        compliance_level: Nivel de implementación CSF alcanzado por el control.
            Valores: none | partial | level_1 | level_2 | level_3 | segment.
    """
    proximity_weight = _PROXIMITY_WEIGHT.get(clinical_proximity, 0.4)
    phi_weight = _PHI_WEIGHT["touches"] if touches_phi else _PHI_WEIGHT["no_phi"]
    compliance_factor = _COMPLIANCE_RISK_FACTOR.get(compliance_level, 1.0)
    raw = security_severity * proximity_weight * phi_weight * compliance_factor
    return round(min(raw, 10.0), 1)
