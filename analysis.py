"""
Deep Compliance Analysis: parsea el repo y construye un inventario
(el 'grafo' en memoria) ANTES de que ningún LLM razone.
Traducción del DCA de Apiiro: entender qué maneja cada módulo.
"""
from __future__ import annotations
from pathlib import Path


def build_inventory(repo: Path) -> dict:
    """Recorre el repo y arma un mapa módulo -> propiedades.
    Marca módulos que tocan PHI y los que participan en decisiones clínicas."""
    modules = []
    for f in repo.rglob("*"):
        if not f.is_file():
            continue
        text = f.read_text(errors="ignore")
        low = text.lower()
        modules.append({
            "path": str(f.relative_to(repo)),
            "touches_phi": any(k in low for k in ["phi", "patient", "diagnosis", "clinical", "lab result"]),
            "clinical_decision": any(k in low for k in ["diagnos", "decision", "evaluate_patient"]),
            "is_infra": f.suffix == ".tf",
        })
    return {
        "root": str(repo),
        "file_count": len(modules),
        "modules": modules,
        "phi_modules": [m["path"] for m in modules if m["touches_phi"]],
        "clinical_modules": [m["path"] for m in modules if m["clinical_decision"]],
    }


def patient_risk_score(security_severity: float,
                       clinical_proximity: str,
                       touches_phi: bool) -> float:
    """Patient Risk Score (§6 de tu doc): producto de tres vectores.
    Rango 0-10. Un gap en un módulo de decisión diagnóstica que toca PHI
    pesa mucho más que uno administrativo."""
    proximity_weight = {
        "diagnostic_decision": 1.0,
        "access_control": 0.7,
        "data_storage": 0.6,
        "administrative": 0.3,
    }.get(clinical_proximity, 0.4)
    phi_weight = 1.0 if touches_phi else 0.5
    raw = security_severity * proximity_weight * phi_weight
    return round(min(raw, 10.0), 1)
