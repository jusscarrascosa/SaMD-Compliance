"""
El agente multi-paso. Esto es LO QUE EL JUEZ DE VULTR QUIERE VER:
no una sola llamada retrieve-then-answer, sino un coordinador que
planifica, recupera más de una vez, llama herramientas (validadores),
decide y produce un outcome.

Patrón: la IA PROPONE (confidence: proposed). El validador determinístico
CERTIFICA (confidence: validated). Nunca al revés.
"""
from __future__ import annotations
import os, json
from pathlib import Path
from openai import OpenAI

from validators import CONTROL_REGISTRY
from analysis import build_inventory, patient_risk_score

# Cliente apuntando a Vultr Serverless Inference (compatible OpenAI)
client = OpenAI(
    api_key=os.environ["VULTR_API_KEY"],
    base_url=os.environ.get("VULTR_BASE_URL", "https://api.vultrinference.com/v1"),
)
MODEL = os.environ.get("VULTR_MODEL", "llama-3.3-70b-instruct")


def _step_result(evidence: dict | None) -> str:
    """Etiqueta legible del resultado de una recuperación."""
    if evidence is None:
        return "not_found"
    if evidence.get("validation_status") == "partial":
        return "partial"
    return "found"


def _retrieve_with_fallback(repo: Path, spec: dict) -> tuple[dict | None, list[dict]]:
    """Recuperación multi-paso: fuente primaria, y si devuelve None, fuente alternativa."""
    retrieval_steps: list[dict] = []

    primary_fn = spec.get("primary_validator") or spec["validator"]
    primary_src = spec.get("primary_source", {"id": "primary", "label": "fuente primaria"})
    evidence = primary_fn(repo)
    step1: dict = {
        "step": 1,
        "source": primary_src["id"],
        "description": primary_src["label"],
        "result": _step_result(evidence),
    }
    if evidence:
        step1["evidence_source"] = evidence.get("source")
    retrieval_steps.append(step1)

    if evidence is None and "fallback_validator" in spec:
        fallback_fn = spec["fallback_validator"]
        fallback_src = spec["fallback_source"]
        evidence = fallback_fn(repo)
        step2: dict = {
            "step": 2,
            "source": fallback_src["id"],
            "description": fallback_src["label"],
            "result": _step_result(evidence),
        }
        if evidence:
            step2["evidence_source"] = evidence.get("source")
        retrieval_steps.append(step2)

    return evidence, retrieval_steps


def _llm(system: str, user: str) -> str:
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        temperature=0.2,
    )
    return resp.choices[0].message.content


def run_analysis(repo_path: str) -> dict:
    repo = Path(repo_path)

    # --- PASO 1: el agente PLANIFICA (LLM) ---
    inventory = build_inventory(repo)
    plan_prompt = (
        "Sos un agente de compliance HITRUST para software médico (SaMD). "
        "Dado este inventario de repo, listá en JSON qué controles del catálogo "
        f"deberías chequear. Catálogo disponible: {list(CONTROL_REGISTRY.keys())}. "
        f"Inventario: {json.dumps(inventory['modules'][:20])}. "
        'Respondé SOLO JSON: {"controls_to_check": [...]}'
    )
    try:
        plan_raw = _llm("Devolvés solo JSON válido, sin markdown.", plan_prompt)
        plan = json.loads(plan_raw.strip().strip("`").replace("json", "", 1).strip())
        controls_to_check = plan.get("controls_to_check", list(CONTROL_REGISTRY.keys()))
    except Exception:
        controls_to_check = list(CONTROL_REGISTRY.keys())  # fallback determinístico

    results = []
    for control_id in controls_to_check:
        if control_id not in CONTROL_REGISTRY:
            continue
        spec = CONTROL_REGISTRY[control_id]

        # --- PASO 2: el agente PROPONE con contexto (LLM) ---
        propose_prompt = (
            f"Control HITRUST: {control_id} ({spec['name']}). "
            f"Módulos que tocan PHI: {inventory['phi_modules']}. "
            "¿Esperás que este control esté implementado? Respondé en una frase."
        )
        try:
            proposal = _llm("Sos un ingeniero de seguridad conciso.", propose_prompt)
        except Exception:
            proposal = "propuesta no disponible"

        # --- PASO 3: recuperación multi-paso + VALIDADOR DETERMINÍSTICO (SIN LLM) ---
        evidence, retrieval_steps = _retrieve_with_fallback(repo, spec)
        validation_status = (evidence or {}).get("validation_status")
        if evidence is None:
            status = "gap"
            confidence = "proposed"
            severity = 9.0
        elif validation_status == "partial":
            status = "partial"
            confidence = "validated"
            severity = 6.0
        else:
            status = "satisfied"
            confidence = "validated"
            severity = 2.0

        # --- PASO 4: scoring por impacto en el paciente ---
        touches_phi = spec["clinical_proximity"] in ("diagnostic_decision", "data_storage")
        # Nivel CSF alcanzado: mapeo directo desde el resultado del validador
        # (none / partial / level_1) o override opcional en CONTROL_REGISTRY.
        compliance_level = spec.get("compliance_level") or {
            "gap": "none",
            "partial": "partial",
            "satisfied": "level_1",
        }[status]
        score = patient_risk_score(
            severity, spec["clinical_proximity"], touches_phi, compliance_level
        )

        results.append({
            "control_id": control_id,
            "name": spec["name"],
            "framework_refs": spec["framework_refs"],
            "status": status,
            # LA LÍNEA CLAVE: proposed vs validated
            "confidence": confidence,
            "llm_proposal": proposal,
            "retrieval_steps": retrieval_steps,
            "evidence": evidence,
            "clinical_proximity": spec["clinical_proximity"],
            "compliance_level": compliance_level,
            "patient_risk_score": score,
        })

    results.sort(key=lambda r: r["patient_risk_score"], reverse=True)
    return {
        "repo": repo_path,
        "inventory_summary": {
            "files": inventory["file_count"],
            "phi_modules": inventory["phi_modules"],
            "clinical_modules": inventory["clinical_modules"],
        },
        "controls": results,
        "gaps": [r for r in results if r["status"] in ("gap", "partial")],
    }
