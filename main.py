"""
API FastAPI. Async: POST encola, GET consulta.
Superficie mínima del §7.2 de tu doc + evidence trail + audit log.
"""
from __future__ import annotations
import uuid, asyncio
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()
from agent import run_analysis  # después de load_dotenv para tener las envs

app = FastAPI(title="SaMD Compliance Engine", version="0.1.0")
JOBS: dict[str, dict] = {}      # análisis en memoria (para el hackathon alcanza)
AUDIT_LOG: list[dict] = []      # audit trail de la propia API — requisito SaMD


def _audit(action: str, request: Request, **extra):
    """Registra cada operación sensible: quién pidió qué y cuándo.
    En SaMD esto es exigencia regulatoria, no un extra."""
    AUDIT_LOG.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "client": request.client.host if request.client else "unknown",
        **extra,
    })


class AnalysisRequest(BaseModel):
    target: str  # ruta al repo


async def _worker(job_id: str, target: str):
    JOBS[job_id]["status"] = "running"
    try:
        result = await asyncio.to_thread(run_analysis, target)
        JOBS[job_id].update(status="completed", result=result)
    except Exception as e:
        JOBS[job_id].update(status="failed", error=str(e))


@app.post("/v1/analyses", status_code=202)
async def create_analysis(req: AnalysisRequest, request: Request):
    job_id = str(uuid.uuid4())
    JOBS[job_id] = {"status": "pending", "result": None}
    _audit("analysis.create", request, analysis_id=job_id, target=req.target)
    asyncio.create_task(_worker(job_id, req.target))
    return {"analysis_id": job_id, "status": "pending"}


@app.get("/v1/analyses/{job_id}")
async def get_analysis(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "not found")
    return {"analysis_id": job_id, **JOBS[job_id]}


@app.get("/v1/analyses/{job_id}/controls")
async def get_controls(job_id: str):
    job = JOBS.get(job_id)
    if not job or job["status"] != "completed":
        raise HTTPException(409, "not ready")
    return {"controls": job["result"]["controls"]}


@app.get("/v1/analyses/{job_id}/gaps")
async def get_gaps(job_id: str):
    job = JOBS.get(job_id)
    if not job or job["status"] != "completed":
        raise HTTPException(409, "not ready")
    return {"gaps": job["result"]["gaps"]}  # ordenados por patient_risk_score


@app.get("/v1/analyses/{job_id}/evidence/{control_id}")
async def get_evidence(job_id: str, control_id: str, request: Request):
    """El evidence file de un control — lo que el auditor HITRUST querrá ver.
    Devuelve estado, madurez, evidencia verificable y qué propuso el LLM vs
    qué se validó determinísticamente."""
    job = JOBS.get(job_id)
    if not job or job["status"] != "completed":
        raise HTTPException(409, "not ready")
    ctrl = next((c for c in job["result"]["controls"]
                 if c["control_id"] == control_id), None)
    if ctrl is None:
        raise HTTPException(404, f"control {control_id} not in this analysis")
    _audit("evidence.read", request, analysis_id=job_id, control_id=control_id)
    return {
        "analysis_id": job_id,
        "control_id": ctrl["control_id"],
        "name": ctrl["name"],
        "framework_refs": ctrl["framework_refs"],
        "status": ctrl["status"],
        "confidence": ctrl["confidence"],          # proposed | validated
        "llm_proposal": ctrl["llm_proposal"],      # lo que la IA afirmó
        "evidence": ctrl["evidence"],              # la prueba verificable (o null)
        "retrieval_steps": ctrl.get("retrieval_steps", []),
        "patient_risk_score": ctrl["patient_risk_score"],
        "clinical_proximity": ctrl["clinical_proximity"],
        "compliance_level": ctrl.get("compliance_level"),
        "auditor_note": (
            "Certificado por validador determinístico con evidencia reproducible."
            if ctrl["confidence"] == "validated"
            else "Solo propuesto por el agente; SIN evidencia validada. No certificable."
        ),
    }


@app.get("/v1/audit-log")
async def audit_log():
    """Trazabilidad total de la API: quién pidió qué análisis y cuándo."""
    return {"entries": AUDIT_LOG}


@app.get("/v1/controls")
async def catalog():
    from validators import CONTROL_REGISTRY
    return {"catalog": [{"control_id": k, "name": v["name"],
                         "framework_refs": v["framework_refs"]}
                        for k, v in CONTROL_REGISTRY.items()]}
