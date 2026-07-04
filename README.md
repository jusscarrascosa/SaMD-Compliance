# SaMD Compliance Engine — RAISE Hackathon (Vultr track)

Motor de compliance HITRUST para Software como Dispositivo Médico.
Agente multi-paso que planifica, recupera del repo, llama validadores
determinísticos y rankea gaps por impacto en el paciente.

## Principio central
La IA PROPONE (confidence: proposed). El validador determinístico
CERTIFICA con evidencia real (confidence: validated). Nunca al revés.

## Setup
    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env      # y pegá tu VULTR_API_KEY

Ver modelos disponibles:
    curl https://api.vultrinference.com/v1/models -H "Authorization: Bearer $VULTR_API_KEY"
Poné el id que uses en VULTR_MODEL del .env.

## Correr
    uvicorn main:app --reload

    curl -X POST localhost:8000/v1/analyses -H "Content-Type: application/json" \
         -d '{"target":"sample_repo"}'
    # devuelve analysis_id
    curl localhost:8000/v1/analyses/{id}          # estado
    curl localhost:8000/v1/analyses/{id}/gaps     # gaps ordenados por patient_risk_score
    curl localhost:8000/v1/analyses/{id}/controls # todos los controles

Docs OpenAPI auto-generadas: http://localhost:8000/docs

## Archivos
- validators.py  : validadores determinísticos (SIN LLM) — el anti-alucinación
- analysis.py    : deep compliance analysis + patient risk score
- agent.py       : loop multi-paso (planifica→propone→valida→rankea) con Vultr
- main.py        : API FastAPI async
- sample_repo/   : repo SaMD de ejemplo (con 1 gap deliberado en audit logging)

## Endpoints nuevos (audit trail)
    GET /v1/analyses/{id}/evidence/{control_id}  # evidence file por control (para el auditor)
    GET /v1/audit-log                            # trazabilidad: quién pidió qué y cuándo
