"""
API FastAPI. Async: POST encola, GET consulta.
Superficie mínima del §7.2 de tu doc + evidence trail + audit log.
"""
from __future__ import annotations
import html
import uuid, asyncio
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
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
        JOBS[job_id].update(
            status="completed",
            result=result,
            completed_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as e:
        JOBS[job_id].update(status="failed", error=str(e))


PRISMA_LEVELS = [
    ("Policy", 0, "Security and privacy policy documentation."),
    ("Procedure", 25, "Documented and assigned operational procedures."),
    ("Implemented", 50, "Controls technically implemented in the system."),
    ("Measured", 75, "Controls measured and monitored with metrics."),
    ("Managed", 100, "Controls continuously managed with improvement."),
]

E1_TOTAL_CONTROL_REFS = 44

HITRUST_DOMAIN_NAMES: dict[str, str] = {
    "01": "01 — Access Control",
    "06": "06 — Data Protection",
    "09": "09 — Operations",
}

_CAP_SUGGESTIONS: dict[str, str] = {
    "HITRUST-06.d": (
        "Implement encryption at rest (KMS, storage_encrypted, or equivalent) "
        "for covered data in storage and databases containing PHI."
    ),
    "HITRUST-01.q": (
        "Implement multi-factor authentication (MFA) and user identity verification "
        "at access points to systems that process PHI."
    ),
    "HITRUST-09.aa": (
        "Implement audit logging with user_id, timestamp, and retention "
        "in modules that handle PHI."
    ),
    "HITRUST-09.l": (
        "Implement automated backups with defined retention "
        "(RDS snapshot, AWS Backup, or scheduled pg_dump) for clinical data."
    ),
    "HITRUST-01.b": (
        "Configure session timeout and idle timeout (e.g. SESSION_TIMEOUT, "
        "expires_in, or cookie maxAge) at system access points."
    ),
    "HITRUST-06.h": (
        "Define data retention and disposal policy (retention_period, "
        "purge, delete_after) for clinical records and PHI."
    ),
}


def _hitrust_domain_key(control_id: str) -> str:
    """Extrae el prefijo de dominio HITRUST (ej. '06' de 'HITRUST-06.d')."""
    if not control_id.startswith("HITRUST-"):
        return "other"
    ref = control_id[len("HITRUST-"):]
    digits = ""
    for ch in ref:
        if ch.isdigit():
            digits += ch
        else:
            break
    return digits or "other"


def _hitrust_domain_label(domain_key: str) -> str:
    return HITRUST_DOMAIN_NAMES.get(
        domain_key,
        f"{domain_key} — Other" if domain_key != "other" else "Other",
    )


def _has_verifiable_evidence(ctrl: dict) -> bool:
    evidence = ctrl.get("evidence") or {}
    return bool(evidence.get("file") and evidence.get("line"))


def _compute_report_metrics(controls: list[dict]) -> dict:
    total = len(controls)
    validated = sum(
        1 for c in controls
        if c.get("confidence") == "validated" and c.get("status") == "satisfied"
    )
    gaps = [c for c in controls if c.get("status") in ("gap", "partial")]
    prisma_pcts = [_prisma_maturity(c)["pct"] for c in controls]
    avg_prisma = round(sum(prisma_pcts) / total, 1) if total else 0.0
    compliance_score = round((validated / total) * 100, 1) if total else 0.0
    verifiable_findings = sum(1 for c in controls if _has_verifiable_evidence(c))

    domain_stats: dict[str, dict[str, int]] = {}
    for ctrl in controls:
        key = _hitrust_domain_key(ctrl.get("control_id", ""))
        if key not in domain_stats:
            domain_stats[key] = {"validated": 0, "gaps": 0, "total": 0}
        domain_stats[key]["total"] += 1
        if ctrl.get("confidence") == "validated" and ctrl.get("status") == "satisfied":
            domain_stats[key]["validated"] += 1
        elif ctrl.get("status") in ("gap", "partial"):
            domain_stats[key]["gaps"] += 1

    return {
        "total": total,
        "validated": validated,
        "gap_count": len(gaps),
        "compliance_score": compliance_score,
        "avg_prisma": avg_prisma,
        "verifiable_findings": verifiable_findings,
        "domain_stats": domain_stats,
    }


def _format_control_id(control_id: str) -> str:
    return control_id.removeprefix("HITRUST-")


def _control_display_name(ctrl: dict) -> str:
    """Nombre para UI: el campo name ya incluye el prefijo (ej. '06.h Data Retention…')."""
    name = (ctrl.get("name") or "").strip()
    if name:
        return name
    return _format_control_id(ctrl.get("control_id", ""))


def _readiness_from_score(score: float) -> tuple[str, str]:
    if score >= 75:
        return "High", "readiness-high"
    if score >= 40:
        return "Partial", "readiness-partial"
    return "Low", "readiness-low"


def _render_verdict_section(
    compliance_score: float,
    validated: int,
    total: int,
    top_gap: dict | None,
) -> str:
    score_display = f"{compliance_score:.0f}%"
    readiness_label, readiness_cls = _readiness_from_score(compliance_score)

    if top_gap:
        gap_label = html.escape(_control_display_name(top_gap))
        gap_score = top_gap.get("patient_risk_score", 0)
        critical_html = f"""
      <p class="verdict-critical">
        Critical priority: <strong>{gap_label}</strong>
        — patient risk {gap_score:.1f}
      </p>"""
    else:
        critical_html = """
      <p class="verdict-critical verdict-clear">
        No critical gaps detected in evaluated controls.
      </p>"""

    return f"""
    <section class="verdict" aria-label="Compliance verdict">
      <div class="verdict-main">
        <div class="verdict-score-block">
          <div class="verdict-score">{score_display}</div>
          <div class="verdict-score-label">Compliance Score</div>
          <div class="verdict-score-detail">{validated} of {total} controls validated</div>
        </div>
        <div class="verdict-readiness">
          <span class="readiness-label">Readiness</span>
          <span class="readiness-badge {readiness_cls}">{readiness_label}</span>
        </div>
      </div>
      {critical_html}
    </section>"""


def _render_action_plan(gaps: list[dict]) -> str:
    if not gaps:
        return """
    <section class="report-section action-plan">
      <h2 class="section-heading">Action Plan</h2>
      <p class="section-empty">No gaps identified. All evaluated controls have validated evidence.</p>
    </section>"""

    items = []
    for rank, ctrl in enumerate(gaps, start=1):
        label = html.escape(_control_display_name(ctrl))
        score = ctrl.get("patient_risk_score", 0)
        action = html.escape(_suggest_cap_action(ctrl))
        items.append(f"""
        <li class="action-item">
          <span class="action-rank">{rank}</span>
          <div class="action-body">
            <div class="action-title">
              <span class="action-name">{label}</span>
              <span class="risk-score">risk {score:.1f}</span>
            </div>
            <p class="action-text">{action}</p>
          </div>
        </li>""")

    return f"""
    <section class="report-section action-plan">
      <h2 class="section-heading">Action Plan</h2>
      <p class="section-lead">Gaps ordered by patient risk. Suggested corrective actions.</p>
      <ol class="action-list">{"".join(items)}</ol>
    </section>"""


def _render_validated_section(validated_controls: list[dict]) -> str:
    if not validated_controls:
        return """
    <section class="report-section validated-section">
      <h2 class="section-heading">Validated Evidence</h2>
      <p class="section-lead">
        Every validated control has verifiable evidence in the code.
        AI proposes; only deterministic evidence certifies.
      </p>
      <p class="section-empty">No controls with validated evidence in this evaluation.</p>
    </section>"""

    items = []
    for ctrl in validated_controls:
        label = html.escape(_control_display_name(ctrl))
        evidence = ctrl.get("evidence") or {}
        file_line = "—"
        match_text = ""
        if evidence.get("file") and evidence.get("line"):
            file_line = html.escape(f"{evidence['file']}:{evidence['line']}")
            match_text = evidence.get("match", "")
        elif evidence.get("source"):
            file_line = html.escape(str(evidence["source"]))

        match_html = (
            f"<pre class='evidence-match'>{html.escape(match_text)}</pre>"
            if match_text
            else ""
        )
        items.append(f"""
        <article class="evidence-item">
          <div class="evidence-header">
            <h3 class="evidence-name">{label}</h3>
          </div>
          <div class="evidence-loc">{file_line}</div>
          {match_html}
        </article>""")

    return f"""
    <section class="report-section validated-section">
      <h2 class="section-heading">Validated Evidence</h2>
      <p class="section-lead">
        Every validated control has verifiable evidence in the code.
        AI proposes; only deterministic evidence certifies.
      </p>
      <div class="evidence-list">{"".join(items)}</div>
    </section>"""


def _render_domain_table(metrics: dict) -> str:
    domain_rows = []
    for key in sorted(metrics["domain_stats"].keys()):
        stats = metrics["domain_stats"][key]
        domain_rows.append(f"""
        <tr>
          <td>{html.escape(_hitrust_domain_label(key))}</td>
          <td class="num">{stats["total"]}</td>
          <td class="num status-validated">{stats["validated"]}</td>
          <td class="num status-gap">{stats["gaps"]}</td>
        </tr>""")
    if not domain_rows:
        return "<p class='section-empty'>No controls evaluated.</p>"
    return f"""
    <table class="tech-table domain-table">
      <thead>
        <tr>
          <th>HITRUST Domain</th>
          <th>Evaluated</th>
          <th>Validated</th>
          <th>Gaps</th>
        </tr>
      </thead>
      <tbody>{"".join(domain_rows)}</tbody>
    </table>"""


def _render_normative_refs(controls: list[dict]) -> str:
    rows = []
    for ctrl in controls:
        refs = ctrl.get("framework_refs", [])
        if not refs:
            continue
        refs_html = ", ".join(html.escape(r) for r in refs)
        rows.append(f"""
        <tr>
          <td class="mono">{html.escape(_format_control_id(ctrl.get("control_id", "")))}</td>
          <td>{html.escape(ctrl.get("name", ""))}</td>
          <td class="refs-cell">{refs_html}</td>
        </tr>""")
    if not rows:
        return "<p class='section-empty'>No normative references recorded.</p>"
    return f"""
    <table class="tech-table refs-table">
      <thead>
        <tr>
          <th>Control</th>
          <th>Requirement</th>
          <th>Normative references</th>
        </tr>
      </thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_skipped_files(skipped: list[dict]) -> str:
    if not skipped:
        return "<p class='scope-empty'>No files skipped during scan.</p>"
    rows = []
    for entry in skipped:
        path = html.escape(str(entry.get("path", "—")))
        reason = html.escape(str(entry.get("reason", entry.get("detail", entry.get("message", "—")))))
        rows.append(f"<tr><td class='mono'>{path}</td><td>{reason}</td></tr>")
    return f"""
    <table class="tech-table scope-table">
      <thead><tr><th>File</th><th>Reason</th></tr></thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_technical_detail(
    metrics: dict,
    controls: list[dict],
    gaps: list[dict],
    repo_path: str,
    files_scanned: int,
    skipped_files: list[dict],
    prisma_html: str,
    caps_html: str,
) -> str:
    total = metrics["total"]
    domain_table = _render_domain_table(metrics)
    refs_table = _render_normative_refs(controls)
    skipped_html = _render_skipped_files(skipped_files)

    return f"""
    <details class="technical-details">
      <summary class="technical-summary">Technical detail</summary>
      <div class="technical-body">
        <div class="tech-block">
          <h3 class="tech-heading">Coverage metrics</h3>
          <div class="tech-metrics">
            <div class="tech-metric">
              <span class="tech-metric-value">{total} of {E1_TOTAL_CONTROL_REFS}</span>
              <span class="tech-metric-label">e1 coverage</span>
            </div>
            <div class="tech-metric">
              <span class="tech-metric-value">{metrics["avg_prisma"]:.1f}%</span>
              <span class="tech-metric-label">Average PRISMA maturity</span>
            </div>
            <div class="tech-metric">
              <span class="tech-metric-value">{metrics["verifiable_findings"]}</span>
              <span class="tech-metric-label">Findings with file:line</span>
            </div>
            <div class="tech-metric">
              <span class="tech-metric-value status-gap">{metrics["gap_count"]}</span>
              <span class="tech-metric-label">Gaps (CAP)</span>
            </div>
          </div>
          <p class="tech-note">
            {total} of {E1_TOTAL_CONTROL_REFS} e1 assessment control references evaluated.
          </p>
        </div>

        <div class="tech-block">
          <h3 class="tech-heading">Distribution by HITRUST domain</h3>
          {domain_table}
        </div>

        <div class="tech-block">
          <h3 class="tech-heading">PRISMA Maturity</h3>
          {prisma_html}
        </div>

        <div class="tech-block">
          <h3 class="tech-heading">Normative references</h3>
          {refs_table}
        </div>

        <div class="tech-block">
          <h3 class="tech-heading">Corrective Action Plans (CAPs)</h3>
          {caps_html}
        </div>

        <div class="tech-block">
          <h3 class="tech-heading">Scan scope</h3>
          <div class="scope-grid">
            <div class="scope-stat">
              <div class="scope-stat-label">Repository</div>
              <div class="scope-stat-value mono">{repo_path}</div>
            </div>
            <div class="scope-stat">
              <div class="scope-stat-label">Files scanned</div>
              <div class="scope-stat-value">{files_scanned}</div>
            </div>
            <div class="scope-stat">
              <div class="scope-stat-label">Skipped files</div>
              <div class="scope-stat-value">{len(skipped_files)}</div>
            </div>
          </div>
          <div class="scope-subheading">Skipped files</div>
          {skipped_html}
        </div>
      </div>
    </details>"""


def _prisma_maturity(ctrl: dict) -> dict:
    """Mapea validated/gap a terminología PRISMA y porcentaje de madurez."""
    is_validated = (
        ctrl.get("confidence") == "validated"
        and ctrl.get("status") == "satisfied"
    )
    if is_validated:
        return {
            "level": "Implemented",
            "pct": 50,
            "label": "Implemented (50%)",
            "css": "prisma-implemented",
            "bar_class": "prisma-bar-implemented",
        }
    return {
        "level": "Not Implemented",
        "pct": 0,
        "label": "Not Implemented (0%)",
        "css": "prisma-none",
        "bar_class": "prisma-bar-none",
    }


def _suggest_cap_action(ctrl: dict) -> str:
    control_id = ctrl.get("control_id", "")
    if control_id in _CAP_SUGGESTIONS:
        return _CAP_SUGGESTIONS[control_id]
    name = (ctrl.get("name") or "").lower()
    if "audit" in name or "logging" in name:
        return (
            "Implement audit logging with user_id, timestamp, and retention "
            "in modules that handle PHI."
        )
    if "encrypt" in name or "protection" in name or "privacy" in name:
        return (
            "Implement encryption at rest and data protection controls "
            "for covered information (PHI)."
        )
    if "auth" in name or "identification" in name:
        return (
            "Implement robust authentication (MFA) and identity management "
            "at system access points."
        )
    if "session" in name or "timeout" in name:
        return (
            "Configure session timeout and idle timeout at access points "
            "to systems that process PHI."
        )
    if "backup" in name:
        return (
            "Implement automated backups with defined retention "
            "for clinical data and databases containing PHI."
        )
    if "retention" in name or "disposal" in name:
        return (
            "Define secure data retention and disposal policy "
            "for clinical records and PHI."
        )
    return (
        f"Implement control {ctrl.get('control_id', '')} per the corresponding "
        "HITRUST CSF requirements, with verifiable evidence in code or infrastructure."
    )


def _render_prisma_maturity_section(controls: list[dict]) -> str:
    level_rows = []
    for level_name, pct, description in PRISMA_LEVELS:
        if level_name == "Implemented":
            at_level = [
                c for c in controls
                if _prisma_maturity(c)["level"] == "Implemented"
            ]
        else:
            at_level = []
        controls_html = ", ".join(
            html.escape(_format_control_id(c.get("control_id", ""))) for c in at_level
        ) or "—"
        level_rows.append(f"""
        <tr>
          <td><strong>{html.escape(level_name)}</strong></td>
          <td class="pct-cell">{pct}%</td>
          <td>{html.escape(description)}</td>
          <td class="controls-cell">{controls_html}</td>
        </tr>""")

    not_impl = [c for c in controls if _prisma_maturity(c)["level"] == "Not Implemented"]
    not_impl_html = ", ".join(
        html.escape(_format_control_id(c.get("control_id", ""))) for c in not_impl
    ) or "—"
    level_rows.append(f"""
    <tr>
      <td><strong>Not Implemented</strong></td>
      <td class="pct-cell">0%</td>
      <td>No technical implementation evidence detected in code or infrastructure.</td>
      <td class="controls-cell">{not_impl_html}</td>
    </tr>""")

    return f"""
    <p class="section-intro">
      The HITRUST PRISMA model defines five control maturity levels.
      This engine analyzes implementation in code and infrastructure; therefore,
      most evaluated controls reach <strong>Implemented (50%)</strong>
      when validated evidence exists, or <strong>Not Implemented (0%)</strong> when a gap is detected.
    </p>
    <table class="prisma-table">
      <thead>
        <tr>
          <th>PRISMA Level</th>
          <th>%</th>
          <th>Description</th>
          <th>Controls at this level</th>
        </tr>
      </thead>
      <tbody>{"".join(level_rows)}</tbody>
    </table>"""


def _render_caps_section(gaps: list[dict]) -> str:
    if not gaps:
        return """
    <p class="section-intro caps-clear">
      No gaps identified. All evaluated controls have validated
      implementation evidence.
    </p>"""
    rows = []
    for ctrl in gaps:
        prisma = _prisma_maturity(ctrl)
        action = _suggest_cap_action(ctrl)
        rows.append(f"""
        <tr>
          <td class="mono">{html.escape(_format_control_id(ctrl.get("control_id", "")))}</td>
          <td>{html.escape(ctrl.get("name", ""))}</td>
          <td><span class="status-label prisma-label {prisma['css']}">{html.escape(prisma['label'])}</span></td>
          <td>{html.escape(action)}</td>
        </tr>""")
    return f"""
    <p class="section-intro">
      Each identified gap is documented as a Corrective Action Plan (CAP)
      with the assessed maturity level and a suggested corrective action.
    </p>
    <table class="caps-table">
      <thead>
        <tr>
          <th>Control</th>
          <th>Requirement</th>
          <th>Assessed maturity</th>
          <th>Suggested corrective action</th>
        </tr>
      </thead>
      <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_report_html(job_id: str, job: dict) -> str:
    result = job["result"]
    repo = result.get("repo", "—")
    repo_name = html.escape(Path(repo).name or repo)
    repo_path = html.escape(repo)

    completed = job.get("completed_at")
    if completed:
        try:
            dt = datetime.fromisoformat(completed)
            date_str = dt.strftime("%d %b %Y, %H:%M UTC")
        except ValueError:
            date_str = html.escape(completed)
    else:
        date_str = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    inventory = result.get("inventory_summary", {})
    files_scanned = inventory.get("files", 0)
    skipped_files = inventory.get("skipped_files", [])

    controls = sorted(
        result.get("controls", []),
        key=lambda c: c.get("patient_risk_score", 0),
        reverse=True,
    )
    validated_controls = [
        c for c in controls
        if c.get("confidence") == "validated" and c.get("status") == "satisfied"
    ]
    gaps = [c for c in controls if c.get("status") in ("gap", "partial")]
    top_gap = max(gaps, key=lambda c: c.get("patient_risk_score", 0)) if gaps else None

    metrics = _compute_report_metrics(controls)
    verdict_html = _render_verdict_section(
        metrics["compliance_score"],
        metrics["validated"],
        metrics["total"],
        top_gap,
    )
    action_html = _render_action_plan(gaps)
    validated_html = _render_validated_section(validated_controls)
    prisma_html = _render_prisma_maturity_section(controls)
    caps_html = _render_caps_section(gaps)
    technical_html = _render_technical_detail(
        metrics,
        controls,
        gaps,
        repo_path,
        files_scanned,
        skipped_files,
        prisma_html,
        caps_html,
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HITRUST CSF Assessment Report — {repo_name}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.55;
      color: #1a1a1a;
      background: #fff;
    }}
    .page {{
      max-width: 880px;
      margin: 0 auto;
      padding: 40px 40px 64px;
    }}

    /* —— Meta header (discreto) —— */
    .report-meta {{
      margin-bottom: 32px;
      padding-bottom: 16px;
      border-bottom: 1px solid #e8e8e8;
    }}
    .report-meta .repo-name {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-size: 1rem;
      color: #1e3a5f;
      margin-bottom: 4px;
    }}
    .report-meta .meta-line {{
      font-size: 0.72rem;
      color: #767676;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}

    /* —— NIVEL 1: Veredicto —— */
    .verdict {{
      margin-bottom: 56px;
      padding-bottom: 40px;
      border-bottom: 2px solid #1a1a1a;
    }}
    .verdict-main {{
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 32px;
      margin-bottom: 28px;
    }}
    .verdict-score {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-size: 5.5rem;
      font-weight: 400;
      line-height: 1;
      color: #1a1a1a;
      letter-spacing: -0.02em;
    }}
    .verdict-score-label {{
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #767676;
      margin-top: 10px;
    }}
    .verdict-score-detail {{
      font-size: 1.05rem;
      color: #4a4a4a;
      margin-top: 6px;
    }}
    .verdict-readiness {{
      display: flex;
      flex-direction: column;
      align-items: flex-end;
      gap: 8px;
      flex-shrink: 0;
    }}
    .readiness-label {{
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #767676;
    }}
    .readiness-badge {{
      font-size: 1.35rem;
      font-weight: 600;
      letter-spacing: 0.02em;
      padding: 6px 16px;
      border: 2px solid;
    }}
    .readiness-high {{
      color: #2d6a4f;
      border-color: #2d6a4f;
    }}
    .readiness-partial {{
      color: #1e3a5f;
      border-color: #1e3a5f;
    }}
    .readiness-low {{
      color: #9b2226;
      border-color: #9b2226;
    }}
    .verdict-critical {{
      font-size: 1.05rem;
      color: #1a1a1a;
      line-height: 1.5;
      padding: 14px 18px;
      background: #fafafa;
      border-left: 4px solid #9b2226;
    }}
    .verdict-critical strong {{ font-weight: 600; }}
    .verdict-critical.verdict-clear {{
      border-left-color: #2d6a4f;
      color: #4a4a4a;
    }}

    /* —— NIVEL 2–3: Secciones principales —— */
    .report-section {{
      margin-bottom: 52px;
      page-break-inside: avoid;
    }}
    .section-heading {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-size: 1.35rem;
      font-weight: 400;
      color: #1a1a1a;
      margin-bottom: 12px;
    }}
    .section-lead {{
      font-size: 0.9rem;
      color: #4a4a4a;
      margin-bottom: 24px;
      line-height: 1.65;
      max-width: 640px;
    }}
    .section-empty {{
      font-size: 0.85rem;
      color: #767676;
      font-style: italic;
    }}

    /* —— Action Plan —— */
    .action-list {{
      list-style: none;
      counter-reset: action;
    }}
    .action-item {{
      display: flex;
      gap: 16px;
      padding: 18px 0;
      border-bottom: 1px solid #e8e8e8;
    }}
    .action-item:first-child {{
      border-top: 2px solid #1a1a1a;
    }}
    .action-rank {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-size: 1.5rem;
      color: #9b2226;
      min-width: 28px;
      line-height: 1.2;
      flex-shrink: 0;
    }}
    .action-title {{
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 8px 12px;
      margin-bottom: 6px;
    }}
    .control-id {{
      font-family: ui-monospace, "Cascadia Code", monospace;
      font-size: 0.75rem;
      color: #767676;
    }}
    .action-name {{
      font-size: 1rem;
      font-weight: 600;
      color: #1a1a1a;
    }}
    .risk-score {{
      font-size: 0.75rem;
      font-variant-numeric: tabular-nums;
      color: #9b2226;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .action-text {{
      font-size: 0.88rem;
      color: #4a4a4a;
      line-height: 1.6;
    }}

    /* —— Validated Evidence —— */
    .evidence-list {{
      display: flex;
      flex-direction: column;
      gap: 0;
    }}
    .evidence-item {{
      padding: 20px 0;
      border-bottom: 1px solid #e8e8e8;
    }}
    .evidence-item:first-child {{
      border-top: 1px solid #d0d0d0;
    }}
    .evidence-header {{
      display: flex;
      align-items: baseline;
      gap: 10px;
      margin-bottom: 8px;
    }}
    .evidence-name {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-size: 1rem;
      font-weight: 400;
      color: #1a1a1a;
    }}
    .evidence-loc {{
      font-family: ui-monospace, "Cascadia Code", monospace;
      font-size: 0.82rem;
      color: #1e3a5f;
    }}
    .evidence-match {{
      margin-top: 8px;
      padding: 10px 12px;
      background: #f5f5f5;
      border: 1px solid #e8e8e8;
      font-family: ui-monospace, "Cascadia Code", monospace;
      font-size: 0.75rem;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    /* —— LEVEL 4: Technical detail (collapsible) —— */
    .technical-details {{
      margin-top: 16px;
      margin-bottom: 32px;
      border: 1px solid #d0d0d0;
    }}
    .technical-summary {{
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: #4a4a4a;
      padding: 14px 18px;
      cursor: pointer;
      list-style: none;
      background: #fafafa;
    }}
    .technical-summary::-webkit-details-marker {{ display: none; }}
    .technical-summary::before {{
      content: "▸ ";
      color: #767676;
    }}
    .technical-details[open] .technical-summary::before {{
      content: "▾ ";
    }}
    .technical-body {{
      padding: 24px 18px 8px;
      font-size: 0.82rem;
      color: #4a4a4a;
    }}
    .tech-block {{
      margin-bottom: 32px;
    }}
    .tech-block:last-child {{ margin-bottom: 8px; }}
    .tech-heading {{
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #767676;
      margin-bottom: 14px;
      padding-bottom: 6px;
      border-bottom: 1px solid #e8e8e8;
    }}
    .tech-metrics {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 12px;
    }}
    .tech-metric {{
      text-align: center;
    }}
    .tech-metric-value {{
      display: block;
      font-size: 1.1rem;
      color: #1a1a1a;
      font-variant-numeric: tabular-nums;
    }}
    .tech-metric-label {{
      display: block;
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #767676;
      margin-top: 4px;
    }}
    .tech-note {{
      font-size: 0.78rem;
      color: #767676;
      line-height: 1.5;
    }}
    .tech-table, .prisma-table, .caps-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
    }}
    .tech-table th, .prisma-table th, .caps-table th {{
      text-align: left;
      padding: 7px 10px;
      border-bottom: 1px solid #1a1a1a;
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #767676;
      font-weight: 600;
    }}
    .tech-table td, .prisma-table td, .caps-table td {{
      padding: 8px 10px;
      border-bottom: 1px solid #e8e8e8;
      vertical-align: top;
      color: #4a4a4a;
    }}
    .tech-table .num {{
      text-align: right;
      font-variant-numeric: tabular-nums;
    }}
    .prisma-table .pct-cell {{ font-variant-numeric: tabular-nums; white-space: nowrap; }}
    .prisma-table .controls-cell, .refs-cell {{
      font-family: ui-monospace, monospace;
      font-size: 0.75rem;
    }}
    .mono {{ font-family: ui-monospace, monospace; font-size: 0.8rem; }}
    .status-validated {{ color: #2d6a4f; }}
    .status-gap {{ color: #9b2226; }}
    .status-label {{
      font-size: 0.65rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .status-label.prisma-implemented {{ color: #1e3a5f; }}
    .status-label.prisma-none {{ color: #9b2226; }}
    .section-intro {{
      font-size: 0.78rem;
      color: #767676;
      margin-bottom: 14px;
      line-height: 1.6;
    }}
    .scope-grid {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
      margin-bottom: 20px;
    }}
    .scope-stat-label {{
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #767676;
      margin-bottom: 4px;
    }}
    .scope-stat-value {{
      font-size: 0.82rem;
      color: #4a4a4a;
      word-break: break-all;
    }}
    .scope-stat-value.mono {{
      font-family: ui-monospace, monospace;
      font-size: 0.75rem;
    }}
    .scope-subheading {{
      font-size: 0.62rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #767676;
      margin: 8px 0 10px;
    }}
    .scope-empty {{
      font-size: 0.78rem;
      color: #767676;
      font-style: italic;
    }}

    /* —— Footer —— */
    .footer-note {{
      margin-top: 8px;
      padding-top: 20px;
      border-top: 1px solid #d0d0d0;
      font-size: 0.78rem;
      color: #767676;
      line-height: 1.65;
    }}
    .footer-note strong {{
      font-family: Georgia, "Times New Roman", Times, serif;
      font-weight: 400;
      color: #1a1a1a;
    }}

    @media (max-width: 720px) {{
      .page {{ padding: 24px 20px 48px; }}
      .verdict-main {{ flex-direction: column; align-items: flex-start; }}
      .verdict-readiness {{ align-items: flex-start; }}
      .verdict-score {{ font-size: 4rem; }}
      .tech-metrics {{ grid-template-columns: repeat(2, 1fr); }}
      .scope-grid {{ grid-template-columns: 1fr; }}
    }}
    @media print {{
      body {{ background: #fff; }}
      .page {{ padding: 0; max-width: 100%; }}
      .technical-details {{ border: none; }}
      .technical-details[open] summary {{ display: none; }}
      .technical-body {{ padding: 0; }}
      .action-item, .evidence-item {{ break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <header class="report-meta">
      <div class="repo-name">{repo_name}</div>
      <div class="meta-line">HITRUST CSF · e1 subset · {date_str} · ID {html.escape(job_id[:8])}…</div>
    </header>

    {verdict_html}

    {action_html}

    {validated_html}

    {technical_html}

    <footer class="footer-note">
      <strong>Legal notice:</strong>
      This report was generated automatically by the SaMD analysis engine
      and does not replace a formal assessment by a certified HITRUST
      External Assessor. Results reflect evidence detected in code and
      infrastructure; official certification requires human review by an
      accredited assessor.
    </footer>
  </div>
</body>
</html>"""


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


@app.get("/v1/analyses/{job_id}/report", response_class=HTMLResponse)
async def get_report(job_id: str, request: Request):
    """Reporte visual HTML del análisis — para revisión en navegador o impresión a PDF."""
    job = JOBS.get(job_id)
    if not job or job["status"] != "completed":
        raise HTTPException(409, "not ready")
    _audit("report.read", request, analysis_id=job_id)
    return HTMLResponse(_render_report_html(job_id, job))


@app.get("/v1/analyses/{job_id}/summary")
async def get_summary(job_id: str):
    """Resumen ejecutivo para demo: conteos, gap crítico y frase de una línea."""
    job = JOBS.get(job_id)
    if not job or job["status"] != "completed":
        raise HTTPException(409, "not ready")

    controls = job["result"]["controls"]
    total = len(controls)
    validated = sum(1 for c in controls if c["confidence"] == "validated")
    proposed = sum(1 for c in controls if c["confidence"] == "proposed")
    gaps = [c for c in controls if c["status"] in ("gap", "partial")]

    top_gap = None
    if gaps:
        top = max(gaps, key=lambda c: c["patient_risk_score"])
        top_gap = {
            "control_id": top["control_id"],
            "name": top["name"],
            "patient_risk_score": top["patient_risk_score"],
        }

    if top_gap:
        headline = (
            f"{validated} de {total} controles certificados; "
            f"gap crítico: {top_gap['name']}"
        )
    else:
        headline = f"{validated} de {total} controles certificados; sin gaps críticos"

    return {
        "analysis_id": job_id,
        "total_controls": total,
        "validated": validated,
        "proposed": proposed,
        "gaps": len(gaps),
        "top_gap": top_gap,
        "headline": headline,
    }


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
