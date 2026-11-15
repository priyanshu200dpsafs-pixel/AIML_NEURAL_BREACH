#!/usr/bin/env python3
"""
Team Neural Breach — Academic Backend Implementation Report PDF Generator
Generates a publication-grade, publication-formatted academic chapter PDF:
reports/BACKEND_IMPLEMENTATION_REPORT.pdf
"""

import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ----------------------------------------------------------------------
# Numbered Canvas for Running Headers and Footers ("Page X of Y")
# ----------------------------------------------------------------------
class AcademicNumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(HexColor("#64748b"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(40, 755, "Team Neural Breach — Backend Architecture & Implementation")
            self.drawRightString(612 - 40, 755, "Academic Project Report Chapter")
            self.setStrokeColor(HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(40, 748, 612 - 40, 748)

        # Footer (all pages)
        self.setStrokeColor(HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(40, 42, 612 - 40, 42)
        self.drawString(40, 31, "GOVERNANCE: STRICTLY OBSERVE-ONLY (NONE_OBSERVE_ONLY) | RESEARCH PROTOTYPE")
        self.drawRightString(612 - 40, 31, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


# ----------------------------------------------------------------------
# PDF Generation Routine
# ----------------------------------------------------------------------
def build_pdf(filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=54,
        bottomMargin=54,
    )
    pw = 532  # Printable width: 612 - 80

    styles = getSampleStyleSheet()

    # Custom Typography Hierarchy
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=HexColor("#0f172a"),
        alignment=0,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=HexColor("#334155"),
    )
    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=HexColor("#1e293b"),
    )
    meta_bold = ParagraphStyle(
        "MetaBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=12,
        textColor=HexColor("#0f172a"),
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=HexColor("#0f172a"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10.0,
        leading=13,
        textColor=HexColor("#1e3a8a"),
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True,
    )
    h3_style = ParagraphStyle(
        "Heading3_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.0,
        leading=12,
        textColor=HexColor("#334155"),
        spaceBefore=5,
        spaceAfter=2,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=11.2,
        textColor=HexColor("#1e293b"),
        spaceBefore=1.5,
        spaceAfter=3,
    )
    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=11.2,
        textColor=HexColor("#1e293b"),
        leftIndent=12,
        spaceBefore=1,
        spaceAfter=1.5,
    )
    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=HexColor("#0f172a"),
    )

    th_style = ParagraphStyle(
        "TableHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=colors.white,
    )
    td_style = ParagraphStyle(
        "TableBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=9.5,
        textColor=HexColor("#1e293b"),
    )
    td_code = ParagraphStyle(
        "TableCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.0,
        leading=9.0,
        textColor=HexColor("#0f172a"),
    )
    td_bold = ParagraphStyle(
        "TableBodyBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9.5,
        textColor=HexColor("#0f172a"),
    )

    callout_text = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.0,
        leading=11,
        textColor=HexColor("#1e3a8a"),
    )
    warn_text = ParagraphStyle(
        "WarnText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.0,
        leading=11,
        textColor=HexColor("#9a3412"),
    )

    def hr():
        return HRFlowable(width="100%", thickness=0.5, color=HexColor("#cbd5e1"), spaceBefore=4, spaceAfter=6)

    def code_box(text):
        pre = Preformatted(text, code_style)
        t = Table([[pre]], colWidths=[pw])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        return t

    def callout_box(text, is_warning=False):
        style = warn_text if is_warning else callout_text
        bg = HexColor("#fff7ed") if is_warning else HexColor("#eff6ff")
        border = HexColor("#ea580c") if is_warning else HexColor("#2563eb")
        p = Paragraph(text, style)
        t = Table([[p]], colWidths=[pw])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg),
            ("LINELEFT", (0, 0), (0, -1), 3.0, border),
            ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        return t

    def build_table(headers, rows, col_widths, code_cols=None):
        code_cols = code_cols or []
        tdata = []
        # Header row
        tdata.append([Paragraph(f"<b>{h}</b>", th_style) for h in headers])
        # Data rows
        for r in rows:
            row_cells = []
            for idx, c in enumerate(r):
                if idx in code_cols:
                    p = Paragraph(str(c), td_code)
                elif idx == 0:
                    p = Paragraph(str(c), td_bold)
                else:
                    p = Paragraph(str(c), td_style)
                row_cells.append(p)
            tdata.append(row_cells)

        t = Table(tdata, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#0f172a")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
            ("TOPPADDING", (0, 0), (-1, -1), 2.2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2),
            ("LEFTPADDING", (0, 0), (-1, -1), 3.5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        return t

    story = []

    # ==================================================================
    # COVER / TITLE BLOCK
    # ==================================================================
    story.append(Paragraph("TEAM NEURAL BREACH — ACADEMIC PROJECT REPORT", subtitle_style))
    story.append(Paragraph("CHAPTER: BACKEND ARCHITECTURE, IMPLEMENTATION AND PLATFORM INTEGRATION", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>AI/ML-Based Network Intrusion Detection & Real-Time Threat Intelligence Platform</b>", subtitle_style))
    story.append(Spacer(1, 6))

    # Metadata Panel Table
    meta_data = [
        [Paragraph("<b>Target Branch:</b>", meta_bold), Paragraph("<code>integration/role7-remediation</code> (HEAD: <code>0c9a8b1</code>)", meta_style),
         Paragraph("<b>Date:</b>", meta_bold), Paragraph("November 2026", meta_style)],
        [Paragraph("<b>Official Baseline:</b>", meta_bold), Paragraph("<code>main</code> (Commit: <code>f8d172d4b81ca3f1</code>)", meta_style),
         Paragraph("<b>Runtime:</b>", meta_bold), Paragraph("Python 3.12 / 3.13 (FastAPI 0.115+)", meta_style)],
        [Paragraph("<b>Test Suite:</b>", meta_bold), Paragraph("<b>124 / 124 Passing (100% Pass Rate in 26.43s)</b>", meta_style),
         Paragraph("<b>Governance:</b>", meta_bold), Paragraph("<b>Strictly Observe-Only (NONE_OBSERVE_ONLY)</b>", meta_style)],
        [Paragraph("<b>Frozen Models:</b>", meta_bold), Paragraph("<b>32 / 32 Certified Artifacts Verified (SHA-256)</b>", meta_style),
         Paragraph("<b>Database:</b>", meta_bold), Paragraph("SQLite (Local) / PostgreSQL 16 (Staging Schema)", meta_style)],
    ]
    meta_table = Table(meta_data, colWidths=[100, 170, 75, 187])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # ==================================================================
    # 1. INTRODUCTION & REPOSITORY BASELINE
    # ==================================================================
    story.append(Paragraph("1. Introduction and Repository Inspection Baseline", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "This chapter provides an exhaustive architectural, algorithmic, and engineering specification of the backend services powering "
        "<b>Team Neural Breach</b>. The platform ingests high-dimensional network telemetry, executes low-latency multi-model machine learning inference, "
        "computes real-time Shapley Explainable AI (XAI) attributions, semantically correlates detections with the MITRE ATT&CK framework, "
        "and delivers prioritized alert streams to Security Operations Center (SOC) analysts via asynchronous WebSockets and an enterprise multi-tenant dashboard.",
        body_style
    ))
    story.append(Paragraph("<b>1.1 Source Code Baseline & Branch Lineage</b>", h2_style))
    story.append(Paragraph(
        "The backend implementation described herein reflects the verified source tree of the official GitHub repository at "
        "<code>https://github.com/priyanshu200dpsafs-pixel/AIML_NEURAL_BREACH</code>. Comparing the official baseline branch <code>main</code> with the active "
        "integration branch <code>integration/role7-remediation</code> documents a controlled, non-destructive progression:",
        body_style
    ))
    story.append(Paragraph("• <b>Baseline Inherited Architecture (Role 6 Backend & Role 5 XAI):</b> Core real-time detection, feature preprocessing, multi-model CPU inference (LightGBM, Isolation Forest, PyTorch DeepAutoencoder), Tree-SHAP attribution, STIX 2.1 MITRE ATT&CK mapping, and in-memory cryptographic alert deduplication residing in <code>src/backend/</code> and <code>src/xai/</code> (commits <code>e27102a</code> and <code>2dbf7ef</code>).", bullet_style))
    story.append(Paragraph("• <b>Remediated Platform Extension (Role 7):</b> Enterprise multi-tenancy, Argon2id credential hashing, PyJWT session rotation, device telemetry ingestion, background worker queueing (<code>SELECT ... FOR UPDATE SKIP LOCKED</code>), Ed25519 cryptographic release signing, and 18 relational domain tables managed via explicit Alembic migrations in <code>src/backend/platform_ext/</code> and <code>alembic/</code> (commits <code>a31bbd2</code>, <code>4e28a36</code>, <code>31d6f4e</code>, and <code>34eec6c</code>).", bullet_style))
    story.append(Paragraph("• <b>Unified Product Delivery:</b> Integration of a production React 19 SOC Single-Page Application (<code>frontend/dist/</code>), zero-setup local launch automation (<code>scripts/start_local_demo.sh</code>), and unified multi-stage containerization (<code>Dockerfile.platform</code>, <code>docker-compose.yml</code>) established in commits <code>46c5c45</code>, <code>2097be6</code>, and <code>0c9a8b1</code>.", bullet_style))

    # ==================================================================
    # 2. BACKEND ARCHITECTURE
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("2. Backend Architecture", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The Team Neural Breach backend is an asynchronous, high-throughput Python service constructed on top of the <b>FastAPI</b> framework and <b>Starlette</b> ASGI core. "
        "It is engineered specifically for defensive cybersecurity monitoring, bridging the gap between raw statistical network flows and actionable SOC triage under an immutable <b>Observe-Only</b> invariant.",
        body_style
    ))

    story.append(Paragraph("<b>2.2 Architecture and Technology Stack</b>", h2_style))
    tech_data = [
        ["Layer", "Component", "Implementation", "Operational Rationale"],
        ["Runtime & Lang", "Core Interpreter", "Python 3.12 / 3.13 (CPython 3.13.7)", "Modern typing, native Starlette concurrency, NumPy/Pandas integration."],
        ["Web / API", "HTTP / ASGI Engine", "FastAPI 0.115+, Starlette, Uvicorn", "Asynchronous non-blocking route handlers, Pydantic v2 validation, OpenAPI."],
        ["Supervised ML", "Primary Classifier", "LightGBM 4.5.0 (joblib)", "High inference throughput (<15ms), native handling of tabular flow statistics."],
        ["Anomaly Engine", "Outlier Detection", "Isolation Forest + PyTorch Autoencoder", "Dual-engine capture of out-of-distribution traffic and statistical drift."],
        ["Explainable AI", "Local Attribution", "SHAP 0.46 (TreeExplainer), LIME 0.2", "Rigorous cooperative game-theoretic feature explanations for analysts."],
        ["Threat Intel", "Semantic Taxonomy", "STIX 2.1 JSON (MITRE ATT&CK v14)", "Industry-standard classification of adversarial tactics, techniques, mitigations."],
        ["Database & ORM", "Relational Layer", "SQLAlchemy 2.0+, Alembic, psycopg", "Type-safe query building, multi-tenant schemas, explicit reversible DDL."],
        ["Worker Queue", "Async Job Broker", "PostgreSQL FOR UPDATE SKIP LOCKED", "Eliminates external Redis dependency; transactionally atomic job claiming."],
        ["Cryptography", "Security Primitives", "Argon2id (argon2-cffi), PyJWT, Ed25519", "Memory-hard password hashing, cryptographically signed agent updates."],
        ["Frontend Serving", "SPA Delivery", "Starlette StaticFiles + FileResponse", "Eliminates CORS during local evaluation; serves React 19 SPA from /ui."],
    ]
    story.append(build_table(tech_data[0], tech_data[1:], [65, 80, 160, 227], code_cols=[2]))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>2.4 Application Initialization and Startup Lifecycle</b>", h2_style))
    story.append(Paragraph(
        "Application lifecycle is managed via modern asynchronous context managers using <code>@asynccontextmanager def lifespan(app: FastAPI)</code> in <code>src/backend/app.py</code>. "
        "During startup, the system eagerly loads all 32 frozen model artifacts (LightGBM classifier, Isolation Forest, PyTorch DeepAutoencoder, StandardScaler) and compiles the SHAP TreeExplainer against the classifier. "
        "Pre-computing the expected value baseline <i>E[f(x)]</i> at startup ensures zero first-request latency spikes when network telemetry flows arrive.",
        body_style
    ))

    story.append(Paragraph("<b>2.8 Coexistence of Role 6 Backend and Role 7 Platform Extension</b>", h2_style))
    story.append(Paragraph(
        "A key architectural achievement is the non-destructive mounting of the Role 7 platform extension onto the Role 6 detection backend via <code>install_platform(app)</code> in <code>src/backend/platform_ext/api/install.py</code>:",
        body_style
    ))
    story.append(Paragraph("• <b>Preservation of Role 6 Endpoints:</b> Unauthenticated diagnostic routes (<code>/api/v1/predict</code>, <code>/api/v1/alerts/simulate</code>, <code>/ws/alerts</code>, <code>/api/v1/health</code>) retain 100% backward compatibility and exact response schemas.", bullet_style))
    story.append(Paragraph("• <b>Selective Hardening Middleware:</b> Role 7 attaches HTTP security headers (<code>X-Content-Type-Options: nosniff</code>, <code>X-Frame-Options: DENY</code>, <code>HSTS</code>) and request size caps (2 MB) without injecting JWT requirements into public evaluation routes.", bullet_style))
    story.append(Paragraph("• <b>Independent Launch Modes:</b> <code>python3 -m src.backend.run_server</code> launches the standalone evaluation server (in-memory storage), while <code>src.backend.platform_main:app</code> launches the enterprise container with PostgreSQL persistence.", bullet_style))

    # ==================================================================
    # 3. FASTAPI AND REST API IMPLEMENTATION
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("3. FastAPI and REST API Implementation", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The backend exposes both core unauthenticated diagnostic endpoints (for evaluation and immediate flow analysis) and enterprise platform endpoints (for multi-tenant RBAC and sensor telemetry).",
        body_style
    ))

    api_headers = ["Method", "Route Path", "Layer", "Auth", "Request / Schema", "Purpose & Status Codes"]
    api_rows = [
        ["GET", "/", "Serving", "None", "None", "Root probe; serves React SPA if Accept: text/html is requested."],
        ["GET", "/ui, /dashboard, /alerts, /demo", "Serving", "None", "None", "Deep-link React SPA client-side routes; returns index.html."],
        ["GET", "/api/v1/health", "Role 6", "None", "None", "Health probe: model loaded states, uptime, observe-only confirmation."],
        ["GET", "/api/v1/ready", "Role 7", "None", "None", "DB readiness probe: selects 1; returns HTTP 503 if DB is unreachable."],
        ["GET", "/api/v1/stats", "Role 6", "None", "None", "SOC metrics: total alerts, severity distribution, top MITRE techniques."],
        ["GET", "/api/v1/alerts", "Role 6", "None", "Query: sev, cat, min_score", "Paginated alert query from in-memory ring buffer (limit/offset)."],
        ["GET", "/api/v1/alerts/{id}", "Role 6", "None", "Path: alert_id", "Single alert detail retrieval; returns HTTP 404 if not found."],
        ["POST", "/api/v1/predict", "Role 6", "None", "PredictRequest (77 features)", "Synchronous inference + SHAP waterfall + MITRE mapping (<25ms)."],
        ["POST", "/api/v1/alerts/simulate", "Role 6", "None", "SimulationRequest", "Streams CSE-CIC-IDS2018 flows to WebSockets; 503 if parquet missing."],
        ["WS", "/ws/alerts", "Role 6", "None", "Optional ping command", "Public WebSocket alert feed for SOC command dashboard."],
        ["POST", "/api/v1/auth/register", "Role 7", "None", "RegisterRequest", "Registers user, org, owner; issues access & refresh JWT tokens."],
        ["POST", "/api/v1/auth/login", "Role 7", "None", "LoginRequest", "Argon2id authentication, lockout check; issues JWT session."],
        ["POST", "/api/v1/auth/refresh", "Role 7", "Refresh", "RefreshRequest", "Opaque refresh token rotation; revokes family on reuse."],
        ["POST", "/api/v1/agents/enroll", "Role 7", "Token", "EnrollRequest", "Enrolls telemetry sensor; returns device ID and secret hash."],
        ["POST", "/api/v1/agents/{id}/telemetry", "Role 7", "Bearer", "BatchTelemetryRequest", "Idempotent telemetry ingestion; enqueues worker inference job."],
        ["GET", "/api/v2/alerts", "Role 7", "JWT", "Query: sev, status, time", "Paginated persistent alerts strictly isolated to caller's org."],
        ["PATCH", "/api/v2/alerts/{id}", "Role 7", "JWT", "AlertUpdateRequest", "Updates triage status (acknowledged, resolved) and notes."],
        ["WS", "/ws/v2/alerts", "Role 7", "Ticket", "Query: ?ticket=...", "Authenticated tenant-isolated WebSocket feed (15s revalidation)."],
    ]
    story.append(build_table(api_headers, api_rows, [38, 115, 45, 42, 112, 180], code_cols=[1]))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>3.2 Request Validation Contracts & Error Handling</b>", h2_style))
    story.append(Paragraph("• <b>Batch Size Boundary (HTTP 413):</b> <code>PredictRequest</code> enforces <code>len(flows) &lt;= 500</code>. Excessively large payloads are rejected with <code>HTTP 413 Content Too Large</code> to protect worker memory.", bullet_style))
    story.append(Paragraph("• <b>Strict 77-Feature Contract (HTTP 422):</b> Every flow record must include all 77 port-agnostic statistical metrics. If any feature is missing, the backend refuses to extrapolate or guess; it returns <code>HTTP 422 Unprocessable Content</code> with the exact list of missing columns.", bullet_style))
    story.append(Paragraph("• <b>Empty Payload Rejection (HTTP 400):</b> Empty submissions (<code>{\"flows\": []}</code>) return <code>HTTP 400 Bad Request</code>.", bullet_style))

    # ==================================================================
    # 4. MACHINE LEARNING BACKEND INTEGRATION
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("4. Machine Learning Backend Integration", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The machine learning inference engine requires an immutable contract of <b>77 bidirectional statistical flow metrics</b> derived from the CIC flow taxonomy. "
        "Port numbers and host IP addresses are deliberately excluded from model training and inference. This prevents the classifier from memorizing static network topology and guarantees generalizability to unseen environments.",
        body_style
    ))
    story.append(Paragraph("<b>4.1 Data Sanitization & Normalization Pipeline</b>", h2_style))
    story.append(Paragraph(
        "Flow records are validated and transformed in <code>CyberDefenseInferenceEngine.validate_and_preprocess()</code> in <code>src/models/inference_engine.py</code>:<br/>"
        "1. <b>Column Reindexing:</b> Enforces exact column alignment matching <code>feature_columns.json</code>: <code>X_df = df[self.expected_features]</code>.<br/>"
        "2. <b>Defensive Imputation:</b> Replaces division-by-zero sensor infinities and NaNs: <code>X_clean = X_df.replace([inf, -inf], NaN).fillna(0.0).values.astype(float32)</code>.<br/>"
        "3. <b>Standardized Scaling:</b> Normalizes features using a frozen <code>StandardScaler</code> fitted strictly on benign training data: <code>X_scaled = self.scaler.transform(X_clean)</code>.",
        body_style
    ))

    story.append(Paragraph("<b>4.2 Multi-Model Execution & Decision Thresholds</b>", h2_style))
    story.append(Paragraph(
        "Inference executes across three independent frozen models in parallel:<br/>"
        "• <b>Supervised LightGBM Classifier:</b> Computes class probabilities <i>P(y = c | X)</i> across 15 attack classes. An operating decision threshold of <b>0.7303</b> is enforced to guarantee a strict <b>1% False Positive Rate (FPR) budget</b>.<br/>"
        "• <b>Unsupervised Isolation Forest:</b> Computes outlier score <i>s_iso</i>. Alerts are triggered when <code>s_iso &lt;= -0.08063</code> (calibrated for 1% FPR).<br/>"
        "• <b>PyTorch DeepAutoencoder (77 -> 48 -> 24 -> 12 -> 24 -> 48 -> 77):</b> Computes Mean Squared Error (MSE) reconstruction loss. Anomaly alerts are triggered when <code>MSE &gt;= 1.29126</code> (calibrated for 1% FPR).<br/>"
        "• <b>Synthesized Threat Level:</b> Evaluated attacks are assigned <b>HIGH</b> (confidence >= 0.80) or <b>MEDIUM</b>. Benign flows triggering either anomaly detector are flagged as <b>SUSPICIOUS_ANOMALY</b>.",
        body_style
    ))

    # ==================================================================
    # 5. DETECTION ADAPTER & ROLE 7 INTEGRATION
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("5. Detection Adapter and Role 7 Integration", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The <code>Role6DetectionAdapter</code> class (<code>src/backend/platform_ext/adapters/detection_adapter.py</code>) bridges the Role 7 background worker to the frozen Role 3/5/6 detection engine:<br/>"
        "• <b>Worker Protocol Adherence:</b> Implements <code>process(flows: List[Dict[str, float]]) -&gt; List[Dict[str, Any]]</code>.<br/>"
        "• <b>Benign Traffic Pruning:</b> Normal non-anomalous flows are pruned from relational database storage, conserving disk I/O while ensuring 100% of attacks and anomalies are persisted.<br/>"
        "• <b>Enforced Invariant Injection:</b> Automatically injects <code>observe_only_mode: True</code> and <code>action_enforced: \"NONE_OBSERVE_ONLY\"</code> into every generated alert record.",
        body_style
    ))

    # ==================================================================
    # 6. DATABASE ARCHITECTURE AND IMPLEMENTATION
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("6. Database Architecture and Implementation", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The enterprise persistence layer resides in <code>src/backend/platform_ext/db/</code> and is built using SQLAlchemy 2.0 declarative mappings. "
        "The schema utilizes portable typings (UUID primary keys as <code>String(36)</code>, JSON columns for unstructured metrics), enabling seamless operation on SQLite (for zero-dependency local evaluation) and PostgreSQL (for production).",
        body_style
    ))

    story.append(Paragraph("<b>6.1 The 18 Relational Domain Tables</b>", h2_style))
    db_headers = ["Table Name", "ORM Model", "Primary Key", "Foreign Keys & Relationships", "Core Domain Purpose"]
    db_rows = [
        ["organizations", "Organization", "id (UUID)", "None (Root Tenant)", "Enterprise customer accounts and organizational boundaries."],
        ["users", "User", "id (UUID)", "None", "User credentials, Argon2id hashes, failed login counters, lockouts."],
        ["memberships", "Membership", "id (UUID)", "users.id, organizations.id", "User-to-org bindings with roles (owner, admin, analyst, viewer)."],
        ["auth_sessions", "AuthSession", "id (UUID)", "users.id, organizations.id", "Refresh token sessions with family_id tracking for reuse detection."],
        ["enrollment_tokens", "EnrollmentToken", "id (UUID)", "organizations.id, users.id", "Single-use cryptographic tokens for agent sensor registration."],
        ["devices", "Device", "id (UUID)", "organizations.id", "Enrolled telemetry sensors with host metadata and status."],
        ["device_credentials", "DeviceCredential", "id (UUID)", "devices.id", "Hashed device secrets (SHA-256) for sensor authentication."],
        ["device_heartbeats", "DeviceHeartbeat", "id (BigInt)", "devices.id", "Sensor health telemetry, client version, and uptime tracking."],
        ["device_configs", "DeviceConfig", "id (UUID)", "organizations.id, devices.id", "Dynamic sensor configuration payloads and policy revisions."],
        ["telemetry_batches", "TelemetryBatch", "id (UUID)", "organizations.id, devices.id", "Ingested telemetry batches with idempotency keys and checksums."],
        ["network_flows", "NetworkFlow", "id (BigInt)", "devices.id, telemetry_batches.id", "Raw statistical flow telemetry rows (the 77-feature contract)."],
        ["jobs", "Job", "id (UUID)", "telemetry_batches.id", "Task queue (queued, running, done, failed) with lease locking."],
        ["alerts", "Alert", "id (UUID)", "organizations.id, devices.id", "Persistent multi-tenant alerts with repeat counts and statuses."],
        ["alert_notes", "AlertNote", "id (UUID)", "alerts.id, users.id", "Analyst investigation comments and forensic observation notes."],
        ["audit_log", "AuditLog", "id (BigInt)", "organizations.id", "Append-only security and administrative audit trail."],
        ["model_versions", "ModelVersion", "id (UUID)", "None", "Registry of active ML models, weights SHA-256, feature contracts."],
        ["releases", "Release", "id (UUID)", "None", "Ed25519-signed agent binary update catalog and signed metadata."],
        ["release_policies", "ReleasePolicy", "channel (PK)", "None", "Channel-based (stable/beta) minimum version enforcement policies."],
    ]
    story.append(build_table(db_headers, db_rows, [95, 85, 55, 125, 172], code_cols=[0, 1]))

    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>6.2 Relational Deduplication & Explicit Migrations</b>", h2_style))
    story.append(Paragraph(
        "• <b>Row-Level Locking Deduplication:</b> In <code>alert_service.upsert_alert()</code>, queries select active alerts matching <code>(org_id, device_id, signature)</code> within a 60-second window using <code>with_for_update()</code>. If found, <code>repeat_count</code> is incremented atomically without inserting duplicate rows.<br/>"
        "• <b>Explicit Reversible Migrations:</b> Schema changes are governed exclusively by Alembic DDL (<code>alembic/versions/0001_initial.py</code>) rather than <code>create_all()</code>, providing safe, reversible zero-downtime database upgrades.",
        body_style
    ))
    story.append(callout_box("<b>PostgreSQL 16 Staging Verification Status:</b> The staging verification script (<code>scripts/verify_postgres16_staging.py</code>) was audited and confirmed safe. However, execution against PostgreSQL 16 staging remains gated awaiting formal cloud infrastructure provisioning. Prior passing concurrency tests were executed on local PostgreSQL 14.24.", is_warning=True))

    # ==================================================================
    # 7. AUTHENTICATION AND SECURITY
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("7. Authentication and Security", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "• <b>Argon2id Password Hashing:</b> Passwords in <code>src/backend/platform_ext/security/passwords.py</code> are hashed using memory-hard Argon2id. When authentication fails on non-existent accounts, computation runs against a pre-compiled <code>DUMMY_HASH</code> to neutralize user-enumeration timing attacks.<br/>"
        "• <b>JWT Lifecycle & Refresh Rotation:</b> Access tokens (HS256) have a 15-minute TTL. Opaque 48-byte refresh tokens are hashed at rest. Submitting an already-rotated refresh token indicates theft and revokes the entire <code>family_id</code> immediately.<br/>"
        "• <b>Account Lockout:</b> Five consecutive failed logins trigger a 15-minute account lock.<br/>"
        "• <b>Ed25519 Signed Releases:</b> Agent binary updates are verified against asymmetric Ed25519 signatures, preventing supply-chain tampering.",
        body_style
    ))

    # ==================================================================
    # 8. BACKGROUND WORKERS & 9. WEBSOCKET SYSTEM
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("8. Background Workers and Job Processing", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The background worker (<code>src/backend/platform_ext/services/worker.py</code>) utilizes a PostgreSQL-backed task queue:<br/>"
        "• <b>Atomic Task Claiming:</b> Workers claim jobs using <code>SELECT ... FOR UPDATE SKIP LOCKED</code>, bypassing locked rows with zero contention.<br/>"
        "• <b>Lease Locking & Sweeping:</b> Crashed workers are recovered by <code>reclaim_stale()</code>, which re-queues jobs whose lock is older than 300 seconds.<br/>"
        "• <b>Exponential Backoff:</b> Failed tasks retry with exponential delay (<code>base * 2^(attempts-1)</code>). After 5 attempts, tasks transition to <code>failed</code> (Dead-Letter state).",
        body_style
    ))

    story.append(Spacer(1, 4))
    story.append(Paragraph("9. WebSocket Real-Time Alert System", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "Real-time streaming is supported via two channels:<br/>"
        "1. <b>Role 6 Channel (<code>/ws/alerts</code>):</b> Public WebSocket hub for local lab demonstration.<br/>"
        "2. <b>Role 7 Channel (<code>/ws/v2/alerts</code>):</b> Authenticated multi-tenant feed managed by <code>AlertBroadcaster</code>.<br/>"
        "• <b>Bounded Queue Overflow:</b> Each client queue is capped at 500 messages. If a slow consumer fills its queue, the broadcaster purges the oldest alert, bounding server memory.<br/>"
        "• <i>Horizontal Scaling Notice:</i> The in-process broadcaster operates within a single process. Multi-node cluster scaling requires Redis Pub/Sub or PostgreSQL <code>NOTIFY</code>.",
        body_style
    ))

    # ==================================================================
    # 10. XAI & 11. OBSERVE-ONLY GOVERNANCE
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("10. Explainable AI and Threat Intelligence Integration", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "• <b>SHAP TreeExplainer Attributions:</b> Calculates exact Shapley feature values <i>phi_j</i> relative to baseline <i>E[f(x)]</i>, producing top-5 waterfall attributions indicating which network features pushed the model toward an attack label.<br/>"
        "• <b>MITRE ATT&CK STIX 2.1 Catalog:</b> Correlates classifications to tactics, technique IDs (e.g., T1498, T1059), and mitigations with explicit accuracy ratings (<code>CONFIRMED_FLOW_SIGNATURE</code> vs <code>UNCONFIRMED_FLOW_SURROGATE</code>).",
        body_style
    ))

    story.append(Spacer(1, 4))
    story.append(Paragraph("11. Observe-Only Governance and Safety", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "• <b>Immutable Settings:</b> <code>OBSERVE_ONLY_MODE = Field(default=True, frozen=True)</code> in <code>src/backend/config.py</code> rejects any environment override attempt.<br/>"
        "• <b>Static Payload Injection:</b> Every generated alert hardcodes <code>observe_only_mode: True</code> and <code>action_enforced: \"NONE_OBSERVE_ONLY\"</code>.<br/>"
        "• <b>Prohibition of Remediation:</b> The codebase contains zero firewall rule injectors, routing table modifiers, or host packet dropping subroutines.",
        body_style
    ))

    # ==================================================================
    # 12. BACKEND TESTING & 13. DEPLOYMENT
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("12. Backend Testing and Validation", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "The backend implementation was verified via <code>pytest</code>, achieving <b>124 passing tests out of 124 collected items (100% pass rate in 26.43s)</b>:",
        body_style
    ))

    test_headers = ["Test Suite File", "Tests", "Core Architectural Capabilities Verified", "Status"]
    test_rows = [
        ["tests/test_role6_backend.py", "17", "Health probes, SHAP/LIME inference, missing feature rejection, SHA-256 dedup, WebSocket handshake, simulation stream, observe-only mode, HTTP 413 limits.", "PASS"],
        ["tests/test_role5_xai.py", "11", "STIX 2.1 taxonomy, 15-class MITRE mapping, anomaly mapping, semantic ratings, SHAP attribution, LIME surrogate, Autoencoder reconstruction error.", "PASS"],
        ["tests/test_preprocessing.py", "9", "Repeated header detection, schema comparison, numeric sanitization, label typo correction (Infilteration), leak-free scaling, Scapy PCAP extraction.", "PASS"],
        ["tests/test_frontend_serving.py", "4", "Content negotiation (JSON for API, HTML for web browsers), React SPA deep-link routes (/ui, /dashboard, /alerts), static asset delivery.", "PASS"],
        ["tests/test_e2e_pipeline.py", "4", "End-to-end alert delivery, live WebSocket broadcast, batch processing throughput (25 flows), concurrent async stress test (30 clients).", "PASS"],
        ["tests/test_role7_integration.py", "10", "Non-regression validation: confirms Role 7 additions do not mutate Role 6 routes, unauthenticated predictions, alert queries, or WebSocket feeds.", "PASS"],
        ["tests_r7/test_core_primitives.py", "29", "Argon2id hashing, timing equalization, JWT life-cycle, RBAC matrix, token-bucket rate limiting, 77-feature contract, Ed25519 signing.", "PASS"],
        ["tests_r7/test_detection_adapter_real.py", "4", "Real adapter initialization, missing feature rejection, real multi-model inference execution, and background worker persistence.", "PASS"],
        ["tests_r7/test_platform_api.py", "31", "Multi-tenant auth, lockout protection, refresh rotation, cross-tenant device/alert isolation, agent enrollment, telemetry batching, Alembic migration.", "PASS"],
        ["tests_r7/test_websocket_broadcaster.py", "5", "Multi-subscriber broadcasting, cross-tenant isolation, device-specific filters, graceful disconnects, and bounded queue overflow protections.", "PASS"],
        ["Total Platform Tests", "124", "Complete platform regression, security, and integration coverage across all suites.", "100% PASS"],
    ]
    story.append(build_table(test_headers, test_rows, [125, 35, 327, 45], code_cols=[0]))

    story.append(Spacer(1, 6))
    story.append(Paragraph("13. Backend Deployment and Operations", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "• <b>Local Demonstration:</b> <code>bash scripts/start_local_demo.sh</code> verifies frozen models, checks React build, and starts FastAPI on port 8000.<br/>"
        "• <b>Multi-Stage Docker Deployment:</b> <code>Dockerfile.platform</code> compiles the React 19 SPA via Node 20-slim and runs the Python backend under non-root UID 10001. <code>docker-compose.yml</code> orchestrates PostgreSQL 16 (<code>db</code>), migrations (<code>migrate</code>), API (<code>api</code>), and worker (<code>worker</code>).",
        body_style
    ))

    # ==================================================================
    # 14. LIMITATIONS & SECTION B, C, D, E, F
    # ==================================================================
    story.append(Spacer(1, 6))
    story.append(Paragraph("14. Backend Limitations and Future Work", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "1. <b>Pre-Extracted Flow Ingestion:</b> Processes 77 statistical flow metrics; does not contain an inline raw packet sniffing daemon (libpcap/eBPF).<br/>"
        "2. <b>Benchmark Replay:</b> Simulation streams historical CSE-CIC-IDS2018 records rather than live attacks against physical networks.<br/>"
        "3. <b>Pending PostgreSQL 16 Cloud Staging:</b> Relational migrations were verified on SQLite and local PostgreSQL 14.24; formal cloud staging on PostgreSQL 16 awaits infrastructure provisioning.<br/>"
        "4. <b>In-Process Broadcaster:</b> WebSocket fan-out is single-process; multi-node scaling requires external Redis Pub/Sub.",
        body_style
    ))

    story.append(Spacer(1, 6))
    story.append(Paragraph("SECTION B: INDIVIDUAL BACKEND CONTRIBUTIONS", h1_style))
    story.append(hr())
    story.append(Paragraph("<b>Role 6 — Backend & Real-Time Detection Engine:</b> <i>[Student Name Placeholder]</i>, Roll No: <i>[Roll Number Placeholder]</i><br/>"
                           "• Modules: <code>src/backend/app.py</code>, <code>config.py</code>, <code>pipeline.py</code>, <code>alert_manager.py</code>, <code>websocket_manager.py</code>, <code>schemas.py</code>, <code>src/models/inference_engine.py</code>.<br/>"
                           "• Deliverables: Sub-50ms multi-model inference pipeline, 60s sliding-window cryptographic deduplication, benchmark traffic simulator, 21 automated tests in <code>tests/test_role6_backend.py</code> and <code>tests/test_e2e_pipeline.py</code>.", body_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph("<b>Role 7 — Platform Extension & Security Architecture:</b> <i>[Student Name Placeholder]</i>, Roll No: <i>[Roll Number Placeholder]</i><br/>"
                           "• Modules: <code>src/backend/platform_ext/api/install.py</code>, <code>db/models.py</code>, <code>services/worker.py</code>, <code>services/alert_service.py</code>, <code>services/broadcaster.py</code>, <code>adapters/detection_adapter.py</code>, <code>security/</code>, <code>alembic/versions/0001_initial.py</code>.<br/>"
                           "• Deliverables: Enterprise multi-tenancy, Argon2id hashing with timing equalization, PostgreSQL-backed worker queue (<code>SKIP LOCKED</code>), 18 ORM domain models, and 79 automated platform/integration tests in <code>tests_r7/</code> and <code>tests/test_role7_integration.py</code>.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("SECTION C: TECHNICAL EVIDENCE TABLE", h1_style))
    story.append(hr())
    ev_headers = ["Architectural Feature", "Implementation File", "Core Operational Mechanism", "Verification Method", "Status"]
    ev_rows = [
        ["77-Feature Schema Guard", "src/models/inference_engine.py", "Reindexes columns; rejects missing with ModelInferenceError.", "test_predict_missing_features_rejected", "VERIFIED (PASS)"],
        ["Supervised Inference", "src/models/inference_engine.py", "Deserializes LightGBM; computes 15-class probabilities.", "test_predict_single_flow_shap", "VERIFIED (PASS)"],
        ["Dual Anomaly Detection", "src/models/inference_engine.py", "Evaluates Isolation Forest and Autoencoder MSE loss.", "test_autoencoder_anomaly_attribution", "VERIFIED (PASS)"],
        ["SHAP XAI Waterfall", "src/xai/explainer.py", "Computes local Shapley contributions relative to E[f(x)].", "test_shap_explanation_structure", "VERIFIED (PASS)"],
        ["MITRE ATT&CK Mapping", "src/xai/mitre_mapper.py", "Correlates classes to STIX 2.1 catalog with semantic ratings.", "test_all_15_classes_mapped", "VERIFIED (PASS)"],
        ["In-Memory Dedup Ring", "src/backend/alert_manager.py", "Sliding-window SHA-256 fingerprinting collapses 60s bursts.", "test_deduplication_repeat_count", "VERIFIED (PASS)"],
        ["Live WebSocket Fan-Out", "src/backend/websocket_manager.py", "Asynchronous broadcast of enriched alerts to dashboards.", "test_websocket_connection_and_ping", "VERIFIED (PASS)"],
        ["Argon2id Credential Hash", "platform_ext/security/passwords.py", "Memory-hard hashing with DUMMY_HASH timing equalization.", "test_hash_and_verify", "VERIFIED (PASS)"],
        ["JWT Family Rotation", "platform_ext/security/tokens.py", "HS256 tokens + opaque refresh with reuse family revocation.", "test_roundtrip", "VERIFIED (PASS)"],
        ["Tenant Relational DB", "platform_ext/db/models.py", "18 SQLAlchemy 2.0 domain models with portable UUID/JSON.", "test_alembic_upgrade_downgrade", "VERIFIED (PASS)"],
        ["Worker Concurrency Lock", "platform_ext/services/worker.py", "Atomic task claiming via SELECT FOR UPDATE SKIP LOCKED.", "test_worker_processes_and_dedups", "VERIFIED (PASS)"],
        ["Detection Bridge Adapter", "platform_ext/adapters/detection_adapter.py", "Protocol bridge invoking frozen Role 3/5/6 pipeline.", "test_real_adapter_executes_real_inference_and_xai", "VERIFIED (PASS)"],
        ["Ed25519 Release Signing", "platform_ext/releases/signing.py", "Asymmetric signature verification of sensor update binaries.", "test_valid", "VERIFIED (PASS)"],
        ["Observe-Only Mode", "src/backend/config.py", "Frozen Pydantic validators prevent overriding OBSERVE_ONLY_MODE.", "test_observe_only_mode_invariant_override_rejection", "VERIFIED (PASS)"],
    ]
    story.append(build_table(ev_headers, ev_rows, [105, 125, 150, 107, 45], code_cols=[1, 3]))

    story.append(Spacer(1, 6))
    story.append(Paragraph("SECTION F: SOURCE CODE VERIFICATION INDEX", h1_style))
    story.append(hr())
    story.append(Paragraph(
        "1. <b>FastAPI Lifespan & Application Instantiation:</b> <code>src/backend/app.py#L53-L79</code> — <code>lifespan()</code>, <code>app = FastAPI(...)</code><br/>"
        "2. <b>Frozen Observe-Only Invariant Enforcement:</b> <code>src/backend/config.py#L28-L51</code> — <code>OBSERVE_ONLY_MODE = Field(default=True, frozen=True)</code><br/>"
        "3. <b>77-Feature Contract Validation:</b> <code>src/models/inference_engine.py#L156-L180</code> — <code>validate_and_preprocess()</code><br/>"
        "4. <b>Multi-Model Decision Thresholds:</b> <code>src/models/inference_engine.py#L113-L123, #L181-L244</code> — Isolation Forest (-0.08063), Autoencoder (1.29126)<br/>"
        "5. <b>Detection Adapter Bridge:</b> <code>src/backend/platform_ext/adapters/detection_adapter.py#L19-L164</code> — <code>Role6DetectionAdapter.process()</code><br/>"
        "6. <b>In-Memory Alert Deduplication:</b> <code>src/backend/alert_manager.py#L42-L100</code> — <code>_compute_signature()</code>, <code>add_alert()</code><br/>"
        "7. <b>Relational Database Models:</b> <code>src/backend/platform_ext/db/models.py#L25-L273</code> — 18 domain models<br/>"
        "8. <b>Worker Queue Concurrency:</b> <code>src/backend/platform_ext/services/worker.py#L35-L100</code> — <code>claim_job(SKIP LOCKED)</code><br/>"
        "9. <b>Relational Alert Deduplication:</b> <code>src/backend/platform_ext/services/alert_service.py#L29-L55</code> — <code>upsert_alert(with_for_update())</code><br/>"
        "10. <b>Argon2id Password Security:</b> <code>src/backend/platform_ext/security/passwords.py#L16-L46</code> — <code>hash_password()</code>, <code>DUMMY_HASH</code><br/>"
        "11. <b>JWT Session & Family Rotation:</b> <code>src/backend/platform_ext/security/tokens.py#L26-L48</code> — <code>encode_jwt()</code>, <code>refresh_session()</code><br/>"
        "12. <b>In-Memory WebSocket Broadcaster:</b> <code>src/backend/platform_ext/services/broadcaster.py#L19-L87</code> — <code>publish_alert()</code><br/>"
        "13. <b>Ed25519 Cryptographic Signing:</b> <code>src/backend/platform_ext/releases/signing.py#L40-L60</code> — <code>verify_signed_metadata()</code><br/>"
        "14. <b>Explicit Reversible Schema Migrations:</b> <code>alembic/versions/0001_initial.py#L16-L321</code> — <code>upgrade()</code>, <code>downgrade()</code><br/>"
        "15. <b>Non-Destructive Platform Extension:</b> <code>src/backend/platform_ext/api/install.py#L38-L134</code> — <code>install_platform(app)</code>",
        body_style
    ))

    # Build Document
    doc.build(story, canvasmaker=AcademicNumberedCanvas)
    print(f"[+] Academic Backend Report PDF generated successfully at: {filename}")


if __name__ == "__main__":
    out_pdf = "reports/BACKEND_IMPLEMENTATION_REPORT.pdf"
    if len(sys.argv) > 1:
        out_pdf = sys.argv[1]
    build_pdf(out_pdf)
