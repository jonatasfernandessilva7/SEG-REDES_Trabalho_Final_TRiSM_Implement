"""
TRiSM Chat v2 — Servidor FastAPI orquestrando os 5 pilares TRiSM implementados.

Execução:
    python main_server.py                # Inicia servidor FastAPI na porta 8000
    python main_server.py --port 8080    # Inicia na porta customizada

Endpoints:
    POST   /api/message                  # Enviar mensagem
    GET    /api/health                   # Health check
    GET    /api/dashboard                # Dashboard completo
    GET    /api/governance-report        # Relatório de governança
    GET    /api/metrics/prometheus       # Métricas Prometheus
    POST   /api/session/clear            # Limpar histórico
    GET    /api/session/info             # Info da sessão
"""

import sys
import json
import hashlib
import time
import uuid
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

import ollama
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from uvicorn import run as run_uvicorn

from utils.config_loader import load_config
from pilar_01_explicabilidade.explainability import ExplainabilityEngine
from pilar_02_modelops.policy_engine import PolicyEngine
from pilar_02_modelops.metrics import MetricsCollector
from pilar_02_modelops.audit_logger import AuditLogger
from pilar_03_appsec.security import SecurityLayer
from pilar_04_privacy.privacy import PrivacyProtector
from pilar_05_adversarial.adversarial import AdversarialDetector
from core.base import RiskLevel, AuditTurn


# =========================================================================
# PYDANTIC MODELS
# =========================================================================
class MessageRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


class MessageResponse(BaseModel):
    response: str
    blocked: bool
    session_id: str
    risk_level: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    policies_triggered: List[str]
    violations: List[str]
    confidence: float
    owasp_categories: List[str]


class HealthResponse(BaseModel):
    status: str
    model: str
    model_version: str
    latency_ms: Optional[float]
    model_loaded: bool


class SessionInfo(BaseModel):
    session_id: str
    start_time: str
    uptime_seconds: float
    total_turns: int
    health: str


# =========================================================================
# SERVIDOR FASTAPI COM TRISM
# =========================================================================
class TRiSMAPIServer:
    """Servidor FastAPI que encapsula a lógica TRiSM Chat."""

    def __init__(self, config_path: str = "config.yaml"):
        self.config = load_config(config_path)
        model_cfg = self.config.get('model', {})
        self.model_name = model_cfg.get('name', 'phi3.5')
        self.model_version = model_cfg.get('version', '1.0.0')
        self.request_logprobs = model_cfg.get('request_logprobs', True)
        self.ollama_timeout = model_cfg.get('timeout_seconds', 600)  # timeout configurável

        # Inicializa todos os 5 pilares (com cache interno)
        self.explainability = ExplainabilityEngine(self.config)
        self.policy_engine = PolicyEngine(self.config)
        self.metrics = MetricsCollector(self.config)
        self.audit_logger = AuditLogger(self.config)
        self.security = SecurityLayer(self.config)
        self.privacy = PrivacyProtector(self.config)
        self.adversarial = AdversarialDetector(self.config)

        # Gerenciamento de sessões
        self.sessions: Dict[str, Dict] = {}
        self.server_start = datetime.now()

        # FastAPI app
        self.app = FastAPI(
            title="TRiSM Chat v2 API",
            description="Trust, Risk and Security Management for AI Chat",
            version=self.model_version
        )
        self._setup_routes()
        self._setup_middleware()

    def _setup_middleware(self) -> None:
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    def _setup_routes(self) -> None:
        """Configura todos os endpoints."""

        @self.app.get("/api/health", response_model=HealthResponse)
        def health_check():
            try:
                start = time.time()
                ollama.chat(
                    model=self.model_name,
                    messages=[{"role": "user", "content": "ping"}],
                    options={"num_predict": 5},
                    timeout=self.ollama_timeout
                )
                latency = (time.time() - start) * 1000
                return HealthResponse(
                    status="healthy",
                    model=self.model_name,
                    model_version=self.model_version,
                    latency_ms=round(latency, 2),
                    model_loaded=True
                )
            except Exception:
                return HealthResponse(
                    status="unhealthy",
                    model=self.model_name,
                    model_version=self.model_version,
                    latency_ms=None,
                    model_loaded=False
                )

        @self.app.post("/api/message", response_model=MessageResponse)
        def send_message(req: MessageRequest):
            session_id = req.session_id or self._create_session()
            return self._process_message(session_id, req.message)

        @self.app.get("/api/dashboard")
        def get_dashboard():
            return {
                "timestamp": datetime.now().isoformat(),
                "dashboard": self._build_dashboard(),
                "server_uptime_seconds": (datetime.now() - self.server_start).total_seconds()
            }

        @self.app.get("/api/governance-report")
        def governance_report():
            return {
                "timestamp": datetime.now().isoformat(),
                "server_uptime_seconds": (datetime.now() - self.server_start).total_seconds(),
                "active_sessions": len(self.sessions),
                "model": {
                    "name": self.model_name,
                    "version": self.model_version,
                    "health": self._check_health()
                },
                "pilar1_explicabilidade": self.explainability.get_status(),
                "pilar2_modelops_metrics": self.metrics.get_summary(),
                "pilar2_modelops_policies": self.policy_engine.get_status(),
                "pilar2_modelops_audit": self.audit_logger.get_status(),
                "pilar3_appsec": self.security.get_status(),
                "pilar4_privacy": self.privacy.get_privacy_status(),
                "pilar5_adversarial": self.adversarial.get_status(),
                "audit_chain": self.audit_logger.verify_integrity(),
            }

        @self.app.get("/api/metrics/prometheus")
        def metrics_prometheus():
            return {"metrics": self.metrics.export_prometheus()}

        @self.app.post("/api/session/clear")
        def clear_session(session_id: str):
            if session_id in self.sessions:
                self.sessions[session_id]["conversation_history"] = []
                return {"status": "success", "message": f"Histórico da sessão {session_id} limpo"}
            raise HTTPException(status_code=404, detail="Sessão não encontrada")

        @self.app.get("/api/session/info", response_model=SessionInfo)
        def session_info(session_id: str):
            if session_id not in self.sessions:
                raise HTTPException(status_code=404, detail="Sessão não encontrada")
            session = self.sessions[session_id]
            return SessionInfo(
                session_id=session_id,
                start_time=session["start_time"].isoformat(),
                uptime_seconds=(datetime.now() - session["start_time"]).total_seconds(),
                total_turns=session["total_turns"],
                health=self._check_health().get("status", "unknown")
            )

        @self.app.get("/api/sessions/list")
        def list_sessions():
            return {
                "total_sessions": len(self.sessions),
                "sessions": [
                    {
                        "session_id": sid,
                        "start_time": s["start_time"].isoformat(),
                        "total_turns": s["total_turns"],
                        "uptime_seconds": (datetime.now() - s["start_time"]).total_seconds()
                    }
                    for sid, s in self.sessions.items()
                ]
            }

    # =====================================================================
    # MÉTODOS AUXILIARES
    # =====================================================================
    def _create_session(self) -> str:
        session_id = hashlib.sha256(f"{uuid.uuid4()}{time.time()}".encode()).hexdigest()
        self.sessions[session_id] = {
            "conversation_history": [],
            "start_time": datetime.now(),
            "total_turns": 0,
            "consent_given": self.privacy.request_consent(session_id, purpose="audit_logging")
        }
        return session_id

    def _check_health(self) -> Dict:
        try:
            start = time.time()
            ollama.chat(
                model=self.model_name,
                messages=[{"role": "user", "content": "ping"}],
                options={"num_predict": 5},
                timeout=self.ollama_timeout
            )
            latency = (time.time() - start) * 1000
            return {
                "status": "healthy",
                "latency_ms": round(latency, 2),
                "model_loaded": True,
                "model_version": self.model_version
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e), "model_loaded": False}

    def _estimate_token_count(self, text: str) -> int:
        return len(text) // 4

    def _process_message(self, session_id: str, user_message: str) -> MessageResponse:
        if session_id not in self.sessions:
            session_id = self._create_session()

        session = self.sessions[session_id]
        violations: List[str] = []
        policies_triggered: List[str] = []
        owasp_categories: List[str] = []
        risk_level = RiskLevel.LOW
        final_message = user_message

        # ════════════════════════════════════════════════════════════════
        # PILAR 4 — Privacidade (entrada)
        # ════════════════════════════════════════════════════════════════
        final_message, redacted_items = self.privacy.redact_pii(final_message)
        if redacted_items:
            policies_triggered.append("pii_redacted")
            owasp_categories.append("LLM02")
        final_message = self.privacy.minimize_data(final_message, 4000)

        # ════════════════════════════════════════════════════════════════
        # PILAR 3 — Sanitização e Validação
        # ════════════════════════════════════════════════════════════════
        final_message = self.security.sanitize_input(final_message)
        sec_check = self.security.validate_message(final_message)
        if not sec_check["is_valid"]:
            risk_level = sec_check["risk_level"]
            violations.extend(sec_check["violations"])
            policies_triggered.extend(["injection_or_encoding_blocked"])
            owasp_categories.extend(["LLM01", "LLM05"])
            self.explainability.generate_explanation(
                action="block",
                reason="Mensagem violou política AppSec",
                policy_triggered="appsec",
                confidence=0.95,
                details={"violations": sec_check["violations"]}
            )
            self.explainability.log_decision_trace(sec_check.get("traces", []))
            return MessageResponse(
                response="[BLOQUEADO] Mensagem bloqueada por política de segurança.",
                blocked=True,
                session_id=session_id,
                risk_level=risk_level.value,
                latency_ms=0,
                input_tokens=self._estimate_token_count(user_message),
                output_tokens=0,
                policies_triggered=policies_triggered,
                violations=violations,
                confidence=0.0,
                owasp_categories=owasp_categories
            )

        # ════════════════════════════════════════════════════════════════
        # PILAR 5 — Adversários
        # ════════════════════════════════════════════════════════════════
        adv = self.adversarial.validate_message(final_message)
        if not adv["is_valid"]:
            risk_level = adv["risk_level"]
            violations.extend(adv["violations"])
            policies_triggered.append("jailbreak_blocked")
            owasp_categories.append("LLM01")
            self.explainability.generate_explanation(
                action="block",
                reason=f"Jailbreak categorias: {list(adv['categories'].keys())}",
                policy_triggered="jailbreak",
                confidence=adv.get("confidence", 0.0)
            )
            return MessageResponse(
                response="[BLOQUEADO] Comportamento não permitido detectado.",
                blocked=True,
                session_id=session_id,
                risk_level=risk_level.value,
                latency_ms=0,
                input_tokens=self._estimate_token_count(user_message),
                output_tokens=0,
                policies_triggered=policies_triggered,
                violations=violations,
                confidence=0.0,
                owasp_categories=owasp_categories
            )

        if adv["extraction_detected"]:
            policies_triggered.append("extraction_attempt")
            owasp_categories.append("LLM07")
            risk_level = RiskLevel.max_of(risk_level, RiskLevel.MEDIUM)

        if adv["multiturn_detected"]:
            policies_triggered.append("multiturn_buildup")
            risk_level = RiskLevel.max_of(risk_level, RiskLevel.HIGH)

        # ════════════════════════════════════════════════════════════════
        # PILAR 2 — Rate Limit
        # ════════════════════════════════════════════════════════════════
        rate_ok, rate_status = self.policy_engine.check_rate_limit(session_id)
        if not rate_ok:
            policies_triggered.append("rate_limit_exceeded")
            owasp_categories.append("LLM10")
            risk_level = RiskLevel.MEDIUM
            return MessageResponse(
                response="[LIMITE] Aguarde antes de enviar nova mensagem.",
                blocked=True,
                session_id=session_id,
                risk_level=risk_level.value,
                latency_ms=0,
                input_tokens=self._estimate_token_count(user_message),
                output_tokens=0,
                policies_triggered=policies_triggered,
                violations=violations,
                confidence=0.0,
                owasp_categories=owasp_categories
            )

        # ════════════════════════════════════════════════════════════════
        # TOKEN BUDGET (PRÉ-CHAMADA)
        # ════════════════════════════════════════════════════════════════
        input_tokens = self._estimate_token_count(final_message)
        budget_ok, budget_status = self.policy_engine.consume_tokens(session_id, input_tokens)
        if not budget_ok:
            policies_triggered.append("token_budget_exceeded")
            owasp_categories.append("LLM10")
            risk_level = RiskLevel.MEDIUM
            return MessageResponse(
                response="[LIMITE] Budget de tokens esgotado para esta sessão.",
                blocked=True,
                session_id=session_id,
                risk_level=risk_level.value,
                latency_ms=0,
                input_tokens=input_tokens,
                output_tokens=0,
                policies_triggered=policies_triggered,
                violations=violations,
                confidence=0.0,
                owasp_categories=owasp_categories
            )

        # ════════════════════════════════════════════════════════════════
        # ENVELOPE HIERÁRQUICO
        # ════════════════════════════════════════════════════════════════
        wrapped = self.security.wrap_user_input(final_message)
        session["conversation_history"].append({"role": "user", "content": wrapped})

        # ════════════════════════════════════════════════════════════════
        # CHAMADA AO MODELO COM LOGPROBS
        # ════════════════════════════════════════════════════════════════
        try:
            api_start = time.time()
            options = {
                "temperature": self.config.get('model', {}).get('parameters', {}).get('temperature', 0.7),
                "top_p": self.config.get('model', {}).get('parameters', {}).get('top_p', 0.9),
            }
            if self.request_logprobs:
                options["logprobs"] = True  # solicita logprobs ao Ollama

            response = ollama.chat(
                model=self.model_name,
                messages=session["conversation_history"],
                options=options,
                timeout=self.ollama_timeout
            )
            latency_ms = (time.time() - api_start) * 1000
            assistant_message = response['message']['content']
            # Extrai a lista de logprobs por token (se disponível)
            logprobs_data = response.get('logprobs', {})
            token_logprobs = logprobs_data.get('token_logprobs', []) if isinstance(logprobs_data, dict) else []
        except Exception as e:
            self.metrics.record_request(0, 0, 0, risk_level, success=False)
            return MessageResponse(
                response=f"[ERRO] Falha ao processar: {e}",
                blocked=True,
                session_id=session_id,
                risk_level=risk_level.value,
                latency_ms=0,
                input_tokens=input_tokens,
                output_tokens=0,
                policies_triggered=policies_triggered,
                violations=violations,
                confidence=0.0,
                owasp_categories=owasp_categories
            )

        # ════════════════════════════════════════════════════════════════
        # TOKEN BUDGET (PÓS-RESPOSTA)
        # ════════════════════════════════════════════════════════════════
        output_tokens = self._estimate_token_count(assistant_message)
        self.policy_engine.consume_tokens(session_id, output_tokens)

        # ════════════════════════════════════════════════════════════════
        # PILAR 3 — Validação de Saída
        # ════════════════════════════════════════════════════════════════
        out_ok, out_violations = self.security.validate_output(assistant_message)
        if not out_ok:
            policies_triggered.append("output_violation")
            owasp_categories.append("LLM05")
            assistant_message = self.security.sanitize_output(assistant_message)
            risk_level = RiskLevel.max_of(risk_level, RiskLevel.MEDIUM)
            violations.append(f"output: {out_violations}")

        # ════════════════════════════════════════════════════════════════
        # PILAR 4 — Redação de PII na Saída
        # ════════════════════════════════════════════════════════════════
        assistant_message, _ = self.privacy.redact_pii(assistant_message)

        # ════════════════════════════════════════════════════════════════
        # PILAR 5 — Repetição Semântica
        # ════════════════════════════════════════════════════════════════
        rep = self.adversarial.validate_response(assistant_message)
        if rep["repetition_detected"]:
            policies_triggered.append("repetition_detected")
            violations.extend(rep["violations"])

        # ════════════════════════════════════════════════════════════════
        # MÉTRICAS e DRIFT
        # ════════════════════════════════════════════════════════════════
        self.metrics.record_request(latency_ms, input_tokens, output_tokens, risk_level, success=True)
        drift = self.metrics.calculate_drift(session["conversation_history"])
        if drift["score"] > self.config['modelops']['monitoring'].get('psi_threshold', 0.25):
            policies_triggered.append("drift_detected")

        # ════════════════════════════════════════════════════════════════
        # EXPLICABILIDADE com logprobs reais
        # ════════════════════════════════════════════════════════════════
        # Converte lista de logprobs em confiança média (probabilidade geométrica)
        logprobs_conf = None
        if token_logprobs:
            # Filtra None e calcula média dos logprobs (valores negativos)
            clean = [lp for lp in token_logprobs if lp is not None]
            if clean:
                avg_logp = sum(clean) / len(clean)
                logprobs_conf = max(0.0, min(1.0, math.exp(avg_logp)))  # converte para [0,1]

        confidence = self.explainability.calculate_confidence(
            violations=violations,
            has_anomalies=bool(rep.get("violations")),
            logprobs_confidence=logprobs_conf  # passa o valor calculado
        )
        self.explainability.generate_explanation(
            action="respond",
            reason="Mensagem processada com governança TRiSM",
            policy_triggered=",".join(policies_triggered) if policies_triggered else None,
            confidence=confidence,
            details={"violations": violations, "drift": drift, "logprobs_confidence": logprobs_conf}
        )

        # ════════════════════════════════════════════════════════════════
        # AUDITORIA
        # ════════════════════════════════════════════════════════════════
        if session["consent_given"]:
            audit_turn = AuditTurn(
                turn_id=str(uuid.uuid4()).replace("-", "")[:16],
                timestamp=datetime.now().isoformat(),
                session_id=session_id,
                user_message=self.privacy.minimize_data(final_message, 500),
                assistant_response=self.privacy.minimize_data(assistant_message, 500),
                latency_ms=latency_ms,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                risk_level=risk_level.value,
                policies_triggered=policies_triggered,
                anomalies_detected=rep.get("violations", []),
                confidence_score=confidence,
                owasp_categories=sorted(set(owasp_categories)),
            )
            self.audit_logger.log_turn(audit_turn)

        session["conversation_history"].append({"role": "assistant", "content": assistant_message})
        session["total_turns"] += 1

        return MessageResponse(
            response=assistant_message,
            blocked=False,
            session_id=session_id,
            risk_level=risk_level.value,
            latency_ms=round(latency_ms, 2),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            policies_triggered=policies_triggered,
            violations=violations,
            confidence=round(confidence, 4),
            owasp_categories=sorted(set(owasp_categories))
        )

    def _build_dashboard(self) -> Dict:
        m = self.metrics.get_summary()
        h = self._check_health()
        priv = self.privacy.get_privacy_status()
        sec = self.security.get_status()
        adv = self.adversarial.get_status()
        xai = self.explainability.get_status()
        pol = self.policy_engine.get_status()
        chain = self.audit_logger.verify_integrity()

        return {
            "pilar1_explicabilidade": {
                "confidence_avg": xai['confidence'].get('avg_confidence', 0),
                "total_traces": xai.get('total_traces', 0),
                "top_policies": [p['policy'] for p in xai.get('top_policies', [])[:3]]
            },
            "pilar2_modelops": {
                "total_requests": m.get('total_requests', 0),
                "error_rate": m.get('error_rate', 0),
                "p50_latency_ms": m.get('p50_latency_ms', 0),
                "p95_latency_ms": m.get('p95_latency_ms', 0),
                "drift_psi_avg": m.get('drift_psi_avg', 0),
                "drift_js_avg": m.get('drift_js_avg', 0),
                "tokens_per_minute": m.get('tokens_per_minute_avg', 0),
                "estimated_cost_usd": m.get('estimated_cost_usd', 0),
                "rate_limit": pol.get('rate_limit_per_minute', 0),
                "token_budget": pol.get('token_budget_per_window', 0),
            },
            "pilar3_appsec": {
                "injection_attempts": sec.get('injection_attempts', 0),
                "encoding_attempts": sec.get('encoding_attempts', 0),
                "output_violations": sec.get('output_violations', 0),
                "use_prompt_hierarchy": sec.get('use_prompt_hierarchy', False)
            },
            "pilar4_privacy": {
                "total_redactions": priv.get('total_redactions', 0),
                "redactions_by_type": priv.get('redactions_by_type', {}),
                "consent_mode": priv.get('consent_mode', 'unknown'),
                "pseudonymization": priv.get('pseudonymization', False)
            },
            "pilar5_adversarial": {
                "jailbreak_attempts": adv.get('jailbreak_attempts', 0),
                "multiturn_alerts": adv.get('multiturn_alerts', 0),
                "extraction_attempts": adv.get('extraction_attempts', 0),
                "repetition_attacks": adv.get('repetition_attacks', 0),
                "categories": adv.get('categories', {})
            },
            "audit": {
                "chain_valid": chain.get('valid', False),
                "total_entries": chain.get('total', 0),
                "invalid_entries": len(chain.get('invalid_indices', []))
            },
            "health": h
        }


def main():
    parser = argparse.ArgumentParser(description="TRiSM Chat v2 FastAPI Server")
    parser.add_argument("--port", type=int, default=8000, help="Porta do servidor (padrão: 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Host do servidor (padrão: 0.0.0.0)")
    args = parser.parse_args()

    config_path = str(Path(__file__).parent / "config.yaml")

    try:
        print("""
╔════════════════════════════════════════════════════════════════╗
║         🚀 TRiSM CHAT v2 — SERVIDOR FastAPI                   ║
║     Trust, Risk and Security Management for AI Chat           ║
╠════════════════════════════════════════════════════════════════╣
║ Pilares ATIVOS:                                                ║
║  P1 - Explicabilidade (logprobs + decision trace)              ║
║  P2 - ModelOps (PSI/JS drift, hash chain, token budget)        ║
║  P3 - AppSec (encoding tricks, output validator, hierarquia)   ║
║  P4 - Privacidade (PII BR completo, pseudonimização)           ║
║  P5 - Adversários (categorias, multi-turno, repetição)         ║
╚════════════════════════════════════════════════════════════════╝
        """)

        server = TRiSMAPIServer(config_path)

        print(f"📡 Iniciando servidor na porta {args.port}...")
        print(f"📚 Documentação Swagger: http://{args.host}:{args.port}/docs")
        print(f"📚 Documentação ReDoc: http://{args.host}:{args.port}/redoc")
        print()

        run_uvicorn(server.app, host=args.host, port=args.port, log_level="info")

    except Exception as e:
        print(f"❌ Erro ao inicializar servidor: {e}")
        sys.exit(1)


if __name__ == "__main__":
    import math  # necessário para exp()
    main()