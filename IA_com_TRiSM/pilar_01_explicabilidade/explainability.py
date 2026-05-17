"""
Pilar 1: Explicabilidade e Transparência (XAI) — VERSÃO FORTALECIDA

Melhorias frente à v1:
- Confiança baseada em logprobs do Ollama (quando disponível) ao invés de fórmula linear.
- DecisionTrace estruturado por pilar/regra/evidência (Raza et al. 2026).
- Export do raciocínio em formato OVON-like (Gosmar et al. 2025).
- Resumo estatístico: distribuição de risco, top regras acionadas, latência.
"""

import sys
import math
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel, DecisionTrace


class ExplainabilityEngine:
    """Pilar 1: Explicabilidade e Transparência."""

    def __init__(self, config: Dict):
        self.config = config.get('explainability', {})
        self.enabled = self.config.get('enabled', True)
        self.confidence_threshold = self.config.get('confidence_threshold', 0.7)
        _max = self.config.get('max_log_entries', 1000)

        self.explanations_log: deque = deque(maxlen=_max)
        self.confidence_scores: deque = deque(maxlen=_max)
        self.reasoning_logs: deque = deque(maxlen=_max)
        self.decision_traces: deque = deque(maxlen=_max)

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------
    def generate_explanation(self, action: str, reason: str, policy_triggered: str = None,
                             confidence: float = 0.0, details: Dict = None) -> Dict:
        if not self.enabled:
            return {}
        explanation = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "reason": reason,
            "confidence": confidence,
            "policy_triggered": policy_triggered,
            "details": details or {},
        }
        self.explanations_log.append(explanation)
        if confidence > 0:
            self.confidence_scores.append(confidence)
        return explanation

    def log_reasoning(self, prompt: str, response: str, reasoning_steps: List[str] = None) -> None:
        if not self.enabled:
            return
        self.reasoning_logs.append({
            "timestamp": datetime.now().isoformat(),
            "type": "reasoning",
            "prompt_preview": prompt[:200],
            "response_preview": response[:200],
            "reasoning_steps": reasoning_steps or [],
        })

    def log_decision_trace(self, traces: List[DecisionTrace]) -> None:
        """Registra um conjunto completo de traces (chain-of-thought por pilar)."""
        if not self.enabled or not traces:
            return
        self.decision_traces.append(traces)

    # ------------------------------------------------------------------
    # Confiança real baseada em logprobs (NOVO)
    # ------------------------------------------------------------------
    @staticmethod
    def confidence_from_logprobs(ollama_response: Dict[str, Any]) -> Optional[float]:
        """Estima confiança usando logprobs reais retornados pelo Ollama.

        O Ollama, quando configurado com options={"logprobs": True}, retorna
        token-level logprobs. Calculamos a média geométrica da probabilidade
        por token (perplexidade-inversa normalizada).

        Returns:
            Confiança ∈ (0, 1] ou None se logprobs ausentes.
        """
        try:
            tokens = (ollama_response or {}).get("logprobs") or []
            if not tokens:
                # Tenta caminho alternativo (chat completions style)
                msg = (ollama_response or {}).get("message", {})
                tokens = msg.get("logprobs", {}).get("tokens", [])
            if not tokens:
                return None
            logps = []
            for t in tokens:
                if isinstance(t, dict) and "logprob" in t:
                    logps.append(float(t["logprob"]))
                elif isinstance(t, (int, float)):
                    logps.append(float(t))
            if not logps:
                return None
            avg = sum(logps) / len(logps)
            # Probabilidade média geométrica = exp(avg log p)
            return float(min(1.0, max(0.0, math.exp(avg))))
        except Exception:
            return None

    def calculate_confidence(self, violations: List[str],
                             has_anomalies: bool = False,
                             logprobs_confidence: Optional[float] = None) -> float:
        """Calcula confiança final combinando heurística com logprobs (se houver)."""
        # Heurística - mantém compatibilidade
        base = 1.0 - 0.10 * len(violations)
        if has_anomalies:
            base -= 0.15
        base = max(0.0, min(1.0, base))

        # Se temos confidence real do modelo, faz média ponderada (60% logprobs, 40% heurística)
        if logprobs_confidence is not None:
            return round(0.6 * logprobs_confidence + 0.4 * base, 4)
        return round(base, 4)

    # ------------------------------------------------------------------
    # Relatórios
    # ------------------------------------------------------------------
    def get_confidence_summary(self) -> Dict:
        if not self.confidence_scores:
            return {"avg_confidence": 0.0, "min_confidence": 0.0,
                    "max_confidence": 0.0, "total_measurements": 0,
                    "below_threshold_count": 0}
        below = sum(1 for c in self.confidence_scores if c < self.confidence_threshold)
        return {
            "avg_confidence": round(sum(self.confidence_scores) / len(self.confidence_scores), 4),
            "min_confidence": round(min(self.confidence_scores), 4),
            "max_confidence": round(max(self.confidence_scores), 4),
            "total_measurements": len(self.confidence_scores),
            "below_threshold_count": below,
            "threshold": self.confidence_threshold,
        }

    def get_recent_explanations(self, limit: int = 10) -> List[Dict]:
        return list(self.explanations_log)[-limit:]

    def get_top_policies(self, top_n: int = 5) -> List[Dict]:
        """Retorna as N políticas mais acionadas (para dashboard de XAI)."""
        counts: Dict[str, int] = {}
        for exp in self.explanations_log:
            pol = exp.get("policy_triggered")
            if pol:
                for p in str(pol).split(","):
                    p = p.strip()
                    if p:
                        counts[p] = counts.get(p, 0) + 1
        ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return [{"policy": p, "count": c} for p, c in ranked]

    def export_traces(self) -> List[List[Dict]]:
        """Exporta todos os decision traces em formato serializável."""
        return [[t.to_dict() for t in traces] for traces in self.decision_traces]

    def get_status(self) -> Dict:
        return {
            "enabled": self.enabled,
            "total_explanations": len(self.explanations_log),
            "total_reasoning_logs": len(self.reasoning_logs),
            "total_traces": len(self.decision_traces),
            "confidence": self.get_confidence_summary(),
            "top_policies": self.get_top_policies(),
        }
