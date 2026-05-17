"""
Pilar 2: ModelOps - Métricas e Observabilidade — VERSÃO FORTALECIDA

Melhorias frente à v1:
- Drift via PSI e Jensen-Shannon Divergence (Ray 2026), não mais apenas média de comprimento.
- Baseline atualizável dinamicamente com janela móvel.
- Métricas exportáveis em formato Prometheus.
- Latência registrada como histograma (p50, p95, p99).
- Custo estimado de tokens por minuto e alerta de Unbounded Consumption (LLM10).
"""

import sys
import time
import threading
from pathlib import Path
from collections import deque
from typing import List, Dict, Any, Optional

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel
from core.metrics_lib import (
    population_stability_index,
    jensen_shannon_divergence,
    length_distribution,
)


class MetricsCollector:
    """Pilar 2 (ModelOps) - Métricas e Observabilidade."""

    def __init__(self, config: Dict):
        self.config = config
        self.modelops_config = config.get('modelops', {})
        self.monitoring_config = self.modelops_config.get('monitoring', {})

        self.metrics: Dict[str, Any] = {
            "total_requests": 0,
            "total_errors": 0,
            "total_latency_ms": 0.0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "response_times": deque(maxlen=500),
            "drift_scores_psi": deque(maxlen=50),
            "drift_scores_js": deque(maxlen=50),
            "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "token_usage_by_minute": deque(maxlen=60),
        }

        self._lock = threading.Lock()
        self.last_minute_token_count = 0
        self.last_minute_check = time.time()

        # Baseline de comprimento de mensagem (atualizado a cada N turnos)
        self._baseline_distribution: Optional[List[float]] = None
        self._baseline_size_target = self.monitoring_config.get('baseline_window', 50)
        self._baseline_buffer: deque = deque(maxlen=self._baseline_size_target)

        # Custo estimado por 1k tokens (configurável; default 0)
        self.cost_per_1k_input = self.monitoring_config.get('cost_per_1k_input_tokens', 0.0)
        self.cost_per_1k_output = self.monitoring_config.get('cost_per_1k_output_tokens', 0.0)

    # ------------------------------------------------------------------
    def record_request(self, latency_ms: float, input_tokens: int, output_tokens: int,
                       risk_level: RiskLevel, success: bool = True) -> None:
        with self._lock:
            self.metrics["total_requests"] += 1
            self.metrics["total_latency_ms"] += latency_ms
            self.metrics["total_input_tokens"] += input_tokens
            self.metrics["total_output_tokens"] += output_tokens
            self.metrics["response_times"].append(latency_ms)

            risk_key = risk_level.value
            self.metrics["risk_distribution"][risk_key] = (
                self.metrics["risk_distribution"].get(risk_key, 0) + 1
            )
            if not success:
                self.metrics["total_errors"] += 1

            self.last_minute_token_count += input_tokens + output_tokens
            now = time.time()
            if now - self.last_minute_check >= 60:
                self.metrics["token_usage_by_minute"].append(self.last_minute_token_count)
                self.last_minute_token_count = 0
                self.last_minute_check = now

    # ------------------------------------------------------------------
    # Drift estatístico — PSI + JS
    # ------------------------------------------------------------------
    def calculate_drift(self, current_messages: List[Dict],
                        bins: int = 10, max_len: int = 1000) -> Dict[str, float]:
        """Calcula drift por PSI e JS divergence sobre comprimento das mensagens.

        Mantém compatibilidade: retorna dict com chaves psi, js, score (max).
        """
        if not current_messages:
            return {"psi": 0.0, "js": 0.0, "score": 0.0}

        observed = length_distribution(current_messages, bins=bins, max_len=max_len)

        # Atualiza baseline gradualmente
        for m in current_messages:
            self._baseline_buffer.append(m)

        if (len(self._baseline_buffer) < self._baseline_size_target
                or self._baseline_distribution is None):
            # Se baseline ainda não está pronto, estabelece o atual como baseline
            self._baseline_distribution = observed
            with self._lock:
                self.metrics["drift_scores_psi"].append(0.0)
                self.metrics["drift_scores_js"].append(0.0)
            return {"psi": 0.0, "js": 0.0, "score": 0.0}

        psi = population_stability_index(self._baseline_distribution, observed)
        js = jensen_shannon_divergence(self._baseline_distribution, observed)

        with self._lock:
            self.metrics["drift_scores_psi"].append(psi)
            self.metrics["drift_scores_js"].append(js)

        # Atualiza baseline (média móvel suave)
        alpha = 0.05
        self._baseline_distribution = [
            (1 - alpha) * b + alpha * o
            for b, o in zip(self._baseline_distribution, observed)
        ]

        return {"psi": round(psi, 4), "js": round(js, 4),
                "score": round(max(psi, js), 4)}

    # ------------------------------------------------------------------
    # Percentis de latência
    # ------------------------------------------------------------------
    def latency_percentiles(self) -> Dict[str, float]:
        with self._lock:
            samples = sorted(self.metrics["response_times"])
        if not samples:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}

        def pct(p):
            k = max(0, min(len(samples) - 1, int(p / 100.0 * (len(samples) - 1))))
            return float(samples[k])

        return {"p50": round(pct(50), 2),
                "p95": round(pct(95), 2),
                "p99": round(pct(99), 2)}

    # ------------------------------------------------------------------
    def estimated_cost_usd(self) -> float:
        """Estimativa de custo em USD (LLM10 — Unbounded Consumption)."""
        with self._lock:
            it = self.metrics["total_input_tokens"]
            ot = self.metrics["total_output_tokens"]
        return round((it / 1000.0) * self.cost_per_1k_input
                     + (ot / 1000.0) * self.cost_per_1k_output, 4)

    # ------------------------------------------------------------------
    def get_summary(self) -> Dict:
        with self._lock:
            total_requests = self.metrics["total_requests"]
            avg_latency = self.metrics["total_latency_ms"] / max(1, total_requests)
            error_rate = self.metrics["total_errors"] / max(1, total_requests)
            total_tokens = self.metrics["total_input_tokens"] + self.metrics["total_output_tokens"]

            psi_recent = list(self.metrics["drift_scores_psi"])
            js_recent = list(self.metrics["drift_scores_js"])
            avg_psi = sum(psi_recent) / max(1, len(psi_recent))
            avg_js = sum(js_recent) / max(1, len(js_recent))

            response_times = list(self.metrics["response_times"])
            avg_response_time = sum(response_times) / max(1, len(response_times))

            tokens_per_min = list(self.metrics["token_usage_by_minute"])
            tpm_avg = sum(tokens_per_min) / max(1, len(tokens_per_min))

        percentiles = self.latency_percentiles()
        return {
            "total_requests": total_requests,
            "error_rate": round(error_rate, 4),
            "avg_latency_ms": round(avg_latency, 2),
            "p50_latency_ms": percentiles["p50"],
            "p95_latency_ms": percentiles["p95"],
            "p99_latency_ms": percentiles["p99"],
            "total_tokens": total_tokens,
            "input_tokens": self.metrics["total_input_tokens"],
            "output_tokens": self.metrics["total_output_tokens"],
            "avg_response_time_ms": round(avg_response_time, 2),
            "drift_psi_avg": round(avg_psi, 4),
            "drift_js_avg": round(avg_js, 4),
            "drift_score": round(max(avg_psi, avg_js), 4),
            "risk_distribution": self.metrics["risk_distribution"].copy(),
            "tokens_per_minute_avg": round(tpm_avg, 2),
            "estimated_cost_usd": self.estimated_cost_usd(),
            "error_count": self.metrics["total_errors"],
        }

    # ------------------------------------------------------------------
    def check_alerts(self) -> List[Dict]:
        alerts: List[Dict] = []
        summary = self.get_summary()

        latency_threshold = self.monitoring_config.get('latency_threshold_ms', 5000)
        if summary["p95_latency_ms"] > latency_threshold:
            alerts.append({
                "type": "high_latency_p95",
                "severity": "medium",
                "value": summary["p95_latency_ms"],
                "threshold": latency_threshold,
                "message": f"p95 latency {summary['p95_latency_ms']}ms excede {latency_threshold}ms",
            })

        # PSI > 0.25 ou JS > 0.30 → drift significativo
        if summary["drift_psi_avg"] > self.monitoring_config.get('psi_threshold', 0.25):
            alerts.append({
                "type": "high_drift_psi", "severity": "medium",
                "value": summary["drift_psi_avg"],
                "threshold": self.monitoring_config.get('psi_threshold', 0.25),
                "message": f"PSI {summary['drift_psi_avg']:.3f} indica drift significativo",
            })
        if summary["drift_js_avg"] > self.monitoring_config.get('js_threshold', 0.30):
            alerts.append({
                "type": "high_drift_js", "severity": "medium",
                "value": summary["drift_js_avg"],
                "threshold": self.monitoring_config.get('js_threshold', 0.30),
                "message": f"JS divergence {summary['drift_js_avg']:.3f} indica drift",
            })

        token_threshold = self.monitoring_config.get('token_alert_threshold', 10000)
        if summary["total_tokens"] > token_threshold:
            alerts.append({
                "type": "high_token_usage", "severity": "low",
                "value": summary["total_tokens"], "threshold": token_threshold,
                "message": f"Uso de tokens {summary['total_tokens']} excede {token_threshold} (LLM10)",
            })

        if summary["error_rate"] > 0.10:
            alerts.append({
                "type": "high_error_rate", "severity": "high",
                "value": round(summary["error_rate"] * 100, 2), "threshold": 10,
                "message": f"Taxa de erro {summary['error_rate']:.1%} excede 10%",
            })

        return alerts

    # ------------------------------------------------------------------
    def export_prometheus(self) -> str:
        """Exporta métricas em formato exposition Prometheus."""
        s = self.get_summary()
        lines = [
            f'trism_total_requests {s["total_requests"]}',
            f'trism_error_rate {s["error_rate"]}',
            f'trism_avg_latency_ms {s["avg_latency_ms"]}',
            f'trism_p95_latency_ms {s["p95_latency_ms"]}',
            f'trism_p99_latency_ms {s["p99_latency_ms"]}',
            f'trism_total_tokens {s["total_tokens"]}',
            f'trism_drift_psi {s["drift_psi_avg"]}',
            f'trism_drift_js {s["drift_js_avg"]}',
            f'trism_estimated_cost_usd {s["estimated_cost_usd"]}',
        ]
        for level, count in s["risk_distribution"].items():
            lines.append(f'trism_risk_distribution{{level="{level}"}} {count}')
        return "\n".join(lines) + "\n"

    def get_status(self) -> Dict:
        return {
            "enabled": self.modelops_config.get('enabled', True),
            "metrics_available": self.metrics["total_requests"] > 0,
            "current_summary": self.get_summary(),
            "baseline_ready": (self._baseline_distribution is not None
                                and len(self._baseline_buffer) >= self._baseline_size_target),
        }
