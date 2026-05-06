"""
Pilar 2: ModelOps - Métricas e Observabilidade

Responsabilidades:
- Coleta de métricas de performance (latência, tokens)
- Detecção de deriva (drift)
- Alertas automáticos
- Dashboard de métricas
"""

import sys
import time
import threading
from pathlib import Path
from collections import deque
from typing import List, Dict, Any

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel


class MetricsCollector:
    """
    Pilar 2 (ModelOps) - Métricas e Observabilidade
    Coleta e disponibiliza métricas do sistema
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.modelops_config = config.get('modelops', {})
        self.monitoring_config = self.modelops_config.get('monitoring', {})
        
        self.metrics = {
            "total_requests": 0,
            "total_errors": 0,
            "total_latency_ms": 0.0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "response_times": deque(maxlen=100),
            "drift_scores": deque(maxlen=50),
            "risk_distribution": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            "token_usage_by_minute": deque(maxlen=60)
        }
        
        self._lock = threading.Lock()
        self.last_minute_token_count = 0
        self.last_minute_check = time.time()
    
    def record_request(self, latency_ms: float, input_tokens: int, output_tokens: int,
                       risk_level: RiskLevel, success: bool = True):
        """
        Registra métricas de uma requisição
        
        Args:
            latency_ms: Latência em milissegundos
            input_tokens: Tokens de entrada
            output_tokens: Tokens de saída
            risk_level: Nível de risco da interação
            success: Se a requisição foi bem sucedida
        """
        with self._lock:
            self.metrics["total_requests"] += 1
            self.metrics["total_latency_ms"] += latency_ms
            self.metrics["total_input_tokens"] += input_tokens
            self.metrics["total_output_tokens"] += output_tokens
            self.metrics["response_times"].append(latency_ms)
            
            risk_key = risk_level.value
            self.metrics["risk_distribution"][risk_key] = self.metrics["risk_distribution"].get(risk_key, 0) + 1
            
            if not success:
                self.metrics["total_errors"] += 1
            
            # Rastreamento por minuto
            self.last_minute_token_count += input_tokens + output_tokens
            now = time.time()
            if now - self.last_minute_check >= 60:
                self.metrics["token_usage_by_minute"].append(self.last_minute_token_count)
                self.last_minute_token_count = 0
                self.last_minute_check = now
    
    def calculate_drift(self, current_messages: List[Dict]) -> float:
        """
        Calcula deriva baseada em padrões de mensagem (R5)
        
        Args:
            current_messages: Histórico atual de mensagens
        
        Returns:
            Drift score entre 0 e 1
        """
        if not current_messages:
            return 0.0
        
        lengths = [len(msg.get("content", "")) for msg in current_messages]
        if not lengths:
            return 0.0
        
        current_mean = sum(lengths) / len(lengths)
        baseline_mean = 100.0  # Baseline empírico
        
        drift = min(1.0, abs(current_mean - baseline_mean) / baseline_mean)
        
        with self._lock:
            self.metrics["drift_scores"].append(drift)
        
        return drift
    
    def get_summary(self) -> Dict:
        """Retorna resumo das métricas para dashboard"""
        with self._lock:
            total_requests = self.metrics["total_requests"]
            avg_latency = self.metrics["total_latency_ms"] / max(1, total_requests)
            error_rate = self.metrics["total_errors"] / max(1, total_requests)
            total_tokens = self.metrics["total_input_tokens"] + self.metrics["total_output_tokens"]
            
            recent_drifts = list(self.metrics["drift_scores"])
            avg_drift = sum(recent_drifts) / max(1, len(recent_drifts))
            
            return {
                "total_requests": total_requests,
                "error_rate": round(error_rate, 4),
                "avg_latency_ms": round(avg_latency, 2),
                "total_tokens": total_tokens,
                "avg_response_time_ms": round(sum(self.metrics["response_times"]) / max(1, len(self.metrics["response_times"])), 2),
                "drift_score": round(avg_drift, 4),
                "risk_distribution": self.metrics["risk_distribution"].copy(),
                "tokens_per_minute_avg": round(sum(self.metrics["token_usage_by_minute"]) / max(1, len(self.metrics["token_usage_by_minute"])), 2),
                "error_count": self.metrics["total_errors"]
            }
    
    def check_alerts(self) -> List[Dict]:
        """Verifica condições de alerta e retorna alertas ativos"""
        alerts = []
        summary = self.get_summary()
        
        # Verificar latência
        latency_threshold = self.monitoring_config.get('latency_threshold_ms', 5000)
        if summary["avg_latency_ms"] > latency_threshold:
            alerts.append({
                "type": "high_latency",
                "severity": "medium",
                "value": summary["avg_latency_ms"],
                "threshold": latency_threshold,
                "message": f"Latência média {summary['avg_latency_ms']}ms excede limite {latency_threshold}ms"
            })
        
        # Verificar drift
        drift_threshold = self.monitoring_config.get('drift_threshold', 0.3)
        if summary["drift_score"] > drift_threshold:
            alerts.append({
                "type": "high_drift",
                "severity": "medium",
                "value": summary["drift_score"],
                "threshold": drift_threshold,
                "message": f"Drift score {summary['drift_score']:.2%} excede limite {drift_threshold:.0%}"
            })
        
        # Verificar tokens
        token_threshold = self.monitoring_config.get('token_alert_threshold', 10000)
        if summary["total_tokens"] > token_threshold:
            alerts.append({
                "type": "high_token_usage",
                "severity": "low",
                "value": summary["total_tokens"],
                "threshold": token_threshold,
                "message": f"Uso de tokens {summary['total_tokens']} excede limite {token_threshold}"
            })
        
        # Verificar taxa de erro
        if summary["error_rate"] > 0.1:  # 10% de erro
            alerts.append({
                "type": "high_error_rate",
                "severity": "high",
                "value": round(summary["error_rate"] * 100, 2),
                "threshold": 10,
                "message": f"Taxa de erro {summary['error_rate']:.1%} excede 10%"
            })
        
        return alerts
    
    def get_status(self) -> Dict:
        """Retorna status do coletor de métricas"""
        return {
            "enabled": self.modelops_config.get('enabled', True),
            "metrics_available": self.metrics["total_requests"] > 0,
            "current_summary": self.get_summary()
        }