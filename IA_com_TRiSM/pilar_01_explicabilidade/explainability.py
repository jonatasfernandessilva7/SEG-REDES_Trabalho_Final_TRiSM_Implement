"""
Pilar 1: Explicabilidade e Transparência (XAI)

Responsabilidades:
- Registrar raciocínio do modelo (chain-of-thought)
- Gerar explicações de decisões (bloqueios, aprovações)
- Calcular confidence scores
- Rastrear quais políticas foram acionadas
"""

import sys
from pathlib import Path

# Adiciona o diretório raiz ao path
sys.path.append(str(Path(__file__).parent.parent))

from datetime import datetime
from typing import List, Dict, Any, Optional
from core.base import RiskLevel


class ExplainabilityEngine:
    """
    Pilar 1: Explicabilidade e Transparência
    Torna o sistema compreensível para humanos
    """
    
    def __init__(self, config: Dict):
        self.config = config.get('explainability', {})
        self.enabled = self.config.get('enabled', True)
        self.explanations_log: List[Dict] = []
        self.confidence_scores: List[float] = []
        self.reasoning_logs: List[Dict] = []
    
    def generate_explanation(self, action: str, reason: str, policy_triggered: str = None,
                            confidence: float = 0.0, details: Dict = None) -> Dict:
        """
        Gera explicação para uma decisão do sistema
        
        Args:
            action: Ação tomada (block, allow, alert)
            reason: Razão textual da decisão
            policy_triggered: Qual política foi acionada
            confidence: Nível de confiança (0-1)
            details: Detalhes adicionais
        
        Returns:
            Dicionário com a explicação gerada
        """
        if not self.enabled:
            return {}
        
        explanation = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "reason": reason,
            "confidence": confidence,
            "policy_triggered": policy_triggered,
            "details": details or {}
        }
        
        self.explanations_log.append(explanation)
        
        if confidence > 0:
            self.confidence_scores.append(confidence)
        
        return explanation
    
    def log_reasoning(self, prompt: str, response: str, reasoning_steps: List[str] = None):
        """
        Registra o raciocínio do modelo (chain-of-thought)
        """
        if not self.enabled:
            return
        
        self.reasoning_logs.append({
            "timestamp": datetime.now().isoformat(),
            "type": "reasoning",
            "prompt_preview": prompt[:200],
            "response_preview": response[:200],
            "reasoning_steps": reasoning_steps or []
        })
    
    def get_confidence_summary(self) -> Dict:
        """Retorna resumo das métricas de confiança"""
        if not self.confidence_scores:
            return {
                "avg_confidence": 0.0,
                "min_confidence": 0.0,
                "max_confidence": 0.0,
                "total_measurements": 0
            }
        
        return {
            "avg_confidence": round(sum(self.confidence_scores) / len(self.confidence_scores), 4),
            "min_confidence": round(min(self.confidence_scores), 4),
            "max_confidence": round(max(self.confidence_scores), 4),
            "total_measurements": len(self.confidence_scores)
        }
    
    def calculate_confidence(self, violations: List[str], has_anomalies: bool = False) -> float:
        """
        Calcula confidence score baseado em violações e anomalias
        
        Args:
            violations: Lista de violações detectadas
            has_anomalies: Se houve anomalias na resposta
        
        Returns:
            Confidence score entre 0 e 1
        """
        base_confidence = 1.0
        
        # Penalidade por violações
        penalty = len(violations) * 0.1
        base_confidence -= penalty
        
        # Penalidade por anomalias
        if has_anomalies:
            base_confidence -= 0.15
        
        return max(0.0, min(1.0, base_confidence))
    
    def get_recent_explanations(self, limit: int = 10) -> List[Dict]:
        """Retorna explicações recentes"""
        return self.explanations_log[-limit:]
    
    def get_status(self) -> Dict:
        """Retorna status do pilar"""
        return {
            "enabled": self.enabled,
            "total_explanations": len(self.explanations_log),
            "total_reasoning_logs": len(self.reasoning_logs),
            "confidence": self.get_confidence_summary()
        }