"""
Pilar 5: Resistência a Ataques Adversários

Responsabilidades:
- Detecção de tentativas de jailbreak
- Prevenção de ataques de repetição
- Detecção de extração de prompt do sistema
- Monitoramento de atividades suspeitas
"""

import sys
import re
import time
from pathlib import Path
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Tuple

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel


class AdversarialDetector:
    """
    Pilar 5: Resistência a Ataques Adversários
    Protege o sistema contra ataques específicos de IA
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.adversarial_config = config.get('adversarial', {})
        self.enabled = self.adversarial_config.get('enabled', True)
        
        # Histórico de atividades suspeitas
        self.suspicious_activities: List[Dict] = []
        
        # Buffer para detecção de repetição
        self.recent_responses: deque = deque(maxlen=self.adversarial_config.get('repetition_window', 100))
        
        # Carregar padrões de jailbreak
        self.jailbreak_patterns = []
        for pattern in self.adversarial_config.get('jailbreak_patterns', []):
            try:
                self.jailbreak_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                print(f"[Adversarial] Erro ao compilar padrão: {pattern}")
        
        # Palavras-chave para extração de prompt
        self.extraction_keywords = [
            "system prompt", "instructions", "rules", "guidelines",
            "what are your", "how do you work", "your programming",
            "prompt original", "instruções do sistema", "regras internas"
        ]
        
        # Estatísticas
        self.jailbreak_attempts = 0
        self.extraction_attempts = 0
        self.repetition_attacks = 0
    
    def detect_jailbreak(self, message: str) -> Tuple[bool, float, List[str]]:
        """
        Detecta tentativas de jailbreak
        
        Args:
            message: Mensagem do usuário
        
        Returns:
            (is_jailbreak, confidence, patterns_matched)
        """
        if not self.enabled:
            return False, 0.0, []
        
        patterns_matched = []
        message_lower = message.lower()
        
        for pattern in self.jailbreak_patterns:
            if pattern.search(message_lower):
                patterns_matched.append(pattern.pattern)
        
        if patterns_matched:
            self.jailbreak_attempts += 1
            # Confiança baseada no número de padrões detectados
            confidence = min(1.0, len(patterns_matched) / 3.0)
            
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "jailbreak_attempt",
                "confidence": confidence,
                "patterns": patterns_matched,
                "message_preview": message[:100]
            })
            
            return True, confidence, patterns_matched
        
        return False, 0.0, []
    
    def detect_repetition_attack(self, new_response: str) -> Tuple[bool, float]:
        """
        Detecta ataques de repetição (looping)
        
        Args:
            new_response: Nova resposta do modelo
        
        Returns:
            (is_attack, confidence)
        """
        if not self.enabled or len(self.recent_responses) < 5:
            self.recent_responses.append(new_response)
            return False, 0.0
        
        # Verificar repetição exata
        exact_matches = sum(1 for r in self.recent_responses if r == new_response)
        
        if exact_matches > 3:
            self.repetition_attacks += 1
            confidence = min(1.0, exact_matches / 10.0)
            
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "repetition_attack",
                "confidence": confidence,
                "exact_matches": exact_matches
            })
            
            return True, confidence
        
        self.recent_responses.append(new_response)
        return False, 0.0
    
    def detect_extraction_attempt(self, message: str) -> bool:
        """
        Detecta tentativas de extração de prompt do sistema
        
        Args:
            message: Mensagem do usuário
        
        Returns:
            True se tentativa de extração detectada
        """
        if not self.enabled:
            return False
        
        message_lower = message.lower()
        matches = sum(1 for kw in self.extraction_keywords if kw in message_lower)
        
        # Se múltiplas palavras-chave, é suspeito
        if matches >= 3:
            self.extraction_attempts += 1
            
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "extraction_attempt",
                "severity": "medium",
                "keywords_matched": matches,
                "message_preview": message[:100]
            })
            
            return True
        
        return False
    
    def validate_message(self, message: str) -> Dict:
        """
        Validação completa de uma mensagem contra ataques adversários
        
        Returns:
            Dict com resultados das validações
        """
        result = {
            "is_valid": True,
            "risk_level": RiskLevel.LOW,
            "jailbreak_detected": False,
            "extraction_detected": False,
            "violations": [],
            "confidence": 0.0
        }
        
        # Detectar jailbreak
        is_jailbreak, confidence, patterns = self.detect_jailbreak(message)
        if is_jailbreak:
            result["is_valid"] = False
            result["jailbreak_detected"] = True
            result["risk_level"] = RiskLevel.CRITICAL
            result["violations"].append(f"jailbreak_attempt (confidence: {confidence:.0%})")
            result["confidence"] = confidence
        
        # Detectar extração (apenas alerta, não bloqueia)
        if self.detect_extraction_attempt(message):
            result["extraction_detected"] = True
            result["violations"].append("extraction_attempt_detected")
            if result["risk_level"].value < RiskLevel.MEDIUM.value:
                result["risk_level"] = RiskLevel.MEDIUM
        
        return result
    
    def validate_response(self, response: str) -> Dict:
        """
        Valida a resposta do modelo
        
        Args:
            response: Resposta gerada pelo modelo
        
        Returns:
            Dict com resultados da validação
        """
        result = {
            "is_valid": True,
            "repetition_detected": False,
            "violations": [],
            "confidence": 0.0
        }
        
        # Detectar repetição
        is_repetition, confidence = self.detect_repetition_attack(response)
        if is_repetition:
            result["repetition_detected"] = True
            result["violations"].append(f"repetition_attack (confidence: {confidence:.0%})")
            result["confidence"] = confidence
        
        return result
    
    def get_suspicious_count(self) -> int:
        """Retorna número de atividades suspeitas detectadas"""
        return len(self.suspicious_activities)
    
    def get_status(self) -> Dict:
        """Retorna status do detector adversarial"""
        return {
            "enabled": self.enabled,
            "jailbreak_patterns_count": len(self.jailbreak_patterns),
            "jailbreak_attempts": self.jailbreak_attempts,
            "extraction_attempts": self.extraction_attempts,
            "repetition_attacks": self.repetition_attacks,
            "total_suspicious_activities": len(self.suspicious_activities),
            "recent_responses_buffer": len(self.recent_responses)
        }