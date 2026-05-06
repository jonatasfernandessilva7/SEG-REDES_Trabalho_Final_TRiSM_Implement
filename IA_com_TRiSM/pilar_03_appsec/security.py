"""
Pilar 3: Segurança de Aplicação (AppSec)

Responsabilidades:
- Detecção de injeção de prompt
- Detecção de conteúdo tóxico
- Sanitização de entrada e saída
- Isolamento de contexto
"""

import sys
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel


class SecurityLayer:
    """
    Pilar 3: Segurança de Aplicação
    Protege o sistema contra ataques comuns de aplicações de IA
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.appsec_config = config.get('appsec', {})
        self.enabled = self.appsec_config.get('enabled', True)
        
        # Carregar padrões bloqueados para injeção de prompt
        self.blocked_patterns = []
        for pattern in self.appsec_config.get('blocked_patterns', []):
            try:
                self.blocked_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                print(f"[Security] Erro ao compilar padrão: {pattern}")
        
        # Carregar termos tóxicos
        self.toxic_terms = config.get('toxicity', {}).get('blocked_terms', [])
        
        # Estatísticas
        self.injection_attempts = 0
        self.toxicity_alerts = 0
        self.sanitized_messages = 0
    
    def detect_injection(self, message: str) -> Tuple[bool, List[str], RiskLevel]:
        """
        Detecta tentativas de injeção de prompt
        
        Returns:
            (is_injection, patterns_matched, risk_level)
        """
        if not self.enabled:
            return False, [], RiskLevel.LOW
        
        patterns_matched = []
        message_lower = message.lower()
        
        for pattern in self.blocked_patterns:
            if pattern.search(message_lower):
                patterns_matched.append(pattern.pattern)
        
        if patterns_matched:
            self.injection_attempts += 1
            # Quanto mais padrões, maior o risco
            risk = RiskLevel.HIGH if len(patterns_matched) >= 2 else RiskLevel.MEDIUM
            return True, patterns_matched, risk
        
        return False, [], RiskLevel.LOW
    
    def detect_toxicity(self, message: str) -> Tuple[bool, List[str], RiskLevel]:
        """
        Detecta conteúdo tóxico na mensagem
        
        Returns:
            (is_toxic, terms_found, risk_level)
        """
        if not self.enabled:
            return False, [], RiskLevel.LOW
        
        toxic_found = []
        message_lower = message.lower()
        
        for term in self.toxic_terms:
            if term.lower() in message_lower:
                toxic_found.append(term)
        
        if toxic_found:
            self.toxicity_alerts += 1
            # Quanto mais termos tóxicos, maior o risco
            risk = RiskLevel.HIGH if len(toxic_found) >= 3 else RiskLevel.MEDIUM
            return True, toxic_found, risk
        
        return False, [], RiskLevel.LOW
    
    def sanitize_input(self, message: str) -> str:
        """
        Sanitiza entrada (remove caracteres potencialmente maliciosos)
        """
        if not self.appsec_config.get('sanitize_input', True):
            return message
        
        # Remover caracteres de controle
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', message)
        
        # Limitar tamanho
        max_length = self.appsec_config.get('max_message_length', 4000)
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "\n... [MENSAGEM TRUNCADA]"
            self.sanitized_messages += 1
        
        return sanitized
    
    def sanitize_output(self, response: str) -> str:
        """
        Sanitiza saída do modelo
        """
        if not self.appsec_config.get('sanitize_output', True):
            return response
        
        # Remover blocos de código potencialmente perigosos (opcional)
        # sanitized = re.sub(r'```.*?```', '[CODE_BLOCK_REMOVED]', response, flags=re.DOTALL)
        
        # Por ora, apenas retorna a resposta sem grandes modificações
        # para não prejudicar a experiência do usuário
        return response
    
    def validate_message(self, message: str) -> Dict:
        """
        Validação completa de uma mensagem
        
        Returns:
            Dict com resultados das validações
        """
        result = {
            "is_valid": True,
            "risk_level": RiskLevel.LOW,
            "injection_detected": False,
            "toxicity_detected": False,
            "violations": [],
            "sanitized_message": self.sanitize_input(message)
        }
        
        # Detectar injeção
        is_injection, patterns, inj_risk = self.detect_injection(message)
        if is_injection:
            result["is_valid"] = False
            result["injection_detected"] = True
            result["risk_level"] = max(result["risk_level"], inj_risk)
            result["violations"].append(f"injection: {patterns}")
        
        # Detectar toxicidade
        is_toxic, terms, tox_risk = self.detect_toxicity(message)
        if is_toxic:
            result["is_valid"] = False
            result["toxicity_detected"] = True
            result["risk_level"] = max(result["risk_level"], tox_risk)
            result["violations"].append(f"toxic: {terms}")
        
        return result
    
    def get_status(self) -> Dict:
        """Retorna status do pilar de segurança"""
        return {
            "enabled": self.enabled,
            "blocked_patterns_count": len(self.blocked_patterns),
            "toxic_terms_count": len(self.toxic_terms),
            "injection_attempts": self.injection_attempts,
            "toxicity_alerts": self.toxicity_alerts,
            "sanitized_messages": self.sanitized_messages,
            "max_message_length": self.appsec_config.get('max_message_length', 4000)
        }