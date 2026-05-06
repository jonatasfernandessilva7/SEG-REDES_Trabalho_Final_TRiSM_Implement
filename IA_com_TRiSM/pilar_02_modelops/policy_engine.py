"""
Pilar 2: ModelOps - Políticas como Código

Responsabilidades:
- Rate limiting por sessão/usuário
- Aplicação de cadeia de políticas
- Registro de decisões de política
"""

import sys
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel


class PolicyEngine:
    """
    Pilar 2 (ModelOps) - Políticas como código
    Gerencia regras de governança e decisões de aprovação/bloqueio
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.policies_log: List[Dict] = []
        self.custom_policies: Dict[str, callable] = {}
        
        # Rate limiting
        self.rate_limit_config = config.get('modelops', {}).get('rate_limiting', {})
        self.request_history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        
        # Limites da sessão
        self.modelops_config = config.get('modelops', {})
    
    def check_rate_limit(self, session_id: str) -> Tuple[bool, Dict]:
        """
        Verifica limite de taxa por sessão (R18)
        
        Args:
            session_id: Identificador único da sessão
        
        Returns:
            (allowed, status_info)
        """
        if not self.rate_limit_config.get('enabled', True):
            return True, {}
        
        with self._lock:
            now = time.time()
            window = self.rate_limit_config.get('window_seconds', 60)
            limit = self.rate_limit_config.get('requests_per_minute', 30)
            
            if session_id not in self.request_history:
                self.request_history[session_id] = []
            
            # Limpar requisições antigas
            self.request_history[session_id] = [
                ts for ts in self.request_history[session_id] 
                if now - ts < window
            ]
            
            allowed = len(self.request_history[session_id]) < limit
            
            if allowed:
                self.request_history[session_id].append(now)
            
            # Calcular tempo de reset
            reset_in = 0
            if self.request_history[session_id]:
                reset_in = window - (now - self.request_history[session_id][0])
            
            status = {
                "allowed": allowed,
                "current_requests": len(self.request_history[session_id]),
                "limit": limit,
                "remaining": max(0, limit - len(self.request_history[session_id])),
                "reset_in_seconds": max(0, round(reset_in))
            }
            
            # Registrar log da política
            self._log_policy("rate_limit", session_id, allowed, status)
            
            return allowed, status
    
    def _log_policy(self, policy_name: str, session_id: str, allowed: bool, details: Dict):
        """Registra aplicação de política"""
        self.policies_log.append({
            "timestamp": datetime.now().isoformat(),
            "policy": policy_name,
            "session_id": session_id,
            "allowed": allowed,
            "details": details
        })
    
    def register_policy(self, name: str, policy_func: callable):
        """Registra uma política personalizada"""
        self.custom_policies[name] = policy_func
    
    def apply_policy_chain(self, message: str, session_id: str) -> Dict:
        """
        Aplica cadeia de políticas na mensagem
        
        Returns:
            Dict com resultado da validação
        """
        result = {
            "allowed": True,
            "risk_level": RiskLevel.LOW,
            "violations": [],
            "policies_triggered": [],
            "sanitized_message": message
        }
        
        # Rate limit policy
        rate_allowed, rate_status = self.check_rate_limit(session_id)
        if not rate_allowed:
            result["allowed"] = False
            result["risk_level"] = RiskLevel.MEDIUM
            result["violations"].append({
                "policy": "rate_limit",
                "details": f"Rate limit exceeded: {rate_status['current_requests']}/{rate_status['limit']}"
            })
            result["policies_triggered"].append("rate_limit_exceeded")
            return result
        
        # Aplicar políticas personalizadas registradas
        for policy_name, policy_func in self.custom_policies.items():
            policy_result = policy_func(message, session_id)
            if not policy_result.get("allowed", True):
                result["allowed"] = False
                result["violations"].append({
                    "policy": policy_name,
                    "details": policy_result.get("reason", "Policy violation")
                })
                result["policies_triggered"].append(policy_name)
                
                # Atualizar nível de risco
                if policy_result.get("risk_level", RiskLevel.LOW).value > result["risk_level"].value:
                    result["risk_level"] = policy_result["risk_level"]
        
        return result
    
    def get_policy_logs(self, limit: int = 100) -> List[Dict]:
        """Retorna logs de políticas aplicadas"""
        return self.policies_log[-limit:]
    
    def get_status(self) -> Dict:
        """Retorna status do motor de políticas"""
        active_sessions = len(self.request_history)
        total_logs = len(self.policies_log)
        
        return {
            "enabled": self.modelops_config.get('enabled', True),
            "rate_limiting_enabled": self.rate_limit_config.get('enabled', True),
            "rate_limit_per_minute": self.rate_limit_config.get('requests_per_minute', 30),
            "active_sessions": active_sessions,
            "total_policy_logs": total_logs,
            "custom_policies_count": len(self.custom_policies)
        }