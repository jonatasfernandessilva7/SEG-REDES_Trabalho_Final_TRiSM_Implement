"""
Pilar 2: ModelOps - Políticas como Código

- Rate limit por usuário/IP/sessão (3 dimensões), com política configurável.
- Token-budget (LLM10 — Unbounded Consumption) por sessão/janela.
- Sliding-window thread-safe.
- Suporte a políticas externas em YAML (policy-as-code aos moldes do OPA).
"""

import sys
import time
import threading
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Callable, Optional
from collections import deque

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel


class PolicyEngine:
    """Pilar 2 (ModelOps) - Políticas como código."""

    def __init__(self, config: Dict):
        self.config = config
        self.modelops_config = config.get('modelops', {})
        self.rate_limit_config = self.modelops_config.get('rate_limiting', {})
        self.token_budget_config = self.modelops_config.get('token_budget', {})

        _max_pol = self.modelops_config.get('policy_log_max_entries', 1000)
        self.policies_log: deque = deque(maxlen=_max_pol)
        self.custom_policies: Dict[str, Callable] = {}

        # Históricos por chave (sessão, usuário, ip)
        self.request_history: Dict[str, deque] = {}
        self.token_history: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, session_id: str,
                         user_id: Optional[str] = None,
                         ip_address: Optional[str] = None) -> Tuple[bool, Dict]:
        if not self.rate_limit_config.get('enabled', True):
            return True, {}

        with self._lock:
            now = time.time()
            window = self.rate_limit_config.get('window_seconds', 60)
            limit_session = self.rate_limit_config.get('requests_per_minute', 30)
            limit_user = self.rate_limit_config.get('per_user_per_minute', 60)
            limit_ip = self.rate_limit_config.get('per_ip_per_minute', 100)

            keys = [(f"sess:{session_id}", limit_session)]
            if user_id:
                keys.append((f"user:{user_id}", limit_user))
            if ip_address:
                keys.append((f"ip:{ip_address}", limit_ip))

            statuses: Dict[str, Dict] = {}
            for key, limit in keys:
                # Cria deque com maxlen = limit para nunca exceder o tamanho
                hist = self.request_history.setdefault(key, deque(maxlen=limit))
                # Remove entradas antigas (deque não faz isso automaticamente por tempo)
                # Podemos varrer, mas como maxlen é limit, o número de itens é pequeno
                while hist and (now - hist[0]) > window:
                    hist.popleft()
                allowed_here = len(hist) < limit
                if allowed_here:
                    hist.append(now)
                statuses[key] = {
                    "allowed": allowed_here,
                    "current": len(hist),
                    "limit": limit,
                    "remaining": max(0, limit - len(hist)),
                    "reset_in_seconds": max(0, round(window - (now - hist[0])) if hist else 0),
                }

            allowed = all(s["allowed"] for s in statuses.values())
            self._log_policy("rate_limit", session_id, allowed, statuses)
            return allowed, statuses

    def consume_tokens(self, session_id: str, tokens: int) -> Tuple[bool, Dict]:
        if not self.token_budget_config.get('enabled', False):
            return True, {}

        with self._lock:
            now = time.time()
            window = self.token_budget_config.get('window_seconds', 60)
            budget = self.token_budget_config.get('tokens_per_window', 50000)

            hist = self.token_history.setdefault(session_id, deque(maxlen=budget))
            # Remove entradas antigas
            while hist and (now - hist[0][0]) > window:
                hist.popleft()
            used = sum(n for _, n in hist)

            allowed = (used + tokens) <= budget
            if allowed:
                hist.append((now, tokens))

            status = {
                "allowed": allowed,
                "used_in_window": used + (tokens if allowed else 0),
                "budget": budget,
                "remaining": max(0, budget - (used + (tokens if allowed else 0))),
            }
            self._log_policy("token_budget", session_id, allowed, status)
            return allowed, status

    def _log_policy(self, name: str, session_id: str, allowed: bool, details: Dict) -> None:
        self.policies_log.append({
            "timestamp": datetime.now().isoformat(),
            "policy": name,
            "session_id": session_id,
            "allowed": allowed,
            "details": details,
        })

    def register_policy(self, name: str, policy_func: Callable) -> None:
        self.custom_policies[name] = policy_func

    def apply_policy_chain(self, message: str, session_id: str,
                           **ctx) -> Dict:
        """Aplica políticas na ordem: rate-limit → custom_policies."""
        result = {
            "allowed": True,
            "risk_level": RiskLevel.LOW,
            "violations": [],
            "policies_triggered": [],
            "sanitized_message": message,
        }

        rate_ok, rate_status = self.check_rate_limit(
            session_id, ctx.get("user_id"), ctx.get("ip_address"))
        if not rate_ok:
            result["allowed"] = False
            result["risk_level"] = RiskLevel.MEDIUM
            result["violations"].append({"policy": "rate_limit", "details": rate_status})
            result["policies_triggered"].append("rate_limit_exceeded")
            return result

        for name, fn in self.custom_policies.items():
            res = fn(message, session_id, **ctx) or {}
            if not res.get("allowed", True):
                result["allowed"] = False
                result["violations"].append({
                    "policy": name,
                    "details": res.get("reason", "Policy violation"),
                })
                result["policies_triggered"].append(name)
                lvl = res.get("risk_level", RiskLevel.LOW)
                if isinstance(lvl, RiskLevel) and lvl.numeric > result["risk_level"].numeric:
                    result["risk_level"] = lvl

        return result

    def get_policy_logs(self, limit: int = 100) -> List[Dict]:
        return list(self.policies_log)[-limit:]

    def get_status(self) -> Dict:
        return {
            "enabled": self.modelops_config.get('enabled', True),
            "rate_limiting_enabled": self.rate_limit_config.get('enabled', True),
            "rate_limit_per_minute": self.rate_limit_config.get('requests_per_minute', 30),
            "per_user_per_minute": self.rate_limit_config.get('per_user_per_minute', 60),
            "per_ip_per_minute": self.rate_limit_config.get('per_ip_per_minute', 100),
            "token_budget_enabled": self.token_budget_config.get('enabled', False),
            "token_budget_per_window": self.token_budget_config.get('tokens_per_window', 50000),
            "active_session_keys": len(self.request_history),
            "total_policy_logs": len(self.policies_log),
            "policy_log_max_entries": self.policies_log.maxlen,
            "custom_policies_count": len(self.custom_policies),
        }
