"""
Pilar 3: Segurança de Aplicação (AppSec)

- Detecção de encoding tricks: Base64, Hex, Unicode invisível, ROT13 (Sebok & Wibowo 2026).
- Output validator: detecta vazamento de PII na saída, secrets, URLs suspeitas.
- Hierarquia de instruções com tags estruturadas (PALADIN Layer 2).
- Sanitização preserva semântica (não destrói código legítimo desnecessariamente).
- Detecção de prompt injection indireto (texto vindo de RAG/arquivos).
"""

import sys
import re
import codecs
import json
from pathlib import Path
from typing import List, Dict, Tuple
from functools import lru_cache

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel, DecisionTrace
from core.metrics_lib import (
    detect_base64_payload,
    detect_hex_payload,
    detect_invisible_chars,
    normalize_unicode,
)


class SecurityLayer:
    """Pilar 3: Segurança de Aplicação."""

    # Padrões para vazamento na saída (LLM02 / LLM05)
    # URL genérica removida: flagear toda URL gera alto FPR.
    # Só endereços internos/privados são suspeitos na saída do modelo.
    _OUTPUT_LEAK_PATTERNS = [
        (re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*\S{8,}"), "credential"),
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private_key"),
        (re.compile(
            r"https?://(?:"
            r"localhost"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|0\.0\.0\.0"
            r")(?::\d+)?(?:/[^\s<>\"]*)?",
            re.IGNORECASE
        ), "internal_url"),
        (re.compile(r"(?i)\b(?:rm\s+-rf|sudo\s+|chmod\s+777|drop\s+table\s+|--exec)"), "dangerous_command"),
    ]

    def __init__(self, config: Dict):
        self.config = config
        self.appsec_config = config.get('appsec', {})
        self.enabled = self.appsec_config.get('enabled', True)

        self.blocked_patterns: List[re.Pattern] = []
        for pattern in self.appsec_config.get('blocked_patterns', []):
            try:
                self.blocked_patterns.append(re.compile(pattern, re.IGNORECASE))
            except re.error:
                print(f"[Security] Erro ao compilar padrão: {pattern}")

        self.indirect_injection_markers = self.appsec_config.get(
            'indirect_injection_markers',
            ["[SYSTEM]", "[INSTRUCTION]", "<!-- system:", "###system###"])

        self.toxic_terms = config.get('toxicity', {}).get('blocked_terms', [])

        # Política de hierarquia (PALADIN Layer 2)
        self.use_hierarchy = self.appsec_config.get('use_prompt_hierarchy', True)

        # Estatísticas
        self.injection_attempts = 0
        self.toxicity_alerts = 0
        self.encoding_attempts = 0
        self.output_violations = 0
        self.sanitized_messages = 0
        
    @lru_cache(maxsize=256)
    def _cached_detect_injection(self, message: str) -> Tuple[bool, str, RiskLevel, str]:
        """Retorna versão serializada para cache (evita objetos não hashable)."""
        is_inj, patterns, risk, traces = self.detect_injection(message)
        # Serializa traces como string (mas traces raramente usados no cache)
        return is_inj, ",".join(patterns), risk, ""

    def detect_injection(self, message: str) -> Tuple[bool, List[str], RiskLevel, List[DecisionTrace]]:
        if not self.enabled:
            return False, [], RiskLevel.LOW, []

        is_inj, patterns_str, risk, _ = self._cached_detect_injection(message)
        patterns = patterns_str.split(",") if patterns_str else []
        return is_inj, patterns, risk, []

    @lru_cache(maxsize=256)
    def _cached_detect_indirect_injection(self, message: str) -> Tuple[bool, str]:
        found, markers = self.detect_indirect_injection(message)
        return found, ",".join(markers)

    def detect_indirect_injection(self, message: str) -> Tuple[bool, List[str]]:
        if not self.enabled:
            return False, []
        found, markers_str = self._cached_detect_indirect_injection(message)
        markers = markers_str.split(",") if markers_str else []
        return found, markers

    def _detect_rot13_payload(self, text: str) -> List[str]:
        """Decodifica ROT13 e verifica se o resultado aciona padrões bloqueados.

        Estratégia: aplica ROT13 ao texto completo e testa os blocked_patterns
        e toxic_terms no resultado — detecta ataques como "vtaber nyy ehyrf" →
        "ignore all rules".
        """
        try:
            decoded = codecs.decode(text, "rot13")
            decoded_lower = decoded.lower()
            hits: List[str] = []
            for pattern in self.blocked_patterns:
                if pattern.search(decoded_lower):
                    hits.append(f"rot13→{pattern.pattern[:40]}")
            for term in self.toxic_terms:
                if re.search(r'\b' + re.escape(term.lower()) + r'\b', decoded_lower):
                    hits.append(f"rot13→toxic:{term}")
            return hits
        except Exception:
            return []

    @lru_cache(maxsize=256)
    def _cached_detect_encoding_tricks(self, message: str) -> Tuple[bool, str]:
        found, details = self.detect_encoding_tricks(message)
        return found, json.dumps(details)
    
    def detect_encoding_tricks(self, message: str) -> Tuple[bool, Dict[str, List[str]]]:
        if not self.enabled:
            return False, {}
        found, details_json = self._cached_detect_encoding_tricks(message)
        details = json.loads(details_json) if details_json else {}
        return found, details

    @lru_cache(maxsize=256)
    def _cached_detect_toxicity(self, message: str) -> Tuple[bool, str, str]:
        is_tox, terms, risk = self.detect_toxicity(message)
        return is_tox, ",".join(terms), risk.value

    def detect_toxicity(self, message: str) -> Tuple[bool, List[str], RiskLevel]:
        if not self.enabled:
            return False, [], RiskLevel.LOW
        is_tox, terms_str, risk_val = self._cached_detect_toxicity(message)
        terms = terms_str.split(",") if terms_str else []
        return is_tox, terms, RiskLevel(risk_val)

    def validate_output(self, response: str) -> Tuple[bool, List[Dict]]:
        """Detecta vazamentos perigosos na saída do modelo."""
        if not self.enabled or not self.appsec_config.get('output_validation', True):
            return True, []
        violations: List[Dict] = []
        for pattern, kind in self._OUTPUT_LEAK_PATTERNS:
            for match in pattern.findall(response):
                preview = match if isinstance(match, str) else str(match)
                violations.append({"kind": kind, "evidence": preview[:60] + "..."})

        # Decodificação na saída (modelo regurgitando base64 com instruções escondidas)
        b64 = detect_base64_payload(response, min_decoded_len=24)
        if b64:
            violations.append({"kind": "encoded_output", "evidence": b64[0]})

        if violations:
            self.output_violations += 1
        return (len(violations) == 0), violations

    def sanitize_input(self, message: str) -> str:
        if not self.appsec_config.get('sanitize_input', True):
            return message
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', message)
        sanitized = normalize_unicode(sanitized)
        max_length = self.appsec_config.get('max_message_length', 4000)
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "\n... [MENSAGEM TRUNCADA]"
            self.sanitized_messages += 1
        return sanitized

    def sanitize_output(self, response: str) -> str:
        """Remove evidências sensíveis detectadas na saída (placeholder substitui credenciais)."""
        if not self.appsec_config.get('sanitize_output', True):
            return response
        sanitized = response
        for pattern, kind in self._OUTPUT_LEAK_PATTERNS:
            if kind in ("credential", "private_key"):
                sanitized = pattern.sub(f"[REDACTED_{kind.upper()}]", sanitized)
        return sanitized

    def wrap_user_input(self, message: str) -> str:
        """Encapsula entrada do usuário em estrutura hierárquica para o modelo entender níveis.

        Convenção: System (level 0) > User (level 1) > External/Untrusted (level 2).
        """
        if not self.use_hierarchy:
            return message
        return (
            "<user_input level=\"1\" trust=\"untrusted\">\n"
            f"{message}\n"
            "</user_input>"
        )

    def validate_message(self, message: str) -> Dict:
        result = {
            "is_valid": True,
            "risk_level": RiskLevel.LOW,
            "injection_detected": False,
            "toxicity_detected": False,
            "encoding_detected": False,
            "indirect_injection": False,
            "violations": [],
            "traces": [],
            "sanitized_message": self.sanitize_input(message),
        }

        is_inj, patterns, risk_inj, traces_inj = self.detect_injection(message)
        if is_inj:
            result["is_valid"] = False
            result["injection_detected"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], risk_inj)
            result["violations"].append(f"injection: {patterns}")
            result["traces"].extend(traces_inj)

        is_toxic, terms, risk_tox = self.detect_toxicity(message)
        if is_toxic:
            result["is_valid"] = False
            result["toxicity_detected"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], risk_tox)
            result["violations"].append(f"toxic: {terms}")

        encoded, encoding_details = self.detect_encoding_tricks(message)
        if encoded:
            result["encoding_detected"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], RiskLevel.HIGH)
            result["violations"].append(f"encoding: {list(encoding_details.keys())}")
            # Encoding com decoded text suspeito é bloqueante por default
            if self.appsec_config.get('block_encoded_payloads', True):
                result["is_valid"] = False

        indirect, markers = self.detect_indirect_injection(message)
        if indirect:
            result["indirect_injection"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], RiskLevel.HIGH)
            result["violations"].append(f"indirect_injection: {markers}")
            if self.appsec_config.get('block_indirect_injection', True):
                result["is_valid"] = False

        return result

    def get_status(self) -> Dict:
        return {
            "enabled": self.enabled,
            "blocked_patterns_count": len(self.blocked_patterns),
            "toxic_terms_count": len(self.toxic_terms),
            "injection_attempts": self.injection_attempts,
            "toxicity_alerts": self.toxicity_alerts,
            "encoding_attempts": self.encoding_attempts,
            "output_violations": self.output_violations,
            "sanitized_messages": self.sanitized_messages,
            "max_message_length": self.appsec_config.get('max_message_length', 4000),
            "use_prompt_hierarchy": self.use_hierarchy,
        }
