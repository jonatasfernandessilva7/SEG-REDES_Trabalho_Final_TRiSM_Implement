"""
Pilar 4: Proteção de Dados e Privacidade — VERSÃO FORTALECIDA

Melhorias frente à v1:
- PII brasileiro completo (CPF, CNPJ, RG, CNH, PIS/PASEP, título de eleitor, CEP, telefone).
- Validação de checksum em CPF e CNPJ para reduzir falsos positivos (Sheng et al. 2025).
- Pseudonimização determinística (mesma PII → mesmo placeholder).
- Consent não-bloqueante: aceita "auto", "deny" ou prompt interativo.
- Auditoria por categoria de PII (relatório por tipo).
- LGPD compliance: campo "purpose" obrigatório no consent.
"""

import sys
import re
import hashlib
from collections import deque
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional

sys.path.append(str(Path(__file__).parent.parent))


# ============================================
# Validadores de checksum
# ============================================
def _validate_cpf(cpf: str) -> bool:
    """Valida CPF pelo dígito verificador (reduz falsos positivos)."""
    digits = re.sub(r"\D", "", cpf)
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    s1 = sum(int(d) * (10 - i) for i, d in enumerate(digits[:9]))
    d1 = (s1 * 10) % 11 % 10
    if d1 != int(digits[9]):
        return False
    s2 = sum(int(d) * (11 - i) for i, d in enumerate(digits[:10]))
    d2 = (s2 * 10) % 11 % 10
    return d2 == int(digits[10])


def _validate_cnpj(cnpj: str) -> bool:
    digits = re.sub(r"\D", "", cnpj)
    if len(digits) != 14 or digits == digits[0] * 14:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6] + weights1
    s1 = sum(int(d) * w for d, w in zip(digits[:12], weights1))
    d1 = 11 - (s1 % 11)
    d1 = 0 if d1 >= 10 else d1
    if d1 != int(digits[12]):
        return False
    s2 = sum(int(d) * w for d, w in zip(digits[:13], weights2))
    d2 = 11 - (s2 % 11)
    d2 = 0 if d2 >= 10 else d2
    return d2 == int(digits[13])


def _validate_cnh(cnh: str) -> bool:
    """Valida CNH pelo algoritmo DETRAN (dígitos verificadores 10 e 11)."""
    digits = re.sub(r"\D", "", cnh)
    if len(digits) != 11 or digits == digits[0] * 11:
        return False
    total1 = sum(int(d) * (9 - i) for i, d in enumerate(digits[:9]))
    d1 = total1 % 11
    dsc = 2 if d1 >= 10 else 0
    if d1 >= 10:
        d1 = 0
    total2 = sum(int(d) * (1 + i) for i, d in enumerate(digits[:9]))
    d2 = (total2 + dsc) % 11
    if d2 >= 10:
        d2 = 0
    return d1 == int(digits[9]) and d2 == int(digits[10])


def _validate_ip(ip: str) -> bool:
    """Valida que cada octeto está em 0–255 (reduz FPR com strings de versão)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 and p == str(int(p)) for p in parts)
    except ValueError:
        return False


def _validate_titulo_eleitor(titulo: str) -> bool:
    """Valida título de eleitor: código de estado (dígitos 9–10) deve ser 01–28."""
    digits = re.sub(r"\D", "", titulo)
    if len(digits) != 12:
        return False
    state_code = int(digits[8:10])
    return 1 <= state_code <= 28


# ============================================
# PrivacyProtector
# ============================================
class PrivacyProtector:
    """Pilar 4: Proteção de Dados e Privacidade."""

    # Padrões enriquecidos para PT-BR (sobreescritos pelo config se fornecido)
    DEFAULT_PATTERNS_BR: Dict[str, str] = {
        "cpf": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
        "cnpj": r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
        "rg": r"\b\d{1,2}\.\d{3}\.\d{3}-[\dXx]\b",
        "cnh": r"\b[0-9]{11}\b",          # validar contexto na prática
        "pis_pasep": r"\b\d{3}\.\d{5}\.\d{2}-\d\b",
        "titulo_eleitor": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "cep": r"\b\d{5}-\d{3}\b",
        "email": r"[\w\.-]+@[\w\.-]+\.\w+",
        "phone": r"\(?\d{2}\)?\s?9?\d{4}-?\d{4}",
        "credit_card": r"\b(?:\d{4}[\s-]?){3}\d{4}\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b",
    }

    VALIDATORS = {
        "cpf": _validate_cpf,
        "cnpj": _validate_cnpj,
        "cnh": _validate_cnh,
        "ip_address": _validate_ip,
        "titulo_eleitor": _validate_titulo_eleitor,
    }

    def __init__(self, config: Dict):
        self.config = config
        self.privacy_config = config.get('privacy', {})
        self.enabled = self.privacy_config.get('enabled', True)

        # Modo de consent: "interactive" (default), "auto_grant", "auto_deny"
        self.consent_mode = self.privacy_config.get('consent_mode', 'interactive')
        self.consent_given: Dict[str, bool] = {}
        self.consent_purpose: Dict[str, str] = {}

        _log_max = self.privacy_config.get('redaction_log_max_entries', 1000)
        self.redaction_log: deque = deque(maxlen=_log_max)
        self.redaction_counts: Dict[str, int] = {}

        # Padrões: usa config se houver, senão DEFAULT_PATTERNS_BR
        cfg_patterns = self.privacy_config.get('pii_patterns')
        if cfg_patterns:
            patterns_source = cfg_patterns
        else:
            patterns_source = self.DEFAULT_PATTERNS_BR

        self.pii_patterns: Dict[str, re.Pattern] = {}
        for name, pattern in patterns_source.items():
            try:
                self.pii_patterns[name] = re.compile(pattern)
            except re.error:
                print(f"[Privacy] Erro ao compilar padrão: {name}")

        self.use_pseudonymization = self.privacy_config.get('pseudonymize', True)
        self.pseudonym_salt = self.privacy_config.get('pseudonym_salt', 'TRiSM-default-salt')
        self._pseudo_cache: Dict[str, str] = {}
        self._pseudo_cache_maxsize = self.privacy_config.get('pseudo_cache_maxsize', 10000)

        self.total_redactions = 0
        self.minimized_messages = 0

    # ------------------------------------------------------------------
    def _pseudonym(self, value: str, kind: str) -> str:
        """Gera pseudônimo determinístico (mesma PII → mesmo token)."""
        cache_key = f"{kind}:{value}"
        if cache_key in self._pseudo_cache:
            return self._pseudo_cache[cache_key]
        # Evicção FIFO quando cache atinge o limite (Python 3.7+ dict é insertion-ordered)
        if len(self._pseudo_cache) >= self._pseudo_cache_maxsize:
            self._pseudo_cache.pop(next(iter(self._pseudo_cache)))
        digest = hashlib.sha256((self.pseudonym_salt + value).encode()).hexdigest()[:8]
        token = f"[REDACTED_{kind.upper()}_{digest}]"
        self._pseudo_cache[cache_key] = token
        return token

    def redact_pii(self, text: str) -> Tuple[str, List[str]]:
        """Substitui PII por placeholders (com validação para CPF/CNPJ)."""
        if not self.enabled or not self.privacy_config.get('redact_pii', True):
            return text, []

        redacted_items: List[str] = []
        out = text

        for kind, pattern in self.pii_patterns.items():
            for match in pattern.findall(out):
                value = match if isinstance(match, str) else match[0]
                # Validação opcional
                validator = self.VALIDATORS.get(kind)
                if validator and not validator(value):
                    continue
                placeholder = (self._pseudonym(value, kind)
                               if self.use_pseudonymization
                               else f"[REDACTED_{kind.upper()}]")
                out = out.replace(value, placeholder)
                redacted_items.append(f"{kind}: {value[:6]}…")
                self.redaction_counts[kind] = self.redaction_counts.get(kind, 0) + 1
                self.total_redactions += 1

        if redacted_items:
            self.redaction_log.append({
                "timestamp": datetime.now().isoformat(),
                "items_redacted": len(redacted_items),
                "types": sorted({i.split(":")[0] for i in redacted_items}),
            })
        return out, redacted_items

    # ------------------------------------------------------------------
    def minimize_data(self, text: str, max_length: int = 500) -> str:
        if not self.enabled:
            return text
        if len(text) > max_length:
            self.minimized_messages += 1
            return text[:max_length] + "... [TRUNCADO]"
        return text

    # ------------------------------------------------------------------
    def request_consent(self, session_id: str, purpose: str) -> bool:
        """Solicita ou aplica consent conforme `consent_mode`.

        Modos:
            interactive — pergunta ao usuário (legacy).
            auto_grant — concede automaticamente (cuidado: requer aviso prévio em UI).
            auto_deny — nega automaticamente; nenhum log é registrado.
            env — lê variável TRISM_CONSENT (s/n) e cai em auto_deny se ausente.
        """
        if not self.privacy_config.get('require_consent', True):
            self.consent_given[session_id] = True
            self.consent_purpose[session_id] = purpose
            return True

        if session_id in self.consent_given:
            return self.consent_given[session_id]

        mode = self.consent_mode
        if mode == "auto_grant":
            self.consent_given[session_id] = True
        elif mode == "auto_deny":
            self.consent_given[session_id] = False
        elif mode == "env":
            import os
            v = (os.environ.get("TRISM_CONSENT", "") or "").strip().lower()
            self.consent_given[session_id] = v in ("s", "sim", "yes", "y", "1", "true")
        else:  # interactive
            try:
                print(f"\n[Consentimento — finalidade: {purpose}]")
                print("Permite o registro auditável anonimizado desta conversa? (s/n): ", end="")
                response = input().strip().lower()
                self.consent_given[session_id] = response in ("s", "sim", "yes", "y")
            except (EOFError, RuntimeError):
                self.consent_given[session_id] = False

        self.consent_purpose[session_id] = purpose
        return self.consent_given[session_id]

    # ------------------------------------------------------------------
    def redact_from_dict(self, data: Dict, fields: List[str]) -> Dict:
        out = data.copy()
        for f in fields:
            if f in out and isinstance(out[f], str):
                out[f], _ = self.redact_pii(out[f])
        return out

    def get_privacy_status(self) -> Dict:
        return {
            "enabled": self.enabled,
            "redact_pii": self.privacy_config.get('redact_pii', True),
            "pseudonymization": self.use_pseudonymization,
            "consent_mode": self.consent_mode,
            "retention_days": self.privacy_config.get('data_retention_days', 30),
            "total_redactions": self.total_redactions,
            "minimized_messages": self.minimized_messages,
            "pii_patterns_count": len(self.pii_patterns),
            "consent_given_sessions": sum(1 for v in self.consent_given.values() if v),
            "consent_denied_sessions": sum(1 for v in self.consent_given.values() if not v),
            "redactions_by_type": self.redaction_counts.copy(),
            "redaction_log_entries": len(self.redaction_log),
            "redaction_log_max_entries": self.redaction_log.maxlen,
            "pseudo_cache_size": len(self._pseudo_cache),
            "pseudo_cache_maxsize": self._pseudo_cache_maxsize,
        }
