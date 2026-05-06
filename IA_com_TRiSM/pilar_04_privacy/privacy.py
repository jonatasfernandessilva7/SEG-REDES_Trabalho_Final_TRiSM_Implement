"""
Pilar 4: Proteção de Dados e Privacidade

Responsabilidades:
- Anonimização/Pseudonimização de PII (CPF, email, telefone)
- Minimização de dados (truncamento)
- Gerenciamento de consentimento do usuário
- Políticas de retenção de dados
"""

import sys
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Tuple

sys.path.append(str(Path(__file__).parent.parent))


class PrivacyProtector:
    """
    Pilar 4: Proteção de Dados e Privacidade
    Protege informações pessoais identificáveis (PII)
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.privacy_config = config.get('privacy', {})
        self.enabled = self.privacy_config.get('enabled', True)
        
        # Consentimento do usuário
        self.consent_given: Dict[str, bool] = {}
        
        # Logs de redação
        self.redaction_log: List[Dict] = []
        
        # Carregar padrões de PII do config
        self.pii_patterns: Dict[str, re.Pattern] = {}
        pii_config = self.privacy_config.get('pii_patterns', {})
        for name, pattern in pii_config.items():
            try:
                self.pii_patterns[name] = re.compile(pattern)
            except re.error:
                print(f"[Privacy] Erro ao compilar padrão: {name}")
        
        # Estatísticas
        self.total_redactions = 0
        self.minimized_messages = 0
    
    def redact_pii(self, text: str) -> Tuple[str, List[str]]:
        """
        Remove/redige informações pessoais identificáveis (PII)
        
        Args:
            text: Texto original
        
        Returns:
            (texto_redigido, lista_de_itens_redigidos)
        """
        if not self.enabled or not self.privacy_config.get('redact_pii', True):
            return text, []
        
        redacted_items = []
        redacted_text = text
        
        for pii_type, pattern in self.pii_patterns.items():
            matches = pattern.findall(redacted_text)
            if matches:
                for match in matches:
                    # Para o CPF, redige apenas os últimos dígitos
                    if pii_type == 'cpf' and len(match) > 5:
                        redacted_part = match[:-5] + "***-**"
                        redacted_text = redacted_text.replace(match, f"[REDACTED_{pii_type.upper()}]")
                    else:
                        redacted_text = redacted_text.replace(match, f"[REDACTED_{pii_type.upper()}]")
                    
                    redacted_items.append(f"{pii_type}: {match[:10]}...")
                    self.total_redactions += 1
        
        if redacted_items:
            self.redaction_log.append({
                "timestamp": datetime.now().isoformat(),
                "items_redacted": len(redacted_items),
                "types": list(set([i.split(':')[0] for i in redacted_items]))
            })
        
        return redacted_text, redacted_items
    
    def minimize_data(self, text: str, max_length: int = 500) -> str:
        """
        Minimiza dados armazenados (trunca textos longos)
        
        Args:
            text: Texto a ser minimizado
            max_length: Tamanho máximo permitido
        
        Returns:
            Texto truncado se necessário
        """
        if not self.enabled:
            return text
        
        if len(text) > max_length:
            self.minimized_messages += 1
            return text[:max_length] + "... [TRUNCADO]"
        return text
    
    def request_consent(self, session_id: str, purpose: str) -> bool:
        """
        Gerencia consentimento do usuário para logging
        
        Args:
            session_id: Identificador da sessão
            purpose: Finalidade do consentimento
        
        Returns:
            True se consentimento foi dado
        """
        if not self.privacy_config.get('require_consent', True):
            return True
        
        if session_id not in self.consent_given:
            print(f"\n[Consentimento] Para fins de auditoria e melhoria do sistema,")
            print(f"deseja permitir o registro anônimo desta conversa? (s/n): ", end='')
            response = input().strip().lower()
            self.consent_given[session_id] = response in ['s', 'sim', 'yes', 'y', 's']
            
            if self.consent_given[session_id]:
                print("[Consentimento] ✓ Obrigado! Seus dados serão tratados com privacidade.")
            else:
                print("[Consentimento] ✓ Entendido. Nenhum dado será registrado.")
        
        return self.consent_given.get(session_id, False)
    
    def get_privacy_status(self) -> Dict:
        """Retorna status da proteção de privacidade"""
        return {
            "enabled": self.enabled,
            "redact_pii": self.privacy_config.get('redact_pii', True),
            "retention_days": self.privacy_config.get('data_retention_days', 30),
            "total_redactions": self.total_redactions,
            "minimized_messages": self.minimized_messages,
            "pii_patterns_count": len(self.pii_patterns),
            "consent_given_sessions": len(self.consent_given)
        }
    
    def redact_from_dict(self, data: Dict, fields: List[str]) -> Dict:
        """
        Redige PII em campos específicos de um dicionário
        
        Args:
            data: Dicionário com dados
            fields: Lista de campos a serem redigidos
        
        Returns:
            Dicionário com dados redigidos
        """
        redacted_data = data.copy()
        for field in fields:
            if field in redacted_data and isinstance(redacted_data[field], str):
                redacted_data[field], _ = self.redact_pii(redacted_data[field])
        return redacted_data