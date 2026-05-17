"""
core/base.py - Classes base e enums compartilhados por todos os pilares

VERSÃO FORTALECIDA (v2):
- Adicionado AuditChain: encadeamento por hash dos turns para auditoria imutável
- ProcessingResult agora inclui evidências (decision trace) para explicabilidade
- ModelMetadata aceita logprobs e parâmetros de quantização do Ollama
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


class RiskLevel(Enum):
    """Níveis de risco para políticas de governança."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @classmethod
    def max_of(cls, *levels: "RiskLevel") -> "RiskLevel":
        """Retorna o nível mais alto entre os fornecidos."""
        if not levels:
            return cls.LOW
        return max(levels, key=lambda lvl: lvl.numeric)


class PolicyType(Enum):
    """Tipos de políticas disponíveis."""
    INPUT_VALIDATION = "input_validation"
    TOXICITY = "toxicity"
    JAILBREAK = "jailbreak"
    RATE_LIMIT = "rate_limit"
    PRIVACY = "privacy"
    ENCODING = "encoding"
    INDIRECT_INJECTION = "indirect_injection"
    OUTPUT_VALIDATION = "output_validation"


class OWASPCategory(Enum):
    """OWASP Top 10 for LLM Applications 2025 - utilizada nos relatórios e benchmarks."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_DISCLOSURE = "LLM02"
    LLM03_SUPPLY_CHAIN = "LLM03"
    LLM04_DATA_POISONING = "LLM04"
    LLM05_OUTPUT_HANDLING = "LLM05"
    LLM06_EXCESSIVE_AGENCY = "LLM06"
    LLM07_PROMPT_LEAKAGE = "LLM07"
    LLM08_VECTOR_WEAKNESSES = "LLM08"
    LLM09_MISINFORMATION = "LLM09"
    LLM10_UNBOUNDED_CONSUMPTION = "LLM10"


@dataclass
class AuditTurn:
    """Registro imutável de cada interação - Pilar 2 (Audit)."""
    turn_id: str
    timestamp: str
    session_id: str
    user_message: str
    assistant_response: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    risk_level: str
    policies_triggered: List[str]
    anomalies_detected: List[str]
    confidence_score: float
    # Campos NOVOS para auditoria robusta
    prev_hash: str = ""        # hash do turn anterior (chain)
    self_hash: str = ""        # hash deste registro (calculado em log_turn)
    owasp_categories: List[str] = field(default_factory=list)


@dataclass
class ModelMetadata:
    """Metadados do modelo para versionamento - Pilar 2 (ModelOps)."""
    model_name: str
    model_version: str
    provider: str = "ollama"
    quantisation: str = "default"
    context_length: int = 4096
    parameters: Dict[str, Any] = field(default_factory=dict)
    digest: str = ""  # hash do modelo retornado pelo Ollama
    model_size_bytes: int = 0


@dataclass
class DecisionTrace:
    """Trace explicável de uma decisão (Pilar 1).
    Substitui o cálculo simplista anterior por evidências estruturadas.
    """
    pillar: str
    rule: str
    matched: bool
    confidence: float
    evidence: str = ""
    risk: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessingResult:
    """Resultado do processamento de uma mensagem."""
    allowed: bool
    message: str
    risk_level: RiskLevel
    violations: List[str]
    policies_triggered: List[str]
    metadata: Dict[str, Any]
    traces: List[DecisionTrace] = field(default_factory=list)
