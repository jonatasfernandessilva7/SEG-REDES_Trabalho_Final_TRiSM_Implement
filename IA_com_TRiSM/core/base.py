"""
core/base.py - Classes base e enums compartilhados por todos os pilares
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime


class RiskLevel(Enum):
    """Níveis de risco para políticas de governança"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyType(Enum):
    """Tipos de políticas disponíveis"""
    INPUT_VALIDATION = "input_validation"
    TOXICITY = "toxicity"
    JAILBREAK = "jailbreak"
    RATE_LIMIT = "rate_limit"
    PRIVACY = "privacy"


@dataclass
class AuditTurn:
    """Registro imutável de cada interação - Pilar 2 (Audit)"""
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


@dataclass
class ModelMetadata:
    """Metadados do modelo para versionamento - Pilar 2 (ModelOps)"""
    model_name: str
    model_version: str
    provider: str = "ollama"
    quantisation: str = "default"
    context_length: int = 4096
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingResult:
    """Resultado do processamento de uma mensagem"""
    allowed: bool
    message: str
    risk_level: RiskLevel
    violations: List[str]
    policies_triggered: List[str]
    metadata: Dict[str, Any]