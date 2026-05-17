"""
Pilar 5: Resistência a Ataques Adversários — VERSÃO FORTALECIDA

Melhorias frente à v1:
- Jailbreak categorizado (DAN, role-play, "ignore instructions", developer mode, encoded).
- Padrões precisos para reduzir falsos positivos (era `.*jailbreak.*`).
- Detecção de repetição semântica (Jaccard + Levenshtein) — não só comparação exata.
- Análise multi-turno: detecta sequências de prompts cuja união é maliciosa
  (Wei et al. 2026: ataques multi-turno atingem 95% ASR).
- Detecção de extração diferenciada (LLM07 — System Prompt Leakage).
- Classificação por confidence: BLOCK / FLAG / ALLOW.
"""

import sys
import re
from pathlib import Path
from collections import deque
from datetime import datetime
from typing import List, Dict, Tuple, Optional

sys.path.append(str(Path(__file__).parent.parent))

from core.base import RiskLevel
from core.metrics_lib import jaccard_similarity, normalized_levenshtein


# ============================================
# Categorias de jailbreak com padrões precisos
# ============================================
JAILBREAK_CATEGORIES: Dict[str, List[str]] = {
    "instruction_override": [
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)",
        r"disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|guidelines?)",
        r"forget\s+(?:everything|all)\s+(?:you\s+were\s+told|prior)",
        r"esque[çc]a\s+(?:tudo\s+)?(?:que\s+|o\s+que\s+)?(?:foi\s+dito|as\s+regras|as\s+instru[çc][õo]es)",
        r"ignor[ea]\s+(?:todas\s+)?(?:as\s+)?(?:instru[çc][õo]es|regras)\s+anteriores",
    ],
    "persona_takeover": [
        r"\bDAN\b",                           # Do-Anything-Now
        r"do\s+anything\s+now",
        r"developer\s+mode\s+enabled",
        r"jailbroken\s+mode",
        r"AIM\s+(?:mode|prompt)",
        r"act\s+as\s+(?:if\s+you\s+are\s+)?(?:an?\s+)?(?:unrestricted|uncensored|evil)",
        r"voc[eê]\s+(?:agora\s+)?[eé]\s+(?:um\s+)?(?:DAN|sem\s+restri[çc][õo]es)",
        r"finja\s+(?:que\s+voc[eê]\s+[eé]|ser)",
    ],
    "policy_bypass": [
        r"without\s+(?:ethical|moral|content)\s+(?:restrictions|filters)",
        r"hypothetically(?:\s+speaking)?,?\s+how\s+(?:would|to)",
        r"in\s+a\s+fictional\s+(?:world|scenario)\s+where",
        r"step[\- ]?by[\- ]?step\s+(?:guide|tutorial|instructions)\s+(?:to|on)\s+(?:hack|kill|break)",
        r"para\s+fins\s+(?:educacionais|de\s+pesquisa).*ensine",
    ],
    "system_extraction": [
        r"(?:reveal|show|print|repeat)\s+(?:your\s+)?(?:system\s+prompt|initial\s+prompt|original\s+instructions)",
        r"what\s+(?:are|were)\s+your\s+(?:initial\s+)?(?:instructions|guidelines|rules)",
        r"output\s+(?:everything|all)\s+(?:above|before)\s+this\s+message",
        r"qual\s+[eé]\s+(?:o\s+seu\s+)?prompt\s+(?:do\s+sistema|original|inicial)",
    ],
    "encoded_payload": [
        r"base64:?\s*[A-Za-z0-9+/=]{20,}",
        r"rot13[: ]",
        r"reverse\s+the\s+text",
        r"decode\s+(?:and\s+)?(?:execute|follow)",
    ],
}


class AdversarialDetector:
    """Pilar 5: Resistência a Ataques Adversários."""

    def __init__(self, config: Dict):
        self.config = config
        self.adversarial_config = config.get('adversarial', {})
        self.enabled = self.adversarial_config.get('enabled', True)

        _act_max = self.adversarial_config.get('suspicious_activities_max_entries', 1000)
        self.suspicious_activities: deque = deque(maxlen=_act_max)
        self.recent_responses: deque = deque(
            maxlen=self.adversarial_config.get('repetition_window', 100))
        self.recent_user_messages: deque = deque(
            maxlen=self.adversarial_config.get('multiturn_window', 6))

        # Compila padrões categorizados (default + extras do config)
        self.category_patterns: Dict[str, List[re.Pattern]] = {}
        self._compile_categories()

        # Lista plana legacy do config — incorporada como custom
        custom_patterns = self.adversarial_config.get('jailbreak_patterns', [])
        if custom_patterns:
            self.category_patterns.setdefault("custom", [])
            for p in custom_patterns:
                try:
                    self.category_patterns["custom"].append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass

        # Palavras-chave para extração (mais precisas)
        self.extraction_keywords = [
            "system prompt", "system instructions", "initial prompt", "original instructions",
            "your guidelines", "your rules", "your programming",
            "prompt original", "instruções do sistema", "regras internas",
        ]

        # Limiares
        self.repetition_threshold_jaccard = self.adversarial_config.get('repetition_jaccard_threshold', 0.85)
        self.repetition_threshold_levenshtein = self.adversarial_config.get('repetition_levenshtein_threshold', 0.85)
        self.extraction_min_keywords = self.adversarial_config.get('extraction_min_keywords', 2)

        # Estatísticas
        self.jailbreak_attempts = 0
        self.extraction_attempts = 0
        self.repetition_attacks = 0
        self.multiturn_alerts = 0

    # ------------------------------------------------------------------
    def _compile_categories(self) -> None:
        for category, patterns in JAILBREAK_CATEGORIES.items():
            self.category_patterns[category] = []
            for p in patterns:
                try:
                    self.category_patterns[category].append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass

    # ------------------------------------------------------------------
    def _match_categories(self, message: str) -> Dict[str, List[str]]:
        """Puro: retorna categorias correspondentes sem efeitos colaterais."""
        msg = message.lower()
        matches: Dict[str, List[str]] = {}
        for category, patterns in self.category_patterns.items():
            hits = [p.pattern for p in patterns if p.search(msg)]
            if hits:
                matches[category] = hits
        return matches

    def detect_jailbreak(self, message: str) -> Tuple[bool, float, Dict[str, List[str]]]:
        """Retorna (detectado, confidence, mapping categoria→padrões)."""
        if not self.enabled:
            return False, 0.0, {}

        matches = self._match_categories(message)
        if not matches:
            return False, 0.0, {}

        # Confidence aumenta com número de categorias (não só de padrões)
        confidence = min(1.0, 0.4 + 0.20 * len(matches) + 0.10 * sum(len(h) for h in matches.values()))
        self.jailbreak_attempts += 1
        self.suspicious_activities.append({
            "timestamp": datetime.now().isoformat(),
            "type": "jailbreak_attempt",
            "confidence": round(confidence, 4),
            "categories": list(matches.keys()),
            "message_preview": message[:120],
        })
        return True, confidence, matches

    # ------------------------------------------------------------------
    def detect_repetition_attack(self, new_response: str) -> Tuple[bool, float, str]:
        """Detecta repetição exata, alta similaridade Jaccard ou Levenshtein."""
        if not self.enabled or len(self.recent_responses) < 3:
            self.recent_responses.append(new_response)
            return False, 0.0, "insufficient_history"

        max_jaccard = 0.0
        max_lev = 0.0
        for prev in self.recent_responses:
            if prev == new_response:
                self.repetition_attacks += 1
                self.suspicious_activities.append({
                    "timestamp": datetime.now().isoformat(),
                    "type": "repetition_attack",
                    "subtype": "exact",
                    "confidence": 1.0,
                })
                return True, 1.0, "exact"
            j = jaccard_similarity(prev, new_response)
            lev = normalized_levenshtein(prev, new_response)
            max_jaccard = max(max_jaccard, j)
            max_lev = max(max_lev, lev)

        self.recent_responses.append(new_response)

        if max_jaccard >= self.repetition_threshold_jaccard:
            self.repetition_attacks += 1
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "repetition_attack",
                "subtype": "jaccard",
                "confidence": round(max_jaccard, 4),
            })
            return True, max_jaccard, "jaccard"
        if max_lev >= self.repetition_threshold_levenshtein:
            self.repetition_attacks += 1
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "repetition_attack",
                "subtype": "levenshtein",
                "confidence": round(max_lev, 4),
            })
            return True, max_lev, "levenshtein"

        return False, max(max_jaccard, max_lev), "below_threshold"

    # ------------------------------------------------------------------
    def detect_extraction_attempt(self, message: str) -> Tuple[bool, List[str]]:
        if not self.enabled:
            return False, []
        msg = message.lower()
        hits = [kw for kw in self.extraction_keywords if kw in msg]
        if len(hits) >= self.extraction_min_keywords:
            self.extraction_attempts += 1
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "extraction_attempt",
                "severity": "medium",
                "keywords_matched": hits,
                "message_preview": message[:100],
            })
            return True, hits
        return False, []

    # ------------------------------------------------------------------
    def detect_multiturn_buildup(self, current_message: str) -> Tuple[bool, str]:
        """Detecta padrões multi-turno onde a soma das mensagens é maliciosa.

        Heurística simples: se nas N últimas mensagens existem duas ou mais
        categorias de jailbreak fragmentadas em mensagens diferentes,
        sinaliza buildup.
        """
        if not self.enabled:
            return False, ""

        self.recent_user_messages.append(current_message)
        if len(self.recent_user_messages) < 3:
            return False, ""

        accumulated_categories = set()
        for msg in self.recent_user_messages:
            # Usa _match_categories (puro) para evitar incrementar contadores
            # de mensagens já auditadas em turnos anteriores.
            accumulated_categories.update(self._match_categories(msg).keys())

        if len(accumulated_categories) >= 2:
            self.multiturn_alerts += 1
            self.suspicious_activities.append({
                "timestamp": datetime.now().isoformat(),
                "type": "multiturn_buildup",
                "categories_accumulated": sorted(accumulated_categories),
                "window": len(self.recent_user_messages),
            })
            return True, ", ".join(sorted(accumulated_categories))
        return False, ""

    # ------------------------------------------------------------------
    def validate_message(self, message: str) -> Dict:
        result = {
            "is_valid": True,
            "risk_level": RiskLevel.LOW,
            "jailbreak_detected": False,
            "extraction_detected": False,
            "multiturn_detected": False,
            "categories": {},
            "violations": [],
            "confidence": 0.0,
        }

        is_jb, conf, categories = self.detect_jailbreak(message)
        if is_jb:
            result["jailbreak_detected"] = True
            result["categories"] = categories
            result["confidence"] = conf
            # Decisão progressiva: confidence < 0.5 → flag, >= 0.5 → block
            if conf >= self.adversarial_config.get('block_threshold', 0.5):
                result["is_valid"] = False
                result["risk_level"] = RiskLevel.CRITICAL
            else:
                result["risk_level"] = RiskLevel.HIGH
            result["violations"].append(f"jailbreak[{','.join(categories.keys())}] (conf={conf:.0%})")

        is_ext, ext_kw = self.detect_extraction_attempt(message)
        if is_ext:
            result["extraction_detected"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], RiskLevel.MEDIUM)
            result["violations"].append(f"extraction_attempt: {ext_kw}")

        is_mt, mt_cats = self.detect_multiturn_buildup(message)
        if is_mt:
            result["multiturn_detected"] = True
            result["risk_level"] = RiskLevel.max_of(result["risk_level"], RiskLevel.HIGH)
            result["violations"].append(f"multiturn_buildup: {mt_cats}")

        return result

    # ------------------------------------------------------------------
    def validate_response(self, response: str) -> Dict:
        result = {
            "is_valid": True,
            "repetition_detected": False,
            "violations": [],
            "confidence": 0.0,
        }
        is_rep, conf, kind = self.detect_repetition_attack(response)
        if is_rep:
            result["repetition_detected"] = True
            result["confidence"] = conf
            result["violations"].append(f"repetition[{kind}] (conf={conf:.0%})")
        return result

    # ------------------------------------------------------------------
    def get_suspicious_count(self) -> int:
        return len(self.suspicious_activities)

    def get_status(self) -> Dict:
        return {
            "enabled": self.enabled,
            "categories": list(self.category_patterns.keys()),
            "patterns_total": sum(len(v) for v in self.category_patterns.values()),
            "jailbreak_attempts": self.jailbreak_attempts,
            "extraction_attempts": self.extraction_attempts,
            "repetition_attacks": self.repetition_attacks,
            "multiturn_alerts": self.multiturn_alerts,
            "total_suspicious_activities": len(self.suspicious_activities),
            "suspicious_activities_max_entries": self.suspicious_activities.maxlen,
            "recent_responses_buffer": len(self.recent_responses),
            "thresholds": {
                "jaccard": self.repetition_threshold_jaccard,
                "levenshtein": self.repetition_threshold_levenshtein,
                "extraction_min_keywords": self.extraction_min_keywords,
                "block_threshold": self.adversarial_config.get('block_threshold', 0.5),
            },
        }
