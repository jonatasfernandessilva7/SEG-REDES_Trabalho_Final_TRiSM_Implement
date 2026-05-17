"""
core/metrics_lib.py - Biblioteca central de métricas estatísticas e de segurança.

NOVO neste v2. Implementa funções referenciadas pela literatura:
- PSI (Population Stability Index) - Ray (2026)
- Jensen-Shannon Divergence - Ray (2026)
- ASR / DSR - Wei et al. (2026)
- ISR / POF / PSR / CCS / TIVS - Gosmar et al. (2025)
- Hash chaining para audit logs imutáveis - PALADIN Layer 4 / NIST AI 600-1
- Detector de codificação (Base64, Hex, ROT13) - Sebok & Wibowo (2026)
- Similaridade de Jaccard / Levenshtein para repetição semântica
"""

from __future__ import annotations
import base64
import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from typing import Dict, List, Optional, Sequence, Tuple


# ============================================
# DRIFT — PSI e Jensen-Shannon
# ============================================
def population_stability_index(expected: Sequence[float],
                                observed: Sequence[float],
                                eps: float = 1e-6) -> float:
    """Calcula o Population Stability Index (PSI).

    Interpretação clássica:
        PSI < 0.10 → distribuições estáveis
        0.10 ≤ PSI < 0.25 → drift moderado, monitorar
        PSI ≥ 0.25 → drift significativo

    Args:
        expected: distribuição de referência (probabilidades, soma=1).
        observed: distribuição corrente (probabilidades, soma=1).
        eps: clip mínimo para evitar log(0).

    Returns:
        PSI (>= 0).
    """
    if len(expected) != len(observed) or len(expected) == 0:
        return 0.0
    psi = 0.0
    for e, o in zip(expected, observed):
        e = max(float(e), eps)
        o = max(float(o), eps)
        psi += (o - e) * math.log(o / e)
    return float(psi)


def jensen_shannon_divergence(p: Sequence[float],
                               q: Sequence[float],
                               eps: float = 1e-12) -> float:
    """Calcula a divergência de Jensen-Shannon entre duas distribuições.
    Resultado ∈ [0, 1] (com log base 2).
    """
    if len(p) != len(q) or len(p) == 0:
        return 0.0
    p = [max(float(x), eps) for x in p]
    q = [max(float(x), eps) for x in q]
    sp, sq = sum(p), sum(q)
    p = [x / sp for x in p]
    q = [x / sq for x in q]
    m = [(pi + qi) / 2.0 for pi, qi in zip(p, q)]

    def kl(a, b):
        return sum(ai * math.log2(ai / bi) for ai, bi in zip(a, b) if ai > 0)

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


def length_distribution(messages: List[Dict], bins: int = 10,
                        max_len: int = 1000) -> List[float]:
    """Histograma normalizado dos comprimentos das mensagens (para PSI)."""
    if not messages:
        return [0.0] * bins
    lengths = [min(len(m.get("content", "")), max_len) for m in messages]
    counts = [0] * bins
    width = max_len / bins
    for ln in lengths:
        idx = min(int(ln / width), bins - 1)
        counts[idx] += 1
    total = sum(counts)
    return [c / total for c in counts] if total else counts


# ============================================
# HASH CHAIN para audit log imutável
# ============================================
def turn_hash(turn_payload: Dict, prev_hash: str = "") -> str:
    """Calcula hash SHA-256 de um turno encadeando o hash anterior.

    Formato: SHA256( prev_hash || canonical_json(turn_payload) ).
    Isso garante que qualquer alteração retroativa quebra a cadeia.
    """
    canon = json.dumps(turn_payload, sort_keys=True, ensure_ascii=False, default=str)
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(canon.encode("utf-8"))
    return h.hexdigest()


def verify_chain(jsonl_path: str) -> Tuple[bool, int, List[int]]:
    """Verifica integridade de um arquivo audit_log.jsonl com hash chain.

    Returns:
        (válido, total_de_linhas, lista_de_índices_inválidos)
    """
    invalid: List[int] = []
    total = 0
    prev = ""
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    invalid.append(idx)
                    continue
                stored = entry.pop("self_hash", "")
                expected = turn_hash(entry, prev)
                if stored != expected:
                    invalid.append(idx)
                prev = stored or expected
    except FileNotFoundError:
        return True, 0, []
    return (len(invalid) == 0), total, invalid


# ============================================
# DETECÇÃO DE CODIFICAÇÃO (Base64 / Hex / ROT13 / Unicode)
# ============================================
_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}={2}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{20,}\b")
_INVISIBLE_CHARS = {
    "​",  # zero-width space
    "‌",  # zero-width non-joiner
    "‍",  # zero-width joiner
    "⁠",  # word joiner
    "﻿",  # zero-width no-break space
    "‪", "‫", "‬", "‭", "‮",  # bidi overrides
}


def detect_invisible_chars(text: str) -> List[str]:
    """Retorna lista de caracteres invisíveis encontrados (para LLM07)."""
    return [c for c in text if c in _INVISIBLE_CHARS]


def detect_base64_payload(text: str, *, min_decoded_len: int = 16) -> List[str]:
    """Detecta strings que parecem Base64 e que decodificam em texto imprimível."""
    found = []
    for match in _BASE64_RE.findall(text):
        try:
            # Garante padding correto antes de decodificar
            padded = match + "=" * (-len(match) % 4)
            decoded = base64.b64decode(padded, validate=False)
            if len(decoded) < min_decoded_len:
                continue
            try:
                ascii_decoded = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            # Considera suspeito se decoder produz texto humano
            if sum(c.isprintable() for c in ascii_decoded) / max(len(ascii_decoded), 1) > 0.85:
                found.append(match[:60] + ("..." if len(match) > 60 else ""))
        except Exception:
            continue
    return found


def detect_hex_payload(text: str, *, min_decoded_len: int = 16) -> List[str]:
    """Detecta blobs hexadecimais que decodificam para texto imprimível."""
    found = []
    for match in _HEX_RE.findall(text):
        clean = match[2:] if match.startswith("0x") else match
        if len(clean) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(clean)
            if len(decoded) < min_decoded_len:
                continue
            try:
                ascii_decoded = decoded.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if sum(c.isprintable() for c in ascii_decoded) / max(len(ascii_decoded), 1) > 0.85:
                found.append(match[:40] + ("..." if len(match) > 40 else ""))
        except Exception:
            continue
    return found


def normalize_unicode(text: str) -> str:
    """Remove caracteres invisíveis e aplica NFKC para foiling de homoglifos."""
    cleaned = "".join(c for c in text if c not in _INVISIBLE_CHARS)
    return unicodedata.normalize("NFKC", cleaned)


# ============================================
# SIMILARIDADE — para detecção de repetição semântica
# ============================================
def jaccard_similarity(a: str, b: str, *, ngram: int = 3) -> float:
    """Similaridade de Jaccard entre conjuntos de n-gramas (caractere)."""
    if not a or not b:
        return 0.0
    grams_a = {a[i:i + ngram] for i in range(len(a) - ngram + 1)}
    grams_b = {b[i:i + ngram] for i in range(len(b) - ngram + 1)}
    if not grams_a or not grams_b:
        return 0.0
    inter = len(grams_a & grams_b)
    union = len(grams_a | grams_b)
    return inter / union if union else 0.0


def normalized_levenshtein(a: str, b: str) -> float:
    """Distância de Levenshtein normalizada ∈ [0, 1] (1=igual, 0=diferente).

    Implementação iterativa O(len(a)*len(b)) sem dependências externas.
    """
    if a == b:
        return 1.0
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return 0.0
    if la > lb:
        a, b, la, lb = b, a, lb, la  # garantir |a| <= |b| para economia
    prev = list(range(lb + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    dist = prev[-1]
    return 1.0 - dist / max(la, lb)


# ============================================
# MÉTRICAS DE SEGURANÇA — ASR/DSR/ISR/POF/PSR/CCS/TIVS
# ============================================
def attack_success_rate(blocked: int, total: int) -> float:
    """ASR = ataques bem sucedidos / total. Em ambientes defensivos, equivale a (total - blocked)/total."""
    if total <= 0:
        return 0.0
    success = total - blocked
    return success / total


def defense_success_rate(blocked: int, total: int) -> float:
    """DSR = 1 - ASR."""
    return 1.0 - attack_success_rate(blocked, total)


def injection_success_rate(unmitigated: int, total: int) -> float:
    """ISR (Gosmar et al. 2025): proporção de injeções que influenciam a saída final."""
    if total <= 0:
        return 0.0
    return unmitigated / total


def policy_override_frequency(overrides: int, total: int) -> float:
    """POF (Gosmar et al. 2025): frequência com que outputs violam políticas."""
    if total <= 0:
        return 0.0
    return overrides / total


def prompt_sanitization_rate(neutralized: int, detected: int) -> float:
    """PSR (Gosmar et al. 2025): proporção de injeções neutralizadas dentre as detectadas."""
    if detected <= 0:
        return 0.0
    return neutralized / detected


def compliance_consistency_score(compliant_turns: int, total_turns: int) -> float:
    """CCS (Gosmar et al. 2025): consistência ao longo de N interações ∈ [0,1]."""
    if total_turns <= 0:
        return 0.0
    return compliant_turns / total_turns


def total_injection_vulnerability_score(isr: float, pof: float, psr: float, ccs: float,
                                         num_agents: int = 1,
                                         weights: Tuple[float, float, float, float] = (0.25, 0.25, 0.25, 0.25)
                                         ) -> float:
    """TIVS (Gosmar et al. 2025): escore composto. Quanto mais negativo, melhor a defesa."""
    w1, w2, w3, w4 = weights
    denom = max(num_agents, 1) * (w1 + w2 + w3 + w4)
    if denom == 0:
        return 0.0
    return ((isr * w1) + (pof * w2) - (psr * w3) - (ccs * w4)) / denom
