"""
benchmark/runner.py — executa os 3 experimentos previstos no artigo.

Experimento E1: Eficácia de detecção (TRiSM Chat vs Ollama puro) sobre 100 prompts OWASP.
Experimento E2: KPIs compostas (ISR/POF/PSR/CCS/TIVS) sobre o subset LLM01.
Experimento E3: Trade-off segurança × eficiência sobre 20 prompts benignos.

Saídas: results/<timestamp>/{e1.csv, e1.md, e1.json, e2.json, e3.json, baseline.csv}.
"""

from __future__ import annotations
import json
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.config_loader import load_config  # noqa: E402
from benchmark.evaluator import BenchmarkEvaluator, TrialOutcome  # noqa: E402


def _send_through_trism(chat, prompt: str) -> Tuple[bool, Dict]:
    """Envia prompt via TRiSMChat e retorna (blocked, metadata)."""
    response, meta = chat.send_message(prompt)
    return bool(meta.get("blocked", False)), meta


def _send_through_baseline(model_name: str, prompt: str) -> Tuple[bool, Dict]:
    """Baseline = chamada direta ao Ollama, sem nenhum controle TRiSM."""
    import ollama
    start = time.time()
    try:
        ollama.chat(model=model_name,
                    messages=[{"role": "user", "content": prompt}],
                    options={"num_predict": 256})
        latency = (time.time() - start) * 1000
        # baseline nunca bloqueia
        return False, {"latency_ms": round(latency, 2),
                        "policies_triggered": [], "risk_level": "low",
                        "owasp_categories": []}
    except Exception as e:
        latency = (time.time() - start) * 1000
        return False, {"latency_ms": round(latency, 2),
                        "policies_triggered": ["model_error"],
                        "risk_level": "low",
                        "owasp_categories": [], "error": str(e)}


def _outcome_from(item: Dict, blocked: bool, meta: Dict, *, is_benign: bool = False) -> TrialOutcome:
    return TrialOutcome(
        item_id=item.get("id", "?"),
        category=item.get("category", "BENIGN" if is_benign else "?"),
        expected_block=item.get("expected_block", False),
        blocked=blocked,
        risk_level=str(meta.get("risk_level", "low")),
        latency_ms=float(meta.get("latency_ms", 0.0)),
        policies_triggered=list(meta.get("policies_triggered", [])),
        owasp_categories=list(meta.get("owasp_categories", []) or []),
        response_preview="",
        is_benign=is_benign,
    )


def run_benchmark(config_path: str = "config.yaml") -> None:
    """Roda os três experimentos."""
    cfg = load_config(config_path)
    bench_cfg = cfg.get("benchmark", {})
    dataset_path = Path(bench_cfg.get("dataset_path", "benchmark/datasets/owasp_llm_top10_pt.json"))
    if not dataset_path.is_absolute():
        dataset_path = Path(__file__).parent.parent / dataset_path
    results_dir = Path(bench_cfg.get("results_dir", "benchmark/results"))
    if not results_dir.is_absolute():
        results_dir = Path(__file__).parent.parent / results_dir

    if not dataset_path.exists():
        print(f"❌ Dataset não encontrado: {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        ds = json.load(f)

    items = ds.get("items", [])
    benign = ds.get("benign_baseline", [])

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = results_dir / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    # Importa TRiSMChat e instancia
    from trism_chat.main import TRiSMChat  # noqa: E402
    chat = TRiSMChat(config_path)

    weights = tuple(bench_cfg.get("tivs_weights", [0.25, 0.25, 0.25, 0.25]))

    # ----------------------------- E1 -------------------------------
    print(f"\n[E1] Detecção em {len(items)} prompts adversariais OWASP…")
    evaluator_trism = BenchmarkEvaluator(num_agents=1, tivs_weights=weights)
    evaluator_baseline = BenchmarkEvaluator(num_agents=1, tivs_weights=weights)
    compare_baseline = bench_cfg.get("compare_baseline", True)

    for i, item in enumerate(items, 1):
        prompt = item.get("prompt", "")
        # via TRiSM
        blocked_t, meta_t = _send_through_trism(chat, prompt)
        evaluator_trism.add(_outcome_from(item, blocked_t, meta_t))
        # baseline opcional
        if compare_baseline:
            blocked_b, meta_b = _send_through_baseline(chat.model_name, prompt)
            evaluator_baseline.add(_outcome_from(item, blocked_b, meta_b))
        if i % 10 == 0:
            print(f"  ... {i}/{len(items)}")

    # Benign baseline para FPR
    print(f"\n[E3] Avaliando {len(benign)} prompts benignos para FPR/latência…")
    for item in benign:
        prompt = item.get("prompt", "")
        blocked_t, meta_t = _send_through_trism(chat, prompt)
        evaluator_trism.add(_outcome_from(item, blocked_t, meta_t, is_benign=True))
        if compare_baseline:
            blocked_b, meta_b = _send_through_baseline(chat.model_name, prompt)
            evaluator_baseline.add(_outcome_from(item, blocked_b, meta_b, is_benign=True))

    # Salvar
    evaluator_trism.to_csv(str(out_dir / "e1_trism.csv"))
    (out_dir / "e1_trism.md").write_text(evaluator_trism.to_markdown(), encoding="utf-8")
    (out_dir / "e1_trism.json").write_text(evaluator_trism.to_json(), encoding="utf-8")

    if compare_baseline:
        evaluator_baseline.to_csv(str(out_dir / "e1_baseline.csv"))
        (out_dir / "e1_baseline.md").write_text(evaluator_baseline.to_markdown(), encoding="utf-8")
        (out_dir / "e1_baseline.json").write_text(evaluator_baseline.to_json(), encoding="utf-8")

    # ----------------------------- E2 -------------------------------
    print("\n[E2] KPIs compostas no subset LLM01 (Prompt Injection)…")
    e2 = BenchmarkEvaluator(num_agents=3, tivs_weights=weights)  # 3 camadas TRiSM efetivas
    for o in evaluator_trism.outcomes:
        if (not o.is_benign) and o.category == "LLM01":
            e2.add(o)
    e2_metrics = e2.overall_metrics()
    if compare_baseline:
        e2_baseline = BenchmarkEvaluator(num_agents=1, tivs_weights=weights)
        for o in evaluator_baseline.outcomes:
            if (not o.is_benign) and o.category == "LLM01":
                e2_baseline.add(o)
        e2_metrics_baseline = e2_baseline.overall_metrics()
    else:
        e2_metrics_baseline = None

    e2_payload = {
        "trism": e2_metrics,
        "baseline": e2_metrics_baseline,
        "delta_tivs": (round(e2_metrics["tivs"] - e2_metrics_baseline["tivs"], 4)
                       if e2_metrics_baseline else None),
    }
    (out_dir / "e2_kpis.json").write_text(
        json.dumps(e2_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # ----------------------------- Resumo -------------------------------
    summary = {
        "timestamp": timestamp,
        "model": chat.model_name,
        "trism_overall": evaluator_trism.overall_metrics(),
        "baseline_overall": (evaluator_baseline.overall_metrics() if compare_baseline else None),
        "by_category_trism": evaluator_trism.detection_rate_by_category(),
        "by_category_baseline": (evaluator_baseline.detection_rate_by_category()
                                  if compare_baseline else None),
        "owasp_coverage_trism": evaluator_trism.owasp_coverage(),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("RESULTADOS RESUMIDOS")
    print("=" * 60)
    m = summary["trism_overall"]
    print(f"TRiSM v2  → ASR={m['asr']:.2%} DSR={m['dsr']:.2%} TIVS={m['tivs']:.4f} FPR_benign={m['fpr_benign']:.2%}")
    if compare_baseline and summary["baseline_overall"]:
        b = summary["baseline_overall"]
        print(f"Baseline  → ASR={b['asr']:.2%} DSR={b['dsr']:.2%} TIVS={b['tivs']:.4f} FPR_benign={b['fpr_benign']:.2%}")
        print(f"Δ TIVS    → {round(m['tivs'] - b['tivs'], 4)} (negativo = TRiSM melhor)")
    print(f"\n📁 Resultados gravados em: {out_dir}")
