"""
tests/test_benchmark_complete.py — Agregador completo para artigo

Executa todos os testes (P1-P5, E1-E3) e gera:
  - Tabela resumida para seção de Resultados
  - Gráfico radar (ASCII) dos pilares
  - Estatísticas por nível

Execução:
    python tests/test_benchmark_complete.py
    python tests/test_benchmark_complete.py --output-dir ./resultados/

Output:
    benchmark_final_table.csv        — tabela para artigo (LaTeX-friendly)
    benchmark_radar_ascii.txt        — visualização ASCII dos 5 pilares
    benchmark_summary.json           — JSON com resumo completo
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from statistics import mean
import argparse
import csv


@dataclass
class PillarResult:
    """Resultado de um pilar em um nível."""
    pilar: str
    nivel: str
    score: float
    std_dev: float
    ic95_lower: float
    ic95_upper: float
    count: int


def run_massa_tests(output_dir: Path) -> Dict[Tuple[str, str], Dict]:
    """Executa test_benchmark_massa.py"""
    print("\n[1/2] Rodando testes MASSA (P1 + P3)...\n")
    try:
        result = subprocess.run(
            [sys.executable, "tests/test_benchmark_massa.py",
             "--output-dir", str(output_dir)],
            cwd=output_dir.parent.parent if output_dir.name != "." else ".",
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print("[STDERR]", result.stderr)

        # Carregar estatísticas
        stats_file = output_dir / "benchmark_statistics.json"
        if stats_file.exists():
            with open(stats_file, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[ERRO] Falha ao rodar testes MASSA: {e}")
        return {}

    return {}


def run_advanced_tests(output_dir: Path) -> Dict[Tuple[str, str], Dict]:
    """Executa test_benchmark_advanced.py"""
    print("\n[2/2] Rodando testes AVANÇADOS (P2 + P4 + P5)...\n")
    try:
        result = subprocess.run(
            [sys.executable, "tests/test_benchmark_advanced.py",
             "--output-dir", str(output_dir)],
            cwd=output_dir.parent.parent if output_dir.name != "." else ".",
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print("[STDERR]", result.stderr)

        # Carregar estatísticas
        stats_file = output_dir / "benchmark_advanced_statistics.json"
        if stats_file.exists():
            with open(stats_file, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[ERRO] Falha ao rodar testes AVANÇADOS: {e}")
        return {}

    return {}


def merge_stats(stats_massa: Dict, stats_advanced: Dict) -> Dict[Tuple[str, str], Dict]:
    """Mescla estatísticas dos dois suites."""
    merged = {}

    # Processar stats_massa
    for key_str, data in stats_massa.items():
        nivel, pilar = key_str.split("/")
        merged[(nivel, pilar)] = data

    # Processar stats_advanced
    for key_str, data in stats_advanced.items():
        nivel, pilar = key_str.split("/")
        merged[(nivel, pilar)] = data

    return merged


def generate_final_table(stats: Dict[Tuple[str, str], Dict],
                        output_file: Path) -> None:
    """Gera tabela CSV pronta para artigo."""
    print(f"\n[Gerando] Tabela final → {output_file}")

    rows = []
    pilares_order = ["P1", "P2", "P3", "P4", "P5"]
    niveis_order = ["E1", "E2", "E3"]

    for nivel in niveis_order:
        for pilar in pilares_order:
            key = (nivel, pilar)
            if key in stats:
                data = stats[key]
                rows.append({
                    "Nível": nivel,
                    "Pilar": pilar,
                    "Descrição": _get_pillar_desc(pilar),
                    "N": data.get("count", 0),
                    "Score Médio": f"{data.get('mean_score', 0):.1f}",
                    "Desvio Padrão": f"{data.get('std_dev', 0):.1f}",
                    "IC95% [inferior, superior]": f"[{data.get('ic95_lower', 0):.1f}, {data.get('ic95_upper', 0):.1f}]",
                    "Taxa Detecção (%)": f"{data.get('detection_rate', 0):.1f}",
                })

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    print(f"✓ Tabela salva: {output_file}")


def generate_radar_ascii(stats: Dict[Tuple[str, str], Dict],
                        output_file: Path) -> None:
    """Gera visualização ASCII em radar."""
    print(f"\n[Gerando] Radar ASCII → {output_file}")

    pilares_order = ["P1", "P2", "P3", "P4", "P5"]
    niveis_order = ["E1", "E2", "E3"]

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("GRÁFICO RADAR — Scores Médios por Pilar\n")
        f.write("=" * 70 + "\n\n")

        for nivel in niveis_order:
            f.write(f"\n{nivel} — Complexidade: {'Básica' if nivel == 'E1' else 'Intermediária' if nivel == 'E2' else 'Avançada'}\n")
            f.write("─" * 70 + "\n\n")

            scores = {}
            for pilar in pilares_order:
                key = (nivel, pilar)
                score = stats.get(key, {}).get("mean_score", 0)
                scores[pilar] = score

            # Draw ASCII bar chart
            max_score = 100
            for pilar in pilares_order:
                score = scores[pilar]
                bar_len = int((score / max_score) * 40)
                bar = "█" * bar_len + "░" * (40 - bar_len)
                desc = _get_pillar_desc(pilar)
                f.write(f"  {pilar} {desc:<35} │{bar}│ {score:6.1f}%\n")

            f.write("\n")

    print(f"✓ Radar ASCII salvo: {output_file}")


def generate_summary_json(stats: Dict[Tuple[str, str], Dict],
                         output_file: Path) -> None:
    """Gera JSON resumido para documentação."""
    print(f"\n[Gerando] Resumo JSON → {output_file}")

    summary = {
        "timestamp": str(Path.cwd()),
        "pilares": {},
    }

    pilares_order = ["P1", "P2", "P3", "P4", "P5"]
    niveis_order = ["E1", "E2", "E3"]

    for pilar in pilares_order:
        summary["pilares"][pilar] = {
            "nome": _get_pillar_desc(pilar),
            "niveis": {}
        }

        for nivel in niveis_order:
            key = (nivel, pilar)
            if key in stats:
                data = stats[key]
                summary["pilares"][pilar]["niveis"][nivel] = {
                    "score_medio": data.get("mean_score", 0),
                    "desvio_padrao": data.get("std_dev", 0),
                    "ic95": {
                        "inferior": data.get("ic95_lower", 0),
                        "superior": data.get("ic95_upper", 0),
                    },
                    "taxa_deteccao_pct": data.get("detection_rate", 0),
                    "n_amostras": data.get("count", 0),
                }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"✓ Resumo JSON salvo: {output_file}")


def _get_pillar_desc(pilar: str) -> str:
    """Retorna descrição do pilar."""
    descs = {
        "P1": "Explicabilidade",
        "P2": "ModelOps",
        "P3": "AppSec",
        "P4": "Privacidade",
        "P5": "Adversarial",
    }
    return descs.get(pilar, "Desconhecido")


def print_summary(stats: Dict[Tuple[str, str], Dict]) -> None:
    """Imprime resumo visual."""
    print("\n" + "=" * 70)
    print("  RESUMO EXECUTIVO — BENCHMARK TRiSM v2")
    print("=" * 70)

    pilares_order = ["P1", "P2", "P3", "P4", "P5"]
    niveis_order = ["E1", "E2", "E3"]

    for nivel in niveis_order:
        print(f"\n[{nivel}] Scores médios:")
        for pilar in pilares_order:
            key = (nivel, pilar)
            if key in stats:
                score = stats[key].get("mean_score", 0)
                std = stats[key].get("std_dev", 0)
                print(f"  {pilar}: {score:6.1f} ± {std:.1f}%")

    # Evolução E1 → E3
    print(f"\n{'─' * 70}")
    print("  EVOLUÇÃO E1 → E2 → E3 (melhoria %)")
    print(f"{'─' * 70}")

    for pilar in pilares_order:
        e1_score = stats.get(("E1", pilar), {}).get("mean_score", 0)
        e2_score = stats.get(("E2", pilar), {}).get("mean_score", 0)
        e3_score = stats.get(("E3", pilar), {}).get("mean_score", 0)

        if e1_score > 0:
            melhoria_e2 = ((e2_score - e1_score) / e1_score * 100) if e1_score > 0 else 0
            melhoria_e3 = ((e3_score - e1_score) / e1_score * 100) if e1_score > 0 else 0

            print(f"\n{pilar} — {_get_pillar_desc(pilar)}")
            print(f"  E1: {e1_score:6.1f}%")
            print(f"  E2: {e2_score:6.1f}% ({melhoria_e2:+.1f}%)")
            print(f"  E3: {e3_score:6.1f}% ({melhoria_e3:+.1f}%)")

    print(f"\n{'═' * 70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Agregador completo de benchmarks TRiSM v2"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Diretório para resultados",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("  BENCHMARK COMPLETO TRiSM v2 (P1-P5, E1-E3)")
    print("=" * 70)

    # Rodar suites
    stats_massa = run_massa_tests(output_dir)
    stats_advanced = run_advanced_tests(output_dir)

    # Mesclar estatísticas
    all_stats = merge_stats(stats_massa, stats_advanced)

    # Gerar artefatos
    if all_stats:
        generate_final_table(all_stats, output_dir / "benchmark_final_table.csv")
        generate_radar_ascii(all_stats, output_dir / "benchmark_radar_ascii.txt")
        generate_summary_json(all_stats, output_dir / "benchmark_summary.json")
        print_summary(all_stats)

        print(f"\n[✓] Todos os resultados salvos em: {output_dir}")
    else:
        print("\n[✗] Nenhum resultado para processar")
        sys.exit(1)


if __name__ == "__main__":
    main()
