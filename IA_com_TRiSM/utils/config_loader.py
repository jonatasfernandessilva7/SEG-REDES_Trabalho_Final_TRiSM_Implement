"""utils/config_loader.py — carrega configuração YAML com defaults v2."""

import sys
import yaml
from pathlib import Path
from typing import Dict, Any

sys.path.append(str(Path(__file__).parent.parent))


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f) or {}
            # mescla com defaults para garantir chaves novas em configs antigas
            return _merge(get_default_config(), cfg)
    except FileNotFoundError:
        print(f"[Config] Arquivo {config_path} não encontrado, usando defaults v2")
        return get_default_config()
    except yaml.YAMLError as e:
        print(f"[Config] Erro ao parsear YAML: {e}")
        return get_default_config()
    except Exception as e:
        print(f"[Config] Erro ao carregar config: {e}")
        return get_default_config()


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def get_default_config() -> Dict[str, Any]:
    """Defaults v2 com todos os controles fortalecidos habilitados."""
    return {
        'model': {
            'name': 'phi3.5',
            'version': '1.0.0',
            'provider': 'ollama',
            'context_length': 4096,
            'parameters': {'temperature': 0.7, 'top_p': 0.9},
            'request_logprobs': True,
        },
        'explainability': {
            'enabled': True,
            'log_chain_of_thought': True,
            'confidence_threshold': 0.7,
        },
        'modelops': {
            'enabled': True,
            'versioning': True,
            'monitoring': {
                'latency_threshold_ms': 5000,
                'psi_threshold': 0.25,
                'js_threshold': 0.30,
                'token_alert_threshold': 10000,
                'baseline_window': 50,
                'cost_per_1k_input_tokens': 0.0,
                'cost_per_1k_output_tokens': 0.0,
            },
            'rate_limiting': {
                'enabled': True,
                'requests_per_minute': 30,
                'per_user_per_minute': 60,
                'per_ip_per_minute': 100,
                'window_seconds': 60,
            },
            'token_budget': {
                'enabled': True,
                'tokens_per_window': 50000,
                'window_seconds': 60,
            },
            'health_check': {'interval_seconds': 30, 'timeout_seconds': 10},
        },
        'appsec': {
            'enabled': True,
            'max_message_length': 4000,
            'use_prompt_hierarchy': True,
            'output_validation': True,
            'block_encoded_payloads': True,
            'block_indirect_injection': True,
            'sanitize_input': True,
            'sanitize_output': True,
            'blocked_patterns': [
                r"ignore\s+(?:all\s+)?previous\s+instructions",
                r"forget\s+(?:everything|all\s+)?(?:rules|prompts)",
                r"system\s+prompt",
                r"you\s+are\s+now",
                r"pretend\s+you\s+are",
                r"from\s+now\s+on",
                r"new\s+role:",
            ],
            'indirect_injection_markers': [
                "[SYSTEM]", "[INSTRUCTION]", "<!-- system:", "###system###",
                "<<system>>", "<system_override>",
            ],
        },
        'privacy': {
            'enabled': True,
            'redact_pii': True,
            'pseudonymize': True,
            'pseudonym_salt': 'TRiSM-default-salt',
            'consent_mode': 'env',           # 'interactive' | 'auto_grant' | 'auto_deny' | 'env'
            'data_retention_days': 30,
            'require_consent': True,
            # Padrões serão complementados com DEFAULT_PATTERNS_BR; descomente
            # para sobreescrever explicitamente:
            # 'pii_patterns': {...}
        },
        'adversarial': {
            'enabled': True,
            'multiturn_window': 6,
            'repetition_window': 100,
            'repetition_jaccard_threshold': 0.85,
            'repetition_levenshtein_threshold': 0.85,
            'extraction_min_keywords': 2,
            'block_threshold': 0.5,
            'block_suspicious': True,
        },
        'toxicity': {
            'enabled': True,
            'blocked_terms': [
                'hate', 'kill', 'murder', 'rape', 'terrorist', 'bomb',
                'suicide', 'racist', 'sexist', 'homophobic',
            ],
        },
        'logging': {
            'audit_file': 'audit_log.jsonl',
            'metrics_file': 'metrics.json',
            'retention_days': 30,
            'max_log_size_mb': 100,
            'encrypt': False,                # ative com cryptography instalado
        },
        'benchmark': {
            'dataset_path': 'benchmark/datasets/owasp_llm_top10_pt.json',
            'results_dir': 'benchmark/results',
            'tivs_weights': [0.25, 0.25, 0.25, 0.25],
            'compare_baseline': True,
        },
    }
