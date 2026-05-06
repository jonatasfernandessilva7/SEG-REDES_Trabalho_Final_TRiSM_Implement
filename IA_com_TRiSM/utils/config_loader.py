"""
Utils: Config Loader
Carrega configuração do arquivo YAML
"""

import sys
import yaml
from pathlib import Path
from typing import Dict, Any

sys.path.append(str(Path(__file__).parent.parent))


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Carrega configuração do arquivo YAML
    
    Args:
        config_path: Caminho para o arquivo de configuração
    
    Returns:
        Dicionário com a configuração
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[Config] Arquivo {config_path} não encontrado, usando defaults")
        return get_default_config()
    except yaml.YAMLError as e:
        print(f"[Config] Erro ao parsear YAML: {e}")
        return get_default_config()
    except Exception as e:
        print(f"[Config] Erro ao carregar config: {e}")
        return get_default_config()


def get_default_config() -> Dict[str, Any]:
    """Retorna configuração padrão"""
    return {
        'model': {'name': 'phi3.5', 'version': '1.0.0'},
        'explainability': {'enabled': True, 'log_chain_of_thought': True, 'confidence_threshold': 0.7},
        'modelops': {
            'enabled': True,
            'versioning': True,
            'monitoring': {'latency_threshold_ms': 5000, 'drift_threshold': 0.3, 'token_alert_threshold': 10000},
            'rate_limiting': {'enabled': True, 'requests_per_minute': 30, 'window_seconds': 60},
            'health_check': {'interval_seconds': 30, 'timeout_seconds': 10}
        },
        'appsec': {
            'enabled': True,
            'max_message_length': 4000,
            'blocked_patterns': ['ignore.*instructions', 'forget.*rules', 'system prompt'],
            'sanitize_output': True,
            'sanitize_input': True
        },
        'privacy': {
            'enabled': True,
            'redact_pii': True,
            'pii_patterns': {
                'cpf': '\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}',
                'email': '[\\w\\.-]+@[\\w\\.-]+\\.\\w+',
                'phone': '\\(?\\d{2}\\)?\\s?\\d{4,5}-?\\d{4}'
            },
            'data_retention_days': 30,
            'require_consent': True
        },
        'adversarial': {
            'enabled': True,
            'jailbreak_patterns': ['.*jailbreak.*', '.*DAN.*'],
            'max_repetition_ratio': 0.5,
            'repetition_window': 100,
            'block_suspicious': True
        },
        'toxicity': {'enabled': True, 'blocked_terms': ['hate', 'kill', 'murder']},
        'logging': {'audit_file': 'audit_log.jsonl', 'retention_days': 30}
    }