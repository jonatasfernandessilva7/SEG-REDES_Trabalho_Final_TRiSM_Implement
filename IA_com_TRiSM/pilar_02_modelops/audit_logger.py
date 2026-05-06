"""
Pilar 2: ModelOps - Logs Imutáveis para Auditoria

Responsabilidades:
- Armazenamento de logs em formato JSON Lines
- Cleanup automático de logs antigos
- Recuperação de logs para análise
"""

import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict

sys.path.append(str(Path(__file__).parent.parent))

from core.base import AuditTurn


class AuditLogger:
    """
    Pilar 2 (ModelOps) - Auditoria
    Logs imutáveis em formato JSON Lines (append-only)
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.log_file = Path(config.get('logging', {}).get('audit_file', 'audit_log.jsonl'))
        self.retention_days = config.get('logging', {}).get('retention_days', 30)
        self.max_log_size_mb = config.get('logging', {}).get('max_log_size_mb', 100)
        
        # Garantir que o diretório existe
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Cleanup periódico
        self._cleanup_old_logs()
    
    def _cleanup_old_logs(self):
        """Remove logs mais antigos que o período de retenção"""
        if not self.log_file.exists():
            return
        
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        
        try:
            lines = self.log_file.read_text(encoding='utf-8').splitlines()
            filtered_lines = []
            removed_count = 0
            
            for line in lines:
                try:
                    entry = json.loads(line)
                    entry_time = datetime.fromisoformat(entry.get('timestamp', '2000-01-01'))
                    if entry_time > cutoff:
                        filtered_lines.append(line)
                    else:
                        removed_count += 1
                except (json.JSONDecodeError, ValueError):
                    # Preservar linhas malformadas para não perder dados
                    filtered_lines.append(line)
            
            # Escrever logs filtrados
            self.log_file.write_text('\n'.join(filtered_lines), encoding='utf-8')
            
            if removed_count > 0:
                print(f"[Audit] Removidos {removed_count} logs antigos (> {self.retention_days} dias)")
                
        except Exception as e:
            print(f"[Audit] Erro na limpeza de logs: {e}")
    
    def log_turn(self, turn: AuditTurn):
        """
        Registra turno de conversa (append-only, imutável)
        
        Args:
            turn: Objeto AuditTurn com dados da interação
        """
        log_entry = {
            "turn_id": turn.turn_id,
            "timestamp": turn.timestamp,
            "session_id": turn.session_id,
            "user_message": turn.user_message,
            "assistant_response": turn.assistant_response,
            "latency_ms": turn.latency_ms,
            "input_tokens": turn.input_tokens,
            "output_tokens": turn.output_tokens,
            "risk_level": turn.risk_level,
            "policies_triggered": turn.policies_triggered,
            "anomalies_detected": turn.anomalies_detected,
            "confidence_score": turn.confidence_score
        }
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False, default=str) + "\n")
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Recupera logs recentes para análise"""
        logs = []
        if not self.log_file.exists():
            return logs
        
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines[-limit:]:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[Audit] Erro ao ler logs: {e}")
        
        return logs
    
    def get_logs_by_session(self, session_id: str, limit: int = 100) -> List[Dict]:
        """Recupera logs de uma sessão específica"""
        all_logs = self.get_recent_logs(limit)
        return [log for log in all_logs if log.get('session_id') == session_id]
    
    def get_logs_by_risk_level(self, risk_level: str, limit: int = 100) -> List[Dict]:
        """Recupera logs por nível de risco"""
        all_logs = self.get_recent_logs(limit)
        return [log for log in all_logs if log.get('risk_level') == risk_level]
    
    def get_status(self) -> Dict:
        """Retorna status do audit logger"""
        file_size_mb = 0
        if self.log_file.exists():
            file_size_mb = self.log_file.stat().st_size / (1024 * 1024)
        
        return {
            "enabled": True,
            "log_file": str(self.log_file),
            "file_size_mb": round(file_size_mb, 2),
            "retention_days": self.retention_days,
            "max_log_size_mb": self.max_log_size_mb
        }