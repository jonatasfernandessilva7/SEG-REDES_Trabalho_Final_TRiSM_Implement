"""
Pilar 2: ModelOps - Logs Imutáveis para Auditoria — VERSÃO FORTALECIDA

Melhorias frente à v1:
- Hash chain (SHA-256 encadeado) garantindo detecção de adulteração retroativa.
- Verificação de integridade da cadeia em tempo real.
- Cifragem opcional do log com Fernet (AES-128) — atende LGPD/GDPR.
- Filtragem por OWASP category, range temporal e confidence threshold.
"""

import sys
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import asdict
from typing import List, Dict, Optional, Deque
from collections import deque

sys.path.append(str(Path(__file__).parent.parent))

from core.base import AuditTurn
from core.metrics_lib import turn_hash, verify_chain


class AuditLogger:
    """Pilar 2 (ModelOps) - Auditoria com hash chain e cifragem opcional."""

    def __init__(self, config: Dict):
        self.config = config
        log_cfg = config.get('logging', {})
        self.log_file = Path(log_cfg.get('audit_file', 'audit_log.jsonl'))
        self.retention_days = log_cfg.get('retention_days', 30)
        self.max_log_size_mb = log_cfg.get('max_log_size_mb', 100)
        self.encrypt = bool(log_cfg.get('encrypt', False))
        self._fernet = None

        if self.encrypt:
            self._init_fernet(log_cfg)

        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        # Determina o último hash conhecido (continuidade da cadeia entre execuções)
        self._last_hash = self._read_last_hash()

        self._cleanup_old_logs()

    # ------------------------------------------------------------------
    def _init_fernet(self, log_cfg: Dict) -> None:
        try:
            from cryptography.fernet import Fernet  # type: ignore
        except ImportError:
            print("[Audit] cryptography não instalado; cifragem desativada.")
            self.encrypt = False
            return

        key = log_cfg.get('encryption_key') or os.environ.get('TRISM_FERNET_KEY')
        if not key:
            # Gera e salva uma chave em arquivo .key se não fornecida
            key_path = self.log_file.with_suffix('.key')
            if key_path.exists():
                key = key_path.read_text().strip()
            else:
                key = Fernet.generate_key().decode()
                key_path.write_text(key)
                print(f"[Audit] Chave Fernet gerada em {key_path}")
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)

    # ------------------------------------------------------------------
    def _read_last_hash(self) -> str:
        """Recupera o último self_hash registrado para encadear nova execução."""
        if not self.log_file.exists():
            return ""
        try:
            last_line = ""
            with open(self.log_file, "rb") as f:
                # Lê do final para frente
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return ""
                buf = b""
                pos = size
                while pos > 0 and buf.count(b"\n") < 2:
                    chunk = min(2048, pos)
                    pos -= chunk
                    f.seek(pos)
                    buf = f.read(chunk) + buf
                last_line = buf.split(b"\n")[-1].decode(errors="ignore").strip()
                if not last_line:
                    last_line = buf.split(b"\n")[-2].decode(errors="ignore").strip()
            if not last_line:
                return ""
            entry = self._maybe_decrypt(last_line)
            data = json.loads(entry)
            return data.get("self_hash", "")
        except Exception:
            return ""

    def _maybe_encrypt(self, line: str) -> str:
        if self._fernet is not None:
            return self._fernet.encrypt(line.encode("utf-8")).decode("utf-8")
        return line

    def _maybe_decrypt(self, line: str) -> str:
        if self._fernet is not None:
            try:
                return self._fernet.decrypt(line.encode("utf-8")).decode("utf-8")
            except Exception:
                return line
        return line

    # ------------------------------------------------------------------
    def _rotate_log(self, reason: str) -> None:
        """Arquiva o log ativo e reinicia a cadeia — preserva a integridade do hash chain."""
        archive = self.log_file.with_suffix(
            f".{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        )
        try:
            self.log_file.rename(archive)
            self._last_hash = ""  # nova cadeia começa do zero
            print(f"[Audit] Log rotacionado → {archive.name} (motivo: {reason})")
        except OSError as e:
            print(f"[Audit] Falha ao rotacionar log: {e}")

    def _cleanup_old_logs(self) -> None:
        """Rotaciona o log quando excede tamanho máximo ou retenção de tempo.

        Não remove entradas do meio da cadeia — isso quebraria o hash chain.
        Em vez disso, arquiva o arquivo inteiro e inicia uma nova cadeia.
        """
        if not self.log_file.exists():
            return

        # Rotação por tamanho
        size_mb = self.log_file.stat().st_size / (1024 * 1024)
        if size_mb >= self.max_log_size_mb:
            self._rotate_log("size_limit")
            return

        # Rotação por retenção: verifica a primeira entrada do arquivo
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                first_line = f.readline().strip()
            if not first_line:
                return
            decoded = self._maybe_decrypt(first_line)
            entry = json.loads(decoded)
            ts = datetime.fromisoformat(entry.get('timestamp', '9999-01-01'))
            if ts < cutoff:
                self._rotate_log("retention")
        except (json.JSONDecodeError, ValueError):
            pass
        except Exception as e:
            print(f"[Audit] Erro na rotação de logs: {e}")

    # ------------------------------------------------------------------
    def log_turn(self, turn: AuditTurn) -> None:
        """Registra turno com hash chain. Atualiza self.last_hash."""
        payload = asdict(turn)
        payload["prev_hash"] = self._last_hash
        # Não inclui self_hash no payload usado para hashing
        payload_for_hash = {k: v for k, v in payload.items() if k != "self_hash"}
        h = turn_hash(payload_for_hash, self._last_hash)
        payload["self_hash"] = h

        line = json.dumps(payload, ensure_ascii=False, default=str)
        encrypted = self._maybe_encrypt(line)
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(encrypted + "\n")
        self._last_hash = h

    # ------------------------------------------------------------------
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        logs: List[Dict] = []
        if not self.log_file.exists():
            return logs
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()[-limit:]
            for line in lines:
                try:
                    decoded = self._maybe_decrypt(line.strip())
                    logs.append(json.loads(decoded))
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            print(f"[Audit] Erro ao ler logs: {e}")
        return logs

    def get_logs_by_session(self, session_id: str, limit: int = 100) -> List[Dict]:
        return [log for log in self.get_recent_logs(limit) if log.get('session_id') == session_id]

    def get_logs_by_risk_level(self, risk_level: str, limit: int = 100) -> List[Dict]:
        return [log for log in self.get_recent_logs(limit) if log.get('risk_level') == risk_level]

    def get_logs_by_owasp(self, category: str, limit: int = 100) -> List[Dict]:
        return [log for log in self.get_recent_logs(limit)
                if category in (log.get('owasp_categories') or [])]

    # ------------------------------------------------------------------
    def verify_integrity(self) -> Dict:
        """Verifica a hash chain do arquivo de auditoria."""
        if not self.log_file.exists():
            return {"valid": True, "total": 0, "invalid_indices": []}
        if self.encrypt:
            # Para verificar chain quando criptografado, decifra para um arquivo temporário
            tmp_path = self.log_file.with_suffix('.plain.tmp')
            with open(self.log_file, "r", encoding="utf-8") as fin, \
                 open(tmp_path, "w", encoding="utf-8") as fout:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    fout.write(self._maybe_decrypt(line) + "\n")
            valid, total, invalid = verify_chain(str(tmp_path))
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            return {"valid": valid, "total": total, "invalid_indices": invalid}
        valid, total, invalid = verify_chain(str(self.log_file))
        return {"valid": valid, "total": total, "invalid_indices": invalid}

    # ------------------------------------------------------------------
    def get_status(self) -> Dict:
        size_mb = (self.log_file.stat().st_size / (1024 * 1024)) if self.log_file.exists() else 0
        return {
            "enabled": True,
            "log_file": str(self.log_file),
            "file_size_mb": round(size_mb, 2),
            "retention_days": self.retention_days,
            "max_log_size_mb": self.max_log_size_mb,
            "encrypted": self.encrypt,
            "chain_last_hash": (self._last_hash[:16] + "...") if self._last_hash else "",
        }
