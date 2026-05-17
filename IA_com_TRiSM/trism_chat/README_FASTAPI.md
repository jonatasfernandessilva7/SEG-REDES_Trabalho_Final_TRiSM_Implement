## 🚀 TRiSM Chat v2 - Servidor FastAPI

Transformação do sistema TRiSM em uma arquitetura de servidor com API REST, permitindo múltiplas sessões e integração com os 5 pilares de governança de IA.

### 📋 Estrutura

```
trism_chat/
├── main.py              # CLI interativo original
├── main_server.py       # 🆕 Servidor FastAPI com todos os pilares
├── config.yaml          # Configuração dos pilares
├── requirements.txt     # Dependências (atualizado com FastAPI)

tests/
├── run_trism_batch.py         # Testes em lote (Ollama direto)
├── run_trism_batch_api.py     # 🆕 Testes em lote via API FastAPI
```

### 🛠️ Instalação e Setup

#### 1. Instalar Dependências

```bash
cd trism_chat
pip install -r requirements.txt
```

Isso instala:
- `fastapi` e `uvicorn` (servidor web)
- `pydantic` (validação de dados)
- `requests` (cliente HTTP)
- `ollama` (cliente Ollama)
- `pyyaml` (configuração)
- `cryptography` (auditoria)

#### 2. Configurar o Ollama

Certifique-se de ter Ollama rodando localmente:

```bash
ollama serve
# Em outro terminal:
ollama pull phi3.5
```

### 🚀 Executando o Servidor FastAPI

#### Opção 1: Porta Padrão (8000)

```bash
python main_server.py
```

Saída esperada:
```
╔════════════════════════════════════════════════════════════════╗
║         🚀 TRiSM CHAT v2 — SERVIDOR FastAPI                   ║
║     Trust, Risk and Security Management for AI Chat           ║
╠════════════════════════════════════════════════════════════════╣
║ Pilares ATIVOS:                                                ║
║  P1 - Explicabilidade (logprobs + decision trace)              ║
║  P2 - ModelOps (PSI/JS drift, hash chain, token budget)        ║
║  P3 - AppSec (encoding tricks, output validator, hierarquia)   ║
║  P4 - Privacidade (PII BR completo, pseudonimização)           ║
║  P5 - Adversários (categorias, multi-turno, repetição)         ║
╚════════════════════════════════════════════════════════════════╝

📡 Iniciando servidor na porta 8000...
📚 Documentação Swagger: http://0.0.0.0:8000/docs
📚 Documentação ReDoc: http://0.0.0.0:8000/redoc
```

#### Opção 2: Porta Customizada

```bash
python main_server.py --port 8080 --host 127.0.0.1
```

### 📡 Endpoints Disponíveis

#### 1. Health Check
```bash
curl http://localhost:8000/api/health
```

Resposta:
```json
{
  "status": "healthy",
  "model": "phi3.5",
  "model_version": "1.0.0",
  "latency_ms": 150.25,
  "model_loaded": true
}
```

#### 2. Enviar Mensagem (Principal)
```bash
curl -X POST http://localhost:8000/api/message \
  -H "Content-Type: application/json" \
  -d '{"message": "O que é segurança de IA?", "session_id": null}'
```

Resposta:
```json
{
  "response": "A segurança de IA...",
  "blocked": false,
  "session_id": "abc123...",
  "risk_level": "low",
  "latency_ms": 1250.50,
  "input_tokens": 50,
  "output_tokens": 150,
  "policies_triggered": [],
  "violations": [],
  "confidence": 0.95,
  "owasp_categories": []
}
```

#### 3. Dashboard Completo
```bash
curl http://localhost:8000/api/dashboard
```

Retorna status de todos os 5 pilares.

#### 4. Relatório de Governança
```bash
curl http://localhost:8000/api/governance-report
```

Relatório detalhado de conformidade e métricas.

#### 5. Métricas Prometheus
```bash
curl http://localhost:8000/api/metrics/prometheus
```

Métricas em formato Prometheus.

#### 6. Limpar Histórico da Sessão
```bash
curl -X POST http://localhost:8000/api/session/clear \
  -H "Content-Type: application/json" \
  -d '{"session_id": "abc123..."}'
```

#### 7. Listar Sessões Ativas
```bash
curl http://localhost:8000/api/sessions/list
```

#### 8. Info da Sessão
```bash
curl http://localhost:8000/api/session/info?session_id=abc123...
```

### 🧪 Testes em Lote via API

O novo arquivo `run_trism_batch_api.py` executa testes consumindo a API em vez de chamar Ollama diretamente:

#### Uso Básico

```bash
# Terminal 1: Inicia o servidor
python main_server.py

# Terminal 2: Executa testes
cd tests
python run_trism_batch_api.py
```

#### Opções Avançadas

```bash
# Com URL customizada
python run_trism_batch_api.py --api-url http://localhost:8080

# Limitando número de testes
python run_trism_batch_api.py --max-tests 50

# Buscando relatório de governança após testes
python run_trism_batch_api.py --fetch-report

# Arquivo Excel customizado
python run_trism_batch_api.py --input-file custom_tests.xlsx
```

#### Saída

```
[  1/100] TEST_0001        | P1 Explicability   | Pilar 1         ... ✅ Score: 92/100 | Latência: 1250ms
[  2/100] TEST_0002        | P3 Injection       | Pilar 3         ... ❌ Score: 35/100 | Latência: 850ms
...

════════════════════════════════════════════════════════════════════════════════
📊 RESUMO DA EXECUÇÃO
════════════════════════════════════════════════════════════════════════════════
⏱️  Duração total: 125.3s
📈 Total de testes: 100
✅ Passou: 92 (92.0%)
❌ Falhou: 8 (8.0%)
🚫 Bloqueado: 3
⏱️  Latência média: 1205ms
📊 Score médio: 87.3/100

🔐 Políticas TRiSM disparadas (Top 5):
   - jailbreak_blocked: 12 vezes
   - pii_redacted: 45 vezes
   - extraction_attempt: 8 vezes
   - rate_limit_exceeded: 2 vezes
   - drift_detected: 5 vezes

🏷️  Categorias OWASP Top 10 detectadas:
   - LLM01: 25 vezes
   - LLM02: 45 vezes
   - LLM05: 15 vezes
   - LLM07: 8 vezes
   - LLM10: 2 vezes

════════════════════════════════════════════════════════════════════════════════
✅ Logs estruturados exportados em: trism_api_execution_log_20260512_120000.json
✅ Relatório CSV exportado em: trism_api_batch_report_20260512_120000.csv
✅ Relatório de governança exportado em: trism_governance_report_20260512_120000.json
```

### 📊 Fluxo de Processamento

```
POST /api/message
    ↓
[P4 Privacidade] Redação de PII (entrada)
    ↓
[P3 AppSec] Validação e sanitização
    ↓
[P5 Adversários] Detecção de jailbreak, extração, multi-turno
    ↓
[P2 ModelOps] Rate limit + Token budget
    ↓
[Modelo] Chamada ao Ollama (Phi 3.5)
    ↓
[P3 AppSec] Validação de saída
    ↓
[P4 Privacidade] Redação de PII (saída)
    ↓
[P5 Adversários] Detecção de repetição semântica
    ↓
[P2 ModelOps] Drift PSI/JS + Métricas
    ↓
[P1 Explicabilidade] Confiança + Decision trace
    ↓
[P2 ModelOps] Auditoria com hash chain
    ↓
Resposta com metadados
```

### 🔐 Segurança e Governança

#### Recursos Implementados

1. **P1 - Explicabilidade**
   - Logprobs do modelo
   - Decision traces estruturadas
   - Confiança híbrida

2. **P2 - ModelOps**
   - Rate limiting por sessão
   - Token budget
   - Drift detectção (PSI/JS)
   - Hash chain para auditoria imutável

3. **P3 - AppSec**
   - Detecção de injeção
   - Encoding tricks
   - Validação de saída
   - Hierarquia de prompts

4. **P4 - Privacidade**
   - Redação de PII (CPF, Email, Telefone, etc.)
   - Minimização de dados
   - Consentimento LGPD

5. **P5 - Adversários**
   - Detecção de jailbreak (categorizado)
   - Detecção multi-turno
   - Detecção de extração de conhecimento
   - Detecção de repetição semântica

### 📈 Comparação: CLI vs API

| Aspecto | CLI (main.py) | API (main_server.py) |
|---------|---------------|----------------------|
| **Modo** | Interativo | REST API |
| **Sessões** | 1 por execução | Múltiplas simultâneas |
| **Escalabilidade** | Local | Escalável (Docker/K8s) |
| **Integração** | Shell | Qualquer cliente HTTP |
| **Dashboard** | Terminal | JSON/Swagger |
| **Testes** | Direto ao Ollama | Via API (run_trism_batch_api.py) |

### 🐳 Containerização (Futuro)

Para usar com Docker:

```dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY trism_chat/requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "trism_chat/main_server.py"]
```

```bash
docker build -t trism-chat:v2 .
docker run -p 8000:8000 trism-chat:v2
```

### 🛠️ Troubleshooting

#### Erro: "API TRiSM não disponível"

```bash
# Verificar se servidor está rodando
curl http://localhost:8000/api/health

# Se não responder, verificar logs do servidor
python main_server.py  # Ver traceback
```

#### Erro: "Module not found: fastapi"

```bash
pip install fastapi uvicorn pydantic requests
```

#### Erro: "Ollama não responde"

```bash
# Verificar se Ollama está rodando
ollama serve

# Verificar modelo
ollama list
```

### 📚 Documentação Swagger

Acesse `http://localhost:8000/docs` para documentação interativa com testes diretos!

### 🔗 Integração com Sistemas Externos

Exemplo em Python:

```python
import requests

api_url = "http://localhost:8000"

# Health check
response = requests.get(f"{api_url}/api/health")
print(response.json())

# Enviar mensagem
response = requests.post(f"{api_url}/api/message", json={
    "message": "Qual é a capital do Brasil?"
})
data = response.json()
print(f"Resposta: {data['response']}")
print(f"Confiança: {data['confidence']:.2%}")
print(f"Risco: {data['risk_level']}")
print(f"Políticas: {data['policies_triggered']}")
```

### 📞 Suporte

Para dúvidas ou problemas, verifique:
1. Configuração em `config.yaml`
2. Logs do servidor
3. Status de saúde do Ollama
4. Arquivo de testes (formato Excel)
