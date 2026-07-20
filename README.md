# JEHWE: Implementação do _Framework_ AI TRiSM em Sistemas de IA Generativa

o JEHWE implementa os pilares do modelo **AI TRiSM (Trust, Risk, and Security Management)** em um chat inteligente baseado em IA generativa, especificamente utilizando a plataforma **Ollama** para execução local de modelos de linguagem.

## 📋 Objetivo Central

Este trabalho pretende demonstrar **de que forma a adoção do modelo TRiSM pode elevar o nível de segurança de aplicações baseadas em IA generativa**, especialmente no contexto de chats inteligentes, por meio da aplicação de mecanismos fundamentados nos **pilares clássicos da segurança da informação**:

- **Confidencialidade**: Proteção dos dados contra acesso não autorizado
- **Integridade**: Garantia de que os dados não foram alterados indevidamente
- **Disponibilidade**: Garantia de acesso aos recursos quando necessário

Além de aspectos complementares como:
- **Autenticidade**: Verificação da identidade dos usuários e dados
- **Rastreabilidade**: Registro e monitoramento de todas as operações
- **Governança**: Controle e direcionamento do comportamento do sistema

## 🎯 Objetivos Específicos

1. **Apresentar os fundamentos do modelo TRiSM** e sua relevância para sistemas de IA generativa
2. **Analisar a arquitetura e o funcionamento do Ollama** como plataforma de execução local de modelos de linguagem
3. **Avaliar como a integração entre TRiSM e IA generativa** pode contribuir para maior segurança, confiabilidade e governança nas interações com sistemas baseados em linguagem natural

## 🏗️ Estrutura do Projeto

O projeto está organizado em ambientes de implementação, um módulo de benchmark/testes e um módulo de análise de resultados:

### `IA_com_TRiSM/` - Implementação com Pilares de Segurança

Sistema de chat inteligente **com aplicação dos pilares TRiSM**:

- **`core/`**: Módulos centrais
  - `base.py`: Classes e tipos base do framework (ex.: `RiskLevel`, `AuditTurn`)
  - `metrics_lib.py`: Biblioteca de métricas TRiSM (ASR, DSR, ISR, POF, PSR, CCS, TIVS)
  - `__init__.py`: Inicialização do pacote

- **`pilar_01_explicabilidade/`**: Pilar da Explicabilidade (Explainability)
  - `explainability.py`: Interpretabilidade, confidence via logprobs e rastreamento de decisões

- **`pilar_02_modelops/`**: Pilar de Model Operations
  - `audit_logger.py`: Auditoria com hash chain e rastreamento
  - `metrics.py`: Coleta e análise de métricas (drift PSI/Jensen-Shannon, latência, custo)
  - `policy_engine.py`: Motor de políticas, rate limiting e orçamento de tokens

- **`pilar_03_appsec/`**: Pilar de Application Security
  - `security.py`: Sanitização de input/output, hierarquia de prompts, bloqueio de payloads codificados e injeção indireta

- **`pilar_04_privacy/`**: Pilar de Privacidade
  - `privacy.py`: Redação e pseudonimização de PII (padrões brasileiros: CPF, CNPJ, RG, CNH, PIS, título de eleitor, CEP, etc.), gestão de consentimento

- **`pilar_05_adversarial/`**: Pilar de Robustez Adversarial
  - `adversarial.py`: Detecção de jailbreak/ataques multi-turno, repetição (Jaccard/Levenshtein) e extração de prompt

- **`trism_chat/`**: Interface do chat com TRiSM
  - `main.py`: CLI interativo original
  - `main_server.py`: Servidor **FastAPI** que orquestra os 5 pilares via API REST (endpoints de mensagem, health check, dashboard, relatório de governança e métricas Prometheus)
  - `config.yaml`: Configuração central de todos os pilares (v2)
  - `audit_log.jsonl`: Registro de auditoria gerado em execução
  - `README_FASTAPI.md`: Documentação detalhada do servidor FastAPI e seus endpoints

- **`benchmark/`**: Framework de benchmark TRiSM vs. baseline
  - `runner.py`: Executa o dataset de prompts contra o sistema com/sem TRiSM
  - `evaluator.py`: Calcula métricas de sucesso/defesa a partir dos resultados
  - `datasets/owasp_llm_top10_pt.json`: Dataset de prompts de teste baseado no **OWASP LLM Top 10** (em português)

- **`tests/`**: Suíte de testes e execução em lote
  - `test_pilares.py`, `test_benchmark_complete.py`, `test_benchmark_advanced.py`, `test_benchmark_massa.py`: Testes unitários e de carga dos pilares e do benchmark
  - `run_trism_batch_api.py`: Execução em lote de prompts contra a API FastAPI (com TRiSM)
  - `run_non_trism_batch.py`: Execução em lote de prompts contra o baseline (sem TRiSM)
  - `TRiSM_v2_300_Test_Suite.xlsx`: Planilha com o conjunto de 300 casos de teste utilizados na avaliação

- **`utils/`**: Utilitários
  - `config_loader.py`: Carregamento e validação do `config.yaml`

### `IA_sem_TRiSM/` - Implementação Baseline (sem TRiSM)

Sistema de chat inteligente **sem aplicação de pilares TRiSM** (utilizado como grupo de controle/comparação):

- `chat.py`: Interface do chat
- `conexao_com_SLM.py`: Conexão direta com Small Language Model (Ollama)

### `analise_dos_resultados/` - Análise Estatística dos Resultados

Scripts e dados usados para comparar quantitativamente as execuções com e sem TRiSM:

- `trism_analysis.py`: Engenharia de atributos, testes de hipótese (Mann-Whitney U) e geração de gráficos comparando os dois cenários
- `audit_data_on.csv` / `audit_data_off.csv`: Dados de auditoria coletados com e sem TRiSM habilitado
- `descriptive_results.csv`, `hypothesis_test.csv`, `modelops_analysis.csv`, `modelops_results.csv`, `success_metrics.csv`: Resultados descritivos, testes estatísticos e métricas de ModelOps
- `modelops_success_metrics.png`: Visualização gráfica das métricas de sucesso

### `utils/` (raiz) - Utilitários Gerais

- `transform_json_to_csv.py`: Converte logs de auditoria em JSON/JSONL para CSV, usados na etapa de análise

## 🔐 Pilares TRiSM Implementados

### 1. **Explicabilidade** (Pilar 01)
- Interpretabilidade das decisões do modelo, com cálculo de *confidence* a partir dos logprobs do Ollama
- Registro da cadeia de raciocínio (*chain of thought*) e rastreamento de decisões

### 2. **Model Operations** (Pilar 02)
- Auditoria completa de operações com *hash chain* (cadeia de hashes) para garantir integridade dos logs
- Coleta de métricas de desempenho, custo e detecção de *drift* (PSI e divergência de Jensen-Shannon)
- Motor de políticas com *rate limiting* (por usuário/IP) e orçamento de tokens (LLM10 - Unbounded Consumption)

### 3. **Application Security** (Pilar 03)
- Validação e sanitização de inputs/outputs
- Hierarquia de prompts (system > developer > user) para reduzir prompt injection
- Bloqueio de payloads codificados (Base64/Hex) e marcadores de injeção indireta

### 4. **Privacidade** (Pilar 04)
- Redação e pseudonimização determinística de PII, com padrões específicos para o Brasil (CPF, CNPJ, RG, CNH, PIS, título de eleitor, CEP, entre outros)
- Gestão de consentimento e retenção de dados
- Conformidade com LGPD/GDPR

### 5. **Robustez Adversarial** (Pilar 05)
- Detecção de jailbreak e ataques adversariais em múltiplas categorias
- Análise de ataques multi-turno e de repetição (similaridade Jaccard/Levenshtein)
- Detecção de tentativas de extração de prompt do sistema

## 🚀 Como Usar

### Pré-requisitos

- Python 3.8+
- Ollama instalado e executando
  - <a>https://ollama.com/download</a>
  - ollama run phi3.5
- Dependências do projeto

### Instalação

1. Clone o repositório:
```bash
git clone <repo-url>
cd SEG-REDES_Trabalho_Final_TRiSM_Implement
```

2. Instale as dependências do projeto (arquivo único na raiz, usado por ambas as implementações):
```bash
pip install -r requirements.txt
```

3. Inicie o Ollama e baixe o modelo utilizado:
```bash
ollama serve
ollama pull phi3.5
```

4. Execute o sistema:

**Com TRiSM (CLI interativo):**
```bash
python IA_com_TRiSM/trism_chat/main.py
```

**Com TRiSM (servidor FastAPI, com API REST e documentação Swagger):**
```bash
python IA_com_TRiSM/trism_chat/main_server.py
# Documentação interativa em http://localhost:8000/docs
```
> Detalhes completos dos endpoints em [`IA_com_TRiSM/trism_chat/README_FASTAPI.md`](IA_com_TRiSM/trism_chat/README_FASTAPI.md).

**Sem TRiSM (baseline):**
```bash
python IA_sem_TRiSM/chat.py
```

### 🧪 Benchmark e Testes

Para comparar quantitativamente o comportamento com e sem TRiSM contra o dataset baseado no OWASP LLM Top 10:

```bash
cd IA_com_TRiSM
python -m benchmark.runner
```

Testes unitários e em lote estão disponíveis em `IA_com_TRiSM/tests/` (ex.: `test_pilares.py`, `run_trism_batch_api.py`, `run_non_trism_batch.py`).

### 📈 Análise dos Resultados

Após a coleta dos dados de auditoria (`audit_data_on.csv` e `audit_data_off.csv`), a análise estatística comparativa pode ser executada com:

```bash
cd analise_dos_resultados
python trism_analysis.py
```

O script aplica engenharia de atributos, testes de hipótese (Mann-Whitney U) e gera visualizações comparando os cenários com e sem TRiSM.

## 📊 Comparação: Com vs Sem TRiSM

| Aspecto | Sem TRiSM | Com TRiSM |
|---------|-----------|----------|
| Explicabilidade | ❌ Limitada | ✅ Completa |
| Auditoria | ❌ Não | ✅ Sim |
| Segurança | ⚠️ Básica | ✅ Avançada |
| Privacidade | ❌ Não | ✅ Implementada |
| Rastreabilidade | ❌ Não | ✅ Total |
| Governança | ❌ Não | ✅ Ativa |

## 📝 Configuração

O sistema com TRiSM utiliza um arquivo de configuração central, `IA_com_TRiSM/trism_chat/config.yaml`, com uma seção dedicada a cada pilar (explicabilidade, ModelOps, AppSec, privacidade, adversarial), além de configurações de toxicidade, logging e benchmark. Exemplo simplificado:

```yaml
model:
  name: "phi3.5"       # Modelo Ollama a utilizar
  provider: "ollama"

explainability:
  enabled: true
  confidence_threshold: 0.7

modelops:
  enabled: true
  rate_limiting:
    requests_per_minute: 30
  token_budget:
    tokens_per_window: 50000

appsec:
  enabled: true
  sanitize_input: true
  sanitize_output: true

privacy:
  enabled: true
  redact_pii: true
  pseudonymize: true

adversarial:
  enabled: true
  block_suspicious: true
```

Consulte o arquivo completo para todos os parâmetros disponíveis, incluindo limites de *drift*, orçamento de tokens, padrões de PII e configuração do benchmark.

## 📚 Referências

- **TRiSM**: Trust, Risk, and Security Management
- **Ollama**: Plataforma de execução local de LLMs
- **Segurança da Informação**: ISO/IEC 27001, 27002, 27005
- **Privacidade**: LGPD, GDPR

## Artigos Base

1. RAZA, Shaina; SAPKOTA, Ranjan; KARKEE, Manoj; EMMANOUILIDIS, Christos. TRiSM for agentic AI: a review of trust, risk, and security management in LLM-based agentic multi-agent systems. AI Open, v. 7, p. 71–95, 2026. DOI: https://doi.org/10.1016/j.aiopen.2026.02.006

2. RAY, Partha Pratim. A review of TRiSM frameworks in artificial intelligence systems: fundamentals, taxonomy, use cases, key challenges and future directions. Expert Systems, v. 43, 2026, e70213. DOI: https://doi.org/10.1111/exsy.70213

## 🎓 Contexto Acadêmico

Este projeto é desenvolvido como trabalho final para a disciplina **CKP8233** (Segurança em Redes), ministrada pelo Prof. Dr. Emanuel Bezerra Rodrigues, demonstrando a aplicação prática dos conceitos de segurança em sistemas modernos de IA generativa.

## 📄 Licença

Ver arquivo [LICENSE](LICENSE) para detalhes.

---

**Desenvolvido como demonstração dos pilares TRiSM em sistemas de IA generativa**
