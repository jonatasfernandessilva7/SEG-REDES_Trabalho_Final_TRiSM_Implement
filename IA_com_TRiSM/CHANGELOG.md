# IA_com_TRiSM — CHANGELOG

## Visão geral das mudanças por pilar

### Pilar 1 — Explicabilidade
**Antes:** `calculate_confidence` era apenas `1.0 - 0.1·violações`. Sem decision trace.
Sem uso de logprobs do modelo.

**Agora:**
- `confidence_from_logprobs(ollama_response)` — extrai logprobs do Ollama (quando
  habilitado em `options={"logprobs": True}`) e calcula a probabilidade média
  geométrica como confiança real do modelo.
- `calculate_confidence` agora combina logprobs (peso 60%) com heurística (40%).
- `DecisionTrace` (em `core/base.py`): estrutura registrada por pilar/regra/
  evidência/risco — habilita o "Whisper Context" estilo OVON (Gosmar et al. 2025).
- `get_top_policies` para dashboard de políticas mais acionadas.
- `confidence_threshold` no config aciona alerta de baixa confiança.

### Pilar 2 — ModelOps
**Antes:** drift via média de comprimento contra baseline fixo de 100 caracteres;
audit log JSONL editável; sem percentis de latência; sem token budget.

**Agora:**
- `core/metrics_lib.py` — biblioteca dedicada com PSI (Population Stability Index)
  e Jensen-Shannon divergence (Ray 2026).
- `MetricsCollector.calculate_drift()` retorna `{psi, js, score}` e atualiza
  baseline com média móvel α=0.05 após `baseline_window` amostras.
- Latência reportada em **p50/p95/p99** (não só média).
- **Token budget por sessão** (`PolicyEngine.consume_tokens`) para LLM10 —
  Unbounded Consumption.
- Rate-limit em **3 dimensões** (sessão, usuário, IP).
- **Hash chain SHA-256** no audit log: cada turn carrega `prev_hash` e `self_hash`,
  e `verify_chain` detecta adulteração retroativa (NIST AI 600-1).
- **Cifragem opcional** do audit log com Fernet (AES-128) — atende LGPD/GDPR.
- `export_prometheus()` — métricas em formato exposition.
- Custo estimado em USD por janela (configurável via `cost_per_1k_*`).

### Pilar 3 — AppSec
**Antes:** apenas regex literal; `sanitize_output` sem efeito (regex comentado);
sem detecção de codificação ou validação de saída.

**Agora:**
- **Detecção de encoding tricks**: Base64 com decodificação real, Hex,
  caracteres Unicode invisíveis (zero-width, bidi overrides), ROT13
  (Sebok & Wibowo 2026).
- **Output validator** (PALADIN Layer 5): regex para credentials/API keys,
  PEM private keys, comandos perigosos (rm -rf, drop table, sudo, chmod 777),
  URLs internas, payloads codificados que vazam pela saída.
- **Hierarquia de prompt** (PALADIN Layer 2): `wrap_user_input()` envelopa
  entrada do usuário em tags `<user_input level="1" trust="untrusted">`.
- **Detecção de injeção indireta** via marcadores `[SYSTEM]`, `<!-- system:`,
  `<<system>>` etc., para bloquear conteúdo vindo de RAG/arquivos.
- `normalize_unicode()` aplica NFKC para foiling de homoglifos.
- `DecisionTrace` produzido por cada regra disparada.
- Blacklist de termos tóxicos preservada e configurável.

### Pilar 4 — Privacidade
**Antes:** apenas regex de CPF/email/telefone; consent bloqueante via `input()`;
sem padrões brasileiros completos; sem validação de checksum.

**Agora:**
- **PII brasileiros completos**: CPF, CNPJ, RG, CNH, PIS/PASEP, título de
  eleitor, CEP, telefone celular/fixo, cartão de crédito, IP, IBAN.
- **Validação por checksum** (CPF e CNPJ) reduz falsos positivos —
  `111.111.111-11` é corretamente ignorado, `529.982.247-25` é redigido.
- **Pseudonimização determinística**: `[REDACTED_CPF_<hash8>]` — mesmo PII
  sempre mapeia para o mesmo placeholder, permitindo análise sem revelar dado.
- **Consent não-bloqueante**: `consent_mode` aceita `interactive`,
  `auto_grant`, `auto_deny`, `env` (lê `TRISM_CONSENT`).
- LGPD-friendly: campo `purpose` registrado por sessão.
- `redactions_by_type` no status — auditoria por categoria de PII.

### Pilar 5 — Resistência Adversária
**Antes:** padrões `.*jailbreak.*` falham com falso positivo óbvio; repetição só
detectava cópia exata; sem análise multi-turno.

**Agora:**
- **Cinco categorias de jailbreak** com regex precisos:
  - `instruction_override` ("ignore previous instructions")
  - `persona_takeover` (DAN, developer mode, AIM)
  - `policy_bypass` (hipotético, ficcional)
  - `system_extraction` (reveal system prompt)
  - `encoded_payload` (base64, ROT13, reverse)
- **Confidence por categoria**: 0.4 base + 0.20·n_categorias + 0.10·n_padrões.
- Threshold configurável (`block_threshold`, default 0.5) separa BLOCK de FLAG.
- **Repetição semântica** via Jaccard (n-grams 3) e Levenshtein normalizada,
  não só comparação exata.
- **Multi-turn buildup detector** (Wei et al. 2026: ataques multi-turno
  atingem 95% ASR): observa N últimas mensagens e dispara se ≥2 categorias
  fragmentadas aparecerem.
- Detecta extração de system prompt (LLM07) com `extraction_min_keywords`
  configurável.

---

## Novo módulo: `benchmark/`

Pasta criada para os experimentos previstos no artigo:

```
benchmark/
├── datasets/
│   └── owasp_llm_top10_pt.json  → 100 prompts adversariais + 20 benignos
├── evaluator.py                 → cálculo de ASR/DSR/ISR/POF/PSR/CCS/TIVS/FPR
├── runner.py                    → orquestra E1/E2/E3 (TRiSM vs baseline)
└── results/<timestamp>/         → CSV/JSON/Markdown gerados a cada execução
```

**Dataset**: 100 prompts distribuídos 10 por categoria OWASP LLM Top 10 (2025),
inspirado em JailbreakBench, AgentDojo e no repositório de Shahin & Alsmadi
(2026), traduzido/adaptado para PT-BR. 20 prompts benignos para medir FPR.

**Evaluator** (`benchmark/evaluator.py`):
- Matriz de confusão (TP/FN/TN/FP) por dataset.
- Detection rate por categoria OWASP.
- Métricas globais: ASR, DSR, ISR, POF, PSR, CCS, TIVS, FPR_benign.
- Latência média/p95/p99.
- Distribuição de políticas acionadas.
- Cobertura OWASP nos turnos auditados.
- Export em CSV / JSON / Markdown.

**Runner** (`benchmark/runner.py`):
- E1: Detecção sobre 100 prompts (TRiSM vs Ollama puro).
- E2: KPIs compostas no subset LLM01 (Prompt Injection).
- E3: FPR e overhead de latência sobre 20 prompts benignos.
- Δ TIVS calculado entre TRiSM e baseline.

---

## Configuração (`trism_chat/config.yaml`)

Novas chaves adicionadas (todas com defaults sensatos):

```yaml
model.request_logprobs: true     # habilita logprobs do Ollama
modelops.monitoring.psi_threshold: 0.25
modelops.monitoring.js_threshold: 0.30
modelops.monitoring.baseline_window: 50
modelops.monitoring.cost_per_1k_*: 0.0
modelops.rate_limiting.per_user_per_minute: 60
modelops.rate_limiting.per_ip_per_minute: 100
modelops.token_budget: { enabled: true, tokens_per_window: 50000 }
appsec.use_prompt_hierarchy: true
appsec.output_validation: true
appsec.block_encoded_payloads: true
appsec.block_indirect_injection: true
appsec.indirect_injection_markers: [...]
privacy.pseudonymize: true
privacy.pseudonym_salt: "..."
privacy.consent_mode: "env"
adversarial.multiturn_window: 6
adversarial.repetition_jaccard_threshold: 0.85
adversarial.repetition_levenshtein_threshold: 0.85
adversarial.extraction_min_keywords: 2
adversarial.block_threshold: 0.5
logging.encrypt: false           # true requer cryptography
benchmark: { dataset_path, results_dir, tivs_weights, compare_baseline }
```

---

## Modos de execução do `main.py`

```bash
python trism_chat/main.py              # chat interativo
python trism_chat/main.py --test       # testes unitários (16 testes)
python trism_chat/main.py --benchmark  # roda dataset OWASP completo
python trism_chat/main.py --verify     # verifica integridade do hash chain
```

Novos comandos no chat:
- `:prometheus` — exporta métricas para scraping
- `:verify` — verifica hash chain do audit log

---

## Mapeamento dos fortalecimentos vs. literatura

| Melhoria | Origem |
|---|---|
| Confidence via logprobs | Raza et al. 2026; OVON Whisper |
| Decision trace estruturado | Gosmar et al. 2025 |
| PSI / JS divergence | Ray 2026 |
| Hash chain audit | NIST AI 600-1, PALADIN Layer 4 |
| Token budget | OWASP LLM10 (2025), Wei et al. 2026 |
| Rate limit multi-dimensional | Wei et al. 2026 |
| Encoding tricks (Base64/Hex/Unicode) | Sebok & Wibowo 2026 |
| Output validator | PALADIN Layer 5 |
| Hierarquia de prompt | PALADIN Layer 2 |
| Indirect injection markers | Sebok & Wibowo 2026 |
| PII com checksum + pseudonimização | Sheng et al. 2025 (PRvL) |
| Jailbreak categorizado | Mazeika et al. 2024 (HarmBench) |
| Multi-turn buildup | Wei et al. 2026 |
| Repetição Jaccard/Levenshtein | Liu et al. 2024 |
| Métricas ISR/POF/PSR/CCS/TIVS | Gosmar et al. 2025 |
| Dataset OWASP categorizado | Shahin & Alsmadi 2026 |
| ASR/DSR | Wei et al. 2026 |
| Cifragem Fernet | EU AI Act, LGPD |

---

## Validação

Dezessete testes internos (sem necessidade de Ollama rodando) verificam todos
os componentes fortalecidos:

```
OK  P5 jailbreak >=2 categorias
OK  P5 falso positivo evitado
OK  P4 PII checksum CPF (válido vs inválido)
OK  P4 PII PT-BR multi-tipo
OK  P3 encoding Base64 detectado
OK  P3 output validator credential
OK  P3 indirect injection
OK  core PSI/JS divergence > 0
OK  core hash chain anti-tamper
OK  core TIVS Gosmar (3 agentes)  TIVS=-0.1146
OK  P1 confidence_from_logprobs
OK  P2 token_budget consume
OK  P1 decision trace registrado
OK  P2 drift PSI/JS dispara em mudança
OK  core verify_chain arquivo inexistente
OK  P4 pseudonimização determinística
OK  Benchmark evaluator overall_metrics
```

**Resultado: 17/17 PASS.**

---

## Próximos passos sugeridos

1. Instalar `cryptography` (opcional) para habilitar `logging.encrypt: true`.
2. Rodar `python trism_chat/main.py --benchmark` com Ollama local (Llama 3.1 8B
   recomendado) e analisar `benchmark/results/<timestamp>/summary.json`.
3. Aproveitar tabelas geradas (E1 detection rate por categoria; E2 KPIs;
   Δ TIVS) diretamente nas seções de Resultados do artigo.
4. Para LLM08 (Vector/Embedding Weaknesses), considerar adicionar um adapter
   RAG que aplique a mesma cadeia TRiSM sobre conteúdo recuperado antes da
   inferência.
