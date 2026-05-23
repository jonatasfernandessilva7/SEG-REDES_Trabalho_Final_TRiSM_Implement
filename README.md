# JEHWE: Implementação do _Framework_ TRiSM em Sistemas de IA Generativa

o JEHWE implementa os pilares do modelo **TRiSM (Trust, Risk, and Security Management)** em um chat inteligente baseado em IA generativa, especificamente utilizando a plataforma **Ollama** para execução local de modelos de linguagem.

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

O projeto está organizado em dois ambientes de implementação:

### `IA_com_TRiSM/` - Implementação com Pilares de Segurança

Sistema de chat inteligente **com aplicação dos pilares TRiSM**:

- **`core/`**: Módulos centrais
  - `base.py`: Classes base para o framework TRiSM
  - `__init__.py`: Inicialização do pacote

- **`pilar_01_explicabilidade/`**: Pilar da Explainability
  - `explainability.py`: Mecanismos para explicabilidade e interpretabilidade do modelo
  
- **`pilar_02_modelops/`**: Pilar de Model Operations
  - `audit_logger.py`: Sistema de auditoria e rastreamento
  - `metrics.py`: Coleta e análise de métricas
  - `policy_engine.py`: Motor de políticas de governança
  
- **`pilar_03_appsec/`**: Pilar de Application Security
  - `security.py`: Mecanismos de segurança da aplicação
  
- **`pilar_04_privacy/`**: Pilar de Privacidade
  - `privacy.py`: Proteção e anonimização de dados
  
- **`pilar_05_adversarial/`**: Pilar de Robustez Adversarial
  - `adversarial.py`: Defesa contra ataques adversariais
  
- **`trism_chat/`**: Interface do chat com TRiSM
  - `main.py`: Aplicação principal
  - `config.yaml`: Configurações do sistema
  - `audit_log.jsonl`: Registro de auditoria
  - `requirements.txt`: Dependências do projeto

- **`utils/`**: Utilitários
  - `config_loader.py`: Carregamento de configurações

### `IA_sem_TRiSM/` - Implementação Baseline (sem TRiSM)

Sistema de chat inteligente **sem aplicação de pilares TRiSM** (para comparação):

- `main.py` / `chat.py`: Interface do chat
- `conexao_com_SLM.py`: Conexão com Small Language Model (Ollama)
- `requirements.txt`: Dependências

## 🔐 Pilares TRiSM Implementados

### 1. **Explicabilidade** (Pilar 01)
- Interpretabilidade das decisões do modelo
- Rastreamento de decisões e recomendações

### 2. **Model Operations** (Pilar 02)
- Auditoria completa de operações
- Coleta de métricas de desempenho
- Motor de políticas para governança

### 3. **Application Security** (Pilar 03)
- Validação de inputs
- Proteção contra injeção de prompts
- Sanitização de saídas

### 4. **Privacidade** (Pilar 04)
- Anonimização de dados sensíveis
- Conformidade com LGPD/GDPR
- Proteção de dados pessoais

### 5. **Robustez Adversarial** (Pilar 05)
- Detecção de ataques adversariais
- Validação de integridade do modelo
- Proteção contra manipulação

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

2. Instale as dependências (com TRiSM):
```bash
cd IA_com_TRiSM/trism_chat
pip install -r requirements.txt
```

Ou para a versão sem TRiSM:
```bash
cd IA_sem_TRiSM
pip install -r requirements.txt
```

3. Inicie o Ollama:
```bash
ollama serve
```

4. Execute o sistema:

**Com TRiSM:**
```bash
python IA_com_TRiSM/trism_chat/main.py
```

**Sem TRiSM (baseline):**
```bash
python IA_sem_TRiSM/chat.py
```

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

O sistema com TRiSM utiliza um arquivo de configuração `config.yaml`:

```yaml
# Exemplo de configuração
model: "llama2"  # Modelo Ollama a utilizar
log_level: "INFO"
enable_audit: true
privacy_mode: true
adversarial_detection: true
```

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
