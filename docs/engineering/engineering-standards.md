# POSEIDON CTI — Padrão Master de Engenharia, Segurança, QA & Excelência Operacional

> **Documento:** `docs/engineering/engineering-standards.md`  
> **Status:** Ativo / Mandatório  
> **Classificação:** Diretriz Normativa de Engenharia de Software & Segurança  
> **Data:** 2026-09-20  

---

## 1. Princípio Fundamental & Ciclo de Vida de Tarefas

O desenvolvimento do **POSEIDON** rejeita categoricamente a premissa de que *"o código compila e responde no happy path, logo está pronto"*.

Uma funcionalidade somente é considerada `DONE` quando sua **implementação, segurança, comportamento sob falha, integração, observabilidade, experiência de usuário, documentação e testes forem validados dentro do contexto operacional em que ela será utilizada**.

### 1.1 O Ciclo Contínuo de Engenharia
Toda alteração estrutural no Poseidon segue o pipeline ordenado de 9 passos:

```text
INVESTIGATE ──> MAP ──> PLAN ──> VALIDATE PLAN ──> IMPLEMENT ──> TEST & BREAK ──> AUDIT ──> REGRESSION ──> DOCUMENT
```

---

## 2. Definition of Done (DoD) Canônica

Nenhuma tarefa é concluída sem que todos os critérios abaixo sejam formalmente satisfeitos:

1. **Código:** Tipagem estrita (Python / TypeScript), conformidade com linters (`ruff`), ausência de código morto e zero segredos expostos.
2. **Funcionalidade:** Validação do *happy path*, *edge cases* (valores extremos, payloads incomuns) e *failure cases* (timeouts, HTTP 429, 500).
3. **Segurança:** Modelagem de ameaças (Threat Modeling), sanitização de entradas não confiáveis, autorização RBAC rigorosa no backend e firewall anti-SSRF ativo.
4. **Testes:** Pirâmide de testes completa (Unitários, Integração, Contratos de API externa, e Testes de Falha deliberada).
5. **Observabilidade:** Logs estruturados em formato JSON (`structlog`), injeção compulsória de `correlation_id` / `request_id`, rastreabilidade de erros e métricas Prometheus.
6. **UX:** Tratamento estrito de todos os estados de interface: *Loading progressivo*, *Empty state explicativo*, *Error state acionável*, *Success* e *Partial success*.
7. **Documentação:** Atualização contínua de documentação técnica, OpenAPI e registros de decisão arquitetural (ADRs).
8. **Operação:** Políticas de timeout, retry com backoff exponencial e circuit breaker explicitamente definidas.

---

## 3. Modelo Epistêmico do Poseidon & Regra Anti-Alucinação

Para impedir que inferências probabilísticas ou deduções heurísticas contaminem a verdade forense, toda informação no Poseidon possui classificação epistêmica estrita:

```text
FACT
  └── Informação empírica diretamente comprovada por evidência técnica indiscutível.
OBSERVATION
  └── Fato técnico registrado diretamente por sondas ou telemetria direta do sistema.
CORRELATION
  └── Vínculo analítico identificado deterministicamente entre duas ou mais entidades.
ASSESSMENT
  └── Conclusão ou avaliação analítica consolidada com base em conjunto de evidências.
HYPOTHESIS
  └── Conjectura ou linha de investigação sob teste (Evidência A Favor vs Contra).
UNKNOWN
  └── Informação insuficiente para estabelecer qualquer conclusão válida.
```

### Regras Mandatórias de Integridade Epistêmica:
* `HYPOTHESIS` **nunca** é transformada em `FACT`.
* `CORRELATION` **nunca** é tratada como causalidade definitiva.
* `NO_DATA` **nunca** é convertido em `SAFE` ou `BENIGN`.
* `SOURCE_UNAVAILABLE` **nunca** é interpretado como ausência de ameaça.
* Nenhuma inferência gerada por IA é apresentada como evidência factual sem apontar para o `source_id`, `raw_record_id` e carimbo UTC de origem.

---

## 4. Rastreabilidade Absoluta de Proveniência & Data Lineage

Toda afirmação, indicador, relação ou relatório no Poseidon é bidirecionalmente rastreável:

```text
[ RAW SOURCE DATA ] (Payload original inviolável com hash SHA256)
        ↓
[ PARSER vX.Y.Z ] (Versão exata do código de extração)
        ↓
[ NORMALIZED RECORD ] (Evidência normalizada vinculada à fonte)
        ↓
[ CANONICAL IOC ] (Entidade canônica desduplicada)
        ↓
[ ENRICHMENT & CONSENSUS ] (Corroboração multi-fonte e pontuação explicável)
        ↓
[ REPORT / UI ] (Apresentação analítica auditável)
```

O caminho inverso (*reverse provenance*) é garantido: ao ler uma afirmação em um relatório executivo, o analista consegue inspecionar o payload bruto original de onde o dado emergiu.

---

## 5. Resiliência de Conectores & Estratégia de Falha

Conectores operam sob o princípio de **Isolamento de Falhas (Failure by Design)**: a indisponibilidade, lentidão ou bloqueio de uma fonte externa jamais derruba o núcleo do Poseidon.

| Cenário de Falha | Comportamento do Conector | Estado de Saúde |
| :--- | :--- | :--- |
| **HTTP 200 / Sucesso** | Normalização e armazenamento imediato | `CONNECTED` |
| **HTTP 429 / Rate Limit** | Leitura de `Retry-After`, pausa imediata e backoff exponencial com jitter | `RATE_LIMITED` |
| **HTTP 401 / 403** | Interrupção de novas chamadas para evitar banimento e alerta imediato | `AUTH_FAILED` |
| **Timeout (> 10s)** | Retry com limite máximo de 3 tentativas e marcação preventiva | `DEGRADED` |
| **API Host Offline / DNS** | Falha rápida (*fail fast*) e preservação dos dados históricos cacheados | `SOURCE_UNAVAILABLE` |
| **Payload Inválido / Drift** | Quarentena do payload bruto e alerta de erro de configuração de parser | `CONFIGURATION_ERROR` |
| **Resposta Vazia** | Registro de `NO_DATA_REPORTED` (sem alterar classificação para benigno) | `CONNECTED` |

---

## 6. Taxonomia Padronizada de Códigos de Erro

Para suportar troubleshooting rápido e automação de alertas, todos os erros da API retornam códigos semânticos padronizados:

* `AUTH-001` a `AUTH-099`: Falhas de autenticação, tokens expirados e credenciais inválidas.
* `SEC-001` a `SEC-099`: Violações de segurança, tentativas de SSRF, acesso a IPs restritos e estouro de privilégios.
* `CONN-001` a `CONN-099`: Erros de conectores, falhas de autenticação em APIs externas, timeouts e rate-limits.
* `ENR-001` a `ENR-099`: Erros de orquestração de enriquecimento e desduplicação.
* `DB-001` a `DB-099`: Falhas de integridade referencial, queries lentas e transações abortadas.
* `SEARCH-001` a `SEARCH-099`: Consultas malformadas, sintaxe inválida de busca e queries excessivamente caras.
* `API-001` a `API-099`: Erros gerais de validação de payload e rotas não encontradas.

---

## 7. Observabilidade & Rastreabilidade por Correlation ID

1. **Injeção de Correlation ID:** Toda requisição HTTP recebe um cabeçalho `X-Correlation-ID` (ou gera um UUID v4 se não fornecido), propagado em:
   * Todos os logs estruturados (`structlog`);
   * Cabeçalho de resposta HTTP para o cliente;
   * Registros de auditoria gerados pela requisição;
   * Tarefas de background disparadas pelo job.
2. **Health Probes Específicos:**
   * `/api/v1/health/live`: Liveness probe para orquestradores (Kubernetes/Docker).
   * `/api/v1/health/ready`: Readiness probe verificando banco de dados e buffers.
   * `/api/v1/health/deps`: Inspeciona o estado detalhado do PostgreSQL, Redis e conectores ativos.

---

## 8. Os Quatro Revisores Virtuais (Virtual Reviewers Gate)

Toda feature relevante antes de ser aprovada deve ser submetida a 4 revisões conceituais:

1. **Reviewer 1 — Engineering:** O código respeita a arquitetura hexagonal? Há vazamentos de recursos ou consultas N+1? Os contratos de API estão estáveis?
2. **Reviewer 2 — Security:** Como este endpoint pode ser abusado? Há risco de SSRF, injeção ou IDOR? Secrets estão cifrados em repouso com AES-256-GCM?
3. **Reviewer 3 — CTI Analyst:** A proveniência foi preservada? A diferença entre Fato e Hipótese está nítida? O score de risco é 100% transparente?
4. **Reviewer 4 — Product / UX:** Os estados de loading, empty e error são claros e acionáveis? Os tokens visuais (Blue Graphite, Cyan, Gold) foram estritamente respeitados?
