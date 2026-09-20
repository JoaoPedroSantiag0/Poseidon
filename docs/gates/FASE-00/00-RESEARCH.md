# Pesquisa Técnica e Fundacional — Fase 00

**Autor:** Architect / Builder  
**Data da Pesquisa:** 2026-09-20 (Atualizado após Emenda Constitucional v2.1 e Auditoria v2)  
**Status:** Concluído — Base para Proposta de ADRs Fundacionais  

---

## 1. Escopo e Propósito

Este documento consolida o levantamento técnico, legal e arquitetural preparatório para a concepção do Poseidon Core, Ingestion Plane, CTI Engine, Response Control Plane e Collector Agent.

Em rigoroso cumprimento à **Lei 1 da Constituição do Poseidon** (*"Nenhuma afirmação sobre API externa sem citação verificada"*), toda declaração técnica a respeito de protocolos, contratos de API, schemas, canais de telemetria e licenças está fundamentada em fontes oficiais consultadas nesta data.

Esta versão incorpora as exigências da **Emenda Constitucional v2.1** e sana integralmente as divergências apontadas no relatório de auditoria `03-AUDIT-REPORT-v2.md`:
- Reestruturação completa da análise de OCSF contra a versão **OCSF 1.9.0** oficial;
- Mapeamento preciso de classes (abandono da classe depreciada 2001 em favor de `detection_finding` 2004, uso de `authentication` 3002, inclusão da Categoria 7 `Remediation` e uso da extensão `win` para Registro do Windows);
- Avaliação do ferramental Pydantic com `py-ocsf-models`;
- Confronto factual com o ECS 9.5.0 sem atalhos retóricos;
- Análise de viabilidade de ETW em Go sem CGO e restrições de PPL/ELAM.

---

## 2. Levantamento por Domínio e Componente

### 2.1 Wazuh: Arquitetura, APIs, Formatos e Licenciamento por Componente

O ecossistema Wazuh é composto por múltiplos subsistemas independentes, com repositórios e licenças distintas.

#### 2.1.1 Análise de Licenciamento por Componente Separado

A verificação foi executada diretamente nos arquivos `LICENSE` dos repositórios oficiais:

| Componente | Repositório Oficial | Licença Verificada | Cláusulas Críticas e Implicações |
|---|---|---|---|
| **Wazuh Manager / Server** | `github.com/wazuh/wazuh` | **GPLv2** (com exceção OpenSSL) | Código histórico OSSEC / Trend Micro. O arquivo `LICENSE` define explicitamente como trabalho derivado: integrar código-fonte, incluir binários em instaladores proprietários ou linkar estaticamente/dinamicamente. **Contudo**, chamadas via rede (REST API) não constituem linkagem sob a GPLv2. |
| **Wazuh Agent** (C codebase) | `github.com/wazuh/wazuh` | **GPLv2** (com exceção OpenSSL) | Compartilha o repositório principal. Qualquer modificação ou redistribuição empacotada requer licenciamento GPLv2. |
| **Wazuh Indexer** (Core) | `github.com/wazuh/wazuh-indexer` | **Apache License 2.0** | Fork/distribuição do OpenSearch 2.x. Permissiva, permitindo conexão via cliente OpenSearch REST sem contaminação copyleft. |
| **Wazuh Indexer Plugins** | `github.com/wazuh/wazuh-indexer-plugins` | **AGPL-3.0** (GNU Affero GPL) | Plugins analíticos e de relatórios (`wazuh-indexer-reporting`). A licença AGPLv3 impõe copyleft mesmo em uso exclusivo via rede (*network interaction clause*, Seção 13) se o software for modificado. |
| **Wazuh Dashboard** | `github.com/wazuh/wazuh-dashboard` | **Apache License 2.0** | Fork do OpenSearch Dashboards. |
| **Wazuh Dashboard Plugins** | `github.com/wazuh/wazuh-dashboard-plugins` | **GPL-2.0** | Plugins que customizam a interface. Fortemente acoplados ao ciclo do upstream. Não possui código AGPL verificado. |
| **Wazuh Agent v5.x (WIP)** | `github.com/wazuh/wazuh-agent` | **AGPL-3.0** | Repositório em desenvolvimento ("Work in progress", não funcional para 4.x). Demonstra a direção futura de licenciamento do agente upstream. |

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh Core LICENSE: [https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE](https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE)
- Wazuh Indexer repo: [https://github.com/wazuh/wazuh-indexer](https://github.com/wazuh/wazuh-indexer)
- Wazuh Indexer Plugins repo: [https://github.com/wazuh/wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins)
- Wazuh Dashboard Plugins repo: [https://github.com/wazuh/wazuh-dashboard-plugins](https://github.com/wazuh/wazuh-dashboard-plugins)
- Wazuh Agent experimental repo: [https://github.com/wazuh/wazuh-agent](https://github.com/wazuh/wazuh-agent)

**Implicação Direta para o Poseidon:**
1. **Consumo via API (Permitido e Seguro):** O Poseidon Backend comunicando-se com a API do Wazuh Manager e com o Wazuh Indexer exclusivamente via HTTP/REST (protocolo de rede padrão) não constitui obra derivada, preservando a propriedade intelectual e arquitetura do Poseidon.
2. **Proibição de Bundling/Linking:** É terminantemente vedado embutir bibliotecas C do Wazuh, compilar binários conjuntos ou forkar o dashboard (conforme preconizado na Lei 3).
3. **Isolamento de Plugins AGPL:** O Poseidon não deve estender nem modificar os plugins AGPL do Wazuh Indexer. Deve tratar o Indexer apenas como uma instância OpenSearch padrão, operando seu próprio cluster OpenSearch 2.x independente sob Apache 2.0.

#### 2.1.2 Wazuh Server / Manager API vs. Wazuh Indexer

- **Wazuh Server API (porta TCP 55000):**
  - **Mecanismo:** HTTPS REST gerenciado pelo serviço `wazuh-apid`.
  - **Autenticação:** `POST /security/user/authenticate` (Basic Auth) retornando JWT (validade padrão 900s).
  - **Endpoints:** Gestão de agentes (`GET /agents`, `GET /agents/{id}`), regras (`GET /rules`) e despacho de resposta ativa (`PUT /active-response`).
  - **Constatação Crítica Confirmada:** **A API do Manager NÃO fornece endpoints de consulta de histórico de alertas.**
- **Wazuh Indexer API (porta TCP 9200):**
  - É a interface OpenSearch 2.x onde os alertas são efetivamente gravados nos índices `wazuh-alerts-4.x-*`.
  - Consultas analíticas são realizadas via `POST /wazuh-alerts-*/_search` com OpenSearch Query DSL.
- **Conector Duplo Necessário:** O conector Wazuh do Poseidon (`integrations/wazuh/`) é duplo por desenho: fala com o Manager (porta 55000) para agentes e regras, e com o Indexer (porta 9200) para extração de alertas.
- **Superfície de Execução no Wazuh Active Response (Auditoria do Código v4.14.7):**
  - Comando prefixado com `!` pula verificação de lista branca (`active_response.py:validate_command`);
  - `agents_list` tem default `'*'` (broadcast na frota);
  - `PUT /agents/upgrade_custom` instala binários WPK locais arbitrários.
  - **Trava Constitucional (Lei 8 v2.1):** O conector Wazuh do Poseidon nunca envia comando com `!`, nunca omite `agents_list`, nunca chama `upgrade_custom`, e nunca deriva argumentos de entrada livre de usuário. A credencial da API do Wazuh equivale a execução de código na frota e recebe proteção de chave de assinatura.

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh API Reference: [https://documentation.wazuh.com/current/user-manual/api/reference.html](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- Wazuh Indexer API: [https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html)
- Repositório Wazuh Core v4.14.7: [https://github.com/wazuh/wazuh/tree/v4.14.7](https://github.com/wazuh/wazuh/tree/v4.14.7)

---

### 2.2 OCSF vs. ECS: Avaliação Aprofundada contra o OCSF 1.9.0

A **Lei 2** estabelece a adoção de padrão aberto consolidado (OCSF ou ECS) com decisão no ADR-002. A **Lei 4 (v2.1)** estipula que a Fase 3 decide o padrão em caráter `PROVISÓRIO`, exercitado compulsoriamente contra **dois corpora gravados obrigatórios e heterogêneos** (alertas reais do Wazuh e telemetria bruta de endpoint), com congelamento definitivo na Fase 9.

Esta análise foi reconstruída diretamente contra os endpoints oficiais da API do schema OCSF (`schema.ocsf.io/api/*`) na versão estável **1.9.0** (publicada em 2026-08-03).

#### 2.2.1 A Estrutura do OCSF 1.9.0: As 8 Categorias Oficiais

Ao contrário de versões legadas que agrupavam 6 domínios, o OCSF 1.9.0 estrutura a taxonomia de segurança em **8 categorias formais**:

| UID | Categoria | Descrição e Escopo no OCSF 1.9.0 | Relevância para o Poseidon |
|:---:|---|---|---|
| **1** | **System Activity** | Eventos originados do sistema operacional e do kernel do endpoint. | Telemetria do Collector Agent (Processos, Arquivos, Memória). |
| **2** | **Findings** | Avaliações, detecções, alertas e achados analíticos de segurança. | Alertas do Wazuh, regras Sigma e detecções do Defender AV. |
| **3** | **Identity & Access Management (IAM)** | Eventos de autenticação, autorização e gestão de contas. | Windows Security Log (4624, 4625), sessões do Poseidon. |
| **4** | **Network Activity** | Telemetria de tráfego de rede e protocolos de aplicação. | Conexões TCP/UDP (Kernel-Network) e DNS (DNS-Client). |
| **5** | **Discovery** | Inventário de dispositivos, serviços e usuários descobertos. | Inventário de ativos e saúde do endpoint. |
| **6** | **Application Activity** | Acesso a recursos web, chamadas de API e logs de aplicações. | Auditoria de rotas da API do Poseidon Server. |
| **7** | **Remediation** | **Ações ativas de mitigação e resposta a incidentes.** | **Response Control Plane (Fase 8, Leis 8, 9 e 10).** |
| **8** | **Unmanned Systems** | Telemetria de veículos e sistemas não-tripulados (drones/robótica). | Fora do escopo do Poseidon. |

#### 2.2.2 Mapeamento Preciso de Classes e Correção de Classes Legadas

A consulta direta a `https://schema.ocsf.io/api/classes` revela correções mandatórias sobre premissas antigas:

1. **Alertas e Detecções de Segurança (Findings):**
   - **Classe Legada Depreciada:** `security_finding` (**Class UID 2001**) está **depreciada desde a versão 1.1.0** com a instrução explícita: *"Use the new specific classes according to the use-case: vulnerability_finding, compliance_finding, detection_finding, incident_finding, data_security_finding"*.
   - **Classe Canônica Correta:** **`detection_finding` (Class UID 2004)**. É a classe moderna, não-depreciada, especificamente desenhada para alertas emitidos por mecanismos de correlação, SIEMs, EDRs e antivírus (perfeita para Wazuh e Sigma).
2. **Autenticação (IAM):**
   - A classe de autenticação é **`authentication` (Class UID 3002)**, cobrindo logon, logoff e falhas (Windows Events 4624/4625).
   - *Nota técnica:* A classe 3001 era `account_change` (depreciada no 1.9.0 em favor de `user_management` 3006), nunca foi a classe de autenticação.
3. **Atividade do Sistema Operacional (System Activity):**
   - `process_activity` (**Class UID 1007**): Criação, término e injeção de processos.
   - `file_activity` (**Class UID 1001**): Criação, modificação e exclusão de arquivos.
   - `memory_activity` (**Class UID 1004**): Alocação e proteção de memória (Nota: a classe 1004 trata de memória, **não** de registro!).
   - `module_activity` (**Class UID 1002**) e `scheduled_job_activity` (**Class UID 1003**).
4. **Registro do Windows (A Extensão `win`):**
   - No núcleo (core) do OCSF não existe classe genérica de registro (chamar `/api/classes/registry_key_activity` retorna 404).
   - Atividades do Registro do Windows são formalmente modeladas na **extensão `win`**:
     - `win/registry_key_activity` (**Class UID 201001**)
     - `win/registry_value_activity` (**Class UID 201002**)
   - O uso de OCSF no Windows exige que o Poseidon habilite e valide formalmente a extensão `win`.
5. **Remediação e Resposta Ativa (Categoria 7):**
   - Diretamente alinhada às capacidades nomeadas da Lei 8 e ao Response Control Plane:
     - `remediation_activity` (**Class UID 7001**): Ação de resposta estruturada com táticas tipadas: `Isolate` (1), `Evict` (2), `Restore` (3), `Harden` (4).
     - `network_remediation_activity` (**Class UID 7004**): Modela perfeitamente `NETWORK_ISOLATE` e `NETWORK_RESTORE`.
     - `file_remediation_activity` (**Class UID 7002**): Modela `QUARANTINE_FILE`.
     - `process_remediation_activity` (**Class UID 7003**): Modela `KILL_PROCESS`.
   - Essa aderência da Categoria 7 do OCSF ao ciclo de resposta é um diferencial técnico que inexiste no ECS.

#### 2.2.3 Cumprimento dos Requisitos Semânticos da Lei 5 (v2.1)

O OCSF 1.9.0 satisfaz diretamente os seis requisitos conceituais da Lei 5 sem necessidade de inventar schema caseiro:

| Conceito Semântico (Lei 5) | Campo Canônico no OCSF 1.9.0 | Tipo e Comportamento |
|---|---|---|
| **Tempo do evento** | `time` / `metadata.original_time` | Timestamp epoch milissegundos / ISO string original do endpoint |
| **Tempo de ingestão** | `metadata.logged_time` (+ `metadata.processed_time`) | Instante em que o coletor/servidor processou o evento |
| **Origem** | `metadata.product` *(obrigatório)* e `metadata.source` | Identificação do gerador (ex: `collector-agent`, `wazuh`) |
| **Identificador na origem** | `metadata.original_event_uid` | ID do registro no sistema nativo (ex: RecordID, AlertID) |
| **Referência ao bruto** | `raw_data` / `raw_data_hash` | Ponteiro URI ou hash SHA-256 do payload bruto preservado |
| **Correlação** | `metadata.correlation_uid` | UUID de agrupamento analítico e rastreamento de caso |
| **Cadeia de Ingestão** | `metadata.loggers` | Array ordenado de objetos Logger descrevendo cada hop da pipeline |
| **Versão do Schema** | `metadata.version` | String da versão OCSF (ex: `"1.9.0"`), atendendo ao `MAJOR-11` |

#### 2.2.4 Avaliação do Ferramental Python

- **`ocsf-lib` (0.10.4):** Biblioteca utilitária oficial mantida pelo comitê OCSF.
- **`py-ocsf-models` (0.10.0):** Pacote sob licença **Apache-2.0** mantido pela equipe do **Prowler** (`prowler-cloud/py-ocsf-models`, ativo com updates em setembro de 2026). Ele gera e expõe classes **Pydantic v2** tipadas para os eventos OCSF, integrando-se nativamente ao stack FastAPI do Poseidon Core.
- **Conclusão:** O custo de manutenção de modelos em Python é significativamente atenuado pela existência do `py-ocsf-models`, viabilizando validação rigorosa na borda sem necessidade de reescrever centenas de classes manualmente.

#### 2.2.5 Comparativo Factual OCSF vs. ECS (Sem Falácias Retóricas)

O Elastic Common Schema (ECS) **não está abandonado**: publicou a versão **v9.5.0 em 2026-08-04** sob licença Apache-2.0, com desenvolvimento ativo em colaboração com as convenções semânticas do OpenTelemetry (OTel). O ECS não exige Elasticsearch (é uma convenção de campos utilizável em OpenSearch).

A decisão em favor do OCSF no Poseidon baseia-se em **méritos técnicos intrínsecos e verificáveis**:

| Critério Técnico | OCSF 1.9.0 (Recomendado) | ECS 9.5.0 |
|---|---|---|
| **Governança** | Linux Foundation (multi-vendor: AWS, IBM, Splunk, CrowdStrike, Datadog). | Elastic / OpenTelemetry (CNCF). |
| **Modelagem de Alertas** | Nativa e especializada: `detection_finding` (2004) segregada de vulnerabilidades e compliance. | Adaptada em `event.kind: alert`, menos rica em metadados de análise. |
| **Modelagem de Resposta/Remediação** | **Nativa: Categoria 7 (Remediation)** com classes 7001 a 7004 para isolamento, quarentena e término de processos. | Inexistente como taxonomia formal de resposta; focado exclusivamente em observabilidade/telemetria. |
| **Rastreamento de Pipeline** | Nativo via `metadata.loggers` (array ordenado de hops de ingestão). | Exige campos customizados `event.ingested` / `observer`. |
| **Extensões de Sistema** | Extensão formal `win` versionada para o Registro do Windows. | Campos de registro integrados no core (`registry.*`). |
| **Aderência ao OpenSearch** | Padrão nativo adotado por AWS Security Lake e ecossistemas abertos. | Historicamente otimizado para o stack Beats/Elasticsearch. |

*Fontes oficiais consultadas em 2026-09-20:*
- OCSF Schema Browser & API: [https://schema.ocsf.io/](https://schema.ocsf.io/)
- OCSF Version API: [https://schema.ocsf.io/api/version](https://schema.ocsf.io/api/version)
- OCSF Detection Finding: [https://schema.ocsf.io/api/classes/detection_finding](https://schema.ocsf.io/api/classes/detection_finding)
- OCSF Remediation Activity: [https://schema.ocsf.io/api/classes/remediation_activity](https://schema.ocsf.io/api/classes/remediation_activity)
- PyPI py-ocsf-models: [https://pypi.org/project/py-ocsf-models/](https://pypi.org/project/py-ocsf-models/)
- Elastic Common Schema v9.5.0: [https://www.elastic.co/guide/en/ecs/current/index.html](https://www.elastic.co/guide/en/ecs/current/index.html)

---

### 2.3 STIX 2.1: Modelagem de Objetos de CTI

Ratificado como OASIS Standard em 10 de Junho de 2021.

- **SDOs (Domain Objects):**
  - `indicator`: padrão observável com sintaxe STIX, `valid_from`, `valid_until`, `confidence`.
  - `observed-data`: dados observados com ponteiros para objetos SCO.
  - `malware`, `threat-actor`, `campaign`.
- **SROs (Relationship Objects):**
  - `relationship`: associações direcionadas (`indicates`, `uses`, `attributed-to`).
  - `sighting`: **Formalmente um SRO** (STIX Relationship Object), conectando o que foi avistado (`sighting_of_ref`) com onde foi avistado (`where_sighted_refs`), contagem (`count`) e intervalo (`first_seen`, `last_seen`).
  - **Aderência à Lei 7:** O `sighting` materializa diretamente a observação de inteligência exigida pela Lei 7 (`IOC -> observação -> {fonte, confiança, first_seen, last_seen, contagem, tags}`), sem necessidade de criar entidades proprietárias paralelas.

*Fontes oficiais consultadas em 2026-09-20:*
- OASIS STIX 2.1 Standard: [https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)

---

### 2.4 Sigma: Regras Canônicas e Licença DRL 1.1

- **Formato:** Regras YAML com seções `logsource`, `detection` (selections, filters, condition), `level` e `tags` (MITRE ATT&CK oficial).
- **Compilação:** pySigma com `pySigma-backend-opensearch` gera queries Lucene e PPL para execução assíncrona contra os índices do OpenSearch.
- **Requisito de Licença DRL 1.1 (Incorporado na Lei 13 v2.1):**
  A *Detection Rule License 1.1* do repositório SigmaHQ impõe que:
  *"messages based on matches with the Rules must retain identification of the author(s)"*.
  Portanto, todo alerta gerado pelo Poseidon com base em regras Sigma **carrega obrigatoriamente a identificação do autor no schema do próprio alerta** (`Class 2004 - detection_finding`).

*Fontes oficiais consultadas em 2026-09-20:*
- SigmaHQ Repository & License: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- pySigma OpenSearch: [https://github.com/SigmaHQ/pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch)

---

### 2.5 AlienVault OTX (Open Threat Exchange)

- **API REST:** Base URL `https://otx.alienvault.com/api/v1`.
- **Autenticação:** Cabeçalho HTTP `X-OTX-API-KEY`.
- **Endpoints:** `GET /api/v1/indicators/IPv4/{ip}/general`, `domain/{domain}/general`, `file/{hash}/general`, e `/api/v1/pulses/subscribed`.
- **Status do Ecossistema:** O produto migrou para a marca **LevelBlue** e o repositório `OTX-Python-SDK` encontra-se sem commits recentes (desde maio de 2024). O conector CTI do Poseidon consumirá a API REST diretamente com cliente HTTP assíncrono padrão (`httpx`), sem depender do SDK desatualizado.
- **Termos de Uso:** Uso comunitário com cache local mandatório para evitar abuso de taxa. Limite de taxa de 10.000 req/h citado em fontes secundárias; marcado como `NÃO VERIFICADO` em documentação primária oficial.

*Fontes oficiais consultadas em 2026-09-20:*
- OTX Portal & API Documentation: [https://otx.alienvault.com/api/](https://otx.alienvault.com/api/)

---

### 2.6 ETW (Event Tracing for Windows): Viabilidade em Go sem CGO, Provedores e PPL

A **Emenda 2.1 da Constituição (§4)** determinou que o Collector Agent consumirá **ETW diretamente e Windows Event Log via `wevtapi.dll`**, declarando com transparência a origem de cada campo e os custos da substituição do Sysmon.

#### 2.6.1 Viabilidade Técnica de Consumo Direto de ETW em Go sem CGO

1. **APIs Win32 Envolvidas:**
   - `StartTraceW` / `ControlTraceW` (`advapi32.dll`): Criação e controle de sessões em tempo real (`EVENT_TRACE_REAL_TIME_MODE`).
   - `EnableTraceEx2` (`advapi32.dll`): Habilitação de provedores por GUID, nível e máscara de palavras-chave.
   - `OpenTraceW` e `ProcessTrace` (`advapi32.dll`): Consumo bloqueante através do callback `PEVENT_RECORD_CALLBACK`.
   - `TdhGetEventInformation` e `TdhGetProperty` (`tdh.dll`): Decodificação do payload de eventos.

2. **Mecanismo de Callbacks em Go sem CGO:**
   - O runtime do Go no Windows provê **`windows.NewCallback`** (`syscall.NewCallback`), que compila em memória um stub x64 compatível com a ABI do Windows x64.
   - Quando a thread do despachante ETW do kernel dispara o callback, o runtime do Go aloca uma estrutura `m` de thread e executa o código Go, **dispensando compilador C/MinGW e sem CGO**.
   - **Restrição Crítica de Performance:** O callback Go é executado síncronamente na thread do ETW. Ele deve executar apenas a cópia de ponteiro/buffer para uma fila e retornar imediatamente `1` (`ERROR_SUCCESS`). I/O ou bloqueios no callback resultam em saturação dos buffers de anel no kernel e descarte de eventos (`EventsLost`).

3. **Cenário de Licenciamento das Bibliotecas Go de ETW:**
   - As bibliotecas maduras sem CGO existentes (`0xrawsec/golang-etw` e `tekert/goetw`) são **GPL-3.0**. Como o Collector Agent é um binário estático distribuído no endpoint, importar uma lib GPL-3.0 forçaria o agente inteiro a adotar GPL-3.0.
   - As opções MIT existentes (`Velocidex/etw`, `fredwangwang/etw`) são forks pontuais de um projeto parado desde 2022 (`bi-zone/etw`).
   - **Decisão:** O Poseidon implementará sua própria camada enxuta de chamadas Win32 sobre `golang.org/x/sys/windows` (BSD-3-Clause) ou consumirá canais através de `wevtapi.dll`, garantindo licença permissiva e controle total de ciclo de vida.

#### 2.6.2 Mapeamento de Provedores e Cobertura (Origem Declarada dos Campos — §4 v2.1)

A Emenda 2.1 estabelece que a origem de cada campo da telemetria deve ser formalmente declarada, assumindo os custos de engenharia:

| Campo / Telemetria | Origem Declarada (§4 v2.1) | Mecanismo Técnico | Custo / Risco Assumido |
|---|---|---|---|
| **Criação de Processo** | ETW `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`) | ETW Event 1 (`ProcessStart`) via Go sem CGO | Fornece PID, ParentPID, ImageName, CreateTime e SID. Não entrega linha de comando confiável. |
| **Linha de Comando** | **Windows Security Event ID 4688** | `wevtapi.dll` (`EvtSubscribe`) sobre Go puro | **Exige a GPO "Include command line in process creation events" habilitada.** Ausência é sinalizada como degradação no Health Center (Lei 12). |
| **Hashes de Imagem** | Calculados pelo próprio Collector Agent | Leitura do binário no disco e hash SHA-256 | Custo de I/O assumido; risco de condição de corrida com exclusão do arquivo pelo malware antes da leitura. |
| **Linha de Comando do Pai** | Árvore de processos em memória | Grafo mantido em memória no agente | Memória adicional consumida no endpoint; risco de perda de contexto se o processo pai foi criado antes do agente subir. |
| **Conexões de Rede** | ETW `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) | ETW Event 12 (Connect Attempt), Event 15 (Established) | Telemetria de alta frequência; exige ring buffer otimizado. |
| **Consultas DNS** | ETW `Microsoft-Windows-DNS-Client` (`{1C950233-43CE-412B-AC34-4E142F578CAE}`) | ETW Event 3008 / canal `DNS-Client/Operational` | Fornece QueryName, QueryType e QueryResults. |
| **Detecções Antivírus** | Log Operacional do Windows Defender | `wevtapi.dll` (Eventos 1116, 1117, 1006, 5001) | Gratuito, local, sem dependência de tenant M365. |

#### 2.6.3 Exigência de Assinatura Anti-Malware / PPL para Provedores Sensíveis

- **Provedor `Microsoft-Windows-Threat-Intelligence` (ETW-TI):**
  - GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.
  - Telemetria de injeção de processos (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtSetContextThread`).
- **Restrição Mandatória de Kernel (PPL / ELAM):**
  - O kernel do Windows restringe o ETW-TI estritamente a processos **Protected Process Light (PPL)** com nível de assinatura **`Antimalware`**.
  - Exige um driver **ELAM (Early Launch Anti-Malware)** formalmente co-assinado pela Microsoft mediante certificação WHQL/Dev Center com validação de empresa de segurança credenciada.
  - Processos executando como Administrador ou `LocalSystem` recebem **`ERROR_ACCESS_DENIED` (`0x5`)**.
- **Conclusão:** O ETW-TI está formalmente fora do MVP do Poseidon. A paridade plena com EDRs comerciais em injeções de memória avançadas exige driver assinado pela Microsoft — custo estratégico registrado como dívida conhecida na Constituição v2.1 (§4).

---

## 3. Matriz de Verificação Atualizada (Lei 1)

Verificação por afirmação individual (conforme `OBSERVATION-13`):

| # | Afirmação Técnica Específica | Fonte Oficial Consultada | Data | Status |
|---|---|---|---|:---:|
| 1 | Wazuh Manager/Server e Agent licenciados sob GPLv2 | `github.com/wazuh/wazuh/blob/master/LICENSE` | 2026-09-20 | **VERIFICADO** |
| 2 | Wazuh Indexer Core licenciado sob Apache License 2.0 | `github.com/wazuh/wazuh-indexer` | 2026-09-20 | **VERIFICADO** |
| 3 | Wazuh Indexer Plugins licenciado sob AGPL-3.0 | `github.com/wazuh/wazuh-indexer-plugins/blob/main/LICENSE` | 2026-09-20 | **VERIFICADO** |
| 4 | Wazuh Dashboard Plugins licenciado sob GPL-2.0 | `github.com/wazuh/wazuh-dashboard-plugins/blob/master/LICENSE` | 2026-09-20 | **VERIFICADO** |
| 5 | Wazuh Agent v5.x experimental sob AGPL-3.0 | `github.com/wazuh/wazuh-agent/blob/main/LICENSE` | 2026-09-20 | **VERIFICADO** |
| 6 | Wazuh Manager API (porta 55000) não possui endpoint de alertas | OpenAPI Spec Wazuh v4.14.7 (`api/api/spec/spec.yaml`) | 2026-09-20 | **VERIFICADO** |
| 7 | Wazuh Active Response ignora lista com prefixo `!` | `wazuh/core/active_response.py` tag v4.14.7 | 2026-09-20 | **VERIFICADO** |
| 8 | OCSF versão oficial corrente é v1.9.0 | `schema.ocsf.io/api/version` (release 2026-08-03) | 2026-09-20 | **VERIFICADO** |
| 9 | OCSF possui 8 categorias formais | `schema.ocsf.io/api/categories` | 2026-09-20 | **VERIFICADO** |
| 10| OCSF Class 2001 (`security_finding`) depreciada desde v1.1.0 | `schema.ocsf.io/api/classes/security_finding` | 2026-09-20 | **VERIFICADO** |
| 11| OCSF Class 2004 (`detection_finding`) é a classe canônica de alertas | `schema.ocsf.io/api/classes/detection_finding` | 2026-09-20 | **VERIFICADO** |
| 12| OCSF Class 3002 é `authentication` (3001 depreciada) | `schema.ocsf.io/api/classes/authentication` | 2026-09-20 | **VERIFICADO** |
| 13| OCSF Categoria 7 é `Remediation` (classes 7001 e 7004) | `schema.ocsf.io/api/classes/remediation_activity` | 2026-09-20 | **VERIFICADO** |
| 14| Registro do Windows não existe no core; exige extensão `win` | `schema.ocsf.io/api/classes/registry_key_activity` (404) | 2026-09-20 | **VERIFICADO** |
| 15| `py-ocsf-models` provê modelos Pydantic v2 sob Apache-2.0 | `pypi.org/project/py-ocsf-models/` v0.10.0 (Prowler Cloud) | 2026-09-20 | **VERIFICADO** |
| 16| ECS versão 9.5.0 ativa sob Apache-2.0 | `github.com/elastic/ecs` release 2026-08-04 | 2026-09-20 | **VERIFICADO** |
| 17| STIX 2.1 aprovado como OASIS Standard; `sighting` é SRO | `docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html` | 2026-09-20 | **VERIFICADO** |
| 18| SigmaHQ DRL 1.1 exige retenção do autor no alerta gerado | `github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection-Rules.md` | 2026-09-20 | **VERIFICADO** |
| 19| Sysinternals EULA proíbe redistribuição e uso para hosting SaaS | `live.sysinternals.com/Eula.txt` | 2026-09-20 | **VERIFICADO** |
| 20| Limite de taxa de 10.000 req/h no OTX autenticado | Fontes secundárias; não confirmado em doc primária | 2026-09-20 | **NÃO VERIFICADO** |
| 21| `Kernel-Process` ETW não fornece `CommandLine` confiável | `learn.microsoft.com/en-us/answers/questions/1331639` | 2026-09-20 | **VERIFICADO** |
| 22| Security Event 4688 fornece CommandLine completa com GPO | `learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688` | 2026-09-20 | **VERIFICADO** |
| 23| `Microsoft-Windows-Threat-Intelligence` exige PPL Antimalware/ELAM | `learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services` | 2026-09-20 | **VERIFICADO** |
| 24| Leitura do canal Security exige `SeSecurityPrivilege` | Microsoft Learn Windows Event Log Architecture | 2026-09-20 | **VERIFICADO** |
| 25| WFP suporta sessões dinâmicas e filtros persistentes | `learn.microsoft.com/en-us/windows/win32/fwp/object-management` | 2026-09-20 | **VERIFICADO** |

---

## 4. Restrições Descobertas e Decisões de Arquitetura

1. **Adoção do OCSF 1.9.0 com Extensão `win`:** A normalização de eventos adotará formalmente a classe `detection_finding` (2004) para alertas de terceiros (Wazuh/Defender), `authentication` (3002) para eventos de identidade, e as classes da Categoria 7 (`remediation_activity` 7001 e `network_remediation_activity` 7004) para ações de resposta do Control Plane. Modificações de Registro serão validadas via extensão `win`.
2. **Telemetria Híbrida sem Sysmon:** O Collector Agent utilizará ETW direto sem CGO para processos, conexões de rede e DNS, complementado pelo Security Event ID 4688 via `wevtapi.dll` para captura auditada da linha de comando, tornando a GPO de linha de comando um requisito mandatório de implantação monitorado pelo Health Center.
3. **Isolamento de Rede Falha-Fechado Criptográfico:** A expiração do isolamento (Lei 10 v2.1) persiste o próprio objeto assinado da Lei 9. A verificação da assinatura Ed25519 é executada antes da reversão das regras; falha na validação mantém o isolamento e aciona alarme de adulteração. O watchdog opera sobre base de tempo monotônica e a recuperação de emergência é estritamente local (sem canal remoto).

---

## 5. Itens Não Verificados / Riscos em Aberto

- `[NÃO VERIFICADO]`: Limite numérico exato de requisições por hora na API do OTX (assumido como orientação, não constante fixa).
- `[NÃO VERIFICADO]`: Comportamento de saturação do buffer de callbacks do Go sob taxas superiores a 50.000 eventos ETW/segundo no Windows (requer teste de estresse em VM descartável na Fase 5).
