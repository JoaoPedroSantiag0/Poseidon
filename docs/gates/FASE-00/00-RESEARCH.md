# Pesquisa Técnica e Fundacional — Fase 00

**Autor:** Architect / Builder  
**Data da Pesquisa:** 2026-09-20  
**Status:** Concluído — Base para Proposta de ADRs Fundacionais  

---

## 1. Escopo e Propósito

Este documento consolida o levantamento técnico, legal e arquitetural preparatório para a concepção do Poseidon Core, Ingestion Plane, CTI Engine e Response Control Plane.

Em rigoroso cumprimento à **Lei 1 da Constituição do Poseidon** (*"Nenhuma afirmação sobre API externa sem citação verificada"*), toda declaração técnica a respeito de protocolos, contratos de API, schemas, canais de telemetria e licenças está fundamentada em fontes oficiais consultadas nesta data.

---

## 2. Levantamento por Domínio e Componente

### 2.1 Wazuh: Arquitetura, APIs, Formatos e Licenciamento por Componente

O ecossistema Wazuh é composto por múltiplos subsistemas independentes, com repositórios e licenças distintas.

#### 2.1.1 Análise de Licenciamento por Componente Separado

A verificação foi executada diretamente nos arquivos `LICENSE` dos repositórios oficiais, e não em portais de marketing institucional:

| Componente | Repositório Oficial | Licença Verificada | Cláusulas Críticas e Implicações |
|---|---|---|---|
| **Wazuh Manager / Server** | `github.com/wazuh/wazuh` | **GPLv2** (com exceção OpenSSL) | Código histórico OSSEC / Trend Micro. O arquivo `LICENSE` define explicitamente como trabalho derivado: integrar código-fonte, incluir binários em instaladores proprietários ou linkar estaticamente/dinamicamente. **Contudo**, chamadas via rede (REST API) não constituem linkagem sob a GPLv2. |
| **Wazuh Agent** (C codebase) | `github.com/wazuh/wazuh` | **GPLv2** (com exceção OpenSSL) | Compartilha o repositório principal. Qualquer modificação ou redistribuição empacotada requer licenciamento GPLv2. |
| **Wazuh Indexer** (Core) | `github.com/wazuh/wazuh-indexer` | **Apache License 2.0** | Fork/distribuição do OpenSearch 2.x. Permissiva, permitindo conexão via cliente OpenSearch REST sem contaminação copyleft. |
| **Wazuh Indexer Plugins** | `github.com/wazuh/wazuh-indexer-plugins` | **AGPL-3.0** (GNU Affero GPL) | Plugins analíticos e de relatórios (`wazuh-indexer-reporting`). A licença AGPLv3 impõe copyleft mesmo em uso exclusivo via rede (*network interaction clause*, Seção 13) se o software for modificado. |
| **Wazuh Dashboard** | `github.com/wazuh/wazuh-dashboard` | **Apache License 2.0** | Fork do OpenSearch Dashboards. |
| **Wazuh Dashboard Plugins** | `github.com/wazuh/wazuh-dashboard-plugins` | **GPLv2 / AGPL-3.0** | Plugins que customizam a interface. Fortemente acoplados ao ciclo do upstream. |

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh Core LICENSE: [https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE](https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE)
- Wazuh Indexer repo: [https://github.com/wazuh/wazuh-indexer](https://github.com/wazuh/wazuh-indexer)
- Wazuh Indexer Plugins repo: [https://github.com/wazuh/wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins)
- Wazuh Dashboard Plugins repo: [https://github.com/wazuh/wazuh-dashboard-plugins](https://github.com/wazuh/wazuh-dashboard-plugins)

**Implicação Direta para o Poseidon:**
1. **Consumo via API (Permitido e Seguro):** O Poseidon Backend comunicando-se com a API do Wazuh Manager e com o Wazuh Indexer exclusivamente via HTTP/REST (protocolo de rede padrão) não constitui obra derivada, preservando a propriedade intelectual e arquitetura do Poseidon.
2. **Proibição de Bundling/Linking:** É terminantemente vedado embutir bibliotecas C do Wazuh, compilar binários conjuntos ou forkar o dashboard (conforme já preconizado na Lei 3).
3. **Isolamento de Plugins AGPL:** O Poseidon não deve estender nem modificar os plugins AGPL do Wazuh Indexer. Deve tratar o Indexer apenas como uma instância OpenSearch padrão, ou utilizar seu próprio cluster OpenSearch 2.x independente sob Apache 2.0.

#### 2.1.2 Wazuh Server / Manager API

- **Mecanismo:** HTTPS REST na porta TCP 55000 (gerenciada pelo serviço `wazuh-apid`).
- **Autenticação:** Basic Authentication no endpoint de emissão de token:
  - `POST /security/user/authenticate` (com cabeçalho `Authorization: Basic <credentials>`).
  - Retorna um token JWT (`{"data": {"token": "..."}}`). Pode-se passar o parâmetro `?raw=true` para receber a string em texto puro.
  - As requisições subsequentes exigem o cabeçalho `Authorization: Bearer <TOKEN>`.
- **Endpoints de Gestão de Agentes:**
  - `GET /agents`: Lista agentes cadastrados. Suporta parâmetros de busca e paginação: `limit`, `offset`, `select`, `status` (`active`, `disconnected`, `never_connected`, `pending`), `sort`, `search`. Retorna `data.affected_items`.
  - `GET /agents/{agent_id}`: Detalhes específicos de um agente (SO, IP, versão, último keepalive).
- **Endpoints de Regras:**
  - `GET /rules`: Consulta regras ativas do engine de detecção. Suporta filtros por `rule_ids`, `level`, `filename`, `status`.
- **Active Response via API:**
  - `PUT /active-response?agents_list=<agent_id>`: Dispara um comando de resposta ativa no agente alvo.
  - Payload padrão:
    ```json
    {
      "command": "!firewall-drop",
      "alert": {
        "data": {
          "srcip": "1.1.5.5"
        }
      }
    }
    ```
  - *Nota técnica de segurança:* Quando o comando inicia com `!`, o agente busca um script local correspondente no diretório de Active Response do agente.
- **Consulta de Alertas de Segurança (Constatação Crítica):**
  - **A API do Wazuh Server (porta 55000) NÃO fornece endpoints para consulta e busca de histórico de alertas.** Ela se restringe ao gerenciamento e configuração de agentes, regras e da aplicação do Manager.
  - Para obter os alertas gerados pelo Wazuh, há dois métodos documentados e suportados:
    1. **Wazuh Indexer API (OpenSearch REST na porta 9200):** Consulta direta aos índices `wazuh-alerts-4.x-*` via endpoint `POST /wazuh-alerts-*/_search` com OpenSearch Query DSL.
    2. **Ingestão via Log Local / Pipeline:** Leitura de `/var/ossec/logs/alerts/alerts.json` (gerado em tempo real pelo daemon `analysisd` no Manager) via conector de streaming / Filebeat / Syslog forwarder.

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh API Reference: [https://documentation.wazuh.com/current/user-manual/api/reference.html](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- Wazuh API Use Cases: [https://documentation.wazuh.com/current/user-manual/api/use-cases.html](https://documentation.wazuh.com/current/user-manual/api/use-cases.html)
- Wazuh Indexer API: [https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html)

#### 2.1.3 Formato de Alerta do Wazuh (`alerts.json`)

Um alerta do Wazuh possui estrutura JSON hierárquica contendo metadados do motor, regra, agente e payload decodificado:
```json
{
  "timestamp": "2026-09-20T14:32:10.123+0000",
  "rule": {
    "level": 7,
    "description": "Sysmon - Event 1: Process creation",
    "id": "100002",
    "firedtimes": 1,
    "groups": ["sysmon", "process_creation"],
    "mitre": {
      "id": ["T1059.001"],
      "tactic": ["Execution"],
      "technique": ["PowerShell"]
    }
  },
  "agent": {
    "id": "001",
    "name": "workstation-alpha",
    "ip": "192.168.10.50"
  },
  "manager": {
    "name": "wazuh-master"
  },
  "id": "1726842730.123456",
  "full_log": "Original raw event log string...",
  "decoder": {
    "name": "windows"
  },
  "data": {
    "win": {
      "eventdata": {
        "commandLine": "powershell.exe -enc ...",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parentImage": "C:\\Windows\\explorer.exe",
        "user": "DOMAIN\\user"
      },
      "system": {
        "eventID": "1",
        "channel": "Microsoft-Windows-Sysmon/Operational"
      }
    }
  },
  "location": "EventChannel"
}
```

---

### 2.2 OCSF vs. ECS: Avaliação Comparativa para o Modelo Normalizado do Poseidon

A Lei 2 da Constituição estipula: *"Evento normalizado: OCSF (preferência) ou ECS — decisão em ADR-002"*.

#### 2.2.1 Open Cybersecurity Schema Framework (OCSF)

- **Governança e Origem:** Projeto aberto e neutro, sob a tutela da Linux Foundation, com cofundadores e mantenedores que incluem AWS, Splunk, IBM, CrowdStrike, Trellix e Datadog. Versão estável do schema: `v1.3.0` / `v1.4.0` (repositório em evolução `v1.9.0`).
- **Arquitetura do Modelo:**
  - **Categorias (1 a 6):** 1: System Activity, 2: Findings, 3: Identity & Access Management, 4: Network Activity, 5: Discovery, 6: Application Activity.
  - **Classes de Eventos Chave para Endpoint:**
    - `Class 1007` — Process Activity (launch, terminate, inject, open)
    - `Class 1001` — File System Activity (create, read, modify, delete, rename)
    - `Class 1004` — Registry Activity (set value, delete key, modify)
    - `Class 4001` — Network Activity (connect, traffic)
    - `Class 4003` — DNS Activity (query, answer)
    - `Class 2001` — Security Finding (normaliza alertas de detecção gerados por terceiros, como Wazuh e Defender)
    - `Class 3001` — Authentication (logon, logoff, fail)
  - **Mecanismo de Extensão:** Sistema formalizado de extensões via namespace dedicado (permite atributos `poseidon.*` sem quebrar compatibilidade com parsers OCSF padrão).
- **Ferramental:** Bibliotecas Python (`pyocsf`), schemas formais JSON Schema, validadores automáticos (`ocsf-validator`).
- **Alinhamento:** Vendor-neutral; não atrela o produto à arquitetura de um único fornecedor de busca/SIEM.

#### 2.2.2 Elastic Common Schema (ECS)

- **Governança e Origem:** Criado originalmente pela Elastic para o ecossistema Elastic Stack (Elasticsearch, Beats, Kibana). Recentemente doado ao projeto OpenTelemetry (OTel) para convergência de convenções semânticas.
- **Arquitetura do Modelo:**
  - Baseado em campos planos estruturados com pontos (`process.name`, `process.parent.executable`, `file.path`, `host.id`, `event.category`, `event.action`).
  - Mapeamentos pré-existentes muito maduros para Windows Event Log e Sysmon mantidos pela comunidade Elastic.
- **Desvantagens para o Poseidon:**
  - Nascido e otimizado para o Elasticsearch. O Poseidon utiliza OpenSearch 2.x (fork Apache 2.0 pós-mudança de licença da Elastic para SSPL) e PostgreSQL.
  - A doação ao OTel iniciou um processo de migração/fusão semântica que gera incerteza sobre a governança de longo prazo do schema original vs convenções OTel.

#### 2.2.3 Síntese Comparativa

| Dimensão | OCSF (Recomendado) | ECS |
|---|---|---|
| **Governança** | Linux Foundation (Multi-vendor: AWS, IBM, Splunk) | OpenTelemetry / Elastic |
| **Neutralidade** | Alta — projetado especificamente para Data Lakes e SOC heterogêneo | Média/Baixa — raízes fortes no ecossistema Elastic |
| **Modelagem de Findings (Alertas)** | Nativa (`Class 2001 - Security Finding`), perfeita para integrar Wazuh | Adaptada (`event.kind: alert`), menos expressiva |
| **Extensibilidade** | Namespace formal de extensões (`poseidon.*`) | Adição livre de campos (risco de fragmentação) |
| **Aderência ao OpenSearch** | Total (adotado pelo Amazon Security Lake) | Requer adaptação contínua pós-fork Elastic |

*Fontes oficiais consultadas em 2026-09-20:*
- OCSF Schema Browser & Documentation: [https://schema.ocsf.io/](https://schema.ocsf.io/)
- OCSF GitHub Schema Repository: [https://github.com/ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema)
- Elastic Common Schema Reference: [https://www.elastic.co/guide/en/ecs/current/index.html](https://www.elastic.co/guide/en/ecs/current/index.html)

---

### 2.3 STIX 2.1: Modelagem de Objetos de CTI e Mapeamento para o Poseidon

O padrão **STIX™ Version 2.1** foi ratificado como Padrão Oficial OASIS em 10 de Junho de 2021 pelo OASIS CTI Technical Committee.

#### 2.3.1 Objetos Chave (SDOs e SROs)

1. **`indicator` (SDO):** Contém um padrão observável de ameaça.
   - Campos: `id`, `type: "indicator"`, `name`, `description`, `pattern` (expressão formal, ex: `[ipv4-addr:value = '198.51.100.1']`), `pattern_type` (`stix`), `valid_from`, `valid_until`, `indicator_types` (`malicious-activity`, `anomalous-activity`), `confidence` (0-100).
2. **`observed-data` (SDO):** Representa telemetria bruta observada em endpoints ou redes.
   - Campos: `first_observed`, `last_observed`, `number_observed`, `objects` / `object_refs` (SCOs como `process`, `file`, `network-traffic`).
3. **`malware` (SDO):** Representa software malicioso.
   - Campos: `name`, `is_family` (boolean), `malware_types` (`ransomware`, `trojan`, `bot`, `spyware`), `capabilities`, `architecture_execution_envs`.
4. **`threat-actor` (SDO):** Entidade hostil real ou hipotética.
   - Campos: `name`, `aliases`, `threat_actor_types` (`nation-state`, `cybercriminal`), `sophistication`, `resource_level`, `primary_motivation`.
5. **`campaign` (SDO):** Conjunto agrupado de atividades maliciosas com alvo ou objetivo comum em dado intervalo temporal.
   - Campos: `name`, `first_seen`, `last_seen`, `objective`.
6. **`relationship` (SRO):** Conexão semântica direcionada entre dois objetos STIX.
   - Campos: `source_ref`, `target_ref`, `relationship_type` (`indicates`, `uses`, `attributed-to`, `mitigates`, `targets`).
7. **`sighting` (SRO):** Declaração de que um elemento de inteligência foi de fato avistado em telemetria real.
   - Campos: `sighting_of_ref` (referência ao `indicator` ou `malware`), `where_sighted_refs` (referência ao `identity`), `observed_data_refs`, `first_seen`, `last_seen`, `count`.

#### 2.3.2 Mapeamento para o CTI Engine do Poseidon

Em conformidade com a **Lei 7** (*"IOC não é string, inteligência carrega proveniência"*):
- Cada IOC ingerido no Poseidon é instanciado como uma entidade normalizada associada a um `indicator` STIX 2.1.
- Toda correlação de telemetria de endpoint com um IOC gera um `sighting` com contagem, timestamp preciso (`first_seen`, `last_seen`) e referência ao evento bruto (`raw_reference`).
- As tabelas relacionais do PostgreSQL refletirão os objetos STIX 2.1 garantindo integridade referencial, enquanto relacionamentos complexos alimentam o Entity Graph do Investigation Workspace via Cytoscape.js.

*Fontes oficiais consultadas em 2026-09-20:*
- OASIS STIX 2.1 Standard: [https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)
- OASIS CTI Documentation: [https://oasis-open.github.io/cti-documentation/](https://oasis-open.github.io/cti-documentation/)
- OASIS STIX Validator: [https://github.com/oasis-open/cti-stix-validator](https://github.com/oasis-open/cti-stix-validator)

---

### 2.4 Sigma: Engenharia de Detecção e Compilação para OpenSearch

O formato Sigma é a especificação aberta e agnóstica para descrição de lógica de detecção de assinaturas em logs de segurança (mantida pela SigmaHQ).

#### 2.4.1 Estrutura Canônica de uma Regra Sigma

- `title`: Nome descritivo da detecção.
- `id`: UUID v4 único e imutável.
- `status`: `experimental`, `test`, `stable`, `deprecated`.
- `description`: Explicação da ameaça detectada.
- `references`: Links e fontes externas.
- `author`: Criador da regra.
- `date`: Data de criação/atualização.
- `logsource`: Mapeamento de origem:
  - `category`: `process_creation`, `network_connection`, `file_event`, `dns`.
  - `product`: `windows`, `linux`.
  - `service`: `sysmon`, `security`.
- `detection`: Lógica booleana contendo seleções, filtros e condição:
  - `selection`: Dicionário de campos e modificadores (`|contains`, `|endswith`, `|startswith`, `|re`).
  - `filter`: Exceções ou falso-positivos conhecidos.
  - `condition`: Expressão lógica (ex: `selection and not filter`).
- `level`: `low`, `medium`, `high`, `critical`.
- `tags`: Identificadores taxonômicos, notadamente `attack.t1059.001`, `attack.execution`.

#### 2.4.2 Ferramental e Compilação via pySigma

- O motor moderno oficial é o **pySigma** (substituto do legatário `sigmac`).
- **Backend OpenSearch (`pySigma-backend-opensearch`):**
  - Converte regras Sigma em queries Lucene compatíveis com OpenSearch (`OpensearchLuceneBackend`).
  - Suporta OpenSearch PPL (Piped Processing Language) para agregações e regras temporais (`OpenSearchPPLBackend`).
  - Permite geração automática de alertas em background ou execução de queries em streaming contra eventos normalizados em OpenSearch.
- **Viabilidade no Poseidon:** O Poseidon armazenará suas regras de detecção nativamente em YAML Sigma (versionadas em `detection/rules/`). Um serviço de compilação em background gerará as queries correspondentes para execução no OpenSearch, dispensando motores de regras proprietários.

*Fontes oficiais consultadas em 2026-09-20:*
- Sigma Specification: [https://sigmahq.io/docs/basics/rules.html](https://sigmahq.io/docs/basics/rules.html)
- pySigma OpenSearch Backend: [https://github.com/SigmaHQ/pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch)
- SigmaHQ Repository: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

---

### 2.5 AlienVault OTX (Open Threat Exchange)

- **Acesso e Autenticação:**
  - Base URL: `https://otx.alienvault.com/api/v1`
  - Autenticação obrigatória via cabeçalho HTTP: `X-OTX-API-KEY: <api_key>`
  - API Key obtida individualmente no painel de configurações do usuário no portal OTX.
- **Endpoints Chave de Consulta:**
  - Indicadores IPv4: `GET /api/v1/indicators/IPv4/{ip}/general` (traz contagem de pulsos, geolocalização, ASN, validação de reputação).
  - Indicadores de Domínio: `GET /api/v1/indicators/domain/{domain}/general`.
  - Indicadores de Hash (MD5/SHA1/SHA256): `GET /api/v1/indicators/file/{hash}/general`.
  - Feeds de Pulsos Inscritos: `GET /api/v1/pulses/subscribed` (permite ingestão assíncrona de CTI em lotes).
- **Limites de Taxa e Termos:**
  - Limite documentado de referência: até 10.000 requisições por hora com chave autenticada.
  - Termos de Uso da Comunidade: Uso colaborativo gratuito para analistas de segurança e equipes de defesa. É exigido cache local com TTL controlado para evitar sobrecarga dos servidores públicos do OTX.

*Fontes oficiais consultadas em 2026-09-20:*
- AlienVault OTX API Guide: [https://otx.alienvault.com/api/](https://otx.alienvault.com/api/)
- AlienVault Developer Documentation: [https://cybersecurity.att.com/documentation/usm-anywhere/otx-integration.htm](https://cybersecurity.att.com/documentation/usm-anywhere/otx-integration.htm)

---

### 2.6 Sysmon (System Monitor) da Microsoft Sysinternals

O Sysmon é um serviço de sistema do Windows (`Sysmon.exe`) acoplado a um driver de dispositivo de filtro em nível de kernel (`SysmonDrv.sys`) que intercepta chamadas de sistema e grava eventos no canal operacional do Windows Event Log.

#### 2.6.1 Event IDs Fundamentais para Detecção

- **Event ID 1: Process Creation**
  - Campos: `UtcTime`, `ProcessGuid` (identificador único persistente do processo), `ProcessId`, `Image` (caminho completo do binário), `CommandLine`, `CurrentDirectory`, `User`, `LogonGuid`, `TerminalSessionId`, `IntegrityLevel`, `Hashes` (SHA256, MD5, etc.), `ParentProcessGuid`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`.
- **Event ID 3: Network Connection Detected**
  - Campos: `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `User`, `Protocol` (tcp/udp), `Initiated` (true/false indicando outbound/inbound), `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname`.
- **Event ID 11: FileCreate**
  - Campos: `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `TargetFilename`, `CreationUtcTime`.
- **Event ID 13: RegistryEvent (Value Set)**
  - Campos: `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `EventType`, `TargetObject` (chave/valor do registro), `Details`.
- **Event ID 22: DNSEvent (DNS Query)**
  - Campos: `UtcTime`, `ProcessGuid`, `ProcessId`, `QueryName`, `QueryStatus`, `QueryResults`, `Image`.

#### 2.6.2 Configuração e Privilégios

- **Canal de Log:** `Microsoft-Windows-Sysmon/Operational`.
- **Configuração Base:** Arquivo XML com esquema versionado (referência: `SwiftOnSecurity/sysmon-config` e `olafhartong/sysmon-modular`).
- **Privilégios:**
  - Instalação e execução do serviço: Requer privilégios de `NT AUTHORITY\SYSTEM`.
  - Leitura do canal: Usuários do grupo `Event Log Readers`, Administradores locais ou `SYSTEM`. O Collector Agent executando como serviço local em Go possui acesso direto à leitura desse canal.

*Fontes oficiais consultadas em 2026-09-20:*
- Microsoft Learn Sysmon Overview: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Learn Sysmon Event Reference: [https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#events)

---

### 2.7 Windows Event Log e Microsoft Defender Antivírus Local

#### 2.7.1 Windows Security Log

- **Canal:** `Security`.
- **Privilégios:** Requer privilégio especial `SeSecurityPrivilege` para abertura e leitura do canal (concedido nativamente a `SYSTEM` e Administradores).
- **Event IDs Relevantes:**
  - `4624`: Sucesso de logon (`LogonType`, `TargetUserName`, `IpAddress`, `IpPort`).
  - `4625`: Falha de autenticação (`FailureReason`, `Status`, `SubStatus`, `TargetUserName`, `IpAddress`).
  - `4688`: Criação de novo processo (requer GPO *"Include command line in process creation events"* habilitada para capturar linha de comando).
  - `4672`: Atribuição de privilégios especiais (auditoria de privilégios administrativos).

#### 2.7.2 Microsoft Defender Antivírus Local (Sem dependência de Tenant Cloud)

- **Canal Operacional:** `Microsoft-Windows-Windows Defender/Operational`.
- **Event IDs Chave:**
  - `1116` (`MALWAREPROTECTION_STATE_MALWARE_DETECTED`): Detecção de malware ou software potencialmente indesejado (PUA). Fornece: Threat Name, Threat ID, Severity, Category, Path.
  - `1117` (`MALWAREPROTECTION_STATE_MALWARE_ACTION_TAKEN`): Ação de proteção executada (Quarantine, Clean, Remove, Block).
  - `1006`: Ação bloqueada pelo motor de Real-Time Protection em tempo de execução.
  - `5001`: Proteção em tempo real desativada (indicador de potencial ação de evasão defensiva).
  - `5007`: Alteração na configuração do antivírus (ex: inclusão maliciosa de exclusões de pasta).

#### 2.7.3 Integração e Coleta via Go (Collector Agent)

- A API moderna do Windows para leitura de logs de eventos é exposta pela DLL de sistema `wevtapi.dll` (Windows Event Log API).
- Funções C nativas:
  - `EvtSubscribe`: Registra subscrição push/pull assíncrona baseada em XPath query no canal desejado (`EvtSubscribeToFutureEvents` ou `EvtSubscribeStartAtOldestRecord`).
  - `EvtQuery` e `EvtNext`: Para leitura em lote com ponteiros para handles de eventos.
  - `EvtRender`: Converte o handle do evento binário em XML canônico (`EvtRenderEventXml`).
- Implementação em Go: O Collector Agent utilizará syscalls tipadas sobre `golang.org/x/sys/windows` chamando `wevtapi.dll`, sem necessidade de CGO, produzindo um binário puramente estático para Windows x64.

*Fontes oficiais consultadas em 2026-09-20:*
- Microsoft Learn Defender Event IDs: [https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- Microsoft Learn Windows Event Log API: [https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference)

---

### 2.8 MITRE ATT&CK: Fonte de Dados, Formato e Atualização

- **Fonte Oficial:** Repositório oficial mantido pelo MITRE: `github.com/mitre-attack/attack-stix-data`.
- **Formato Normativo:** Arquivo STIX 2.1 Collection Bundle: `enterprise-attack/enterprise-attack.json`.
- **Objetos Mapeados:**
  - Técnicas e Subtécnicas: objetos `attack-pattern` com `external_references` contendo `source_name: "mitre-attack"` e `external_id` (ex: `T1059.001`).
  - Táticas: objetos `x-mitre-tactic` (ex: `execution`, `persistence`).
  - Ameaças/Grupos: objetos `intrusion-set`.
  - Softwares: objetos `malware` e `tool`.
- **Estratégia de Sincronização:** O Poseidon manterá uma rotina periódica assíncrona no backend para download das tags versionadas de `enterprise-attack.json`, populando as tabelas de referência do PostgreSQL sem dependência de consultas online dinâmicas em tempo de triagem de incidentes.

*Fontes oficiais consultadas em 2026-09-20:*
- MITRE ATT&CK STIX Data Repository: [https://github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
- MITRE ATT&CK Matrix Official: [https://attack.mitre.org/](https://attack.mitre.org/)

---

## 3. Matriz de Verificação (Lei 1)

| Item / Afirmação Técnica | Fonte Oficial Consultada | Data | Status |
|---|---|---|---|
| Wazuh Core (Server/Agent) sob licença GPLv2 com cláusula de obra derivada | `github.com/wazuh/wazuh/blob/master/LICENSE` | 2026-09-20 | **VERIFICADO** |
| Wazuh Indexer Core sob Apache 2.0; Plugins sob AGPL-3.0 | `github.com/wazuh/wazuh-indexer-plugins/blob/main/LICENSE` | 2026-09-20 | **VERIFICADO** |
| Wazuh Server API (porta 55000) autentica via `POST /security/user/authenticate` com Basic Auth retornando JWT | `documentation.wazuh.com/current/user-manual/api/reference.html` | 2026-09-20 | **VERIFICADO** |
| Wazuh Server API não possui endpoint para busca de histórico de alertas | `documentation.wazuh.com/current/user-manual/api/reference.html` | 2026-09-20 | **VERIFICADO** |
| Wazuh Indexer expõe porta 9200 com OpenSearch Query DSL para índices `wazuh-alerts-*` | `documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html` | 2026-09-20 | **VERIFICADO** |
| Wazuh Active Response dispara via `PUT /active-response?agents_list=<id>` | `documentation.wazuh.com/current/user-manual/api/reference.html` | 2026-09-20 | **VERIFICADO** |
| OCSF Class 1007 (Process Activity) e Class 2001 (Security Finding) sob Linux Foundation | `schema.ocsf.io` | 2026-09-20 | **VERIFICADO** |
| STIX 2.1 aprovado como OASIS Standard com SDOs/SROs formalizados | `docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html` | 2026-09-20 | **VERIFICADO** |
| pySigma-backend-opensearch compila regras Sigma para OpenSearch Lucene e PPL | `github.com/SigmaHQ/pySigma-backend-opensearch` | 2026-09-20 | **VERIFICADO** |
| OTX API autentica via cabeçalho `X-OTX-API-KEY` com base `otx.alienvault.com/api/v1` | `otx.alienvault.com/api/` | 2026-09-20 | **VERIFICADO** |
| Sysmon grava eventos 1, 3, 11, 13, 22 em `Microsoft-Windows-Sysmon/Operational` | `learn.microsoft.com/en-us/sysinternals/downloads/sysmon` | 2026-09-20 | **VERIFICADO** |
| Defender Antivírus local grava eventos 1116 e 1117 no canal Windows Defender/Operational | `learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus` | 2026-09-20 | **VERIFICADO** |
| Windows Event Log consome `wevtapi.dll` para subscrição e renderização XML | `learn.microsoft.com/en-us/windows/win32/wes/windows-event-log-reference` | 2026-09-20 | **VERIFICADO** |
| MITRE ATT&CK STIX 2.1 disponibilizado em `mitre-attack/attack-stix-data` | `github.com/mitre-attack/attack-stix-data` | 2026-09-20 | **VERIFICADO** |

---

## 4. Restrições Descobertas e Impactos no Design

1. **Wazuh Indexer Plugins sob AGPL-3.0:** O Poseidon não deve estender plugins do Wazuh Indexer nem incluir código deles. A integração com alertas deve ocorrer consumindo a API REST padrão do OpenSearch ou lendo o stream de `alerts.json`. Para a persistência do próprio Poseidon, utilizaremos OpenSearch 2.x padrão (Apache 2.0).
2. **Inexistência de endpoint `/alerts` no Wazuh Server:** Tentativas de consultar histórico de alertas na porta 55000 falhariam. O Poseidon Adapter para Wazuh precisará consultar a porta 9200 do Indexer ou escutar o forward de eventos em tempo real.
3. **Leitura de Windows Security Log sem privilégio de Admin falha:** O Collector Agent precisa obrigatoriamente rodar como serviço Windows (`LocalSystem`) para invocar `EvtSubscribe` no canal `Security` com sucesso.
4. **Sysmon é opcional no endpoint do cliente:** O Collector Agent deve operar em modo adaptativo: se o canal do Sysmon não existir na máquina, o Collector deve manter a coleta dos logs de Security (4624, 4625, 4688) e Defender local, sinalizando no Health Center a ausência de telemetria estendida.

---

## 5. Itens Não Verificados / Riscos Abertos

- [NÃO VERIFICADO]: Comportamento do OpenSearch PPL Backend em clusters OpenSearch sob carga extrema de eventos em streaming (necessário teste de estresse na Fase 11).
- [NÃO VERIFICADO]: Variações de nomes de campos em versões legadas do Sysmon (v13 ou inferior). A config base do Poseidon suportará oficialmente Sysmon v14+.
