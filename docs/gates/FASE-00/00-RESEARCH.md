# Pesquisa Técnica e Fundacional — Fase 00

**Autor:** Architect / Builder  
**Data da Pesquisa:** 2026-09-20 (Atualizado após Emenda Constitucional v2.0)  
**Status:** Concluído — Base para Proposta de ADRs Fundacionais  

---

## 1. Escopo e Propósito

Este documento consolida o levantamento técnico, legal e arquitetural preparatório para a concepção do Poseidon Core, Ingestion Plane, CTI Engine, Response Control Plane e Collector Agent.

Em rigoroso cumprimento à **Lei 1 da Constituição do Poseidon** (*"Nenhuma afirmação sobre API externa sem citação verificada"*), toda declaração técnica a respeito de protocolos, contratos de API, schemas, canais de telemetria e licenças está fundamentada em fontes oficiais consultadas nesta data.

Esta versão incorpora os requisitos da **Emenda Constitucional v2.0**, com foco especial na **viabilidade de consumo direto de ETW em Go sem CGO**, análise comparativa de cobertura contra o Sysmon, exigências de PPL/ELAM e adequação à ambição SaaS do produto.

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
| **Wazuh Dashboard Plugins** | `github.com/wazuh/wazuh-dashboard-plugins` | **GPLv2 / AGPL-3.0** | Plugins que customizam a interface. Fortemente acoplados ao ciclo do upstream. |

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh Core LICENSE: [https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE](https://raw.githubusercontent.com/wazuh/wazuh/master/LICENSE)
- Wazuh Indexer repo: [https://github.com/wazuh/wazuh-indexer](https://github.com/wazuh/wazuh-indexer)
- Wazuh Indexer Plugins repo: [https://github.com/wazuh/wazuh-indexer-plugins](https://github.com/wazuh/wazuh-indexer-plugins)
- Wazuh Dashboard Plugins repo: [https://github.com/wazuh/wazuh-dashboard-plugins](https://github.com/wazuh/wazuh-dashboard-plugins)

**Implicação Direta para o Poseidon:**
1. **Consumo via API (Permitido e Seguro):** O Poseidon Backend comunicando-se com a API do Wazuh Manager e com o Wazuh Indexer exclusivamente via HTTP/REST (protocolo de rede padrão) não constitui obra derivada, preservando a propriedade intelectual e arquitetura do Poseidon.
2. **Proibição de Bundling/Linking:** É terminantemente vedado embutir bibliotecas C do Wazuh, compilar binários conjuntos ou forkar o dashboard (conforme já preconizado na Lei 3).
3. **Isolamento de Plugins AGPL:** O Poseidon não deve estender nem modificar os plugins AGPL do Wazuh Indexer. Deve tratar o Indexer apenas como uma instância OpenSearch padrão, operando seu próprio cluster OpenSearch 2.x independente sob Apache 2.0.

#### 2.1.2 Wazuh Server / Manager API vs. Wazuh Indexer

- **Wazuh Server API (porta TCP 55000):**
  - **Mecanismo:** HTTPS REST gerenciado pelo serviço `wazuh-apid`.
  - **Autenticação:** `POST /security/user/authenticate` (Basic Auth) retornando JWT (validade padrão 900s).
  - **Endpoints:** Gestão de agentes (`GET /agents`, `GET /agents/{id}`), regras (`GET /rules`) e despacho de resposta ativa (`PUT /active-response`).
  - **Constatação Crítica:** **A API do Manager NÃO fornece endpoints de consulta de histórico de alertas.**
- **Wazuh Indexer API (porta TCP 9200):**
  - É a interface OpenSearch 2.x onde os alertas são efetivamente gravados nos índices `wazuh-alerts-4.x-*`.
  - Consultas analíticas são realizadas via `POST /wazuh-alerts-*/_search` com OpenSearch Query DSL.
- **Conector Duplo Necessário:** O conector Wazuh do Poseidon (`integrations/wazuh/`) deve ser duplo por desenho arquitetural: fala com o Manager (porta 55000) para topologia e contenção, e com o Indexer (porta 9200) para extração de alertas.
- **Superfície de Execução no Wazuh Active Response (Auditoria do Código v4.14.7):**
  - Comando prefixado com `!` pula verificação de lista branca (`active_response.py:validate_command`);
  - `agents_list` tem default `'*'` (broadcast na frota);
  - `PUT /agents/upgrade_custom` instala binários WPK locais arbitrários.
  - **Trava Constitucional (Lei 8 v2.0):** O conector Wazuh do Poseidon nunca envia comando com `!`, nunca omite `agents_list`, nunca chama `upgrade_custom`, e nunca deriva argumentos de entrada livre de usuário.

*Fontes oficiais consultadas em 2026-09-20:*
- Wazuh API Reference: [https://documentation.wazuh.com/current/user-manual/api/reference.html](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- Wazuh Indexer API: [https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/indexer-api.html)
- Repositório Wazuh Core v4.14.7: [https://github.com/wazuh/wazuh/tree/v4.14.7](https://github.com/wazuh/wazuh/tree/v4.14.7)

---

### 2.2 OCSF vs. ECS: Avaliação para o Modelo Normalizado

A **Lei 2** define OCSF (preferência) ou ECS com decisão no ADR-002, e a **Lei 4 (v2.0)** estabelece que o modelo nasce `PROVISÓRIO` na Fase 3 e é congelado na Fase 9.

#### 2.2.1 Open Cybersecurity Schema Framework (OCSF)

- **Governança:** Linux Foundation (AWS, IBM, Splunk, CrowdStrike, Trellix). Versão atual: **v1.9.0** (2026-08-03).
- **Alinhamento com a Lei 5 (v2.0):**
  O OCSF 1.9 já fornece nativamente os seis conceitos semânticos exigidos pela Lei 5:
  - Tempo do evento: `time` / `metadata.original_time`
  - Tempo de ingestão: `metadata.logged_time`
  - Origem: `metadata.product` (obrigatório) e `metadata.source`
  - ID na origem: `metadata.original_event_uid`
  - Referência ao bruto: `raw_data` / `raw_data_hash`
  - Correlação: `metadata.correlation_uid`
  - Pipeline de rastreamento: `metadata.loggers` (array ordenado de cada hop no pipeline)
- **Classes de Destaque:**
  - `Class 1007` — Process Activity
  - `Class 4001` — Network Activity
  - `Class 4003` — DNS Activity
  - `Class 1001` — File System Activity
  - `Class 1004` — Registry Activity
  - `Class 2001` — Security Finding (normaliza alertas de detecção)
  - `Class 3001` — Authentication
- **Trade-off Real (Auditoria):** O ferramental Python oficial (`ocsf/ocsf-lib-py`) possui manutenção esparsa. Assumimos o custo arquitetural de manter modelos Pydantic v2 estritos manualmente no backend do Poseidon.

*Fontes oficiais consultadas em 2026-09-20:*
- OCSF Schema Browser & API: [https://schema.ocsf.io/](https://schema.ocsf.io/)
- OCSF Releases: [https://github.com/ocsf/ocsf-schema/releases](https://github.com/ocsf/ocsf-schema/releases)

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
- **Requisito de Licença DRL 1.1 (Incorporado na Lei 13 v2.0):**
  A *Detection Rule License 1.1* do repositório SigmaHQ impõe que:
  *"messages based on matches with the Rules must retain identification of the author(s)"*.
  Portanto, todo alerta gerado pelo Poseidon com base em regras Sigma **carrega obrigatoriamente a identificação do autor no schema do próprio alerta** (`Class 2001 - Security Finding`).

*Fontes oficiais consultadas em 2026-09-20:*
- SigmaHQ Repository & License: [https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- pySigma OpenSearch: [https://github.com/SigmaHQ/pySigma-backend-opensearch](https://github.com/SigmaHQ/pySigma-backend-opensearch)

---

### 2.5 AlienVault OTX (Open Threat Exchange)

- **API REST:** Base URL `https://otx.alienvault.com/api/v1`.
- **Autenticação:** Cabeçalho HTTP `X-OTX-API-KEY`.
- **Endpoints:** `GET /api/v1/indicators/IPv4/{ip}/general`, `domain/{domain}/general`, `file/{hash}/general`, e `/api/v1/pulses/subscribed`.
- **Status do Ecossistema:** O produto migrou para a marca **LevelBlue** e o repositório `OTX-Python-SDK` encontra-se sem commits recentes (desde maio de 2024). O conector CTI do Poseidon consumirá a API REST diretamente com cliente HTTP assíncrono padrão (`httpx`), sem depender do SDK desatualizado.
- **Termos de Uso:** Uso comunitário com cache local mandatório para evitar abuso de taxa.

*Fontes oficiais consultadas em 2026-09-20:*
- OTX Portal & API Documentation: [https://otx.alienvault.com/api/](https://otx.alienvault.com/api/)

---

### 2.6 ETW (Event Tracing for Windows): Viabilidade em Go sem CGO, Provedores e PPL

A **Emenda 2.0 da Constituição (§4)** determinou que o Collector Agent consumirá **ETW diretamente e Windows Event Log via `wevtapi.dll`**, eliminando a dependência do Sysmon do produto em razão das restrições de redistribuição e uso em SaaS da EULA Sysinternals.

Esta seção detalha o levantamento aprofundado exigido para viabilizar a Fase 5.

#### 2.6.1 Viabilidade Técnica de Consumo Direto de ETW em Go sem CGO

O subsistema ETW do Windows é exposto através de bibliotecas Win32 de sistema (`advapi32.dll` e `tdh.dll`):

1. **APIs Win32 Envolvidas:**
   - `StartTraceW` / `ControlTraceW`: Criação e controle de sessões de rastreamento em tempo real (`EVENT_TRACE_REAL_TIME_MODE`).
   - `EnableTraceEx2`: Habilitação de provedores específicos por GUID, níveis de severidade (`Level`) e máscaras de palavra-chave (`MatchAnyKeyword`).
   - `OpenTraceW`: Inicialização do handle de consumo baseado na estrutura `EVENT_TRACE_LOGFILEW`.
   - `ProcessTrace`: Loop bloqueante que consome buffers de eventos e despacha chamadas para o callback registrado.
   - `CloseTrace`: Encerramento da sessão.
   - `TdhGetEventInformation` e `TdhGetProperty` (em `tdh.dll`): Decodificação de schemas e extração tipada de propriedades de eventos.

2. **Mecanismo de Callbacks em Go sem CGO:**
   - A função Win32 `OpenTraceW` exige um ponteiro de função para `PEVENT_RECORD_CALLBACK`.
   - O runtime do Go para Windows disponibiliza nativamente **`windows.NewCallback`** (e `syscall.NewCallback`). Essa função compila em memória um pequeno *trampoline* em assembly x64 compatível com a convenção de chamada da ABI do Windows x64.
   - Quando o despachante de ETW do kernel chama o callback em uma thread nativa do Windows, o runtime do Go intercepta a transição, anexa uma estrutura de thread (`m`) e executa a função Go de forma segura, **sem necessidade de compilador C (GCC/MinGW) e sem CGO**.
   - **Restrição Crítica de Performance:** O callback Go é invocado na thread de entrega do ETW. Se o callback for lento ou executar operações bloqueantes (I/O em disco, rede, alocações pesadas), os buffers de anel no kernel enchem e eventos são silenciosamente descartados (`EventsLost`). O callback do Poseidon deve realizar apenas a cópia do buffer bruto para uma fila em memória/canal pré-alocado e retornar imediatamente `ERROR_SUCCESS` (`1`).

3. **Análise de Licenciamento das Bibliotecas Go Existentes:**
   - Bibliotecas como `0xrawsec/golang-etw` e `tekert/goetw` provam a viabilidade do consumo sem CGO. Contudo, **ambas são licenciadas sob GPL-3.0**. Importá-las como dependência forçaria o Collector Agent inteiro a ser GPL-3.0.
   - **Decisão Arquitetural:** O Poseidon implementará seu próprio consumidor ETW minimalista em Go puro diretamente sobre chamadas de sistema com `golang.org/x/sys/windows` (licença BSD-3-Clause permissiva), garantindo total soberania de licenciamento do agente.

#### 2.6.2 Mapeamento de Provedores e Cobertura comparada ao Sysmon

Para substituir o Sysmon nos endpoints clientes, mapeamos os provedores nativos do Windows correspondentes aos eventos essenciais do SOC:

| Telemetria Desejada | Sysmon de Referência | Provedor Nativo Windows / ETW | Mecanismo de Coleta | Campos Coletados |
|---|---|---|---|---|
| **Criação de Processo** | Event ID 1 | `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`) + **Windows Security Log Event 4688** | ETW Event 1 (`ProcessStart`) + `wevtapi.dll` (Event 4688) | PID, ParentPID, ImageName, CreateTime, User SID. **Nota sobre CommandLine:** O evento 4688 com GPO auditada fornece a linha de comando completa de forma 100% íntegra e estável. |
| **Conexões de Rede** | Event ID 3 | `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`) | ETW em tempo real (Event 12: TCP Connect Attempt; Event 15: TCP Connect Established; Event 42/43: UDP) | PID, SourceIP, DestinationIP, SourcePort, DestinationPort. |
| **Resoluções DNS** | Event ID 22 | `Microsoft-Windows-DNS-Client` (`{1C950233-43CE-412B-AC34-4E142F578CAE}`) | Canal `DNS-Client/Operational` via `wevtapi.dll` ou ETW Event 3008 | `QueryName`, `QueryType`, `QueryResults`, `ResponseStatus`. |
| **Atividade de Arquivo** | Event ID 11 | `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`) | ETW em tempo real (Event 12: Create, Event 30: SetInfo) | Volume elevado; requer filtro rígido de extensões sensíveis. |
| **Modificações de Registro**| Event ID 13 | `Microsoft-Windows-Kernel-Registry` (`{70EB4F03-C1DE-4F73-A051-33D13D5413BD}`) | ETW em tempo real (Event 1: CreateKey, Event 7: SetValueKey) | Chave do registro, nome do valor, tipo de dado. |
| **Detecções Antivírus** | - | `Microsoft-Windows-Windows Defender/Operational` | `wevtapi.dll` (Eventos 1116, 1117, 1006, 5001) | ThreatName, Severity, Path, ActionTaken. |

#### 2.6.3 Exigência de Assinatura Anti-Malware / PPL para Provedores Sensíveis

Uma descoberta fundamental de segurança diz respeito ao provedor de Threat Intelligence da Microsoft:

- **Provedor `Microsoft-Windows-Threat-Intelligence` (ETW-TI):**
  - GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.
  - Fornece visibilidade de baixo nível de chamadas de kernel críticas: injeção de processos (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`), manipulação de contexto de thread (`NtSetContextThread`) e injeções de APC (`NtQueueApcThread`).
- **A Barreira do PPL (Protected Process Light):**
  - O kernel do Windows impõe uma restrição de acesso categórica ao ETW-TI: **apenas processos executando no nível Protected Process Light (PPL) com o atributo `Antimalware` possuem permissão para assinar ou habilitar este provedor**.
  - Para um processo obter proteção PPL Antimalware, o software precisa carregar um driver **ELAM (Early Launch Anti-Malware)** formalmente co-assinado pela Microsoft mediante certificação WHQL/Dev Center com comprovação de entidade de segurança da informação.
  - Se um processo executando como Administrador local ou como serviço `NT AUTHORITY\SYSTEM` tentar invocar `EnableTraceEx2` para o GUID do ETW-TI sem o status de PPL, o Windows retorna imediatamente **`ERROR_ACCESS_DENIED` (`0x5`)**.
- **Conclusão Arquitetural para o MVP:**
  O Poseidon Collector Agent no MVP **não pode depender do provedor `Microsoft-Windows-Threat-Intelligence`**, pois obter assinatura ELAM com a Microsoft está fora de cogitação na fase atual.
  O agente utilizará com segurança os **provedores de kernel padrão** (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-Network`, `Microsoft-Windows-DNS-Client`) e a API de Event Log (`wevtapi.dll`), que **não exigem PPL** e operam plenamente com privilégios administrativos padrão de serviço Windows (`LocalSystem` / `SE_SYSTEM_PROFILE_NAME`).

---

### 2.7 Windows Event Log e Microsoft Defender Antivírus Local

- **Canal de Segurança:** `Security` (requer `SeSecurityPrivilege`). Eventos:
  - `4624` (Logon bem-sucedido), `4625` (Falha de logon);
  - `4688` (Criação de processo com linha de comando auditada);
  - `4672` (Privilégios administrativos especiais).
- **Microsoft Defender Antivírus Local (sem tenant cloud):**
  - Canal `Microsoft-Windows-Windows Defender/Operational`.
  - `Event ID 1116`: Detecção de malware / PUA com gravidade e caminho;
  - `Event ID 1117`: Ação de contenção executada (Quarantine, Clean, Remove);
  - `Event ID 1006`: Bloqueio por proteção em tempo real;
  - `Event ID 5001`: Desativação da proteção em tempo real.
- **Acesso em Go:** Syscalls tipadas sobre `wevtapi.dll` (`EvtSubscribe`, `EvtRenderEventXml`) sem dependência de runtimes externos.

---

### 2.8 MITRE ATT&CK

- **Fonte:** Repositório oficial `mitre-attack/attack-stix-data` (STIX 2.1).
- **Bundle:** `enterprise-attack/enterprise-attack.json`.
- **Licenciamento:** Requer inclusão do aviso formal de copyright da MITRE Corporation no produto (incorporado na **Lei 13 v2.0**).
- **Atualização:** Download e sincronização de releases versionadas (ex: v19.x) para cache relacional no PostgreSQL.

---

## 3. Matriz de Verificação Atualizada (Lei 1)

| Item / Afirmação Técnica | Fonte Oficial Consultada | Data | Status |
|---|---|---|---|
| Wazuh Core sob GPLv2; Indexer Core sob Apache 2.0; Indexer Plugins sob AGPL-3.0 | `github.com/wazuh/wazuh/blob/master/LICENSE`, `github.com/wazuh/wazuh-indexer-plugins/blob/main/LICENSE` | 2026-09-20 | **VERIFICADO** |
| Wazuh Manager API (porta 55000) não expõe endpoint para busca de histórico de alertas | `documentation.wazuh.com/current/user-manual/api/reference.html` e OpenAPI spec `v4.14.7` | 2026-09-20 | **VERIFICADO** |
| Wazuh Active Response ignora lista com prefixo `!`; broadcast default com `*` | Código fonte `wazuh/wazuh` tag `v4.14.7` (`active_response.py`) | 2026-09-20 | **VERIFICADO** |
| OCSF 1.9.0 provê nativamente os 6 conceitos de proveniência e tempo da Lei 5 | `schema.ocsf.io/api/classes/base_event` e `/api/objects/metadata` | 2026-09-20 | **VERIFICADO** |
| STIX 2.1 define `sighting` formalmente como SRO (Relationship Object) | `docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_rck8012693sm` | 2026-09-20 | **VERIFICADO** |
| SigmaHQ DRL 1.1 exige retenção de identificação do autor nas mensagens geradas | `github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection-Rules.md` | 2026-09-20 | **VERIFICADO** |
| Sysinternals EULA proíbe redistribuição e uso para commercial software hosting (SaaS) | `live.sysinternals.com/Eula.txt` | 2026-09-20 | **VERIFICADO** |
| ETW suporta consumo em Go sem CGO via `windows.NewCallback` com `ProcessTrace` | Documentação Microsoft Win32 ETW API e Go `syscall_windows.go` | 2026-09-20 | **VERIFICADO** |
| `Microsoft-Windows-Threat-Intelligence` exige processo PPL com assinatura Antimalware (ELAM) | Microsoft Learn ELAM / Protected Processes e pesquisas de segurança do Windows Kernel | 2026-09-20 | **VERIFICADO** |
| Provedores de kernel padrão (`Kernel-Process`, `Kernel-Network`, `DNS-Client`) não exigem PPL | Microsoft Learn ETW Reference e SDK Win32 | 2026-09-20 | **VERIFICADO** |
| Defender Antivírus local grava eventos 1116/1117 no canal Windows Defender/Operational | `learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus` | 2026-09-20 | **VERIFICADO** |
| Windows Filtering Platform suporta objetos dinâmicos (sessão) e persistentes | `learn.microsoft.com/en-us/windows/win32/fwp/object-management` | 2026-09-20 | **VERIFICADO** |

---

## 4. Restrições Descobertas e Decisões de Arquitetura

1. **Inviabilidade do Sysmon para SaaS:** Confirmada a restrição da licença Sysinternals. O Collector Agent do Poseidon operará nativamente com ETW e `wevtapi.dll`, sem qualquer dependência ou empacotamento do Sysmon.
2. **Inviabilidade do ETW-TI no MVP:** O provedor `Microsoft-Windows-Threat-Intelligence` requer certificação ELAM e processo PPL, inacessíveis no momento. A detecção de injeções avançadas no MVP apoiar-se-á nos eventos do Defender local (Eventos 1116/1117) e análise de integridade de processo no Core.
3. **Licenciamento de bibliotecas Go ETW:** As bibliotecas públicas que evitam CGO (`0xrawsec/golang-etw` e `tekert/goetw`) são **GPL-3.0**. O Poseidon construirá sua própria camada de bindings Win32 em Go sobre `golang.org/x/sys/windows` para manter o agente com licença limpa e permissiva.
4. **Isolamento de Rede Falha-Fechado com Watchdog Independente:** Como o isolamento persiste através de reboots (Lei 10 v2.0), usaremos regras persistentes do WFP/Firewall e um serviço/tarefa agendada watchdog autônoma no Windows que consulta o arquivo de expiração em disco.

---

## 5. Itens Não Verificados / Riscos em Aberto

- `[NÃO VERIFICADO]`: Comportamento de saturação do buffer de callbacks do Go sob taxas superiores a 50.000 eventos ETW/segundo no Windows (requer teste de carga com gerador de eventos em VM descartável na Fase 5).
- `[NÃO VERIFICADO]`: Variação de formato de propriedades de eventos ETW entre compilações antigas do Windows 10 (21H2) e Windows 11 24H2.
