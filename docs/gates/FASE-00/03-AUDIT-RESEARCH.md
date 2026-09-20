# Levantamento independente do Auditor — Fase 0

> Produzido **sem** leitura do `00-RESEARCH.md` do Builder, por exigência da seção 8.3 do
> `02-AUDITOR.md`. A comparação entre os dois documentos é o produto; este é apenas um
> dos lados.
>
> **Data de consulta de todas as fontes: 2026-09-20.**
> Autor: Auditor · Método: leitura de documentação oficial, de arquivos `LICENSE` nos
> repositórios de origem, de especificações OpenAPI e de código-fonte em *tag* fixa.

---

## 0. Como ler este documento

Cada afirmação é marcada:

| Marca | Significado |
|---|---|
| **[V]** | Verificado diretamente na fonte primária (arquivo, spec, código, doc oficial) |
| **[D]** | Derivado de fonte oficial secundária (página de documentação, não o artefato em si) |
| **[NV]** | **NÃO VERIFICADO** — não confirmado em fonte primária; não pode virar premissa de código (Lei 1) |

Nada aqui é premissa de implementação até constar de um ADR aprovado.

---

## 1. Wazuh — licenciamento por componente

Esta foi a primeira verificação porque ADR-001 é, junto de ADR-002, a decisão mais cara de
reverter. Li o arquivo `LICENSE` de cada repositório, não o site institucional.

| Componente | Repositório | Licença | Marca |
|---|---|---|---|
| Wazuh server/manager + agente 4.x + API | `wazuh/wazuh` | **GPLv2** + exceção OpenSSL | **[V]** |
| Wazuh indexer | `wazuh/wazuh-indexer` | **Apache-2.0** | **[V]** |
| Wazuh dashboard | `wazuh/wazuh-dashboard` | **Apache-2.0** | **[V]** |
| Plugins do dashboard | `wazuh/wazuh-dashboard-plugins` | **GPL-2.0** | **[V]** |
| **Agente (linha 5.x, em desenvolvimento)** | `wazuh/wazuh-agent` | **AGPL-3.0** | **[V]** |

Fontes:
- https://raw.githubusercontent.com/wazuh/wazuh/main/LICENSE
- https://raw.githubusercontent.com/wazuh/wazuh-indexer/main/LICENSE.txt
- https://raw.githubusercontent.com/wazuh/wazuh-dashboard/main/LICENSE.txt
- https://raw.githubusercontent.com/wazuh/wazuh-agent/main/LICENSE
- API do GitHub (`/repos/{owner}/{repo}`) para confirmação cruzada do SPDX declarado.

### 1.1 A licença **não é uniforme** — e está mudando

**[V]** O repositório `wazuh/wazuh-agent` contém o texto verbatim da **GNU Affero General
Public License v3.0** (661 linhas, cabeçalho "GNU AFFERO GENERAL PUBLIC LICENSE, Version 3,
19 November 2007"). O SPDX declarado no GitHub é `AGPL-3.0`.

**[V]** Contexto que impede alarme prematuro: o README desse repositório declara
*"**Work in progress:** This project is currently under development. It is not functional
and is not compatible with the official release version of the Wazuh manager."* O
repositório não possui *tags* de release.

**[V]** A release estável corrente é **v4.14.7 (publicada em 2026-07-30)**; a linha 5.0.0
está em `v5.0.0-beta5`. Portanto o agente **efetivamente distribuído hoje** é o de
`wazuh/wazuh`, sob GPLv2.

**Consequência para ADR-001:** a premissa "Wazuh é GPLv2" é verdadeira **hoje** e
**provavelmente falsa no horizonte do projeto**. O ADR-001 precisa registrar a licença
*por componente e por versão*, e declarar explicitamente o que acontece se o agente 5.x
AGPL-3.0 entrar no laboratório. AGPL-3.0 tem cláusula de uso em rede (§13) que GPLv2 não
tem — é a diferença que importa para uma plataforma que serve interface web.

### 1.2 A cláusula de "derived works" do Wazuh

**[V]** O `LICENSE` do `wazuh/wazuh` contém uma interpretação própria de obra derivada:

> *"For the purpose of this license, we consider an application to constitute a 'derivative
> work' or a work based on this program if it does any of the following (list not
> exclusive): Integrates source code/data files from Wazuh. Includes Wazuh copyrighted
> material. Includes/integrates Wazuh into a proprietary executable installer. Links to a
> library or executes a program that does any of the above."*
>
> *"These restrictions only apply if you actually redistribute Wazuh (or parts of it)."*

**Leitura para o Poseidon:** consumir a API do Wazuh por HTTP a partir de processo separado
não é, por essa redação, obra derivada — a restrição é condicionada à **redistribuição**. O
risco real não é a API: é **empacotar Wazuh no instalador do Poseidon**, que o texto nomeia
explicitamente. Isso precisa constar do ADR-001 como decisão consciente, não como omissão.

**[NV]** Não verifiquei se a interpretação de "executes a program that does any of the
above" alcança um `docker compose` que sobe a imagem oficial do Wazuh ao lado do Poseidon.
Isso é questão jurídica, não técnica, e cai na **Condição de Parada §9.2** da constituição.

### 1.3 A API do Wazuh Manager **não expõe alertas**

Este é o achado técnico mais consequente desta seção.

**[V]** Baixei a especificação OpenAPI da *tag* fixa v4.14.7:
`https://raw.githubusercontent.com/wazuh/wazuh/v4.14.7/api/api/spec/spec.yaml`
(20.062 linhas, `openapi: 3.0.0`). Enumerei **todos** os *paths* declarados. **Nenhum**
contém a palavra `alert`.

Os caminhos existentes cobrem: agentes, grupos, cluster, manager, regras, decoders,
listas CDB, `syscheck`, `rootcheck`, `sca`, `syscollector`, `mitre/*`, `security/*`,
`logtest`, `tasks/status`, `active-response` e `events`.

**[V]** `/events` é **entrada**, não saída — serve para *injetar* eventos no Wazuh, não para
ler alertas.

**Consequência arquitetural:** o adaptador Wazuh do Poseidon terá de falar com **dois
sistemas distintos, com dois modelos de autenticação distintos**:

| Necessidade | Sistema | Porta | Autenticação |
|---|---|---|---|
| Agentes, regras, resposta ativa, inventário | Wazuh Manager API | 55000 | JWT via `POST /security/user/authenticate` |
| **Alertas** | Wazuh Indexer (OpenSearch) | 9200 | credencial do indexer |

Isso muda ADR-001 e toca ADR-008. E cria um risco de Lei 4 deslocado: ler
`wazuh-alerts-*` significa acoplar o Poseidon ao **schema de índice do Wazuh** — o molde
do Wazuh volta pela camada de consulta, mesmo que o modelo de evento fique limpo.

### 1.4 API do Manager — fatos verificados

**[V]** Da própria spec v4.14.7 (`info.description`) e da doc 4.14.1:

- Base: `https://<HOST>:55000/`
- Autenticação: `POST /security/user/authenticate` com **HTTP Basic**; resposta
  `{"data": {"token": "..."}, "error": 0}`; `?raw=true` devolve o token puro.
- Header subsequente: `Authorization: Bearer <token>`
- **Duração padrão do JWT: 900 segundos.** Alterável via `PUT /security/config`
  (`auth_token_exp_timeout`).
- **Qualquer alteração na configuração de segurança revoga todos os tokens emitidos.**
- Credencial padrão documentada: `wazuh:wazuh`.
- Respostas de erro padronizadas incluem `401`, `403`, `405`, `406`, `413`, `429`.

Fonte: https://documentation.wazuh.com/current/user-manual/api/getting-started.html (doc
declara cobrir 4.14.1) e a spec da tag v4.14.7.

**Implicação operacional:** token de 15 min + revogação global em qualquer mudança de
config significa que o conector Wazuh precisa de *refresh* resiliente e de tratamento
explícito de 401 no meio de uma operação — não é detalhe, é caminho de falha parcial
(dimensão 4.4 da auditoria).

**[NV]** Rate limit exato do Manager API: a spec declara resposta `429` e o Wazuh tem
configuração de *throttling*, mas não confirmei os valores padrão na documentação oficial.

---

## 2. Wazuh Active Response — análise de superfície (relevante à Lei 8)

Investiguei isto porque a constituição (§7, nota sobre Defender) planeja **"Wazuh Active
Response como segundo caminho de resposta"**, e a Lei 8 proíbe execução arbitrária no
agente. Precisava saber se o segundo caminho respeita a lei do primeiro.

### 2.1 O contrato da API

**[V]** Spec v4.14.7, `PUT /active-response`, corpo `ActiveResponseBody`:

```yaml
ActiveResponseBody:
  type: object
  properties:
    arguments:
      description: "Command arguments"
      type: array
      items:
        type: string          # <-- sem 'format', sem validador
    command:
      description: "Command running in the agent. If this value starts with `!`,
        then it refers to a script name instead of a command name"
      type: string
      format: active_response_command
    alert:
      type: object
  required:
    - command
```

**[V]** Parâmetro `agents_list` tem **default `'*'`**, e o controlador define
`broadcasting=(agents_list == '*')` — uma chamada sem lista atinge **toda a frota**.
Fonte: `api/api/controllers/active_response_controller.py`, tag v4.14.7.

### 2.2 O que é e o que não é validado

**[V]** `api/api/validator.py`, tag v4.14.7:

```python
_paths = re.compile(r'^[\w\-.\\/:]+$')
_active_response_command = re.compile(f"^!?{_paths.pattern.lstrip('^')}")
```

Ou seja: `command` não aceita espaço nem metacaractere de shell. **Isto é uma defesa real** e
seria injusto ignorá-la.

**[V]** Porém, `framework/wazuh/core/active_response.py`, tag v4.14.7:

```python
def validate_command(self, command: str):
    if not command:
        raise WazuhError(1650)
    if not command.startswith('!'):
        commands = get_commands()
        if command not in commands:
            raise WazuhError(1652)
```

→ **Se `command` começa com `!`, a verificação contra a lista de comandos configurados é
inteiramente pulada.** O `!` é o seletor de "nome de script", e scripts residem em
`active-response/bin/` no endpoint.

**[V]** E o tratamento dos argumentos difere por versão de agente:

```python
class ARStrMessage(...):      # agentes legados
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) ...

class ARJsonMessage(...):     # agentes modernos
    msg_queue = json.dumps(create_wazuh_socket_message(
        ..., command=command,
        parameters={'extra_args': arguments if arguments else [], 'alert': ...}))
```

→ No caminho **moderno** (`ARJsonMessage`), os argumentos entram **verbatim** em
`parameters.extra_args`. `shell_escape()` **só é aplicado no caminho legado**.

### 2.3 Conclusão da seção

O Wazuh Active Response é um **despachante de scripts nomeados com vetor de argumentos não
validado**, com *bypass* da lista de permissões via prefixo `!`, e com difusão para toda a
frota por omissão de parâmetro.

Não é um shell remoto. Mas é **exatamente** o padrão que a seção 7.1 do `02-AUDITOR.md`
manda procurar ativamente: *"passagem de argumentos não validados para uma capacidade
legítima"*.

**[V]** Some-se `PUT /agents/upgrade_custom`, que instala **um arquivo WPK local arbitrário**
na lista de agentes indicada.

**Portanto:** quem detém a credencial da API do Wazuh detém, na prática, execução de código
na frota Wazuh. O Poseidon vai deter essa credencial. Isso precisa estar em ADR-001 e
ADR-006, e a Lei 8 precisa dizer se vale para o agente que o Poseidon **escreve**, para o
agente que o Poseidon **comanda**, ou para ambos. Hoje ela só cobre o primeiro.

---

## 3. OCSF vs. ECS — insumo para ADR-002

### 3.1 Estado factual dos dois padrões (não da narrativa sobre eles)

| | OCSF | ECS |
|---|---|---|
| Versão corrente **[V]** | **1.9.0** (2026-08-03) | **9.5.0** (2026-08-04) |
| Licença **[V]** | Apache-2.0 | Apache-2.0 |
| Repositório ativo **[V]** | sim (push em 2026-09-18) | sim (push em 2026-09-18) |
| Cadência **[V]** | ~trimestral: 1.4 (2025-02) → 1.9 (2026-08) | — |

Fontes: `https://schema.ocsf.io/api/version` devolveu `{"version":"1.9.0"}`;
API do GitHub em `ocsf/ocsf-schema` e `elastic/ecs`.

### 3.2 Sobre o argumento "ECS foi doado ao OpenTelemetry, logo está morto"

**Esse argumento não se sustenta na fonte oficial e não deve ser usado para decidir ADR-002.**

**[V]** A página oficial da Elastic sobre ECS e OpenTelemetry
(https://www.elastic.co/docs/reference/ecs/ecs-opentelemetry) descreve a doação de abril de
2023 como *"a directional decision for the evolution of both standards rather than a single
event that merged both schemas into a single standard"*. **Não há anúncio de sunset nessa
página.**

**[V]** ECS lançou **v9.5.0 em 2026-08-04**, um dia depois do OCSF 1.9.0. Não é um projeto
parado.

**[D]** Material da Elastic descreve um "sunset period" durante o qual a evolução do ECS
passa a se dar sobre o schema comum. Isso é direção declarada, não depreciação executada.

Se o ADR-002 escolher OCSF, que escolha por mérito técnico — não por um obituário do ECS que
a documentação oficial não escreveu.

### 3.3 Cobertura de eventos de endpoint — OCSF 1.9.0 (verificado na API do schema)

**[V]** Categorias e classes obtidas de `https://schema.ocsf.io/api/classes` e
`/api/categories`:

- **1 System Activity**: `file_activity` (1001), `kernel_extension_activity` (1002),
  `kernel_activity` (1003), `memory_activity` (1004), `module_activity` (1005),
  `scheduled_job_activity` (1006), **`process_activity` (1007)**, `event_log_actvity` (1008),
  `script_activity` (1009), `peripheral_activity` (1010), `device_power_state_activity`
  (1011), `clipboard_activity` (1012)
- **4 Network Activity**: `network_activity` (4001), `http_activity` (4002),
  **`dns_activity` (4003)**, `dhcp_activity`, `rdp_activity`, `smb_activity`, `ssh_activity`,
  `ftp_activity`, `email_*`, `ntp_activity`, `tunnel_activity`
- **3 IAM**: **`authentication` (3002)**, `authorize_session` (3003), `account_change` (3001), …
- **2 Findings**: `security_finding` (2001), **`detection_finding` (2004)**,
  `incident_finding` (2005), `vulnerability_finding`, `compliance_finding`, …
- **5 Discovery**: inventário e *queries* — `inventory_info` (5001), `process_query` (5015),
  `network_connection_query` (5012), `software_info` (5020), `evidence_info` (5040), …
- **7 Remediation**: `remediation_activity` (7001), `file_remediation_activity` (7002),
  `process_remediation_activity` (7003), `network_remediation_activity` (7004)

**[V] Extensões disponíveis (3, todas em 1.9.0):** `linux` (uid 1), **`win` (uid 2)**,
`macos` (uid 3).

**[V] Ponto que muda o desenho:** eventos de **registro do Windows** — Sysmon 12/13/14 —
não têm classe no núcleo. Estão na **extensão `win`**: `win/registry_key_activity`,
`win/registry_value_activity`, `win/windows_service_activity`,
`win/windows_resource_activity`, e em Discovery `win/registry_key_query`,
`win/registry_value_query`, `win/prefetch_query`.

Adotar OCSF para telemetria Windows **obriga a adotar a extensão `win`**. Isso não é
problema, mas é uma decisão que o ADR-002 precisa tomar explicitamente, porque muda o
pipeline de validação e o versionamento.

**[V] Armadilha de implementação:** a classe 1008 está **grafada errada no próprio schema**
— `event_log_actvity` (falta o "i"). Qualquer geração de código a partir do OCSF vai
carregar esse erro de digitação, e corrigi-lo silenciosamente quebra compatibilidade.

**[V] Presença de perfis relevantes:** `host`, `datetime`, `security_control`, `incident`,
`osint`, `record_integrity`, `data_classification`, `container`, `cloud`.

**[NV]** A API do schema devolve `cloud` e `osint` como `required` em `base_event`. Isso é
muito provavelmente artefato da renderização com perfis aplicados, e não uma exigência real
de todo evento. **Não confirmei.** Não trate como premissa; confirme antes de gerar modelos.

### 3.4 Ferramental — o ponto fraco do OCSF

**[V]** API do GitHub, consultada em 2026-09-20:

| Projeto | Licença | Último push | Estrelas |
|---|---|---|---|
| `ocsf/ocsf-validator` | Apache-2.0 | 2026-07-29 | 12 |
| `ocsf/ocsf-lib-py` | Apache-2.0 | **2025-07-07** | 16 |
| `valllabh/ocsf-tool` (Go) | Apache-2.0 | 2025-03-17 | 12 |

Para um projeto cuja stack é Python/Pydantic v2, isto significa: **modelos OCSF serão
escritos e mantidos à mão pelo Poseidon**, ou gerados por ferramenta própria. Com cadência
de release trimestral do OCSF, isso é custo recorrente, não custo único.

Esse custo é o principal argumento honesto **contra** OCSF. Ele deve aparecer na seção
"Consequências" do ADR-002. Se não aparecer, o ADR está vendendo a decisão, não a
documentando.

### 3.5 Lei 5 mapeada contra OCSF 1.9.0 — **verificado campo a campo**

A Lei 5 obriga seis campos. Todos já existem no OCSF, com **outros nomes**:

| Campo exigido pela Lei 5 | Equivalente OCSF 1.9.0 **[V]** |
|---|---|
| `event_time` | `time` / `start_time` (base_event) + `metadata.original_time` *(string pass-through da fonte)* |
| `ingestion_time` | `metadata.logged_time` (e `metadata.processed_time` para etapas intermediárias) |
| `source` | `metadata.product` *(required)*, `metadata.source`, `metadata.log_provider`, `metadata.log_source` |
| `source_event_id` | `metadata.original_event_uid` (+ `metadata.event_code` para o Event ID do Windows) |
| `raw_reference` | `raw_data`, `raw_data_hash`, `raw_data_size` (base_event) |
| `correlation_id` | `metadata.correlation_uid` |

Fontes: `https://schema.ocsf.io/api/classes/base_event` e
`https://schema.ocsf.io/api/objects/metadata`.

**[V]** `metadata` é `required` em `base_event`. **[V]** OCSF ainda oferece
`metadata.loggers` — *"An ordered array of Logger objects describing each hop in the event
pipeline"* — que é mais forte que o que a Lei 5 pede, e resolve cadeia de custódia de
ingestão de graça.

**Conclusão da seção:** a Lei 5 está conceitualmente correta e lexicalmente redundante.
Ver `[BLOCKER-01]` no relatório de auditoria.

---

## 4. STIX 2.1 — insumo para ADR-003

**[V]** Status formal: **OASIS Standard, aprovado em 10 de junho de 2021**.
Fonte: https://www.oasis-open.org/standard/stix-version-2-1/

**[V]** Existe um **Errata 01** em estágio **Committee Specification Draft 01**, publicado em
**02 de abril de 2025**. Fonte: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
→ *Errata é rascunho de comitê, não padrão aprovado.* Citar "STIX 2.1" no ADR-003 deve
significar o OS de 2021; se alguma correção do Errata for necessária, cite o Errata
nominalmente e registre que é CSD.

**[V] 18 SDOs:** Attack Pattern, Campaign, Course of Action, Grouping, Identity, Indicator,
Infrastructure, Intrusion Set, Location, Malware, Malware Analysis, Note, Observed Data,
Opinion, Report, Threat Actor, Tool, Vulnerability.

**[V] 18 SCOs**, incluindo File, IPv4/IPv6 Address, Domain Name, URL, Process,
**Windows Registry Key**, User Account, Network Traffic, X.509 Certificate, Artifact, Mutex.

**[V] Correção relevante:** **`sighting` NÃO é um SDO — é um SRO** (STIX Relationship
Object), um dos dois definidos, usado para *"capture cases where an entity has 'seen' an
SDO"*. O outro é `relationship`.

Isso importa porque o modelo de "observação" da **Lei 7** é, quase literalmente, um
`sighting`:

| Lei 7 | STIX 2.1 |
|---|---|
| `fonte` | `created_by_ref` / `where_sighted_refs` |
| `confiança` | `confidence` *(propriedade comum, 0–100)* |
| `first_seen` / `last_seen` | `first_seen` / `last_seen` *(do sighting)* |
| `contagem` | `count` |
| ligação ao IOC | `sighting_of_ref` |
| evidência observada | `observed_data_refs` → `observed-data` → SCO |

A Lei 7 está bem desenhada. O ADR-003 só precisa dizer que adota `sighting` como SRO e não
inventar um "IOCObservation" paralelo.

**[V]** SDK oficial: `oasis-open/cti-python-stix2`, **BSD-3-Clause**, último push
2026-02-12, 439 estrelas. Licença compatível; manutenção morna.

---

## 5. Sigma — insumo para ADR-004

**[V] Especificação:** release corrente **v2.1.0 (2025-09-12)**, repositório
`SigmaHQ/sigma-specification`.

**[V] Licenciamento — e aqui há uma armadilha que a constituição não cobre.** O `LICENSE` de
`SigmaHQ/sigma` diz:

> *"The Sigma specification (…) and the Sigma logo are public domain"*
> *"The rules contained in the SigmaHQ repository (…) are released under the
> [Detection Rule License (DRL) 1.1]"*

→ Especificação: domínio público, sem restrição.
→ **Regras: DRL 1.1**, que é permissiva **mas com uma condição incomum**:

> *"If you **use** the Rules (including in modified form) **on data**, **messages based on
> matches with the Rules must retain** … identification of the author(s) ('author' field) of
> the Rule and any others designated to receive attribution…"*

Fonte: https://raw.githubusercontent.com/SigmaHQ/Detection-Rule-License/main/LICENSE.Detection.Rules.md

**Isto é um requisito de licença que vira requisito de schema:** todo alerta do Poseidon
gerado por uma regra do SigmaHQ precisa **carregar o autor da regra no próprio alerta** —
não basta atribuir no repositório. Não vi isso contemplado em nenhuma lei da constituição.

**[V] Releases de regras** são *tags* datadas; a mais recente é `r2026-07-01`.

**[V] Ferramental (API do GitHub, 2026-09-20):**

| Projeto | Licença | Último push |
|---|---|---|
| `SigmaHQ/pySigma` | **LGPL-2.1** | 2026-09-20 |
| `SigmaHQ/sigma-cli` | **LGPL-2.1** | 2026-09-20 |
| `SigmaHQ/pySigma-backend-opensearch` | **LGPL-3.0** | 2026-09-07 |
| `SigmaHQ/pySigma-backend-elasticsearch` | **LGPL-3.0** | 2026-09-19 |
| `SigmaHQ/pySigma-pipeline-sysmon` | **LGPL-2.1** | 2025-11-30 |
| `SigmaHQ/pySigma-pipeline-windows` | **LGPL-2.1** | 2025-11-30 |

Ecossistema **vivo** e com **backend OpenSearch mantido** — Sigma como formato canônico é
viável no stack escolhido. Duas ressalvas:

1. **LGPL no backend.** Importar pySigma em um produto Python é uso, não linkagem estática;
   a obrigação prática é não modificar-e-fechar. Mas *é uma decisão de licença* e pertence ao
   ADR-004, não ao silêncio.
2. **[V]** O Wazuh **não consome Sigma nativamente** — usa regras XML próprias e decoders.
   Nenhum endpoint da API 4.14.7 aceita Sigma. Portanto "Sigma como formato canônico"
   significa que o Poseidon **compila Sigma para o OpenSearch por conta própria**, e as
   regras do Wazuh permanecem uma **segunda** população de detecções, em outro formato, com
   outro ciclo de vida. O ADR-004 precisa dizer como as duas convivem — ou o Poseidon terá
   dois motores de detecção sem dono declarado.

---

## 6. Sysmon — insumo para ADR-005 e para a Fase 5

**[V]** Documentação oficial consultada:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (página publicada em
**2026-09-10**).

**[V] Canal de log, citado literalmente:**
`Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`
(em sistemas antigos, o log `System`). **"Event timestamps are in UTC standard time."**

**[V] Plataformas suportadas, literal:** *"Client: Windows 11 and higher. Server: Windows
Server 2019 and higher."* — define o piso do laboratório.

**[V] Natureza:** *"a Windows system service and device driver"*, instalado como
*boot-start driver*; *"The service runs as a protected process"*. Instalação exige
privilégio administrativo; **não exige reboot**.

**[V] Eventos pedidos pela constituição:**

| ID | Evento | Nota verificada |
|---|---|---|
| 1 | Process creation | *"Logs process creation with full command line for both current and parent processes."* Inclui `ProcessGUID` e hashes. |
| 3 | Network connection | **desabilitado por padrão** |
| 11 | FileCreate | criação/sobrescrita de arquivo |
| 12 | RegistryEvent (create/delete) | usa nomes de raiz abreviados: `HKLM`, `HKU`, `HKCR` |
| 13 | RegistryEvent (value set) | grava o valor para `DWORD`/`QWORD` |
| 22 | DNSEvent (DNS query) | *"telemetry … added for Windows 8.1 so it is not available on Windows 7 and earlier"* |

Outros padrões desligados que importam: **7 (ImageLoad)** e **10 (ProcessAccess)** —
a doc alerta que ambos geram volume alto e exigem filtro. A config base do Poseidon precisa
tratar volume como requisito, não como ajuste posterior.

**[V] Hashes:** `HashAlgorithms` suporta `MD5, SHA1, SHA256, IMPHASH, *`. *(A doc é
internamente inconsistente: o texto diz que SHA1 é o padrão, a tabela de configuração diz
`Default: None`. Adote explicitamente no XML; não confie no padrão.)*

### 6.1 Sysmon **não pode ser redistribuído pelo Poseidon** — verificado

**[V]** Sysinternals Software License Terms, texto integral em
https://live.sysinternals.com/Eula.txt. Cláusulas literais em "Scope of License" — *"you may
not"*:

> *"publish the software for others to copy;"*
> *"rent, lease or lend the software;"*
> *"transfer the software or this agreement to any third party; or"*
> *"**use the software for commercial software hosting services.**"*

**Consequências diretas, nenhuma delas registrada na constituição:**

1. O instalador do Poseidon **não pode empacotar** `Sysmon64.exe`. O operador instala o
   Sysmon por conta própria; o Poseidon entrega, no máximo, um `sysmonconfig.xml`
   recomendado (configuração é obra do Poseidon, não da Microsoft).
2. A cláusula *"commercial software hosting services"* **inviabiliza qualquer oferta SaaS do
   Poseidon que dependa de Sysmon nos endpoints monitorados.** Se SaaS estiver no horizonte
   do produto, a dependência de Sysmon é estratégica, não técnica.
3. **[V]** A EULA contém cláusula "Sensitive Information" avisando que ferramentas
   Sysinternals capturam *"usernames, passwords, paths to files accessed"*. É a Lei 11
   antecipada pelo fornecedor — e confirma que o problema existe na origem, antes de
   qualquer redação feita pelo Poseidon.

**Alternativa estratégica [NV]:** um agente em Go pode consumir **ETW diretamente**
(`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-DNS-Client` etc.) sem Sysmon e sem
essa EULA. **Não verifiquei** cobertura, exigência de PPL/assinatura anti-malware para os
provedores sensíveis, nem esforço. Registro como alternativa que o ADR-005 deve ao menos
nomear e recusar conscientemente — não como recomendação.

---

## 7. Windows Event Log e Defender Antivírus local

**[D]** Canal do Defender Antivírus:
`Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational`.

**[D]** Eventos centrais:
- **1116** — detecção de malware/PUA (nome da ameaça, categoria, severidade, caminho, ação
  inicial). É evento de **detecção**.
- **1117** — **ação de remediação executada** (quarentena/remoção). É o registro definitivo
  de remediação.

**[D] Regra de correlação que vale a pena implementar desde a Fase 5:** um **1116 sem 1117
correspondente** é uma ameaça que o Defender viu e **não tratou** — resultado canônico de
abuso de exclusão e de *tampering*. Isso é um detector barato e de alto valor.

**[NV]** Não confirmei esses IDs na documentação oficial da Microsoft nesta sessão — as
fontes que consegui consultar foram secundárias. **Antes de virar código, exigir confirmação
em `learn.microsoft.com`.** Marcado `NÃO VERIFICADO` deliberadamente.

**[NV]** Acesso a canais do Windows Event Log a partir de Go (via `EvtQuery`/`EvtSubscribe`
da Windows Event Log API, ou biblioteca de terceiros): não verifiquei bibliotecas
candidatas, licenças, nem se subscrição *push* é viável sem CGO. É insumo obrigatório para o
ADR-005 e está em aberto.

---

## 8. MITRE ATT&CK — insumo para mapeamento de técnicas

**[V]** Fonte canônica de dados: `mitre-attack/attack-stix-data` (formato **STIX 2.1**,
coleções **Enterprise**, **Mobile**, **ICS**).

**[V]** Versão corrente: **v19.2, publicada em 2026-08-05** (v19.0 em 2026-04-28, v18.0 em
2025-10-28) — cadência aproximada de duas versões maiores por ano.

**[V]** Licença, texto literal do `LICENSE.txt`:

> *"The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to
> use ATT&CK® for research, development, and commercial purposes. Any copy you make for such
> purposes is authorized provided that you reproduce MITRE's copyright designation and this
> license in any such copy."*

→ Uso comercial permitido, **com reprodução obrigatória do aviso de copyright**. Mais uma
obrigação de atribuição que precisa existir no produto, ao lado da DRL 1.1 do Sigma.

**[V]** A API do Wazuh Manager já expõe `/mitre/techniques`, `/mitre/tactics`,
`/mitre/groups`, `/mitre/software`, `/mitre/mitigations`, `/mitre/references`. **Não use como
fonte** — é a cópia do Wazuh, na versão do Wazuh. Consumir ATT&CK do Wazuh é acoplar a
taxonomia do Poseidon ao ciclo de release de um fornecedor, exatamente o que a Lei 4 combate.
A fonte deve ser o `attack-stix-data`, versionado pelo próprio Poseidon.

---

## 9. OTX — insumo para a Fase 6

**[V]** Header de autenticação e endpoints, lidos do SDK oficial
(`AlienVault-OTX/OTX-Python-SDK`, `OTXv2.py`):

```python
API_V1_ROOT = "/api/v1"
SUBSCRIBED  = "{}/pulses/subscribed".format(API_V1_ROOT)
EVENTS      = "{}/pulses/events".format(API_V1_ROOT)
...
'X-OTX-API-KEY': self.key
...
status_forcelist=[429, 500, 502, 503, 504]
```

→ Base `https://otx.alienvault.com`, header **`X-OTX-API-KEY`**, paginação por `page=`,
endpoint incremental `/api/v1/pulses/events?since=<timestamp>` (preferível a varrer
`subscribed` inteiro).

**[V] Riscos de dependência:** último push do SDK em **2024-05-09** — parado há ~2 anos e 4
meses. O produto migrou de marca AlienVault para **LevelBlue**, e a página
`https://otx.alienvault.com/api` é renderizada por JavaScript, o que impede verificação
automatizada da documentação.

**[NV] Limites de taxa:** o SDK trata `429`, logo o limite existe. **O valor não foi
verificado em documentação oficial.** Não codificar nenhum número.

**[NV] Termos de uso / redistribuição do conteúdo dos pulses:** não verificados. Isto é
**Condição de Parada §9.2** — armazenar e reexibir IOCs de terceiros é questão de
licenciamento, e a Fase 6 não deve começar sem resposta.

---

## 10. Isolamento de endpoint — pesquisa própria (Lei 10)

Não constava da lista da Fase 0, mas a Lei 10 é a mais perigosa da constituição e ADR-006 vai
depender disto.

**[V]** Documentação oficial do Windows Filtering Platform,
https://learn.microsoft.com/en-us/windows/win32/fwp/object-management:

> *"When creating a new session, the caller can create a dynamic session by passing the
> **FWPM_SESSION_FLAG_DYNAMIC** flag to FwpmEngineOpen0. **Any objects added during a dynamic
> session are automatically deleted when the session ends.**"*

> *"The session ends either when the client calls FwpmEngineClose0 **or the client process
> terminates**."*

E, em "Object Lifetimes":

> *"**Dynamic** — An object is dynamic only if it is added using a dynamic session handle.
> Dynamic objects live until they are deleted or the owning session terminates."*
> *"**Static** — Objects are static by default. Static objects live until they are deleted,
> BFE stops, or the system is shutdown."*
> *"**Persistent** — … Persistent objects live until they are deleted."*

**Por que isso é o achado mais útil desta pesquisa:**

Um filtro WFP criado em **sessão dinâmica** é um *dead-man's-switch implementado pelo
sistema operacional*. Se o Collector Agent travar, for morto, for desinstalado ou o serviço
parar, **o isolamento cai sozinho**, sem depender de timer, de relógio ou de contato com o
servidor. É estruturalmente superior ao timer em processo que a Lei 10 descreve, porque não
depende do próprio componente que falhou.

O contraste importa: regras criadas via `netsh advfirewall` são **persistentes**. Elas
sobrevivem à morte do agente e ao reboot. É precisamente o cenário que a Lei 10 teme —
*"um erro transforma a máquina em algo que só se recupera fisicamente."*

**Contrapartida honesta:** filtro dinâmico **não sobrevive a reboot nem a restart do
agente**. Se um analista isolou uma máquina comprometida e o atacante reinicia o host, o
isolamento cai. **A constituição não diz o que deve acontecer com o isolamento através de um
reboot.** As duas respostas são defensáveis e a escolha é irreversível no protocolo. Ver
`[MAJOR-08]` e `[OBSERVATION-03]` no relatório.

**[NV]** Não verifiquei: exigência de privilégio para `FwpmEngineOpen0`; interação com
perfis do Windows Defender Firewall; como garantir exceção para o canal do Poseidon quando o
servidor está atrás de DNS dinâmico (armadilha 7.3 do `02-AUDITOR.md`); comportamento em
Windows 11 com "Filtro de rede" de terceiros instalado. **Tudo isso é pré-requisito da Fase
8 e deve ser exercitado em VM descartável.**

---

## 11. Verificações de stack

**[V]** Consultas à API do GitHub e ao PyPI em 2026-09-20:

| Componente | Situação | Leitura |
|---|---|---|
| `etcd-io/bbolt` | MIT, push 2026-09-15, 9.746 ★ | Saudável. Escolha adequada para buffer do agente. |
| `arq` (`python-arq/arq`) | MIT, **0.28.0** (2026-04-16), 3.014 ★ | Vivo, mas **ainda 0.x** e com cadência baixa. A constituição o fixa no stack sem ADR. Ver `[MINOR-06]`. |
| `oasis-open/cti-python-stix2` | BSD-3, push 2026-02-12 | Adequado. |
| `SigmaHQ/pySigma` + backend OpenSearch | LGPL, push 2026-09 | Adequado, com ressalva de licença. |
| `ocsf/ocsf-lib-py` | Apache-2.0, push **2025-07-07** | Frágil. Ver §3.4. |
| `AlienVault-OTX/OTX-Python-SDK` | push **2024-05-09** | Parado. Ver §9. |

---

## 12. Perguntas abertas para o humano

Nenhuma destas é minha para decidir.

1. **§9.2 — Licenciamento.** Empacotar imagens do Wazuh no `docker compose` do Poseidon
   conta como redistribuição sob a cláusula de *derived works* do Wazuh? (§1.2)
2. **§9.2 — Licenciamento.** Os termos de uso do OTX permitem armazenar e reexibir IOCs de
   terceiros dentro do Poseidon? A Fase 6 depende da resposta. (§9)
3. **Estratégico.** O Poseidon tem ambição de SaaS? Se sim, a dependência de Sysmon esbarra
   na cláusula *"commercial software hosting services"* e a decisão da Fase 5 muda. (§6.1)
4. **§9.3 — Irreversível.** Isolamento deve sobreviver a um reboot do endpoint? A resposta
   escolhe entre filtro WFP dinâmico (falha-aberto, seguro para o usuário) e regra
   persistente (falha-fechado, seguro para a contenção). (§10)
5. **§9.3 — Irreversível.** A Lei 8 vale também para o caminho Wazuh Active Response, que o
   Poseidon vai comandar? Se sim, o Poseidon precisa restringir o que envia — inclusive
   proibir `command` com prefixo `!` e recusar `agents_list` vazio. (§2)
6. **ADR-002.** Adotar a extensão `win` do OCSF é aceitável, dado que eventos de registro do
   Windows não existem no núcleo? (§3.3)

---

## 13. O que eu não verifiquei

Explicitamente, para que o buraco da auditoria seja visível:

- Rate limits reais de Wazuh Manager API, OTX, VirusTotal e AbuseIPDB.
- IDs de evento do Defender Antivírus em fonte primária da Microsoft (§7).
- Formato do alerta do Wazuh (`wazuh-alerts-*`) campo a campo — só confirmei **onde** ele
  **não** está (a API do Manager).
- TAXII 2.1: não pesquisado nesta rodada.
- VirusTotal API v3, AbuseIPDB v2, MISP: não pesquisados nesta rodada.
- Bibliotecas Go para Windows Event Log e para WFP; viabilidade sem CGO.
- Se `cloud`/`osint` são de fato obrigatórios em `base_event` do OCSF 1.9.0 (§3.3).
- Qualquer questão jurídica. Só relatei texto de licença; não sou a fonte de interpretação.
