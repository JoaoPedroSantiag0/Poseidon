# POSEIDON — Constituição do Projeto

> **Documento de leitura obrigatória.** Nenhum agente (humano ou IA) executa trabalho
> neste repositório sem ter lido este arquivo por inteiro na sessão atual.
> Este documento tem precedência sobre qualquer instrução de papel
> (`01-BUILDER.md`, `02-AUDITOR.md`) e sobre qualquer preferência do modelo.
>
> Versão: **2.1** · Status: vigente · Emendada em 2026-09-20
>
> **Emenda 2.1** — resposta aos três BLOCKER da segunda rodada de auditoria
> (`03-AUDIT-REPORT-v2.md`), dois deles **criados pela emenda 2.0**. Mudaram: Lei 4 (dois
> corpora obrigatórios, não um), Lei 10 (a expiração é o objeto assinado da Lei 9; base de
> tempo monotônica; watchdog cobre falha, não remoção; recuperação fora de banda é local e
> canal remoto é proibido) e §4 (ETW deixa de ser afirmação e passa a declarar a origem de
> cada campo, com o custo da troca registrado).
>
> **Emenda 2.0** — motivada pela auditoria da Fase 0 (`docs/gates/FASE-00/03-AUDIT-REPORT.md`,
> 4 BLOCKER) e por duas decisões do humano: o Poseidon tem ambição de **SaaS**, e o
> isolamento é **falha-fechado**. Mudaram: Lei 4 (decidir ≠ congelar), Lei 5 (requisitos
> semânticos, não nomes de campo), Lei 8 (alcance estendido a caminhos de terceiros),
> Lei 10 (reescrita), Lei 13 (nova), §4 (ETW no lugar de Sysmon), §7 (roadmap) e §11
> (multi-tenancy não construída, mas não impedida).

---

## 1. O que é o Poseidon

O Poseidon é uma **plataforma modular de Security Operations Center** que utiliza motores
externos de detecção (Wazuh, telemetria de endpoint própria, EDRs de terceiros) como
*fontes*, e constrói sobre eles uma camada própria de correlação, inteligência de ameaças,
investigação e resposta auditada.

**O Poseidon não é um frontend alternativo para o Wazuh.** O Wazuh é um dos motores do
Poseidon. Qualquer decisão de implementação que torne o Poseidon inseparável do Wazuh
viola esta constituição.

### Princípio operacional

```
O Wazuh detecta.
O CTI contextualiza.
O Poseidon Core correlaciona.
O Investigation Workspace explica.
O Analista decide.
O Response Control Plane executa, sob autorização e registro.
```

### Ciclo do produto

```
DETECT → UNDERSTAND → INVESTIGATE → DECIDE → RESPOND → LEARN
```

Toda funcionalidade proposta deve ser justificável dentro de uma dessas seis etapas.
Funcionalidade que não cabe em nenhuma é escopo indevido e deve ser recusada.

---

## 2. As Leis Não-Negociáveis

Estas leis não podem ser flexibilizadas por conveniência, prazo ou elegância de código.
Violá-las é motivo automático de **BLOCKER** em auditoria.

### Lei 1 — Nenhuma afirmação sobre API externa sem citação verificada

Qualquer afirmação sobre o comportamento de Wazuh, OTX, VirusTotal, AbuseIPDB, MISP,
Microsoft Defender, Sysmon, Windows Event Log, STIX, OCSF ou Sigma deve vir acompanhada
de link para documentação oficial e data de consulta. Não existe "eu acho que a API faz
X". Se não foi possível verificar, o texto deve dizer `NÃO VERIFICADO` e o item vira
pendência aberta, nunca premissa de código.

### Lei 2 — Não inventamos schema

Adotamos padrões existentes:

| Domínio | Padrão adotado |
|---|---|
| Evento normalizado | **OCSF** (preferência) ou **ECS** — decisão em ADR-002 |
| Objetos de Threat Intelligence | **STIX 2.1** |
| Regras de detecção | **Sigma** |
| Técnicas adversárias | **MITRE ATT&CK** (IDs oficiais, nunca texto livre) |
| Transporte de CTI | **TAXII 2.1** quando aplicável |

Extensões próprias são permitidas, desde que documentadas como extensão do padrão e
isoladas em namespace `poseidon.*`. Substituir o padrão por um modelo caseiro exige ADR
com justificativa técnica e aprovação humana explícita.

### Lei 3 — Não forkamos o `wazuh-dashboard`

O dashboard do Wazuh é um plugin do OpenSearch Dashboards. Manter um fork visual dele
quebra a cada upgrade do upstream. A interface do Poseidon é uma aplicação independente
que consome a **API do Wazuh Manager** e, quando necessário, o **OpenSearch/Wazuh Indexer**.
Nenhum arquivo do `wazuh-dashboard` entra neste repositório.

### Lei 4 — Nenhum modelo de evento nasce de uma fonte só

Um normalizador validado contra uma única fonte é, por construção, o formato daquela fonte
com outro nome. Por isso **decidir o padrão e congelar o modelo são atos separados**:

- **Decidir** (ADR-002, Fase 3): escolher OCSF ou ECS. Pode ser feito com pesquisa.
  O modelo resultante nasce marcado `PROVISÓRIO` e todas as migrações das Fases 4–8
  permanecem reversíveis por causa disso.
- **Congelar** (Fase 9): só depois de o modelo ter sido exercitado contra **no mínimo duas
  fontes heterogêneas** — telemetria de endpoint via Collector Agent, e alertas do Wazuh.
  O congelamento é artefato explícito, com ADR próprio (`Supersedes: ADR-002`).

Para antecipar as duas fontes sem antecipar as integrações, a Fase 3 exige **dois corpora
gravados, obrigatórios e heterogêneos entre si**:

1. **Alertas reais do Wazuh** — subir um container uma vez e capturar `alerts.json`.
2. **Telemetria bruta de endpoint** — ETW e Security Log capturados de uma máquina real,
   antes do Collector existir, com um script descartável.

Um corpus só não cumpre a Lei 4: modelaria contra fonte única, apenas trocando o Wazuh
pelo Sysmon como molde. São **duas naturezas diferentes de dado** — alerta já interpretado
por um motor de terceiro versus telemetria bruta de sistema operacional — e é justamente a
tensão entre elas que expõe as premissas escondidas do normalizador.

### Lei 5 — O tempo do evento nunca é o tempo de ingestão

**Esta lei enuncia requisitos semânticos, não nomes de campo.** Os nomes concretos são os
do padrão adotado no ADR-002 — inventá-los aqui violaria a Lei 2. Todo evento carrega,
obrigatoriamente e de forma **distinta entre si**, estes seis conceitos:

| Conceito | Significado |
|---|---|
| tempo do evento | quando aconteceu no endpoint/fonte |
| tempo de ingestão | quando o Poseidon recebeu |
| origem | qual fonte produziu |
| identificador na origem | id do evento no sistema de origem |
| referência ao bruto | ponteiro para o evento original preservado |
| correlação | agrupamento lógico |

Conceito sem equivalente no padrão adotado nasce sob `poseidon.*`, conforme a Lei 2.

O núcleo inegociável da lei é: **o tempo do evento nunca é o tempo de ingestão**, e **o
evento bruto original é preservado e nunca sobrescrito pela versão normalizada**. Colapsar
os dois primeiros ou descartar o terceiro destrói a capacidade forense da plataforma.

### Lei 6 — Case Timeline e Audit Log são coisas diferentes

```
CASE TIMELINE   narrativa do incidente     "Host isolado às 10:12"
AUDIT LOG       registro de quem fez o quê  "joao executou POST /agents/123/isolate às 10:12:03, IP 10.0.0.5, request_id abc"
```

São duas tabelas, dois modelos, dois controles de acesso. O Audit Log é
**append-only** e não é editável por nenhum papel, incluindo Super Admin.

### Lei 7 — IOC não é string, e inteligência carrega proveniência

Um IOC é uma entidade com tipo, valor, ciclo de vida e relacionamentos. Nenhum veredito
de reputação existe sem origem:

```
IOC → observação → { fonte, confiança, first_seen, last_seen, contagem, tags }
```

É proibido persistir ou exibir "este IOC é malicioso" sem indicar **quem** afirmou isso,
**quando** e com **que confiança**. Fonte externa nunca vira verdade absoluta do sistema.

### Lei 8 — Nenhum caminho de execução arbitrária, próprio ou de terceiro

**Esta lei vale para todo caminho de execução que o Poseidon comanda** — o agente que
escrevemos e o agente que comandamos através da API de outro fornecedor. A proibição é da
plataforma, não de um componente.

Não existe, em nenhuma hipótese, um endpoint do tipo `POST /agent/execute {command}`.
O agente expõe um **conjunto fechado de capacidades nomeadas**, implementadas em código,
verificadas por assinatura. Tudo fora dessa lista é rejeitado pelo próprio agente.

**Para caminhos de terceiros, o Poseidon se autoimpõe as restrições que o fornecedor não
impõe.** No caso do Wazuh Active Response, verificado no código-fonte da tag v4.14.7:
comando prefixado com `!` pula a verificação contra a lista de comandos permitidos;
`agents_list` tem default `'*'` e atinge a frota inteira; argumentos entram sem escape no
caminho de agentes modernos; e `PUT /agents/upgrade_custom` instala binário WPK arbitrário.
Portanto o conector Wazuh do Poseidon:

```
❌ nunca envia command com prefixo '!'
❌ nunca omite agents_list
❌ nunca chama upgrade_custom
❌ nunca deriva arguments de entrada do usuário
✅ usa conta com RBAC restrito no próprio Wazuh
```

Registre-se como fato arquitetural: **a credencial da API do Wazuh equivale a execução de
código na frota Wazuh.** Ela recebe o mesmo nível de proteção de uma chave de assinatura.

Capacidades autorizadas do MVP:

```
NETWORK_ISOLATE           NETWORK_RESTORE
KILL_PROCESS              QUARANTINE_FILE
COLLECT_PROCESS_TREE      COLLECT_NETWORK_CONNECTIONS
COLLECT_SYSTEM_INFO       COLLECT_FILE
HEALTH_REPORT
```

Adicionar capacidade exige ADR + revisão de segurança + aprovação humana.

### Lei 9 — Toda ação de resposta é um objeto autorizado, assinado e expirável

```json
{
  "action_id": "ACT-2026-000183",
  "type": "NETWORK_ISOLATE",
  "target_agent_id": "agent-102",
  "incident_id": "INC-2026-00017",
  "reason": "Possible infostealer activity",
  "requested_by": "analyst-12",
  "approved_by": "soc-admin-03",
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "signature": "..."
}
```

O agente valida, antes de executar: assinatura, destinatário correto, expiração, nonce
não reutilizado, capacidade habilitada na política local. Falha em qualquer verificação
resulta em rejeição registrada, nunca em execução parcial.

Máquina de estados obrigatória:

```
PENDING → AUTHORIZED → DISPATCHED → ACKNOWLEDGED → EXECUTING → SUCCESS
                                                             ↘ FAILED | TIMEOUT | REJECTED | EXPIRED
```

### Lei 10 — Isolamento tem failsafe, ou não existe

Isolar um endpoint é a operação mais perigosa da plataforma: um erro transforma a máquina
em algo que só se recupera fisicamente.

**Decisão registrada (2026-09-20, humano):** o isolamento é **falha-fechado** — sobrevive
ao reboot da máquina e à morte do agente. A contenção vale mais que a conveniência de
recuperação. A consequência direta é que **o failsafe não pode morar no agente**, porque
é exatamente o agente que pode ter morrido.

Requisitos obrigatórios e simultâneos:

1. **Snapshot** do estado de firewall antes de aplicar, com restauração exata.
2. **Somente isolamento seletivo no MVP.** Exceção garantida para o canal de saída do
   Poseidon, DNS e infraestrutura de gerenciamento. **Isolamento total está fora do MVP** —
   com transporte exclusivamente outbound, um host totalmente isolado é um host que o
   Poseidon não alcança mais, e prometer contenção total sem dizer isso é mentir para o
   analista no pior momento possível.
3. **A expiração é o objeto de ação assinado da Lei 9, persistido íntegro** — nunca um
   timestamp solto derivado dele. Um host isolado é, por premissa, um host comprometido:
   se a expiração for um valor editável em disco, o atacante libera a própria máquina e o
   evento fica indistinguível de uma expiração legítima. Quem restaura **verifica a
   assinatura antes de restaurar**; falha na verificação mantém o isolamento (falha-fechado)
   e gera sinal de severidade alta — adulteração detectada significa que o host contido
   está sendo operado.
4. **A base de tempo não pode ser o relógio de parede do host isolado.** Mínimo: relógio
   monotônico desde a aplicação, imune a salto de relógio; divergência entre monotônico e
   relógio de parede é sinal (Lei 12).
5. **Watchdog independente do processo do agente**, nomeado explicitamente no ADR-006, para
   o caso de **falha** do agente (crash, travamento). O caso de **remoção deliberada** do
   agente não é cobrível localmente — quem tem privilégio para matar o agente tem
   privilégio para remover o watchdog — e pertence ao item 6. O ADR-006 declara também qual
   componente é a fonte da verdade do estado de isolamento quando agente e watchdog
   discordam.
6. **Caminho de recuperação fora de banda, obrigatoriamente local** — acesso físico ou
   console, mídia de boot, modo de segurança, procedimento documentado de remoção do
   filtro. **Canal remoto de recuperação é proibido**: ou ele é uma exceção de firewall não
   declarada que o atacante no host pode tentar usar, ou não funciona. Documentado e
   **testado**; nenhuma capacidade de isolamento vai para produção antes disso.
7. **Teste obrigatório em VM descartável** antes de qualquer execução em máquina real.
   Nenhum PR de isolamento é aprovado sem evidência desse teste.

A Lei 10 distingue **"perdeu contato porque algo quebrou"** de **"perdeu contato porque foi
isolado a mando"**. Tratar os dois como a mesma coisa é o defeito que esta redação corrige.

### Lei 11 — O Collector não coleta segredos

Permitido: eventos de autenticação, criação de processo, conexões de rede, DNS, eventos
de sistema e segurança, atividade de arquivo, inventário, métricas, detecções do
Defender Antivírus local.

**Proibido:** senhas, hashes de credenciais, chaves privadas, tokens de sessão, cookies,
conteúdo de cofres, memória de processos de autenticação. Linhas de comando são coletadas
mas passam por redação de padrões sensíveis antes do envio.

Uma plataforma de segurança que agrega credenciais é um alvo, não uma defesa.

### Lei 12 — O SOC monitora a si mesmo

Um SOC que perdeu telemetria parece tranquilo justamente porque parou de enxergar.
O Health Center não é funcionalidade de conveniência: é requisito de correção. Toda fonte,
conector, fila, worker e agente reporta saúde, e ausência de dados é tratada como sinal,
não como silêncio.

### Lei 13 — Atribuição e proteção de dados são requisitos de schema, não rodapé

O Poseidon consome obras de terceiros cujas licenças impõem obrigações **que viajam com o
dado**, não com o repositório:

- **Regras do SigmaHQ (Detection Rule License 1.1):** se as regras forem usadas sobre
  dados, *"messages based on matches with the Rules must retain identification of the
  author(s)"*. Todo alerta gerado por uma regra do SigmaHQ **carrega o autor da regra no
  próprio alerta**. Atribuir no repositório não cumpre a licença.
- **MITRE ATT&CK:** uso comercial permitido mediante **reprodução do aviso de copyright e
  da licença** em qualquer cópia. O aviso existe no produto, não só no README.
- **Feeds de CTI de terceiros:** armazenar e reexibir IOCs alheios dentro de um produto
  SaaS é questão de licenciamento, não de engenharia. Nenhum feed entra em produção sem
  que seus termos tenham sido lidos e registrados em ADR.

**Consequência arquitetural: política por fonte, não decisão global.** Todo conector de CTI
declara, como parte do seu contrato, o que lhe é permitido:

```
consulta ao vivo · cache e TTL · persistir veredito · persistir acervo ·
exibir ao cliente · exige tier comercial pago
```

O motor de CTI aplica essa política na consulta e na exibição. Isso é possível porque a
Lei 7 já obriga cada observação a carregar sua fonte — e é o que transforma a proveniência
de recurso de qualidade em mecanismo de conformidade.

**A distinção que governa tudo:** o **acervo do terceiro** (pulses, listas, descrições) é
restrito e replicável por qualquer concorrente. As **observações do Poseidon** (*"vimos o
IOC X no host Y em T"*) são inteiramente suas, sem restrição, e são o ativo que compõe com
o tempo. O armazém de observações próprias é entidade de primeira classe; o acervo de
terceiros é cache governado por política.

E, porque o Poseidon processa telemetria de endpoints de pessoas físicas em nome de
terceiros: **a LGPD se aplica, e o Poseidon é operador de dados pessoais.** Isso não é item
de conformidade para a Fase 15. É requisito de desenho — finalidade declarada, minimização,
retenção com prazo, segregação por tenant e capacidade de eliminação a pedido nascem com o
modelo de dados, não depois dele.

---

## 3. Arquitetura de Referência

```
                         POSEIDON UI
        Dashboard · Alertas · Investigação · Casos · CTI
        Assets · Agentes · Integrações · Administração
                              │
                         POSEIDON CORE
        Alert · Correlation · Case · IOC · Asset · Timeline
        Investigation · RBAC/Auth · Health
                              │
      ┌───────────────────────┼───────────────────────┐
      │                       │                       │
 INGESTION PLANE         CTI ENGINE           INTEGRATION HUB
 Collector Agent         IOC / STIX           Wazuh · OTX · VT
 Wazuh · Syslog · API    Enrichment           AbuseIPDB · MISP
 Normalizadores          Relationships        (Defender: contrato)
      │                  ATT&CK mapping
      │
 RESPONSE CONTROL PLANE
 Action Engine · Policy Engine · Authorization
 Approval Workflow · Dispatcher · Execution Tracking · Audit
      │
 DATA / EVENT LAYER
 PostgreSQL (metadados, casos, IOCs, ações, auditoria)
 OpenSearch (eventos brutos e normalizados, busca)
 Object Storage (evidências, artefatos, chain of custody)
```

### Pipeline de ingestão — obrigatório para toda fonte

```
SOURCE → ADAPTER → NORMALIZER → VALIDATOR → ENRICHER → CORRELATOR → POSEIDON EVENT
```

O Core **nunca** sabe de onde veio o evento. Se existir um `if source == "wazuh"` fora da
camada de adapter, é violação arquitetural.

### Regra de nomenclatura de contrato

```
✅ get_alert()        ❌ get_wazuh_alert()
✅ isolate_host()     ❌ defender_isolate()
```

---

## 4. Stack Padrão

Desvios exigem ADR com justificativa. Não improvisar.

**Backend** — Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2.x (async) · Alembic ·
PostgreSQL 16 · OpenSearch 2.x · Redis 7 · workers com ARQ · JWT (access+refresh) com
argon2id e TOTP · pytest + pytest-asyncio + testcontainers · ruff + mypy (strict)

**Frontend** — React 18 · TypeScript 5 · Vite · TailwindCSS · shadcn/ui ·
TanStack Query/Router/Table · Cytoscape.js (entity graph) · Vitest + Playwright

**Collector Agent** — **Go 1.22+**, binário estático único, sem runtime externo.
Serviço Windows nativo. Buffer local em bbolt/SQLite com teto de tamanho.

**Fonte de telemetria: ETW + Windows Event Log, não Sysmon.** A EULA do Sysinternals proíbe
redistribuição e veda *"use the software for commercial software hosting services"*. Como o
Poseidon tem ambição de SaaS (decisão registrada, 2026-09-20), depender de Sysmon é
inviável no produto. O Sysmon serve apenas como **referência de laboratório** para comparar
cobertura, e o instalador do Poseidon jamais o empacota.

**Esta troca tem custo, e o custo é declarado aqui, não descoberto na Fase 5.** O provedor
`Microsoft-Windows-Kernel-Process` **não entrega linha de comando de forma confiável**, nem
linha de comando do processo pai, nem hashes, nem GUID de processo imune a reúso de PID.
Portanto a §4 declara **de onde vem cada campo**, não apenas qual API é usada:

| Campo | Origem |
|---|---|
| criação de processo, rede, DNS | ETW (`Kernel-Process`, `Kernel-Network`, `DNS-Client`) via Go sem CGO |
| **linha de comando** | **Security Event ID 4688** via `wevtapi.dll` — exige a GPO *"Include command line in process creation events"* como **requisito de implantação declarado**; sua ausência é degradação de saúde reportada pelo Health Center (Lei 12), nunca silêncio |
| hashes de imagem | calculados pelo próprio Collector, com o custo de I/O e a corrida com exclusão de arquivo assumidos |
| linha de comando do pai | derivada de árvore de processos mantida em memória pelo agente — decisão e consequências no ADR-005 |

O provedor `Microsoft-Windows-Threat-Intelligence`, que traria paridade real, exige processo
**PPL com atributo Antimalware**, o que exige driver **ELAM** co-assinado pela Microsoft.
Está fora do alcance do MVP. **Paridade plena com um EDR comercial exige componente em modo
kernel assinado — esse é o custo estratégico da decisão de SaaS, e fica registrado como
dívida conhecida, não como surpresa futura.**
Transporte **HTTPS + mTLS, exclusivamente outbound**, com *polling* para ações pendentes
(não usamos conexão de entrada: o agente precisa funcionar atrás de NAT, proxy e,
principalmente, durante o próprio isolamento).

**Infra** — Docker Compose no desenvolvimento. Nada distribuído antes de medição que
justifique. Monólito modular + workers, não microsserviços.

**Justificativa de Go no agente:** um agente de segurança com capacidade de resposta
precisa ser um binário assinável, sem dependência de runtime instalado, com footprint
baixo e serviço Windows nativo. Python no endpoint é decisão errada por empacotamento,
superfície e consumo.

---

## 5. Estrutura do Repositório

```
D:\PoseidonProject
├── docs
│   ├── prompts          esta constituição e os papéis
│   ├── architecture     diagramas e documentos de arquitetura
│   ├── adr              decisões arquiteturais numeradas
│   ├── gates            relatórios de fase (Builder ↔ Auditor)
│   ├── api              contratos, OpenAPI
│   ├── data-model       OCSF/STIX/entidades
│   ├── integrations     um documento por conector
│   ├── security         threat model, hardening, secrets
│   └── runbooks         operação
├── backend
├── frontend
├── collector-agent
├── detection            regras Sigma versionadas
├── integrations         conectores
├── lab                  cenários de teste e replay
├── infrastructure       compose, configs
├── scripts
└── tests
```

---

## 6. Protocolo de Fase

Nenhuma fase avança sem passar por todas as etapas, nesta ordem:

```
RESEARCH → PLAN → IMPLEMENT → TEST → SECURITY REVIEW → DOCUMENT → GATE → próxima fase
```

Cada fase produz, em `docs/gates/FASE-XX/`:

| Arquivo | Autor | Conteúdo |
|---|---|---|
| `00-RESEARCH.md` | Builder | fontes consultadas, com links e datas; o que foi verificado e o que não foi |
| `01-PLAN.md` | Builder | escopo, critérios de aceite, arquivos a criar/alterar, riscos |
| `02-BUILD-REPORT.md` | Builder | o que foi feito, como testar, comando de demonstração, desvios do plano |
| `03-AUDIT-REPORT.md` | Auditor | achados com severidade e evidência |
| `04-REMEDIATION.md` | Builder | resposta item a item aos achados |
| `05-VERDICT.md` | Auditor | `PASS` ou `FAIL`, assinado com data |

**O Builder não emite veredito sobre o próprio trabalho. O Auditor não escreve código de
produção.** Nenhuma fase começa com a anterior em `FAIL` ou sem veredito.

### Definition of Done (obrigatório para todas as fases)

- [ ] Todos os critérios de aceite do `01-PLAN.md` atendidos
- [ ] Testes unitários e de integração com asserções reais — teste que só verifica
      "não lançou exceção" não conta
- [ ] Nenhum `TODO`/`FIXME` sem referência a item rastreado
- [ ] Nenhum erro silenciado: exceção capturada é exceção tratada e registrada
- [ ] Migrações testadas para cima **e** para baixo
- [ ] `gitleaks` limpo; nenhum segredo no repositório ou no histórico
- [ ] ADR escrito para cada decisão não-óbvia
- [ ] Documentação do módulo atualizada
- [ ] **Comando de demonstração**: uma linha documentada que prova a fase funcionando

---

## 7. Roadmap

```
Fase 0   Research + ADRs fundacionais (licenças, OCSF/ECS, STIX, Sigma, viabilidade ETW)
Fase 1   Foundation + Design System
Fase 2   Identity / RBAC / Audit Log        ← modelo de tenant presente, operação single-tenant
Fase 3   Event Model PROVISÓRIO  ← decide o padrão; exercita contra corpus gravado do Wazuh (Lei 4)
Fase 4   Ingestion Framework
Fase 5   Collector Agent v0.1   (ETW + Security Log + Defender AV local)
Fase 6   CTI Engine + OTX
Fase 7   Cases + Timeline
Fase 8   Response Control Plane + isolamento com failsafe
Fase 9   Wazuh como 2ª fonte real  ← CONGELA o Event Model (ADR próprio, Supersedes ADR-002)
Fase 10  Investigation Workspace + Entity Graph
Fase 11  Detection Engineering (Sigma) + Event Replay Lab
Fase 12  Evidence Locker + chain of custody
Fase 13  Policy Engine / SOAR semi-automático
Fase 14  Hardening + Threat Model completo
Fase 15  Production Readiness
Fase N   Microsoft Defender     ← quando existir tenant licenciado
```

### Nota sobre o Microsoft Defender

**O usuário não possui tenant Microsoft 365 com Defender for Endpoint P2 ou Business.**
A API de isolamento e o Advanced Hunting exigem app registration no Entra ID com
permissões de aplicativo e licença. Portanto:

- O Defender **não está no caminho crítico** e foi movido para o fim do roadmap.
- Na Fase 8, construímos o **contrato** `EDRConnector` (`isolate`, `restore`, `hunt`,
  `get_device`), implementado contra o formato documentado da API e testado com respostas
  gravadas/mockadas, entregue **desabilitado**.
- Telemetria de endpoint vem de **ETW + Windows Security Log + log operacional do Defender
  Antivírus local** — tudo gratuito, sem tenant e sem amarra de licença (ver §4).
- Capacidade de isolamento é **inteiramente nossa** (Windows Firewall/WFP no Collector),
  com Wazuh Active Response como segundo caminho de resposta.

Nenhum agente deve propor cronograma, arquitetura ou funcionalidade que dependa de acesso
ao Defender for Endpoint antes da Fase N.

---

## 8. Severidade de Achados

| Nível | Definição | Efeito no gate |
|---|---|---|
| **BLOCKER** | Viola lei desta constituição, introduz vulnerabilidade explorável, corrompe/perde dados, quebra o contrato de isolamento, ou baseia código em API não verificada | Reprova. Sem exceção. |
| **MAJOR** | Erro de correção, acoplamento arquitetural indevido, ausência de teste em caminho crítico, erro silenciado, migração irreversível | Reprova salvo aceite explícito do humano registrado no veredito |
| **MINOR** | Qualidade, legibilidade, duplicação, documentação incompleta | Não reprova; entra em backlog rastreado |
| **OBSERVATION** | Risco futuro, sugestão, dívida consciente | Registro apenas |

---

## 9. Condições de Parada

Ambos os papéis **param e perguntam ao humano** — não decidem sozinhos — quando:

1. O comportamento de uma API externa não pode ser verificado em documentação oficial.
2. Surge questão de licenciamento (componentes do Wazuh, termos de uso de feeds de CTI,
   redistribuição de componentes).
3. A decisão é arquiteturalmente irreversível (formato de dados persistido, protocolo do
   agente, esquema de identidade do agente).
4. Uma ação tocaria máquina real, rede real, ou serviço externo com efeito colateral.
5. O escopo da fase precisaria crescer para que o trabalho ficasse correto.
6. Builder e Auditor chegam a impasse técnico após um ciclo de remediação.

Inventar para não parar é falha grave. Parar e perguntar é comportamento correto.

**As decisões já tomadas pelo humano estão em [`docs/DECISOES-DO-HUMANO.md`]
(../DECISOES-DO-HUMANO.md), têm a mesma precedência deste documento, e devem ser lidas
junto com ele.** Nenhum ADR pode contradizê-las; ADR que dependa de uma delas deve citá-la.
Não repropor uma decisão registrada ali — se houver razão técnica para revê-la, levante
como achado e deixe a revisão para o humano.

---

## 10. Convenções

- **Idioma**: código, identificadores, comentários e documentação técnica em **inglês**.
  Conversa com o usuário e relatórios de gate em **português**.
- **Commits**: Conventional Commits com escopo de fase — `feat(fase-05/collector): add bbolt buffer`
- **Branches**: `fase-05-collector-agent`; merge só após veredito `PASS`.
- **Tags**: `v0.<fase>.0` a cada gate aprovado.
- **ADR**: numerados, imutáveis. Decisão revista não é editada — cria-se novo ADR com
  `Supersedes: ADR-0XX` e o antigo recebe `Superseded by: ADR-0YY`.
- **Segredos**: nunca no repositório. Credenciais de integração são cifradas em repouso
  com envelope encryption e chave mestra fora do banco.

---

## 11. Escopo — o que o MVP **não** é

Para proteger o projeto de morrer de ambição, está explicitamente **fora** do MVP:

**Adiado — cabe depois da Fase 13, não antes:** NDR · UEBA · IA tomando ação autônoma ·
agentes Linux/macOS · correlação avançada com machine learning · marketplace de
integrações · chat entre IAs como funcionalidade do produto.

**Vedado — não é questão de prazo:** resposta automática sem aprovação humana, e
**isolamento total** (Lei 10, item 2). Estes não voltam por antiguidade; só por emenda
explícita desta constituição, que teria de enfrentar o motivo pelo qual foram vedados.

Proposta de qualquer item da primeira lista antes da Fase 13, ou de qualquer item da
segunda em qualquer momento, deve ser recusada pelo Auditor como desvio de escopo, ainda
que tecnicamente elegante.

### Multi-tenancy: não construída, mas não impedida

O Poseidon tem ambição de SaaS (decisão registrada, 2026-09-20). Multi-tenancy **não é
construída no MVP** — a operação é single-tenant — mas o modelo de dados **não pode
inviabilizá-la**. Concretamente: entidades que pertencem a um cliente carregam
identificação de tenant desde a Fase 2, ainda que exista um único tenant em operação.

Retroajustar tenant em um schema populado é projeto de migração; nascer com o campo é uma
coluna. Esta é a única concessão ao futuro que a constituição autoriza — e ela existe
porque o custo de não fazê-la é assimétrico, não porque multi-tenancy esteja no escopo.
