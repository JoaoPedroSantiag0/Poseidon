# POSEIDON — Constituição do Projeto

> **Documento de leitura obrigatória.** Nenhum agente (humano ou IA) executa trabalho
> neste repositório sem ter lido este arquivo por inteiro na sessão atual.
> Este documento tem precedência sobre qualquer instrução de papel
> (`01-BUILDER.md`, `02-AUDITOR.md`) e sobre qualquer preferência do modelo.
>
> Versão: 1.0 · Status: vigente

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

O modelo de evento normalizado (ADR-002) só pode ser congelado depois de ter sido
exercitado contra **no mínimo duas fontes heterogêneas** — na prática: Sysmon/Windows
Event Log via Collector Agent, e alertas do Wazuh. Um normalizador validado contra uma
única fonte é, por construção, o formato daquela fonte com outro nome.

### Lei 5 — `event_time` nunca é `ingestion_time`

Todo evento carrega, obrigatoriamente e de forma distinta:

```
event_time         quando aconteceu no endpoint/fonte
ingestion_time     quando o Poseidon recebeu
source             origem
source_event_id    id no sistema de origem
raw_reference      ponteiro para o evento bruto preservado
correlation_id     agrupamento lógico
```

Colapsar esses campos destrói a capacidade forense da plataforma. O evento bruto
original é preservado e nunca é sobrescrito pela versão normalizada.

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

### Lei 8 — O Collector Agent não executa comandos arbitrários

Não existe, em nenhuma hipótese, um endpoint do tipo `POST /agent/execute {command}`.
O agente expõe um **conjunto fechado de capacidades nomeadas**, implementadas em código,
verificadas por assinatura. Tudo fora dessa lista é rejeitado pelo próprio agente.

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
em algo que só se recupera fisicamente. Requisitos obrigatórios e simultâneos:

1. **Snapshot** do estado de firewall antes de aplicar, com restauração exata.
2. **Dead-man's-switch**: se o agente perder contato com o control plane por N minutos
   (padrão: 30, configurável, com mínimo e máximo travados em código), ele **restaura
   automaticamente** a conectividade e registra o evento.
3. **Exceção garantida** para o canal de saída do Poseidon, DNS e infraestrutura de
   gerenciamento — isolamento seletivo é o padrão; isolamento total é opção explícita.
4. **Teste obrigatório em VM descartável** antes de qualquer execução em máquina real.
   Nenhum PR de isolamento é aprovado sem evidência desse teste.

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
Fase 0   Research + ADRs fundacionais (licença Wazuh, OCSF/ECS, STIX, Sigma)
Fase 1   Foundation + Design System
Fase 2   Identity / RBAC / Audit Log
Fase 3   Event Model            ← modelado contra Sysmon E Wazuh (Lei 4)
Fase 4   Ingestion Framework
Fase 5   Collector Agent v0.1   (Sysmon + Security Log + Defender AV local)
Fase 6   CTI Engine + OTX
Fase 7   Cases + Timeline
Fase 8   Response Control Plane + isolamento com failsafe
Fase 9   Wazuh como segunda fonte  ← valida que o Event Model não é moldado a ninguém
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
- Telemetria de endpoint no laboratório vem de **Sysmon + Windows Security Log + log
  operacional do Defender Antivírus local** — tudo gratuito e sem tenant.
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

NDR · UEBA · multi-tenant · IA tomando ação autônoma · resposta automática sem aprovação
humana · agentes Linux/macOS · correlação avançada com machine learning · marketplace de
integrações · chat entre IAs como funcionalidade do produto.

Proposta de qualquer um desses itens antes da Fase 13 deve ser recusada pelo Auditor como
desvio de escopo, ainda que tecnicamente elegante.
