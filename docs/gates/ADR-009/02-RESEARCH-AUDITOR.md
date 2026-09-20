# ADR-009 — Levantamento independente do Auditor

**Data de consulta de todas as fontes: 2026-09-20**
**Produzido sem leitura do `01-RESEARCH-BUILDER.md`** — que, no momento da escrita, ainda
não existia em disco.

> **Método:** para as três perguntas que o humano marcou como suspeitas de entusiasmo, não
> aceitei analogia nem documentação. Fui ao **código-fonte na tag fixa `v4.14.7`** do Wazuh e
> ao **código do plugin** do OpenSearch Security Analytics, e **medi** o corpus do SigmaHQ na
> tag `r2026-07-01`. Onde não consegui chegar à fonte primária, está marcado `NÃO VERIFICADO`.

| Marca | Significado |
|---|---|
| **[V]** | Verificado em fonte primária — código, arquivo `LICENSE`, spec, ou medição própria |
| **[D]** | Documentação oficial secundária |
| **[NV]** | **NÃO VERIFICADO** — não vira premissa (Lei 1) |

---

## 1. Sumário — os três achados que mudam a decisão

**1. A hipótese central da B′ é falsa, e a falsificação é estrutural, não de formato.**
O decoder `windows_eventchannel` do Wazuh é selecionado pelo **primeiro byte da mensagem**
(`msg[0]`), não pelo conteúdo. Syslog injeta `'2'`, a API injeta `'1'`, e só `'f'` chega ao
decoder — e `'f'` só é produzido pelo logcollector do agente. **Nenhum envelope que o
Collector emita muda isso.** A B′ entrega o manager sem a biblioteca de regras de Windows,
que é justamente o que o briefing lista como a vantagem dela sobre a opção C.

**2. Em alerta injetado, `agent.id` é `"000"` — hardcoded.** O humano suspeitou certo. Todo
alerta vindo por syslog ou por `POST /events` é atribuído ao manager. O Poseidon perde a
amarração alerta→endpoint nos campos padrão.

**3. O suporte a Sigma do Security Analytics é subconjunto da especificação — e o
subconjunto cobre 3.140 das 3.142 regras do SigmaHQ.** A suspeita de que "se for subconjunto,
a opção C perde muito" **não se confirma** no eixo de modificadores. Medi. O risco da C está
em outro lugar.

---

## 2. Opção B′ — verificação a fundo

A B′ é a única das quatro que nunca foi auditada, e é a que tem a hipótese mais frágil.
Dediquei a ela a maior parte do esforço.

### 2.1 A hipótese central: **falsificada em código-fonte**

O briefing formula a hipótese assim:

> *"Se o Collector emitir o mesmo envelope, as regras devem casar — **isto é a hipótese
> central da opção B′ e não está verificada**."*

Verifiquei. **O envelope é irrelevante.** A seleção do decoder de eventchannel não olha o
payload.

**[V] Passo 1 — o roteamento é por byte de tipo de mensagem.**
`src/analysisd/analysisd.c`, tag v4.14.7, linhas 1231–1420:

```c
if (msg[0] == SYSCHECK_MQ)           { ... }
else if (msg[0] == ROOTCHECK_MQ)     { ... }
else if (msg[0] == SCA_MQ)           { ... }
else if (msg[0] == SYSCOLLECTOR_MQ)  { ... }
else if (msg[0] == HOSTINFO_MQ)      { ... }
else if (msg[0] == WIN_EVT_MQ)       { queue_push_ex(decode_queue_winevt_input, copy); }
else if (msg[0] == DBSYNC_MQ)        { ... }
...
else { if (msg[0] == SYSLOG_MQ) {...} else if (msg[0] == LOCALFILE_MQ) {...} }
```

E só quem sai de `decode_queue_winevt_input` chama o decoder
(`w_decode_winevt_thread`, linha 1875):

```c
if (DecodeWinevt(lf)) {
    /* We don't process windows events further */
```

**[V] Passo 2 — os valores dos bytes.** `src/headers/mq_op.h`:

```c
#define LOCALFILE_MQ    '1'
#define SYSLOG_MQ       '2'
#define WIN_EVT_MQ      'f'
```

**[V] Passo 3 — quem produz `'f'`.** Exatamente um lugar:
`src/logcollector/read_win_event_channel.c`, linha 526 —

```c
SendMSG(logr_queue, msg_sent, "EventChannel", WIN_EVT_MQ)
```

É o **logcollector do agente Wazuh**, no endpoint. Nenhum outro componente emite `WIN_EVT_MQ`.

**[V] Passo 4 — o que os dois caminhos de injeção da B′ produzem.**

| Caminho | Onde está | Byte emitido | `location` | Chega ao `DecodeWinevt`? |
|---|---|---|---|---|
| Syslog remoto | `src/remoted/syslog.c:112` — `SendMSG(logr.m_queue, buffer_pt, srcip, SYSLOG_MQ)` | `'2'` | o **IP de origem** | **não** |
| `POST /events` | `framework/wazuh/event.py` — `MSG_HEADER = '1:API-Webhook:'` | `'1'` | `API-Webhook` | **não** |

**Consequência.** O `windows_eventchannel` é inalcançável pelos dois caminhos que a B′ propõe.
Os campos `data.win.system.eventID` e `data.win.eventdata.*` **nunca são produzidos**, porque
quem os produz é `DecodeWinevt()`, que nunca roda. Toda regra do Wazuh que referencia
`win.system.*` ou `win.eventdata.*` fica estruturalmente incapaz de casar.

**[V] O que se perde, em tamanho.** `ruleset/rules` na v4.14.7 tem 168 arquivos, dos quais 15
são a biblioteca Windows: `0840-win_event_channel.xml`, `0595-win-sysmon_rules.xml`,
`0600-win-wdefender_rules.xml`, `0915-win-powershell_rules.xml`, `0220-msauth_rules.xml`,
`0330-sysmon_rules.xml`, `0430-ms_wdefender_rules.xml` e os oito arquivos `08xx/09xx-sysmon_id_*`.

Essa é a linha da tabela do briefing que diz *"Maior perda da opção C → você **mantém** a
biblioteca de decoders e regras do Wazuh"*. **Para Windows, essa linha está errada.** E o
Poseidon é, pela §4 da constituição, um produto Windows-first.

**O que sobraria funcionando:** o caminho genérico de syslog e o conjunto de regras que casa
em texto de log — `0015-syslog_rules.xml` e correlatos. Útil para appliances de rede,
firewalls e Linux via syslog. Não é o que a B′ foi proposta para preservar.

### 2.2 Atribuição de endpoint: `agent.id = "000"`, hardcoded

O humano perguntou: *"Em alerta vindo por syslog, o que aparece em `agent.id`/`agent.name`/`agent.ip`?"*

**[V]** `src/analysisd/cleanevent.c`, linhas 538–591. O comentário do próprio código declara o
contrato:

```c
/* Every message must be in the format
 * hostname->location or
 * [id] (agent) ip->location.
 */
if (lf->location[0] == '[') {
    /* Messages from an agent */
    lf->agent_id = lf->location + 1;      // extrai o id de dentro de [ ]
    ...
} else {
    os_strdup(lf->hostname ? lf->hostname : __shost, lf->hostname);
    os_strdup("000", lf->agent_id);        // ← hardcoded
}
```

A atribuição de agente depende **exclusivamente** de a `location` começar com `[`. E:

- syslog põe em `location` o **IP de origem** (`SendMSG(..., srcip, SYSLOG_MQ)`) — não começa com `[`;
- a API põe `API-Webhook` — não começa com `[`.

**Logo: `agent_id = "000"` e `agent_name` = hostname do manager, para todo evento injetado.**

**Impacto no Investigation Workspace.** Todo alerta produzido pelo Wazuh sob B′ chegaria ao
Poseidon atribuído ao manager. Para amarrar ao endpoint de origem, o Poseidon teria de
extrair o host de **dentro** do payload decodificado — o que exige que um decoder tenha
extraído o campo, que é precisamente o que §2.1 mostra que não acontece para Windows. As duas
falhas se compõem: sem decoder, não há campo; sem campo, não há host.

Há um paliativo parcial: o IP de origem vira a `location`, então se **cada endpoint** falasse
syslog direto com o manager, o IP identificaria o host. Mas a B′ é desenhada exatamente ao
contrário — a telemetria passa pelo **Ingestion do Poseidon** antes. Todos os eventos
chegariam com o IP do Poseidon. **[NV]** Não verifiquei se há configuração de `location`
personalizada por conector que contorne isso no caminho syslog.

### 2.3 Transporte — os limites concretos

**[V] Syslog UDP.** `src/remoted/syslog.c`: `HandleSyslog()` faz `recvfrom` no `logr.udp_sock`
com buffer `OS_MAXSTR + 2`, e `OS_MAXSTR = OS_SIZE_65536` (`src/headers/defs.h:51`). O
buffer do manager comporta 64 KB, mas o **datagrama** continua sujeito a MTU e fragmentação —
eventos de criação de processo com linha de comando longa passam de 1.500 bytes com
facilidade. UDP não tem entrega garantida: perda sob carga é silenciosa, o que colide
frontalmente com a Lei 12.

**[V] Syslog TCP existe** — `src/remoted/syslogtcp.c`, com remoção do cabeçalho PRI
(`w_get_pri_header_len`) e a mesma lista de IPs permitidos (`OS_IPNotAllowed`). **[NV]** Não
verifiquei o enquadramento (delimitador de linha vs. octet-counting da RFC 6587) nem o
comportamento com mensagens multi-linha, que é decisivo para JSON de eventchannel.

**[V] `POST /events` tem teto rígido de lote:** `api/api/models/event_ingest_model.py` —
`MAX_EVENTS_PER_REQUEST = 100`. **[NV]** Rate limit real do endpoint não verificado.

**[V] Uma observação de segurança que o briefing não levanta:** a API de eventos exige a ação
RBAC `event:ingest` e injeta com `location = API-Webhook`. Como o `msg[0]` é fixado em `'1'`
pelo framework, **o chamador não escolhe o tipo de mensagem** — o que é bom para segurança e
fatal para a B′.

### 2.4 Auditoria da tabela "o que isto resolve" do briefing

| Linha do briefing | Veredito |
|---|---|
| `MAJOR-26` — dois agentes no endpoint | ✅ **resolve de fato.** É o ganho mais sólido da B′ |
| As sete obrigações da D-005 | ✅ **resolve**, com ressalva em §2.6 |
| Risco do agente 5.x virar AGPL-3.0 | ✅ **resolve** |
| `BLOCKER-13` — custódia de credencial | ⚠️ **resolve em parte.** Elimina o caminho do agente Wazuh. **Não toca o `BLOCKER-09`**: o evento bruto do próprio Poseidon continua carregando a credencial do 4688. B′ remove um dos três caminhos, não o problema |
| `BLOCKER-03` — Active Response como superfície | ✅ resolve — **e é também perda de capacidade.** A §7 da constituição lista *"Wazuh Active Response como segundo caminho de resposta"*. Sem agente no endpoint, esse caminho deixa de existir. O briefing conta como ganho; é ganho e perda |
| *"você **mantém** a biblioteca de decoders e regras do Wazuh"* | ❌ **falso para Windows** — §2.1 |

### 2.5 A única variante tecnicamente viável da B′, e o que ela custa

Existe **um** caminho que produziria `WIN_EVT_MQ` sem agente Wazuh no endpoint: o Poseidon
falar o **protocolo de agente** (porta 1514, `SECURE_MQ`), registrando-se como agente e
emitindo mensagens com o byte `'f'` e `location = "EventChannel"`.

Custos, e eles são altos:

1. **Não há especificação pública do protocolo.** Derivá-lo significa ler o código GPLv2 —
   o que colide com a **D-005 item 6**, *"o Collector do Poseidon permanece com zero código
   derivado do Wazuh"*, que é o que mantém o repositório do Poseidon privado sem conflito.
2. Exigiria gerenciar chaves e registro de agente do Wazuh a partir do Poseidon — ou seja,
   **reimplementar o agente Wazuh**, que é o que a B′ existia para evitar.
3. **[NV]** Não verifiquei se `remoted/secure.c` preserva integralmente o byte de fila do
   agente ao repassar para o analysisd. O desenho sugere que sim; não confirmei linha a linha.

**Leitura:** a B′ não é "quase viável com um ajuste de formato". Para preservar o valor que
ela promete, ela se transforma na reimplementação do agente que ela queria eliminar.

### 2.6 Licenciamento sob B′ — ganho real, com uma ressalva

**[V] O ganho é real.** Sem distribuição do agente, as sete obrigações da D-005 desaparecem:
não há oferta de código-fonte por release, não há preservação de avisos em artefato
distribuído, não há restrição sobre o EULA, não há risco de empacotamento indevido. E a
GPLv2 **não tem cláusula de rede** — hospedar não é distribuir.

**Ressalva que ninguém levantou.** Um deployment padrão do Wazuh inclui o **Wazuh Indexer**, e
`wazuh/wazuh-indexer-plugins` é **AGPL-3.0** **[V]**, verificado na rodada 3. A AGPL-3.0 §13
dispara **na modificação**, não no mero uso em rede: hospedar sem modificar não gera
obrigação. Portanto a B′ continua limpa — **desde que o Poseidon não modifique os plugins do
indexer**. Isso precisa virar restrição escrita, porque é exatamente o tipo de coisa que se
faz "só para ajustar um mapeamento" e que muda o regime de licença de um produto SaaS.

---

## 3. Opção C — OpenSearch Security Analytics + osquery

### 3.1 Sigma: subconjunto da especificação — **medido**, não estimado

**[V] O que o plugin implementa.** `SigmaModifierFacade.java`, `modifierMap` — 14 entradas:

```
contains · startswith · endswith · base64 · base64offset · wide · windash
re · cidr · all · lt · lte · gt · gte
```

Modificador fora do mapa lança `SigmaModifierError("modifier not found-...")` — a regra
**falha na importação**, não degrada em silêncio. Falha barulhenta é o comportamento certo.

**[V] O que a especificação v2.1.0 tem e o plugin não:**
`exists`, `cased`, `neq`, `utf16be`, `utf16` (só `wide`/`utf16le` está), as seis de tempo
(`minute`, `hour`, `day`, `week`, `month`, `year`), `expand`, e `fieldref`.

Em número bruto: **14 de ~26**. Parece grave. Medi se é.

**[V] Medição no corpus real.** Baixei `SigmaHQ/sigma` na tag `r2026-07-01` — **3.142 regras
em `rules/`, das quais 2.403 são Windows** — e enumerei todos os modificadores efetivamente
usados:

| Modificador | Ocorrências no corpus | Suportado? |
|---|---|:---:|
| `contains` | 3.290 | ✅ |
| `endswith` | 2.107 | ✅ |
| `all` | 746 | ✅ |
| `startswith` | 432 | ✅ |
| `windash` | 102 | ✅ |
| `re` | 65 | ✅ |
| `cidr` | 32 | ✅ |
| `base64offset` | 4 | ✅ |
| `i` (sub-modificador de `re`) | 1 | ✅ |
| **`fieldref`** | **2** | ❌ |

*(Método: extração de `campo|modificador:` de todos os `.yml` sob `rules/`, com validação
cruzada — os modificadores suportados aparecem com frequência coerente, o que confirma que o
padrão de extração funciona.)*

**Resultado: o corpus inteiro usa 9 construções, e o Security Analytics implementa 8.**
A única lacuna é `fieldref`, em **2 regras de 3.142 — 0,06%**.

**A suspeita do humano não se confirma neste eixo.** "Subconjunto" é verdade formal; o
subconjunto cobre o corpus. Os modificadores ausentes são recentes na especificação e ainda
não têm adoção no acervo do SigmaHQ.

### 3.2 O que o Security Analytics faz e não faz, além de modificadores

**[V] Agregação: suportada.** `SigmaCondition.java` carrega um parser ANTLR dedicado
(`AggregationLexer`, `AggregationParser`, `AggregationTraverseVisitor`), separando a condição
do trecho após ` | `. Condições com agregação são processadas.

**[V] Regras de correlação do Sigma: não suportadas.** O pacote
`rules/objects` tem `SigmaRule`, `SigmaDetection`, `SigmaDetections`, `SigmaCondition`,
`SigmaLogSource`, `SigmaLevel`, `SigmaStatus`, `SigmaRuleTag`, `SigmaDetectionItem` — **não há
classe de correlação**. A `sigma-correlation-rules-specification.md` não tem implementação
aqui. O "motor de correlação" do Security Analytics é outra coisa: correlaciona *findings*
entre log types, não executa regras de correlação Sigma.

**[NV] O risco real da opção C, que eu não consegui dimensionar:** o **mapeamento de campos
por log type**. Uma regra que importa sem erro ainda precisa que os campos existam no índice
com os nomes que o detector espera. Não consegui enumerar os log types predefinidos nem as
suas tabelas de mapeamento no repositório pelo caminho que tentei. **É aqui que a opção C
pode perder — não nos modificadores.** Precisa ser verificado antes de qualquer decisão a
favor de C, e é o item que eu colocaria no topo da lista do Builder.

**[V] Licença e atividade:** `opensearch-project/security-analytics` é **Apache-2.0**, push em
2026-09-16. Sem cláusula de rede, sem restrição a serviço gerenciado. Compatível com D-002.

### 3.3 osquery e gerenciamento de frota — licenças verificadas

| Componente | Licença **[V]** | Consequência sob D-002 (SaaS) |
|---|---|---|
| **osquery** | **dual Apache-2.0 / GPL-2.0** — o `LICENSE` declara contribuição *"under the terms of both"* | Caminho permissivo disponível. Sem problema |
| **Fleet** (gestão de frota osquery) | **MIT Expat** no núcleo; **o diretório `ee/` tem licença própria**; `docs/` é CC BY-SA 4.0 | Open-core. Usável sob MIT **se `ee/` não for tocado**. Precisa de verificação do que está em `ee/` antes de depender de qualquer funcionalidade |
| **Velociraptor** | **AGPL-3.0** | Cláusula de rede. Hostil a SaaS se houver modificação. Eu não o incluiria sem ADR próprio |

**[NV] Cobertura do osquery comparada ao agente Wazuh** para FIM, SCA/CIS e detecção de
vulnerabilidade: não verifiquei em profundidade. O que sei estruturalmente é que o osquery é
um motor de **consulta por SQL sobre estado**, não um motor de política — SCA/CIS e casamento
com CVE seriam construídos por cima, não herdados. **[NV]** Paridade de `file_events` no
Windows versus Linux/macOS: não verificada, e é item conhecido de assimetria.

---

## 4. Opção A — SIEM de terceiro + CTI

Não precisa de verificação técnica nova; precisa de honestidade sobre as perguntas do §6 do
briefing.

**De onde vem a telemetria de endpoint sem Collector próprio?** Do agente do SIEM escolhido.
Se for Wazuh, volta a valer tudo que já foi verificado: o agente coleta linha de comando sem
redação **[V, rodada 3]**, e o Active Response é superfície de execução **[V, rodada 1]**.

**O `BLOCKER-13` desaparece ou muda de dono?** **Muda de dono, e só se o cliente hospedar o
próprio Wazuh.** Se o Poseidon hospedar — que é o cenário D-002 — o Poseidon continua
custodiante das linhas de comando, sem nenhum ponto onde possa redigir, porque não há
Collector próprio na fronteira. **A opção A, sob SaaS operado pelo Poseidon, é a pior das
quatro para custódia de dado pessoal.** Sob SIEM hospedado pelo cliente, é a melhor: o
Poseidon nunca vê o dado bruto.

Isso significa que **a opção A não é uma opção — são duas**, com consequências opostas no
critério 4, e o briefing não as separa:

- **A1 — SIEM do cliente.** O Poseidon consome API e nunca custodia telemetria bruta.
- **A2 — SIEM hospedado pelo Poseidon.** O Poseidon custodia tudo, sem fronteira de redação.

**Fecha portas para as Fases 8–13?** Não fecha, mas inverte a ordem de dificuldade: o Response
Control Plane (Fase 8) passa a depender do caminho de resposta do SIEM de terceiro — que, no
caso do Wazuh, é o Active Response que a Lei 8 disciplina mas não elimina. A Fase 12
(evidências) e a 11 (detecção) também passam a depender do que o terceiro expõe.

---

## 5. Opção B — o estado atual

Nada novo a verificar: é o que três rodadas de auditoria já descreveram. Registro apenas o
saldo conhecido, porque ele é o ponto de comparação.

Dois agentes no endpoint (`MAJOR-26`), dois formatos de detecção (Sigma e XML do Wazuh, sem
dono declarado), dois caminhos de resposta, dois caminhos de credencial (`BLOCKER-09` e
`BLOCKER-13`), dois clientes de API (Manager 55000 + Indexer 9200, **[V]** rodada 1), e as
sete obrigações de redistribuição da D-005 sem dono (`MAJOR-27`).

---

## 6. As quatro opções contra os dez critérios

Descrição de consequência, sem pontuação e sem recomendação — a recomendação é do Builder e a
decisão é do humano.

| Critério | **A1** (SIEM do cliente) | **A2** (SIEM hospedado) | **B** (atual) | **B′** | **C** |
|---|---|---|---|---|---|
| **1. Entrega do MVP** | a mais rápida: nenhum agente para escrever | rápida, mas com operação de SIEM desde o dia um | a mais lenta: Collector + modelo + resposta | igual a B **menos** o valor que §2.1 mostra que não chega | intermediária: Collector + mapeamento de log types **[NV]** |
| **2. Diferenciação** | toda a diferenciação vive na camada de investigação e CTI — que é onde ela sempre esteve | idem | alta, mas paga em escopo | igual a B | igual a B |
| **3. Licenciamento sob SaaS** | do cliente, não seu | GPLv2 hospedado: sem cláusula de rede; indexer-plugins AGPL se modificados | GPLv2 **distribuído** — 7 obrigações da D-005 | **o melhor dos quatro**: hospeda, não distribui | Apache-2.0 puro no motor; osquery dual; Fleet open-core |
| **4. Custódia de dado pessoal** | **a melhor**: o Poseidon nunca vê o bruto | **a pior**: custodia tudo, sem fronteira de redação | dois caminhos de credencial | um caminho a menos que B; `BLOCKER-09` intacto | um caminho, com fronteira de redação no Collector |
| **5. Superfície de execução** | do terceiro; a Lei 8 não alcança | idem | dois caminhos; Lei 8 alcança um por política | **um caminho** — o do Poseidon | um caminho |
| **6. Duplicação** | zero agentes próprios | zero | 2 agentes · 2 formatos · 2 respostas · 2 APIs | 1 agente · 1 formato útil · 1 resposta · 2 APIs | 1 agente · 1 formato · 1 resposta · 1 API |
| **7. Dependência estratégica** | total do terceiro, mas trocável | alta | agente 5.x → AGPL é risco vivo | não usa o agente deles: risco neutralizado | depende do ritmo do OpenSearch; Apache-2.0 protege |
| **8. Maturidade** | herda tudo do SIEM | idem | herda tudo | **herda muito menos do que o briefing supõe** (§2.1) | perde decoders, SCA/CIS, CVE; ganha Sigma nativo medido em §3.1 |
| **9. Posicionamento** | "integramos com o seu SIEM" | "SOC gerenciado sobre Wazuh" | "baseado em Wazuh" | "baseado em Wazuh" — com ressalva de honestidade: a parte de Windows não usa as regras deles | "stack aberta, sem amarra de licença" |
| **10. Reversibilidade** | A→B/C é caro: escrever o Collector depois | idem | B→B′ é barato (parar de distribuir); B→C é caro | B′→C é o mais barato dos caminhos de saída | C→B é caro |

**Duas observações que a tabela não comporta:**

A primeira é que **B′ e C convergem**. Se a B′ não entrega a biblioteca de regras de Windows,
o que ela entrega é: um agente, um formato, motor de detecção de terceiro hospedado. É a
mesma forma da opção C, com um motor pior no eixo que importa — o Wazuh não consome Sigma
**[V, rodada 2]** e o Security Analytics consome, com cobertura medida de 99,94% do corpus.

A segunda é que **o critério 9 tem um custo de honestidade sob B′**. Comunicar "baseado em
Wazuh" enquanto a detecção de Windows não usa as regras do Wazuh é uma afirmação que não
sobrevive a uma pergunta técnica de cliente.

---

## 7. Alternativas transversais — licenças verificadas antes de qualquer entusiasmo

| Projeto | Licença **[V]** | Leitura sob D-002 |
|---|---|---|
| **MISP** | **AGPL-3.0** | Citado na §3 da constituição e nunca pesquisado. Cláusula de rede. Hospedar sem modificar é livre; modificar obriga a ofertar fonte a quem usa pela rede. **Exige ADR antes de qualquer adoção** |
| **Suricata** | GPL-2.0 | Hospedar não é distribuir. NDR está fora do MVP pelo §11 |
| **Zeek** | **[NV]** — `LICENSE` não estava no caminho esperado | não verificado |
| **Velociraptor** | **AGPL-3.0** | mesma leitura do MISP |
| **osquery** | dual Apache-2.0 / GPL-2.0 | sem problema |
| **Fleet** | MIT Expat + `ee/` proprietário | usável com cuidado de fronteira |

---

## 8. Perguntas abertas para o humano

1. **A opção A precisa ser desdobrada em A1 e A2** antes de ser decidida. Elas têm resultados
   opostos no critério 4, que é onde moram dois BLOCKER abertos. Qual das duas está na mesa?
2. **Se B′ não entrega a biblioteca de regras de Windows, a B′ ainda interessa?** A pergunta
   é honesta: ela continua resolvendo `MAJOR-26`, as obrigações da D-005 e o risco do AGPL.
   Só não resolve pelo motivo que o briefing dá.
3. **A `D-005` deve ser revogada?** O briefing a coloca em revisão. Tanto B′ quanto C quanto
   A1 a tornam desnecessária.

---

## 9. Não verificado

- **Enquadramento do syslog TCP** (delimitador vs. octet-counting) e comportamento com
  payload multi-linha. Decisivo para B′ se ela sobreviver ao §2.1.
- **Rate limit real do `POST /events`** — só o teto de 100 eventos por requisição está
  verificado.
- **Preservação do byte de fila do agente em `remoted/secure.c`** (§2.5, item 3).
- **Log types e mapeamento de campos do Security Analytics** — §3.2. **É o item mais
  importante da lista**, porque é onde a opção C pode perder.
- **Cobertura do osquery** para FIM, SCA/CIS e CVE comparada ao agente Wazuh; paridade de
  `file_events` no Windows.
- **Conteúdo do diretório `ee/` do Fleet** e o que depende dele.
- **Licença do Zeek.**
- **Termos do OTX/LevelBlue** — pendência herdada, ainda aberta (`MAJOR-24`).
- **Nada jurídico.** Li texto de licença e de código. As leituras de GPLv2 e AGPL-3.0 aqui são
  técnicas; a ressalva da D-005 sobre advogado continua valendo e eu a estendo à AGPL do MISP
  e do Velociraptor.
