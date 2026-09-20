# Auditoria — Fase 0 · Rodada 2

**Data:** 2026-09-20
**Auditor:** Auditor
**Base:** `00-CONSTITUTION.md` v2.0 (emendada em 2026-09-20) · `01-BUILDER.md` e
`02-AUDITOR.md` atualizados · `docs/gates/FASE-00/00-RESEARCH.md` do Builder (29.310 bytes,
gravado às 10:46) · ADRs `001`–`008` presentes em `docs/adr/` mas **não auditados nesta
rodada** (ver "Não verificado").

Este documento tem duas partes:

- **Parte I** — a emenda v2.0 fecha os quatro BLOCKER, ou apenas os moveu? Inclui achados
  novos **introduzidos pela própria emenda**.
- **Parte II** — o confronto entre `00-RESEARCH.md` (Builder) e `03-AUDIT-RESEARCH.md`
  (Auditor), pendência registrada na rodada 1.

A numeração de achados **continua** a da rodada 1. BLOCKER-01 a 04, MAJOR-01 a 12,
MINOR-01 a 06 e OBSERVATION-01 a 11 estão no `03-AUDIT-REPORT.md`. Esta rodada abre
BLOCKER-05 a 07, MAJOR-13 a 17, MINOR-07 a 08 e OBSERVATION-12 a 15. O razão é único
para a fase.

---

## Método

1. Releitura integral da constituição v2.0 e dos dois documentos de papel atualizados,
   comparando cláusula a cláusula com a redação v1.0.
2. Para cada BLOCKER da rodada 1: verificar se a **correção exigida** foi atendida no
   texto, e depois procurar ativamente o defeito que a nova redação cria. Emenda é código
   novo; código novo tem bug novo.
3. Leitura do `00-RESEARCH.md` do Builder **somente agora**, após o meu levantamento estar
   fechado — o isolamento era o ponto do exercício.
4. Para **cada** divergência entre os dois documentos, ida à fonte primária. Nenhuma
   divergência foi resolvida por plausibilidade ou por autoridade de quem escreveu.
5. Verificação nova, disparada pela emenda: viabilidade real do caminho ETW, que a v2.0
   promoveu a fonte de telemetria do produto.

Fontes primárias desta rodada, todas consultadas em **2026-09-20**: API do schema OCSF
(`schema.ocsf.io/api/*`), API do GitHub e arquivos `LICENSE` brutos, PyPI, código do
SDK do OTX, Microsoft Learn (Q&A oficial sobre ETW), e a especificação OpenAPI do Wazuh
na tag `v4.14.7` já baixada na rodada 1.

**Nota de escopo:** o `00-RESEARCH.md` foi gravado às 10:46, **antes** da emenda. Onde ele
trata Sysmon como dependência do produto, não é erro dele — é documento anterior à decisão.
Marquei esses casos como *superado*, não como achado. As divergências factuais de
schema, licença e API independem da emenda e valem integralmente.

---

# PARTE I — A emenda v2.0 fecha os BLOCKER?

## Quadro-resumo

| ID | Assunto | Veredito | Resíduo |
|---|---|---|---|
| **BLOCKER-01** | Lei 5 inventava schema | ✅ **FECHADO** | `MINOR-07` |
| **BLOCKER-02** | Lei 4 inexequível no roadmap | ⚠️ **PARCIAL** | metade estrutural fechada; metade substantiva vira **`BLOCKER-05`** |
| **BLOCKER-03** | Alcance da Lei 8 | ✅ **FECHADO** | `MAJOR-14` |
| **BLOCKER-04** | Isolamento total incompatível | ✅ **FECHADO** | — |

**Três de quatro fechados.** Mas a emenda introduz **três BLOCKER novos** — um deles
resíduo do BLOCKER-02, dois inteiramente novos, ambos nas áreas que a emenda reescreveu.
O saldo de BLOCKER abertos é **3**, não 0.

---

## BLOCKER-01 — ✅ FECHADO

**O que foi pedido:** declarar que a Lei 5 enuncia requisitos semânticos, não nomes de
campo; nomes concretos vêm do ADR-002; conceito sem equivalente nasce sob `poseidon.*`.

**O que a v2.0 fez:** exatamente isso. A lei agora abre com *"Esta lei enuncia requisitos
semânticos, não nomes de campo"*, substitui o bloco de código por uma tabela conceito →
significado, remete os nomes ao ADR-002, e fecha com *"Conceito sem equivalente no padrão
adotado nasce sob `poseidon.*`, conforme a Lei 2"*. O núcleo inegociável — tempo do evento
≠ tempo de ingestão, bruto nunca sobrescrito — foi preservado e ficou mais explícito.

Correção limpa. A contradição com a Lei 2 não existe mais.

### [MINOR-07] Os nomes inventados sobrevivem no título da lei e no checklist do Auditor

**Arquivos:** `00-CONSTITUTION.md` — título da Lei 5; `02-AUDITOR.md` §4.1 e §7.5

O corpo da lei foi corrigido, mas o **título** continua `### Lei 5 — `event_time` nunca é
`ingestion_time``, com os dois nomes em crase — grafia de identificador. E o
`02-AUDITOR.md` mantém, como itens normativos de verificação:

> §4.1: *"`event_time` e `ingestion_time` são distintos e o bruto foi preservado? (Lei 5)"*
> §7.5: *"**`event_time` colapsado com `ingestion_time`**, ou evento bruto descartado"*

Um Builder que procure os termos normativos da Lei 5 encontra os nomes antigos em três
lugares, em formatação de código, e o corpo corrigido em um. É a mesma ambiguidade que
gerou o defeito original, em dose menor.

**Correção:** manter o título como mnemônico, mas desambiguar — por exemplo
*"Lei 5 — tempo do evento nunca é tempo de ingestão (`event_time` ≠ `ingestion_time` é
mnemônico, não nome de campo)"* — e alinhar as duas linhas do `02-AUDITOR.md`.

---

## BLOCKER-02 — ⚠️ PARCIALMENTE FECHADO

**O que foi pedido:** separar decidir de congelar, ou antecipar a segunda fonte, ou emendar
a lei.

**O que a v2.0 fez:** as duas primeiras, juntas — mais do que eu havia pedido.

- Lei 4 agora distingue **decidir** (ADR-002, Fase 3, modelo nasce `PROVISÓRIO`, migrações
  das Fases 4–8 reversíveis por isso) de **congelar** (Fase 9, ADR próprio com
  `Supersedes: ADR-002`).
- Introduz o **corpus gravado de alertas reais do Wazuh** para exercitar o normalizador na
  Fase 3, marcado *"obrigatório, não opcional"*.
- O roadmap foi reescrito coerentemente: Fase 3 = "Event Model PROVISÓRIO ← decide o
  padrão; exercita contra corpus gravado do Wazuh"; Fase 9 = "CONGELA o Event Model".

A metade **estrutural** do achado está resolvida, e bem. A metade **substantiva** não.

### [BLOCKER-05] A Fase 3 continua modelando contra fonte única — agora contra o Wazuh

**Arquivo:** `00-CONSTITUTION.md` — Lei 4, contra §7 (Roadmap)
**Lei/dimensão violada:** Lei 4; dimensões 4.1 e 4.6

**Evidência.** A Lei 4 fixa o limiar: *"exercitado contra **no mínimo duas fontes
heterogêneas** — telemetria de endpoint via Collector Agent, e alertas do Wazuh."*

A emenda supre **uma** das duas na Fase 3 — o corpus do Wazuh. A outra, telemetria de
endpoint, só existe na **Fase 5**, quando o Collector Agent é construído. O texto da Lei 4
diz *"Para antecipar **a segunda** fonte…"*, o que pressupõe que a primeira já esteja
disponível na Fase 3. Ela não está: o roadmap v2.0 mantém `Fase 5 Collector Agent v0.1`.

Contagem de fontes reais disponíveis na Fase 3, pela v2.0:

| Fonte | Disponível na Fase 3? |
|---|---|
| Alertas do Wazuh (corpus gravado) | **sim** — a emenda criou |
| Telemetria de endpoint (ETW / Security Log) | **não** — Fase 5 |

**Cenário de falha.** A Fase 3 entrega um normalizador exercitado contra **exatamente uma**
fonte, e essa fonte é o **Wazuh**. O modelo `PROVISÓRIO` nasce com a forma do alerta do
Wazuh: hierarquia `rule` / `agent` / `manager` / `decoder` / `data`, severidade em escala
de nível 0–15, `mitre` embutido no objeto da regra. Nas Fases 4 a 8 esse formato vira o
vocabulário de trabalho do time. Na Fase 5 a telemetria de endpoint chega e não encaixa —
e a saída barata é adaptá-la ao que já existe.

Isto é literalmente a armadilha 7.4 do `02-AUDITOR.md` — *"Event Model moldado ao Wazuh —
campos que só existem porque o alerta do Wazuh tem aquela forma"* — e a v1.0 protegia
contra ela por acidente, porque a Fase 3 não tinha fonte nenhuma. A emenda melhorou de zero
para uma, e ao fazê-lo escolheu que a única fosse justamente a que a Lei 4 nomeia como
risco.

**Impacto.** A Lei 4 declara um limiar de duas fontes e o roadmap entrega uma. O modelo
`PROVISÓRIO` reduz o dano — as migrações são reversíveis —, mas não elimina: vocabulário e
hábito não têm migração reversível.

**Correção exigida.** Simetria. O corpus precisa ser **dois**, não um:

1. Corpus gravado de alertas do Wazuh — já exigido.
2. **Corpus gravado de telemetria de endpoint** — arquivos `.evtx` exportados de uma VM
   Windows com Security Log auditado, e/ou uma sessão ETW gravada em `.etl`. Ambos são
   capturáveis em uma tarde, sem Collector Agent, sem integração e sem tocar máquina real
   (VM descartável, §9.4 respeitada).

Só com os dois a Fase 3 satisfaz o limiar que a própria Lei 4 estabelece. O custo é uma
captura; o benefício é que a lei passa a valer no momento em que ela importa.

### [MAJOR-13] O corpus virou peça de sustentação da Lei 4 e não tem requisito de proveniência

**Arquivo:** `00-CONSTITUTION.md` — Lei 4

A emenda tornou o corpus **obrigatório** e o colocou como a evidência que satisfaz a Lei 4
na Fase 3. Mas não exige que ele registre: versão do Wazuh que o produziu, data de captura,
configuração de regras e decoders ativos, e se as fontes dos alertas são as mesmas que o
Poseidon usará em produção.

**Cenário de falha.** O corpus é capturado de um Wazuh 4.14.7 com decoder `windows` lendo
o canal **do Sysmon** — que é, inclusive, exatamente a forma do exemplo de alerta no
`00-RESEARCH.md` do Builder (`"channel": "Microsoft-Windows-Sysmon/Operational"`). A v2.0
acabou de tirar o Sysmon do produto. O normalizador é então validado, na Fase 3, contra
alertas derivados de uma fonte que o produto não usa. Na Fase 9, o Wazuh real produz
alertas com outra forma, e a Lei 4 não pega — porque a Lei 4 já foi "cumprida" na Fase 3
com um corpus cuja procedência ninguém registrou.

**Correção exigida.** O corpus é artefato versionado, com manifesto: versão do Wazuh, data,
ruleset, e **de quais canais/fontes os alertas se originaram**. Um corpus sem manifesto não
satisfaz a Lei 4, porque não é auditável — e a Lei 1 exige que o que sustenta uma afirmação
seja rastreável.

---

## BLOCKER-03 — ✅ FECHADO

**O que foi pedido:** declarar o alcance da Lei 8 sobre caminhos de terceiros; restringir
o conector Wazuh; registrar que a credencial equivale a execução de código na frota.

**O que a v2.0 fez:** as três. O título mudou para *"Nenhum caminho de execução arbitrária,
próprio ou de terceiro"*. O texto diz *"A proibição é da plataforma, não de um
componente"*, cita a evidência da tag v4.14.7 nominalmente, lista as quatro proibições
concretas (`!`, `agents_list` omitido, `upgrade_custom`, `arguments` derivados de entrada
do usuário) e registra o fato arquitetural: *"a credencial da API do Wazuh equivale a
execução de código na frota Wazuh. Ela recebe o mesmo nível de proteção de uma chave de
assinatura."*

Correção precisa, e a mais bem escrita da emenda.

### [MAJOR-14] As proibições da Lei 8 não têm ponto de imposição nem exigência de teste

**Arquivo:** `00-CONSTITUTION.md` — Lei 8

A lista `❌ / ✅` é **política**, não **mecanismo**. A lei não diz onde a proibição é
imposta, nem que ela seja coberta por teste. Compare com a Lei 10, que acabou de ganhar
*"documentado e **testado**"* no item 5 — a Lei 8 não ganhou equivalente.

Uma proibição sem ponto de imposição sobrevive ao primeiro Builder e morre no terceiro.

Além disso, `✅ usa conta com RBAC restrito no próprio Wazuh` não nomeia **a quê**. A spec
v4.14.7 declara as ações RBAC por endpoint (`x-rbac-actions`), então é possível ser
específico — e sem ser específico, "restrito" é aspiração.

**Cenário de falha.** O conector implementa as quatro proibições na v0.1. Seis meses
depois, uma funcionalidade de "resposta customizada" passa `arguments` montados a partir de
um campo de formulário do analista. Nenhum teste quebra, porque nunca existiu teste para
isso, e a revisão não lembra da lista.

**Correção exigida.** (a) Nomear o ponto único de imposição — o conector Wazuh valida e
**rejeita**, e nenhuma outra camada monta requisição de Active Response. (b) Exigir teste
que prove a rejeição de cada um dos quatro casos. (c) Nomear as ações RBAC a negar na conta
do Poseidon — no mínimo `agent:upgrade` (fecha `upgrade_custom`), mantendo
`active-response:command` sob a restrição do conector.

---

## BLOCKER-04 — ✅ FECHADO

**O que foi pedido:** remover isolamento total do MVP, ou dar-lhe contrato próprio; e
distinguir "perdeu contato porque quebrou" de "perdeu contato porque foi isolado".

**O que a v2.0 fez:** escolheu a opção mais limpa e foi além.

- Lei 10, item 2: *"**Isolamento total está fora do MVP**"*, com a justificativa correta
  explicitada — transporte outbound-only, host totalmente isolado é host inalcançável,
  *"prometer contenção total sem dizer isso é mentir para o analista"*.
- §11 acrescentou `isolamento total` à lista de fora de escopo.
- O dead-man's-switch por perda de contato **saiu** e foi substituído por expiração
  absoluta persistida (item 3) + watchdog fora do processo (item 4) + caminho de
  recuperação fora de banda testado (item 5).
- A lei fecha nomeando a distinção que eu havia apontado.

A incompatibilidade lógica não existe mais. O achado está fechado.

**Mas a nova redação é onde estão os dois achados mais graves desta rodada.** A decisão
falha-fechado é do humano e não a discuto; o que discuto é o mecanismo que a lei agora
descreve.

### [BLOCKER-06] A expiração do isolamento é persistida em disco sem integridade — o host isolado controla a própria libertação

**Arquivo:** `00-CONSTITUTION.md` — Lei 10, itens 3 e 4, contra Lei 9
**Lei/dimensão violada:** Lei 9 (autorização assinada) e o contrato de isolamento;
dimensões 4.1 e 4.3

**Evidência.** Lei 10, item 3: *"**Expiração absoluta persistida em disco.** Toda ação de
isolamento grava um instante de expiração. Passado esse instante sem reautorização, o
isolamento cai."*

Item 4: *"**Watchdog independente do serviço do agente** — mecanismo do sistema operacional
… responsável por honrar a expiração do item 3 mesmo que o agente esteja morto, travado ou
desinstalado."*

A Lei 9 exige que a **ação** seja assinada, com `nonce`, `expires_at` e verificação pelo
agente. Nada, em nenhuma lei, exige que o **registro de expiração em disco** seja assinado,
encadeado ou de outra forma à prova de adulteração. E o watchdog, por construção, precisa
funcionar **sem o agente** — logo sem o componente que detém a lógica de verificação de
assinatura da Lei 9.

**Cenário de falha.** Host comprometido, atacante com privilégio administrativo local —
que é a premissa de qualquer isolamento, porque isolar um host pressupõe que ele está
comprometido. Analista isola às 10:00, expiração gravada para 22:00. Às 10:02 o atacante
edita o registro de expiração em disco para 09:00 — ou simplesmente adianta o relógio do
sistema, contra o qual a constituição continua sem defesa (`MAJOR-09`, rodada 1, não
endereçado). O watchdog do item 4 cumpre seu dever e restaura a conectividade. O Poseidon
registra "isolamento expirado", que é indistinguível do caso legítimo.

A contenção falha **e parece ter funcionado**. Pior que falhar barulhentamente.

**Impacto.** O contrato de isolamento — que o §8 nomeia explicitamente como critério de
BLOCKER — tem uma superfície de controle não autenticada, no próprio host que ele deveria
conter. A decisão falha-fechado, que existe para garantir contenção, é revertida à escolha
do atacante. E o `MAJOR-09` da rodada 1 deixa de ser risco teórico: o relógio virou insumo
de uma decisão de segurança executada por um componente sem verificação de assinatura.

**Correção exigida.** A Lei 10 precisa estender à expiração a mesma garantia que a Lei 9 dá
à ação:

1. O registro de expiração é **o objeto de ação assinado da Lei 9**, persistido íntegro —
   não um timestamp solto derivado dele. O watchdog **verifica a assinatura** antes de
   restaurar; falha na verificação é falha-fechado (mantém o isolamento) e gera sinal.
2. A base de tempo do watchdog não pode ser o relógio local do host isolado sozinho. No
   mínimo: monotônico desde a aplicação (imune a salto de relógio), e divergência entre
   monotônico e relógio de parede tratada como sinal (Lei 12).
3. Adulteração detectada do registro é evento de segurança de severidade alta — é
   indicador de que o host contido está sendo operado.

Isto também fecha, de lambuja, o `MAJOR-09` no caminho que mais importa.

### [MAJOR-15] O watchdog "do sistema operacional" não é identificado, e "mesmo que desinstalado" contradiz desinstalação limpa

**Arquivo:** `00-CONSTITUTION.md` — Lei 10, item 4

A lei exige *"mecanismo do sistema operacional, não um timer dentro do processo"* que honre
a expiração *"mesmo que o agente esteja morto, travado ou **desinstalado**"*. Não nomeia o
mecanismo, e os candidatos óbvios não satisfazem o enunciado:

- **Tarefa agendada (Scheduled Task):** removível com o mesmo privilégio administrativo
  necessário para matar o agente. Não sobrevive a um atacante, só a um crash.
- **Segundo serviço Windows:** idem, e agora há dois componentes com autoridade sobre o
  firewall, sem que a constituição diga qual é a fonte da verdade entre eles.
- **Sessão dinâmica do WFP:** resolveria a morte do processo automaticamente, mas cai no
  reboot — e a decisão do humano é justamente sobreviver ao reboot. Incompatível aqui.

E há a contradição de ciclo de vida: se o watchdog sobrevive à **desinstalação** do
Poseidon, então desinstalar o produto deixa na máquina do cliente um artefato residual com
poder sobre o firewall. Se não sobrevive, o item 4 não é cumprido. A lei exige as duas
coisas.

**Correção exigida.** Nomear o mecanismo no ADR-006, e separar os dois casos que a redação
atual junta: **falha do agente** (watchdog local cobre) e **remoção deliberada do agente**
(não é cobrível localmente — é o caminho de recuperação fora de banda do item 5, com
autorização, não automação). Definir também qual componente é a fonte da verdade do estado
de isolamento quando agente e watchdog discordam.

### [MAJOR-16] O caminho de recuperação fora de banda não é qualificado como local

**Arquivo:** `00-CONSTITUTION.md` — Lei 10, item 5

*"**Caminho de recuperação fora de banda**, documentado e testado, capaz de remover o
isolamento de uma máquina cujo agente não responde mais."*

Não diz se é local ou remoto. As duas leituras são ruins de formas opostas:

- **Remoto:** contradiz o próprio isolamento. Ou o canal existe — e então é uma exceção de
  firewall não declarada, que um atacante no host pode tentar usar — ou não existe, e o
  caminho não funciona.
- **Local/físico** (mídia de boot, modo de segurança, procedimento documentado de remoção
  do filtro): coerente, mas precisa estar dito, porque muda o que a Fase 8 entrega e o que
  o runbook promete ao operador.

**Correção exigida.** Qualificar explicitamente como **local, com acesso físico ou
console**, e proibir canal remoto de recuperação — ou, se remoto for desejado, tratá-lo como
capacidade da Lei 8, com autorização assinada da Lei 9, e declará-lo como exceção de
firewall no item 2.

---

## Achado novo sobre a decisão de ETW

A substituição Sysmon → ETW foi consequência de um achado meu (`MAJOR-04`, EULA da
Sysinternals) combinado com a decisão de SaaS. A **decisão de tirar o Sysmon do produto
está correta e não a contesto.** O que auditei é o substituto, tal como a §4 o especifica.

### [BLOCKER-07] A §4 fixa como resolvido um caminho técnico que o próprio `01-BUILDER.md` marca como bloqueante e não verificado

**Arquivo:** `00-CONSTITUTION.md` §4 (Stack · Collector Agent)
**Lei/dimensão violada:** Lei 1; dimensão 4.2

**Evidência do conflito interno.** A §4 da constituição afirma, em modo declarativo:

> *"O Collector consome **ETW** (`Microsoft-Windows-Kernel-Process`,
> `Microsoft-Windows-DNS-Client` e equivalentes) e o **Windows Event Log** via
> `wevtapi.dll` (`EvtSubscribe`/`EvtRender` sobre `golang.org/x/sys/windows`, sem CGO)."*

O `01-BUILDER.md` §7.4, atualizado na mesma emenda, instrui:

> *"**ETW**: viabilidade de consumo direto em Go sem CGO; provedores equivalentes a criação
> de processo, conexão de rede e consulta DNS; exigência de assinatura anti-malware/PPL para
> provedores sensíveis; cobertura comparada ao Sysmon. **Este item é bloqueante** — a Fase 5
> inteira depende da resposta."*

A constituição decidiu; o documento de papel manda pesquisar depois. Pela Lei 1, a ordem
está invertida — e a constituição tem precedência, então o que ficou normativo foi a
versão não verificada.

Na rodada 1 eu havia escrito, sobre exatamente esta alternativa: *"**[NV]** Não verifiquei
cobertura, exigência de PPL/assinatura anti-malware para os provedores sensíveis, nem
esforço. Registro como alternativa que o ADR-005 deve ao menos nomear e recusar
conscientemente — **não como recomendação**."* A emenda a promoveu de alternativa não
verificada a item de stack.

**Evidência técnica — verificada agora, e o resultado é ruim.**

O provedor nomeado **não entrega linha de comando**. Resposta oficial da Microsoft, em
`learn.microsoft.com`, à pergunta direta "how can I get the CommandLine through the process
start event provided by Microsoft-Windows-Kernel-Process":

> *"Win32 doesn't expose a process's command line to other processes. From Win32's point of
> view, the command line is just a string that is copied into the address space of the new
> process."*

Fonte: https://learn.microsoft.com/en-us/answers/questions/1331639/how-can-i-get-the-commandline-through-the-process
(consultada em 2026-09-20). O campo `CommandLine` aparece no manifesto do provedor, mas não
é populado de forma confiável para observadores externos.

Perda de capacidade que a §4 não reconhece, comparando com o Sysmon Event ID 1 que ela
substitui:

| Campo | Sysmon EID 1 (verificado, doc de 2026-09-10) | `Microsoft-Windows-Kernel-Process` |
|---|---|---|
| `CommandLine` | sim, completa | **não confiável** |
| `ParentCommandLine` | sim | **não** |
| `ProcessGuid` / `ParentProcessGuid` | sim, imune a reúso de PID | não (só PID/ParentId) |
| `Hashes` (SHA256/IMPHASH) | sim, calculados pelo driver | **não** |
| `IntegrityLevel`, `LogonGuid` | sim | não |

**Cenário de falha.** A Fase 5 é planejada assumindo paridade com o Sysmon. Na
implementação descobre-se que não há linha de comando. A alternativa disponível é o
**Security Event ID 4688**, que o próprio Builder documentou corretamente — mas 4688 (a)
depende da GPO *"Include command line in process creation events"*, **desligada por
padrão**, (b) não traz linha de comando do processo pai, e (c) não traz hash nem GUID de
processo. O resultado é que a maior parte do corpus de regras Sigma para Windows, que casa
em `CommandLine`, deixa de funcionar — em silêncio, porque a telemetria continua chegando.

É o `MAJOR-03` da rodada 1 (redação vs. Sigma) reaparecendo por outra porta, e desta vez
sem que ninguém tenha escolhido.

**Impacto.** A Fase 5 inteira, mais toda a engenharia de detecção da Fase 11. E a
constituição, que é o documento de precedência, afirma como resolvido algo que não está —
que é a definição de BLOCKER no §8 (*"baseia código em API não verificada"*).

**Correção exigida.** Não desfazer a decisão — completá-la. A §4 precisa dizer **de onde
vem cada campo**, não apenas qual API é usada:

1. **Linha de comando vem do Security 4688**, com a GPO como **requisito de implantação
   declarado**, e a sua ausência tratada como degradação de saúde pelo Health Center
   (Lei 12) — não como silêncio.
2. **Hashes**: calculados pelo próprio Collector, com o custo de I/O e a corrida com
   exclusão de arquivo assumidos explicitamente.
3. **`ParentCommandLine`**: aceitar a perda, ou derivá-la de uma árvore de processos que o
   agente mantém em memória — decisão do ADR-005, com a consequência registrada.
4. Reclassificar a §4 sobre ETW de afirmação para **decisão condicionada à pesquisa
   bloqueante do `01-BUILDER.md` §7.4**, até que essa pesquisa exista.

### [MAJOR-17] A cadeia de suprimento do consumo de ETW em Go é frágil, e a §4 a trata como resolvida

**Arquivo:** `00-CONSTITUTION.md` §4

A §4 junta numa frase **duas APIs diferentes do Windows**, com maturidades muito diferentes
em Go:

- **Windows Event Log** (`wevtapi.dll`: `EvtSubscribe`, `EvtQuery`, `EvtRender`) — chamada
  por handle, mapeável direto sobre `golang.org/x/sys/windows`. A afirmação da §4 é
  plausível aqui. *(Não implementei; não afirmo mais que plausível.)*
- **ETW em tempo real** (`advapi32`: `StartTrace`, `OpenTrace`, `ProcessTrace`) — API
  baseada em callback, com `ProcessTrace` bloqueando a thread do SO até o fim da sessão.
  Não é a mesma coisa, e `golang.org/x/sys/windows` não a cobre de forma pronta.

Estado real das bibliotecas Go de **consumo** de ETW, verificado na API do GitHub em
2026-09-20:

| Biblioteca | Licença | Último push | Estrelas | Nota |
|---|---|---|---|---|
| `tekert/goetw` | **GPL-3.0** | 2026-06-09 | 10 | a mais capaz e a única mantida com tração |
| `Velocidex/etw` | MIT | 2026-09-15 | 1 | fork pessoal |
| `fredwangwang/etw` | MIT | 2026-08-16 | 0 | fork pessoal |
| `bi-zone/etw` | MIT | **2022-07-13** | 75 | upstream dos forks, parado há ~4 anos |
| `0xrawsec/golang-etw` | **GPL-3.0** | **2022-09-22** | 46 | parado |
| `microsoft/go-winio` `pkg/etw` | MIT | ativo | 1.079 | **é produtor, não consumidor** — só escreve eventos |
| `Microsoft/krabsetw` | — | ativo | 801 | C++/.NET — exige CGO ou runtime, ambos vedados pela §4 |

Consumo de ETW em Go sem CGO **é possível** — não estou dizendo que a §4 é impossível. Estou
dizendo que a opção mantida e capaz é **GPL-3.0**, e que as opções MIT são forks pessoais
com 0 e 1 estrela.

**Por que a licença importa aqui especificamente:** o Collector Agent é **distribuído** —
instalado no endpoint do cliente. GPL-3.0 incorporada a um binário distribuído impõe a
GPL-3.0 ao binário inteiro, com oferta de fonte e cláusula anti-tivoization. Para um agente
de segurança assinado, de um produto SaaS, isso é decisão de produto, não detalhe de
dependência. Note a ironia: o Sysmon saiu por restrição de licença, e a substituição entrou
com outra.

**Correção exigida.** ADR-005 decide explicitamente entre: (a) MIT a partir de um fork
pessoal, assumindo manutenção própria; (b) GPL-3.0 com as consequências de distribuição
mapeadas; (c) implementação própria das chamadas de `advapi32` — o que é trabalho real e
precisa de estimativa, não de uma linha na §4.

---

## Outros efeitos da emenda

### [OBSERVATION-12] Lei 13 e a seção de multi-tenancy fecham três achados da rodada 1

A Lei 13 nova absorve, corretamente: `MINOR-05` (atribuição de autor de regra do SigmaHQ
no alerta, com a citação exata da DRL 1.1), a obrigação de aviso de copyright do ATT&CK,
a exigência de ADR de termos de uso para feeds de CTI, e `OBSERVATION-01` (LGPD),
elevando-a de ausência a requisito de desenho. A seção "Multi-tenancy: não construída, mas
não impedida" fecha `MAJOR-10` na parte que importava — identificação de tenant desde a
Fase 2, e o roadmap foi atualizado coerentemente.

A formulação *"obrigações que viajam com o dado, não com o repositório"* é precisa e é o
enquadramento certo.

### [MINOR-08] O §11 ainda expressa exclusão permanente como prazo, e agora contradiz a Lei 10

`MAJOR-10` da rodada 1 foi resolvido para multi-tenant, mas a redação *"Proposta de
qualquer um desses itens **antes da Fase 13** deve ser recusada"* continua — e a emenda
acrescentou `isolamento total` a essa lista.

A Lei 10 proíbe isolamento total por uma razão arquitetural — transporte exclusivamente
outbound — que **não expira na Fase 13**. Pela letra do §11, a partir da Fase 13 eu não
tenho base para recusar a proposta; pela Lei 10, continuo tendo. Duas seções da mesma
constituição, respostas diferentes.

**Correção:** separar a lista em "excluído do produto" (isolamento total, NDR, UEBA, ML) e
"adiado para Fase 13+", como eu havia sugerido na rodada 1.

### Razão dos achados da rodada 1 não endereçados

Para o humano saber onde está o passivo. Continuam **abertos** e sem menção na v2.0:

| ID | Assunto | Observação |
|---|---|---|
| `MAJOR-01` | integridade do Audit Log (append-only sem mecanismo) | intocado |
| `MAJOR-03` | redação de linha de comando vs. detecção Sigma | intocado, e agravado por `BLOCKER-07` |
| `MAJOR-05` | identidade/enrolamento/revogação do agente | intocado |
| `MAJOR-06` | retenção e cotas | Lei 13 cobre retenção de **dado pessoal**; retenção de evento/evidência continua sem lei nem fase |
| `MAJOR-07` | atualização do agente em campo | intocado |
| `MAJOR-09` | confiança no relógio do endpoint | intocado — e agora é insumo do `BLOCKER-06` |
| `MAJOR-11` | versão de schema no evento persistido | intocado |
| `MAJOR-12` | rotação de credenciais | intocado — e a Lei 8 acabou de declarar que a credencial do Wazuh vale uma chave de assinatura |
| `MINOR-01` a `MINOR-04`, `MINOR-06` | processo e redação | intocados |

Fechados pela emenda: `MAJOR-02` (o `01-BUILDER.md` §7.4 agora diz que a API do Manager
*"não serve alertas"* e descreve o conector duplo), `MAJOR-04` (Sysmon saiu do produto),
`MAJOR-10` (parcial, ver `MINOR-08`), `MINOR-05` e `OBSERVATION-01` (viraram Lei 13).

---

# PARTE II — Confronto das duas pesquisas

Comparei `00-RESEARCH.md` (Builder) com `03-AUDIT-RESEARCH.md` (Auditor). Toda divergência
foi levada à fonte primária. Quando a fonte contraria a mim, digo que contraria a mim.

## Quadro de divergências

| # | Ponto | Builder | Auditor | Fonte primária sustenta |
|---|---|---|---|---|
| D1 | OCSF classe 1004 | "Registry Activity" | `memory_activity`; registro está na extensão `win` | **Auditor** |
| D2 | OCSF classe 3001 | "Authentication" | `account_change` (depreciada); Authentication é 3002 | **Auditor** |
| D3 | OCSF classe 2001 | "Security Finding — perfeita para integrar Wazuh" | depreciada desde 1.1.0 → usar `detection_finding` (2004) | **Auditor** |
| D4 | Categorias OCSF | "1 a 6" | 8 categorias; falta 7 Remediation e 8 Unmanned Systems | **Auditor** |
| D5 | Versão do OCSF | "estável v1.3.0/v1.4.0; repo em v1.9.0" | 1.9.0 é a versão corrente (2026-08-03) | **Auditor** |
| D6 | Biblioteca Python OCSF | `pyocsf` | `ocsf-lib`; e `py-ocsf-models` (Pydantic) | **Auditor** no nome; **Builder** na direção |
| D7 | `wazuh-indexer-plugins` AGPL-3.0 | sim | **não levantei este repositório** | **Builder** |
| D8 | `wazuh-dashboard-plugins` | "GPLv2 / AGPL-3.0" | GPL-2.0 | **Auditor** |
| D9 | Agente Wazuh 5.x AGPL-3.0 | ausente | `wazuh/wazuh-agent` = AGPL-3.0 | **Auditor** (complemento) |
| D10 | API do Manager não serve alertas | sim | sim | **ambos — convergência** |
| D11 | ECS: doação ao OTel gera incerteza | sim | fonte oficial não sustenta; ECS 9.5.0 em 2026-08-04 | **Auditor** |
| D12 | Limite de taxa do OTX | "10.000/h", marcado VERIFICADO | não verificado em fonte primária | **número plausível; status errado** |
| D13 | Endpoints de indicador do OTX | `/indicators/{tipo}/{ioc}/general` | idem, lido do SDK | **ambos — Builder correto** |
| D14 | SDK do OTX parado / marca LevelBlue | ausente | parado desde 2024-05-09 | **Auditor** (complemento) |
| D15 | `sighting` é SRO | sim, com campos corretos | sim | **ambos — e o Builder corrigiu o `01-BUILDER.md`** |
| D16 | DRL 1.1 / atribuição de autor | ausente | exigida; virou Lei 13 | **Auditor** |
| D17 | Licença e versão do ATT&CK | ausentes | v19.2; aviso de copyright obrigatório | **Auditor** |
| D18 | `SeSecurityPrivilege` para o canal Security | exigido; Event Log Readers não basta | não levantei | **Builder** |
| D19 | `wevtapi` em Go sem CGO | afirmado | plausível, não verificado por mim | **indeterminado** — ver `MAJOR-17` |

## As divergências que mudam decisão

### D3 — O argumento central do Builder para OCSF repousa numa classe depreciada

É a divergência mais cara. O `00-RESEARCH.md` §2.2.3 apresenta, como linha decisiva da
tabela comparativa OCSF × ECS:

> *"**Modelagem de Findings (Alertas):** Nativa (`Class 2001 - Security Finding`), perfeita
> para integrar Wazuh"*

Consulta a `https://schema.ocsf.io/api/classes/security_finding` em 2026-09-20 devolve:

```json
"uid": 2001, "name": "security_finding", "caption": "Security Finding",
"@deprecated": {
  "message": "Use the new specific classes according to the use-case:
     vulnerability_finding, compliance_finding, detection_finding,
     incident_finding, data_security_finding",
  "since": "1.1.0"
}
```

**Depreciada desde a versão 1.1.0** — oito versões menores atrás. A classe correta para
alertas de detecção de terceiros é **`detection_finding` (2004)**, que não está depreciada.

A **conclusão** do Builder (preferir OCSF) permanece defensável, e eu concordo com ela. O
**argumento** não: se implementado como escrito, o normalizador de alertas do Wazuh nasce
sobre uma classe que o OCSF já pediu para abandonar, e a migração cairia justamente no
congelamento da Fase 9.

### D1, D2, D4, D5 — o mapa de classes do OCSF está desatualizado em bloco

Verificado em `https://schema.ocsf.io/api/classes` e `/api/categories` (2026-09-20):

| Afirmação do Builder | Verificado |
|---|---|
| "Class 1004 — Registry Activity" | 1004 é `memory_activity`. Registro é `win/registry_key_activity` **201001** e `win/registry_value_activity` **201002**, na extensão `win` — `/api/classes/registry_key_activity` devolve **404** no núcleo |
| "Class 3001 — Authentication" | 3001 é `account_change`, **depreciada desde 1.9.0** (→ `user_management`). Authentication é **3002** |
| "Categorias (1 a 6)" | São 8. Falta **7 Remediation** (`remediation_activity` 7001, `file_` 7002, `process_` 7003, `network_` 7004) e 8 Unmanned Systems |
| "estável v1.3.0/v1.4.0, repo em v1.9.0" | `/api/version` → `{"version":"1.9.0"}`; release 1.9.0 em 2026-08-03; 1.4.0 é de 2025-02-05 |

D5 provavelmente **explica** D1–D4: o levantamento foi feito contra uma leitura do schema
com cerca de dezenove meses de atraso.

Três consequências práticas:

1. **Eventos de registro do Windows obrigam a extensão `win`.** Isso muda pipeline de
   validação e versionamento, e precisa ser decisão explícita do ADR-002 — eu já havia
   levantado isso; a pesquisa do Builder não o registra porque acreditava haver classe no
   núcleo.
2. **A categoria 7 (Remediation) passou despercebida** e é diretamente relevante: o
   Response Control Plane executa remediação, e o OCSF tem classes nativas para isso. É
   argumento *a favor* do OCSF que o Builder não usou.
3. **A classe de autenticação está errada por um dígito** — e o alvo certo, 3002, é o que
   recebe os eventos 4624/4625 que o próprio Builder documentou na §2.7.1.

### D6 — eu estava parcialmente errado sobre o ferramental do OCSF

O Builder cita *"Bibliotecas Python (`pyocsf`)"*. `https://pypi.org/pypi/pyocsf/json`
devolve **404** — o pacote não existe com esse nome, e a afirmação não tem fonte.

Mas ao verificar, encontrei algo que **melhora o quadro que eu mesmo havia reportado**:

| Pacote | Versão | Licença | Origem |
|---|---|---|---|
| `ocsf-lib` | 0.10.4 | Apache-2.0 | `ocsf/ocsf-lib-py` |
| **`py-ocsf-models`** | **0.10.0** | **Apache-2.0** | **`prowler-cloud/py-ocsf-models`**, push em 2026-09-07 |

`py-ocsf-models` é uma implementação dos modelos OCSF **em Pydantic**, mantida pela equipe
do Prowler. Na rodada 1, meu `OBSERVATION-06` afirmou que "modelos OCSF serão escritos e
mantidos à mão" com base apenas nos repositórios da organização `ocsf`. **Essa conclusão
foi apressada** — eu olhei a organização, não o ecossistema. Correção em
"Onde eu estava errado", abaixo.

### D7 — o Builder encontrou um repositório que eu não levantei

`wazuh/wazuh-indexer-plugins` é declarado **AGPL-3.0** (API do GitHub, 2026-09-20). Eu
consultei `wazuh`, `wazuh-indexer`, `wazuh-dashboard`, `wazuh-dashboard-plugins`,
`wazuh-agent` e `wazuh-qa`, e **não consultei este**. O Builder consultou, e a implicação
que ele extrai está correta: não estender nem modificar plugins do Indexer; tratar o
Indexer como OpenSearch padrão.

É o melhor achado da pesquisa dele, e é exatamente o tipo de coisa que justifica duas
pesquisas independentes.

### D8 — a outra metade da afirmação de licença não se sustenta

O Builder registra `wazuh-dashboard-plugins` como *"GPLv2 / AGPL-3.0"*. O `LICENSE` bruto
em `master` **e** em `main` é o texto da **GNU General Public License Version 2, June 1991**,
e o SPDX declarado no GitHub é `GPL-2.0`. Não localizei AGPL nesse repositório.

Não muda decisão — a Lei 3 já proíbe tocar no dashboard — mas na matriz de verificação da
Lei 1 a linha está marcada **VERIFICADO** para uma afirmação dupla cuja metade não confere.

### D11 — o argumento contra o ECS não se sustenta na fonte

O Builder escreve que a doação ao OTel *"gera incerteza sobre a governança de longo prazo"*,
classifica a neutralidade do ECS como *"Média/Baixa"* e afirma que o ECS *"requer adaptação
contínua pós-fork Elastic"*.

Verificado:

- A página oficial da Elastic sobre ECS e OpenTelemetry descreve a doação como *"a
  directional decision for the evolution of both standards rather than a single event that
  merged both schemas into a single standard"*. Não há anúncio de sunset.
- O ECS publicou **v9.5.0 em 2026-08-04** — um dia depois do OCSF 1.9.0 — sob **Apache-2.0**,
  com o repositório ativo (push em 2026-09-18).
- *"pós-fork Elastic"* confunde duas coisas: o **Elasticsearch** foi relicenciado para
  SSPL/Elastic License; o **ECS** é Apache-2.0. E o ECS é uma convenção de nomes de campo —
  não exige Elasticsearch para ser usado, nem requer adaptação para rodar em OpenSearch.

Eu havia registrado isto preventivamente na rodada 1 (`OBSERVATION-05`) como "o atalho
retórico mais provável a favor do OCSF". Ele foi usado.

**Isto não reverte a escolha.** OCSF continua sendo, na minha leitura, a escolha certa — por
razões verificáveis que o Builder não usou: classes nativas de **remediação** (categoria 7),
`detection_finding` (2004) para alertas de terceiros, extensão `win` formal para registro,
e `metadata.loggers` para cadeia de ingestão. O ADR-002 deve ser escrito sobre essas razões,
não sobre o obituário do ECS.

### D12 — o número do OTX é provavelmente certo; o rótulo "VERIFICADO" não é

O Builder registra *"Limite documentado de referência: até 10.000 requisições por hora com
chave autenticada"* e marca a linha de OTX como **VERIFICADO** na matriz da Lei 1.

Fontes secundárias corroboram o par 1.000/h anônimo e 10.000/h autenticado. **Não localizei
isso em documentação primária** — a página `otx.alienvault.com/api` é renderizada por
JavaScript e não é verificável automaticamente. O que consegui verificar em fonte primária
é que o SDK oficial trata `429` (`status_forcelist=[429, 500, 502, 503, 504]`), o que prova
que existe limite, não qual é.

O número deve ser tratado como orientação de projeto, não como constante de código; e a
linha da matriz deveria ler `NÃO VERIFICADO` quanto ao valor. É a Lei 1 aplicada ao grão
certo: a matriz verifica por *linha*, e cada linha contém várias afirmações.

### D16, D17 — ausências do Builder que a emenda tornou normativas

A §2.4 do `00-RESEARCH.md` cobre Sigma em detalhe — estrutura da regra, `logsource`,
modificadores, backend OpenSearch — e **não menciona licenciamento**. A seção de ATT&CK
(§2.8) descreve formato e sincronização e **não menciona a licença**.

Desde a emenda, ambas são obrigações de schema pela **Lei 13**: alerta gerado por regra do
SigmaHQ carrega o autor da regra; o aviso de copyright do ATT&CK existe no produto. O
Builder precisa incorporar as duas ao `01-PLAN.md` e ao ADR-004.

Complemento verificado que não está no documento dele: a especificação Sigma é **domínio
público** e está em `v2.1.0` (2025-09-12); as **regras** são DRL 1.1; e o ferramental
pySigma é **LGPL-2.1/3.0** — o que é decisão de licença própria, não coberta pela Lei 13.

### D13, D15, D18 — onde o Builder está certo e eu não tinha o dado

Registro por simetria, porque um relatório que só lista erros do outro lado não é auditoria.

- **D13:** os endpoints de indicador do OTX conferem. O SDK constrói
  `/api/v1/indicators/{tipo}/{indicador}/{seção}` com `section='general'` por padrão
  (`create_indicator_detail_url`). A forma citada por ele está correta.
- **D15:** ele trata `sighting` corretamente como **SRO**, com `sighting_of_ref`,
  `where_sighted_refs`, `observed_data_refs`, `first_seen`, `last_seen`, `count` — e mapeia
  para a Lei 7 exatamente como eu propus, de forma independente. Meu `MINOR-04` apontava o
  erro no `01-BUILDER.md`, não nele. E a citação dele do STIX 2.1
  (`docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html`, HTTP 200 verificado) é **melhor
  que a minha**: aponta o OASIS Standard, enquanto eu citei o Errata 01, que é rascunho de
  comitê. Adoto a fonte dele.
- **D18:** *"Requer privilégio especial `SeSecurityPrivilege` para abertura e leitura do
  canal"* `Security`. As fontes que consultei confirmam que pertencer ao grupo
  **Event Log Readers não é suficiente** para o canal Security. É um detalhe operacional
  real que eu não havia levantado, e que decide se o Collector precisa rodar como
  `LocalSystem` — insumo direto do ADR-005.

### D10 — a convergência mais valiosa

Os dois documentos, por métodos independentes — ele pela documentação, eu enumerando os
*paths* da especificação OpenAPI da tag `v4.14.7` — chegaram à mesma conclusão: **a API do
Wazuh Manager não expõe alertas**. Ele foi além e documentou os dois caminhos alternativos
(Indexer na 9200 via `POST /wazuh-alerts-*/_search`, ou `alerts.json` em disco).

Quando duas pesquisas independentes convergem num achado contraintuitivo que contrariava a
instrução original do projeto, a confiança nesse achado é qualitativamente diferente. Este
pode ser tratado como estabelecido.

## Itens do Builder superados pela emenda (não são achados)

- §2.6 inteira (Sysmon como fonte) e §4.4 (*"Sysmon é opcional … modo adaptativo"*): o
  documento é de 10:46, a emenda é posterior. O conteúdo permanece útil como **referência de
  cobertura**, que é exatamente o papel que a §4 da v2.0 reserva ao Sysmon.
- §2.1.2, exemplo de Active Response com `{"command": "!firewall-drop"}`: era o payload
  padrão documentado pelo Wazuh; desde a emenda é **o padrão que a Lei 8 proíbe
  expressamente** (`❌ nunca envia command com prefixo '!'`). Precisa ser corrigido antes de
  virar código ou exemplo de conector.
- §2.1.3, exemplo de alerta com `"channel": "Microsoft-Windows-Sysmon/Operational"`: ver
  `MAJOR-13` — o corpus da Lei 4 não pode ser derivado de Sysmon.

## Observação sobre método, não sobre fatos

### [OBSERVATION-13] A matriz de verificação da Lei 1 verifica por linha; as afirmações estão no parágrafo

O `00-RESEARCH.md` §3 traz 14 linhas, todas marcadas **VERIFICADO**, e apenas 2 itens em
"Não Verificados". Meu levantamento tem 10.

A diferença não é diligência — é **granularidade**. Linhas como *"OCSF Class 1007 (Process
Activity) e Class 2001 (Security Finding) sob Linux Foundation — VERIFICADO"* agregam três
afirmações: 1007 (certa), 2001 (depreciada) e governança (certa). A linha inteira recebe um
carimbo. O mesmo acontece com a linha do OTX, que absorve o limite de taxa não verificado, e
com a de licenças, que absorve a metade AGPL não confirmada do `wazuh-dashboard-plugins`.

Não é má-fé; é que a Lei 1 opera no grão da afirmação e a matriz opera no grão da linha. O
`README.md` §"Sinais de que o processo está degradando" nomeia exatamente este risco:
*"`NÃO VERIFICADO` sumindo dos relatórios sem que nada tenha sido verificado"*.

**Sugestão:** uma afirmação por linha, e status por afirmação. Custa pouco e é o que faz a
matriz valer alguma coisa.

---

## Onde eu estava errado

Por exigência da §6 do `02-AUDITOR.md`. Estas correções valem contra o meu próprio
`03-AUDIT-RESEARCH.md`.

1. **`OBSERVATION-06` (ferramental OCSF) estava apressado.** Eu escrevi que "modelos OCSF
   serão escritos e mantidos à mão" tendo consultado apenas os repositórios da organização
   `ocsf`. Existe **`py-ocsf-models` 0.10.0** (Apache-2.0, `prowler-cloud`, push em
   2026-09-07), uma implementação dos modelos OCSF em **Pydantic** — diretamente aplicável
   ao stack da §4. O custo de ferramental do OCSF é **menor** do que eu reportei. O
   argumento continua válido em grau — 38 estrelas e mantenedor único não é o ecossistema do
   ECS — mas não na forma categórica em que o escrevi. O ADR-002 deve avaliar
   `py-ocsf-models` explicitamente.

2. **Omiti `wazuh/wazuh-indexer-plugins` (AGPL-3.0).** Enumerei seis repositórios do Wazuh e
   não incluí este. O Builder incluiu. A instrução era verificar **cada componente**, e a
   minha enumeração não foi exaustiva.

3. **Citei a fonte errada para o STIX 2.1.** Usei
   `docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html`, que serve o **Errata 01, Committee
   Specification Draft 01**. A citação correta para o OASIS Standard é
   `docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html`, que é a que o Builder usou.
   Eu compensei declarando o status do documento no texto, mas a fonte dele é a certa.

4. **Não levantei o requisito de `SeSecurityPrivilege`** para leitura do canal `Security`,
   que decide o contexto de execução do Collector. O Builder levantou.

---

## Verificações realizadas sem achado

- **Lei 4, mecânica de decidir≠congelar** — internamente coerente, e o `Supersedes:
  ADR-002` casa com a regra de imutabilidade de ADR do §10. Sem achado além do
  `BLOCKER-05`.
- **Lei 8, lista de restrições do conector Wazuh** — as quatro proibições são tecnicamente
  corretas e suficientes contra os vetores que documentei na rodada 1. O achado
  `MAJOR-14` é sobre imposição, não sobre conteúdo.
- **Lei 10, itens 1, 2 e 6** — snapshot, isolamento seletivo apenas, e teste obrigatório em
  VM: corretos e sem contradição com o restante.
- **Lei 13** — não encontrei erro. As duas citações de licença que ela faz conferem com os
  textos originais que li na rodada 1.
- **§11, seção de multi-tenancy** — o raciocínio (*"retroajustar tenant em um schema
  populado é projeto de migração; nascer com o campo é uma coluna"*) está correto, e a
  Fase 2 do roadmap foi atualizada de forma consistente.
- **`01-BUILDER.md` §7.4, correção sobre a API do Wazuh** — agora descreve corretamente o
  conector duplo. `MAJOR-02` fechado.
- **`00-RESEARCH.md` §2.7.1 (Security Log)** — eventos 4624, 4625, 4688, 4672 e a
  dependência de GPO para linha de comando no 4688: corretos e úteis. É, inclusive, a peça
  que resolve parte do `BLOCKER-07`.
- **`00-RESEARCH.md` §2.7.3 (wevtapi em Go)** — descrição das funções
  `EvtSubscribe`/`EvtQuery`/`EvtNext`/`EvtRender` e das flags consistente com a API do
  Windows. Não implementei; não achei erro.
- **`00-RESEARCH.md` §2.4 (Sigma)** — estrutura da regra, `logsource`, modificadores e
  backend correto. A lacuna é de licença (`D16`), não de técnica.
- **`00-RESEARCH.md` §2.8 (ATT&CK)** — repositório, formato de bundle STIX 2.1 e tipos de
  objeto (`attack-pattern`, `x-mitre-tactic`, `intrusion-set`, `malware`/`tool`) corretos.
  A lacuna é de licença e versão (`D17`).

---

## Não verificado

1. **Os oito ADRs em `docs/adr/` não foram auditados.** Existem em disco e não entraram no
   escopo desta rodada, que o humano definiu como emenda + comparação de pesquisas. A
   avaliação de formulação dos ADRs está no `03-AUDIT-REPORT.md` §"Avaliação dos ADRs
   propostos" e é **anterior** ao conteúdo que hoje está nesses arquivos. **Precisam de
   rodada própria antes de qualquer `PASS` da Fase 0.**
2. **Viabilidade prática do `wevtapi` em Go sem CGO** — plausível, não implementada nem por
   mim nem por ninguém neste repositório.
3. **`Microsoft-Windows-DNS-Client`** — nomeado na §4. Não verifiquei cobertura,
   disponibilidade por versão do Windows, nem paridade com o Sysmon EID 22.
4. **Exigência de PPL / assinatura anti-malware** para provedores ETW sensíveis (p. ex.
   `Microsoft-Windows-Threat-Intelligence`). Continua sem verificação, e é item da pesquisa
   bloqueante do `01-BUILDER.md` §7.4.
5. **Formato do alerta do Wazuh campo a campo.** O Builder apresenta uma estrutura concreta
   (`data.win.eventdata.commandLine`, `rule.mitre.id`, `full_log`). Não a verifiquei contra
   um Wazuh real. Ela é a base do corpus da Lei 4 e precisa ser confirmada na captura.
6. **Limite de taxa do OTX** — valor não confirmado em fonte primária (`D12`).
7. **Nenhum teste em VM.** Nada nesta rodada exercita isolamento, WFP, watchdog ou ETW em
   máquina real ou virtual.
8. **Nada jurídico.** AGPL-3.0 nos plugins do Indexer, GPL-3.0 na biblioteca de ETW,
   GPL-3.0 vs. distribuição do agente: reportei texto de licença e a consequência técnica.
   Interpretação não é minha.

---

## Resumo para decisão

**Rodada 1:** 4 BLOCKER · 12 MAJOR · 6 MINOR · 11 OBSERVATION
**Fechados pela emenda:** BLOCKER-01, BLOCKER-03, BLOCKER-04 · MAJOR-02, MAJOR-04 ·
MINOR-05 · OBSERVATION-01 · MAJOR-10 (parcial)
**Abertos nesta rodada:** 3 BLOCKER · 5 MAJOR · 2 MINOR · 4 OBSERVATION

**Saldo: 3 BLOCKER abertos.** A Fase 0 continua sem condição de `PASS`.

| ID | Achado | Origem |
|---|---|---|
| `BLOCKER-05` | Fase 3 modela contra fonte única — e a fonte é o Wazuh | resíduo do BLOCKER-02 |
| `BLOCKER-06` | Expiração do isolamento persistida sem integridade; host isolado se liberta | **criado pela emenda** |
| `BLOCKER-07` | §4 fixa ETW como resolvido; o provedor nomeado não entrega linha de comando | **criado pela emenda** |

Os dois últimos existem porque a emenda reescreveu as Leis 10 e a §4 — áreas que não tinham
esses defeitos na v1.0. Isso não é argumento contra a emenda: os defeitos que ela corrigiu
eram piores. É argumento a favor de auditar emenda como se audita código.

Ordem que eu recomendaria:

1. **`BLOCKER-07`** — é o que trava a Fase 5 inteira e o que mais depende de pesquisa, não
   de redação. A correção não desfaz a decisão de SaaS: especifica de onde vem cada campo.
2. **`BLOCKER-06`** — correção barata de redação (a expiração é o objeto assinado da Lei 9),
   e fecha de lambuja o `MAJOR-09` no caminho que importa.
3. **`BLOCKER-05`** — correção barata de execução: exigir o segundo corpus, de telemetria de
   endpoint, ao lado do corpus do Wazuh.

Sobre a pesquisa do Builder: **a conclusão principal (preferir OCSF) está certa; a base
factual que a sustenta precisa ser refeita contra o OCSF 1.9.0.** Classes 1004, 2001 e 3001
estão erradas, faltam duas categorias, e a versão de referência está cerca de dezenove meses
atrasada. O ADR-002 não deve ser escrito sobre o §2.2 como está.

E o crédito que importa: ele encontrou o `wazuh-indexer-plugins` AGPL-3.0, que eu não
levantei; acertou `SeSecurityPrivilege`; citou a fonte certa do STIX; e chegou
independentemente à mesma conclusão que eu sobre a inexistência do endpoint de alertas — a
convergência mais valiosa das duas pesquisas.
