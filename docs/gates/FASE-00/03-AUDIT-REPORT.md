# Auditoria — Fase 0

**Data:** 2026-09-20
**Auditor:** Auditor (sessão de bootstrap)
**Base:** repositório sem controle de versão inicializado; sem código de produção.

---

## Escopo

Auditado:

- `docs/prompts/00-CONSTITUTION.md` (v1.0, 18.771 bytes) — **alvo principal**
- `docs/prompts/01-BUILDER.md` (11.782 bytes) — auditado apenas quanto a contradições com
  a constituição e a afirmações técnicas verificáveis
- `docs/prompts/02-AUDITOR.md` (13.721 bytes) — idem
- `docs/prompts/README.md` (3.276 bytes) — protocolo operacional

Fora de escopo, por inexistência:

- Código de produção, testes, migrações, dependências, ADRs. Não existem. Nenhuma das
  dimensões 4.3 (Segurança), 4.4 (Correção), 4.5 (Qualidade de teste) e 4.8
  (Operabilidade) do `02-AUDITOR.md` pôde ser exercida sobre artefato real.
- `docs/gates/FASE-00/00-RESEARCH.md` do Builder — **deliberadamente não lido**, conforme
  `02-AUDITOR.md` §8.3. A comparação entre as duas pesquisas é etapa posterior.

**Nota sobre severidade.** A tabela do §8 da constituição foi escrita para achados sobre
código. Aqui ela é aplicada aos artefatos da Fase 0. Leia assim:

| Severidade | Significado nesta auditoria |
|---|---|
| **BLOCKER** | Defeito que, se não resolvido, faz o ADR correspondente nascer errado ou a lei ser inexequível. A Fase 0 não deve receber `PASS` com nenhum destes aberto. |
| **MAJOR** | Ausência ou erro que vai cobrar caro em fase identificável, e cuja correção é muito mais barata agora. |
| **MINOR** | Defeito de redação ou de processo sem consequência estrutural. |
| **OBSERVATION** | Risco futuro, insumo para decisão, ou divergência que o humano precisa conhecer. |

---

## Método

1. Leitura integral dos quatro documentos, duas passadas: a primeira para entender, a
   segunda procurando contradição entre seções distantes.
2. Verificação em fonte primária de **toda** afirmação técnica verificável contida nos
   documentos — não apenas das que pareciam duvidosas.
3. Pesquisa independente dos oito temas da Fase 0, registrada em
   `docs/gates/FASE-00/03-AUDIT-RESEARCH.md`. **Todas as evidências citadas abaixo têm
   fonte e data lá.**
4. Teste adversário das Leis 8, 9, 10 e 11 contra o mecanismo real que o roadmap propõe
   usar (Wazuh Active Response, Windows Filtering Platform, Sysmon).

Ferramentas: leitura de `LICENSE` nos repositórios de origem; download da especificação
OpenAPI do Wazuh na *tag* fixa `v4.14.7`; leitura de código-fonte do Wazuh na mesma *tag*;
consulta à API do schema OCSF (`schema.ocsf.io/api/*`); documentação oficial da Microsoft,
OASIS e Elastic. Data única de consulta: **2026-09-20**.

Profundidade por dimensão:

| Dimensão | Profundidade |
|---|---|
| 4.1 Conformidade com a constituição | alta — as doze leis, uma a uma |
| 4.2 Veracidade técnica | **alta — foco da sessão** |
| 4.6 Arquitetura | alta |
| 4.7 Escopo e documentação | média |
| 4.3 / 4.4 / 4.5 / 4.8 | **não exercidas** — sem artefato |

---

## Confirmação de leitura da constituição

Conforme `02-AUDITOR.md` §8.1, com minhas palavras:

**Lei 1.** Não se afirma nada sobre o comportamento de um sistema externo sem ter aberto a
documentação oficial e registrado link e data. Quando a verificação não foi possível, o
texto diz `NÃO VERIFICADO` e o item vira pendência aberta — nunca premissa silenciosa de
código. O propósito é impedir que o modo de falha dominante do desenvolvimento assistido
por IA — código construído sobre uma API imaginada — entre no produto.

**Lei 4.** O modelo de evento normalizado não pode ser congelado tendo sido exercitado
contra uma única fonte. Precisa de no mínimo duas fontes heterogêneas — Sysmon/Windows
Event Log e alertas do Wazuh. A razão é que um normalizador validado contra uma fonte só é,
por construção, o formato daquela fonte renomeado; a generalidade seria fictícia e só
apareceria como dívida quando a segunda fonte chegasse.

**Lei 8.** O Collector Agent não tem, e não pode ganhar, caminho de execução de comando
arbitrário. Ele expõe um conjunto fechado de capacidades nomeadas, implementadas em código
e verificadas por assinatura; qualquer coisa fora dessa lista é recusada **pelo próprio
agente**, não apenas pelo servidor. Isso inclui, explicitamente, disfarces: "plugin",
"script configurável", e passagem de argumentos não validados para uma capacidade legítima.
Ampliar a lista exige ADR, revisão de segurança e aprovação humana.

---

## Achados

### [BLOCKER-01] A Lei 5 inventa schema — que a Lei 2 proíbe — e decide o ADR-002 antes dele existir

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 5, contra Lei 2
**Lei/dimensão violada:** Lei 2 ("Não inventamos schema"); dimensão 4.1 e 4.6

**Evidência.** A Lei 2 estabelece que o evento normalizado adota **OCSF (preferência) ou
ECS**, com a decisão delegada ao ADR-002, e que extensões próprias devem ser "documentadas
como extensão do padrão e isoladas em namespace `poseidon.*`".

Três leis adiante, a Lei 5 fixa seis nomes de campo obrigatórios, sem namespace:

```
event_time · ingestion_time · source · source_event_id · raw_reference · correlation_id
```

Nenhum desses nomes existe em OCSF ou em ECS. Todos os seis conceitos, porém, **já existem
no OCSF 1.9.0**, verificado campo a campo em `https://schema.ocsf.io/api/classes/base_event`
e `https://schema.ocsf.io/api/objects/metadata` (2026-09-20):

| Lei 5 | OCSF 1.9.0 |
|---|---|
| `event_time` | `time` / `start_time` + `metadata.original_time` |
| `ingestion_time` | `metadata.logged_time` (+ `metadata.processed_time`) |
| `source` | `metadata.product` *(required)*, `metadata.source`, `metadata.log_provider` |
| `source_event_id` | `metadata.original_event_uid` (+ `metadata.event_code`) |
| `raw_reference` | `raw_data` / `raw_data_hash` / `raw_data_size` |
| `correlation_id` | `metadata.correlation_uid` |

O OCSF ainda oferece `metadata.loggers` — *"an ordered array of Logger objects describing
each hop in the event pipeline"* — que é **mais forte** do que a Lei 5 pede.

**Cenário de falha.** O Builder lê a Lei 5 como normativa, porque ela está escrita em bloco
de código e diz "obrigatoriamente". Implementa um modelo com esses seis campos no topo.
Depois adota OCSF por força da Lei 2. O resultado é um envelope caseiro embrulhando um
objeto OCSF, com dois nomes para cada conceito de tempo e duas noções de proveniência. Em
dois ciclos ninguém sabe qual é canônico, a consulta no OpenSearch precisa cobrir os dois, e
a "adoção de OCSF" é rótulo.

**Impacto.** Atinge a camada mais cara de reverter do sistema — o formato persistido. É o
mesmo modo de falha da Lei 4 (modelo moldado a uma fonte), um andar acima: modelo moldado a
uma convenção interna. E pré-decide o ADR-002, que a constituição classifica como uma das
duas decisões irreversíveis.

**Correção exigida.** Reescrever a Lei 5 declarando explicitamente que ela enuncia
**requisitos semânticos, não nomes de campo**, e que os nomes concretos são os do padrão
escolhido no ADR-002. A lei deve exigir *que os seis conceitos existam, distintos e
preenchidos* — mantendo intacta sua parte realmente essencial: "`event_time` nunca é
`ingestion_time`" e "o evento bruto nunca é sobrescrito". Se algum campo não tiver
equivalente no padrão adotado, ele nasce sob `poseidon.*`, conforme a própria Lei 2.

---

### [BLOCKER-02] A Lei 4 é inexequível na ordem em que o roadmap está escrito

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 4 contra §7 (Roadmap)
**Lei/dimensão violada:** Lei 4; dimensão 4.1 e 4.7

**Evidência.** A Lei 4:

> *"O modelo de evento normalizado (ADR-002) só pode ser congelado depois de ter sido
> exercitado contra no mínimo duas fontes heterogêneas — na prática: Sysmon/Windows Event
> Log via Collector Agent, e alertas do Wazuh."*

O roadmap:

```
Fase 3   Event Model            ← modelado contra Sysmon E Wazuh (Lei 4)
Fase 4   Ingestion Framework
Fase 5   Collector Agent v0.1   (primeira fonte real: Sysmon)
Fase 6   CTI Engine + OTX
Fase 7   Cases + Timeline
Fase 8   Response Control Plane + isolamento com failsafe
Fase 9   Wazuh como segunda fonte  ← valida que o Event Model não é moldado a ninguém
```

Na Fase 3 existem **zero** fontes. A primeira chega na Fase 5, a segunda na Fase 9. A
anotação "modelado contra Sysmon E Wazuh (Lei 4)" ao lado da Fase 3 descreve algo que a
própria linha do tempo torna impossível.

**Cenário de falha.** Fases 4, 5, 6, 7 e 8 — incluindo o Response Control Plane e o
isolamento, a capacidade mais perigosa do produto — são construídas sobre um modelo que a
constituição considera não-validado. Na Fase 9 o Wazuh chega e revela o que faltava. Nesse
momento existem migrações, índices de OpenSearch já populados, casos, timelines e registros
de auditoria referenciando o formato antigo. A correção passa a ser um projeto de migração
de dados, e a pressão para "adaptar o Wazuh ao modelo" — precisamente o que a Lei 4 proíbe —
torna-se a saída barata.

**Impacto.** A Lei 4 vira ornamento: formalmente presente, estruturalmente impossível de
cumprir. É a única lei da constituição cujo cumprimento depende da ordem das fases, e a
ordem escolhida a inviabiliza.

**Correção exigida.** Uma das três, decidida pelo humano e registrada:

1. **Separar decidir de congelar.** Fase 3 *decide* o padrão (ADR-002) e entrega o modelo
   marcado `PROVISÓRIO`; o congelamento é um artefato explícito da Fase 9, com ADR próprio
   (`Supersedes: ADR-002`). Fases 4–8 assumem formalmente que o formato pode mudar e
   mantêm as migrações reversíveis por isso. **É a opção que preserva o roadmap.**
2. **Antecipar a segunda fonte.** Mover o consumo de alertas do Wazuh para antes da Fase 3,
   ainda que por *fixtures* gravadas. O Wazuh não precisa estar integrado para que seus
   alertas exercitem o normalizador — basta um corpus de alertas reais.
3. **Emendar a Lei 4**, assumindo explicitamente o risco. Se for esta, que seja por decisão
   registrada, não por omissão.

Qualquer que seja a escolha, a anotação "← modelado contra Sysmon E Wazuh (Lei 4)" na Fase 3
está incorreta como está e precisa sair ou ser reescrita.

---

### [BLOCKER-03] A Lei 8 protege o agente que escrevemos e ignora o agente que comandamos

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 8 contra §7 (nota sobre o Defender)
**Lei/dimensão violada:** Lei 8; dimensões 4.1, 4.3 e 4.6

**Evidência.** A Lei 8 diz: *"Não existe, em nenhuma hipótese, um endpoint do tipo
`POST /agent/execute {command}`"*, e define um conjunto fechado de nove capacidades.

Mas §7 planeja: *"Capacidade de isolamento é inteiramente nossa (Windows Firewall/WFP no
Collector), **com Wazuh Active Response como segundo caminho de resposta**."*

Examinei esse segundo caminho na fonte, *tag* `v4.14.7`:

**1. A lista de permissões tem um *bypass* documentado.**
`framework/wazuh/core/active_response.py`:

```python
def validate_command(self, command: str):
    if not command:
        raise WazuhError(1650)
    if not command.startswith('!'):          # <-- prefixo '!' pula a verificação
        commands = get_commands()
        if command not in commands:
            raise WazuhError(1652)
```

Comando prefixado com `!` **não é conferido contra a lista de comandos configurados**. É o
seletor de "nome de script", resolvido em `active-response/bin/` no endpoint.

**2. Os argumentos não são validados nem escapados no caminho moderno.**
Mesma classe, `ARJsonMessage.create_message`:

```python
parameters={'extra_args': arguments if arguments else [], 'alert': ...}
```

`shell_escape()` existe no arquivo, mas **só é aplicado em `ARStrMessage`**, o caminho de
agentes legados. No schema da API, `arguments` é `type: array / items: {type: string}` —
sem `format`, sem validador.

**3. O default atinge a frota inteira.**
`api/api/controllers/active_response_controller.py`: `agents_list: str = '*'` e
`broadcasting=(agents_list == '*')`.

**4. Existe um canal paralelo pior.**
`PUT /agents/upgrade_custom` instala **um arquivo WPK local arbitrário** nos agentes
indicados — implantação de binário arbitrário na frota.

**Cenário de falha.** Um atacante que obtenha a credencial da API do Wazuh — que o Poseidon
necessariamente armazena — emite
`PUT /active-response` com `command: "!qualquer-script"` e `arguments: [...]`, sem lista de
agentes. Resultado: execução, com argumentos que ele controla, em toda a frota gerenciada
pelo Wazuh. Nenhuma das nove capacidades da Lei 8 foi envolvida, nenhuma assinatura da Lei 9
foi verificada, nenhum failsafe da Lei 10 existe nesse caminho.

**Impacto.** A Lei 8 é a lei que impede o Poseidon de virar RCE distribuída autorizada. Ela
cobre metade da superfície de resposta e a constituição não sinaliza isso. Pior: a leitura
natural do texto é que a proibição é da *plataforma*, não de um componente — um Builder de
boa-fé vai assumir que está coberto.

**Correção exigida.** A Lei 8 precisa declarar seu alcance. No mínimo:

1. Dizer explicitamente que a lei vale para **todo caminho de execução que o Poseidon
   comanda**, próprio ou de terceiros.
2. Para o caminho Wazuh, definir no ADR-001/ADR-006 as restrições que o Poseidon se impõe:
   `command` **nunca** prefixado com `!`; `arguments` derivados de um conjunto fechado e
   nunca de entrada do usuário; `agents_list` **sempre** explícito, nunca omitido;
   `upgrade_custom` **proibido**.
3. Registrar que a credencial da API do Wazuh é equivalente a execução de código na frota, e
   tratá-la nesse nível de proteção — o que reforça `[MAJOR-12]`.
4. Se possível, restringir por RBAC do próprio Wazuh a conta usada pelo Poseidon
   (`x-rbac-actions: active-response:command` é granular na spec) — defesa em profundidade
   do lado do fornecedor.

---

### [BLOCKER-04] Isolamento total é incompatível com o dead-man's-switch e com o transporte escolhido

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 10, itens 2 e 3, contra §4 (Stack)
**Lei/dimensão violada:** Lei 10; dimensões 4.1 e 4.4

**Evidência.** A Lei 10 exige, simultaneamente:

> *"2. **Dead-man's-switch**: se o agente perder contato com o control plane por N minutos
> (padrão: 30 …), ele **restaura automaticamente** a conectividade e registra o evento."*
>
> *"3. Exceção garantida para o canal de saída do Poseidon, DNS e infraestrutura de
> gerenciamento — isolamento seletivo é o padrão; **isolamento total é opção explícita**."*

E o §4 fixa o transporte: *"HTTPS + mTLS, exclusivamente outbound, com polling para ações
pendentes"*.

Com transporte exclusivamente *outbound* por *polling*, "contato com o control plane" é,
por definição, **um poll bem-sucedido**. No isolamento **total**, por definição, não há
exceção para o canal do Poseidon — logo o agente não consegue pollar — logo, após N minutos,
o dead-man's-switch dispara e desfaz o isolamento total.

**Cenário de falha.** Analista aciona isolamento total num host com ransomware em
propagação, às 10:00. Às 10:30 (padrão da própria lei), o agente conclui que perdeu contato
— o que é verdade, e é consequência direta da ação solicitada — e restaura a conectividade.
O host volta à rede. Nada no sistema registra isto como anomalia: o agente está executando a
Lei 10 corretamente.

**Impacto.** Isolamento total tem vida útil máxima garantida de N minutos, e a constituição
o apresenta como "opção explícita" sem essa ressalva. Um analista lê "isolamento total" e
entende contenção; recebe uma contenção com prazo de validade que ninguém lhe contou. Numa
plataforma de resposta a incidentes, essa é uma promessa falsa no pior momento possível.

**Correção exigida.** Escolher e registrar uma destas, no texto da Lei 10:

1. **Remover isolamento total do MVP.** Isolamento seletivo — que preserva o canal do
   Poseidon — é o único modo coerente com *polling* e com o dead-man's-switch. É a opção
   mais simples e provavelmente a correta.
2. **Manter isolamento total com contrato próprio**: sem dead-man's-switch por perda de
   contato (porque a perda é esperada), e com um temporizador local absoluto e explícito —
   "isolamento total expira em T e requer reautorização" — mais um caminho de recuperação
   fora de banda documentado.
3. Em qualquer caso, a lei precisa distinguir **"perdeu contato porque algo quebrou"** de
   **"perdeu contato porque foi isolado a mando"**. Hoje ela trata as duas como a mesma
   coisa, e é essa confusão que gera o defeito.

---

### [MAJOR-01] A Lei 6 exige uma propriedade que o stack escolhido não consegue garantir

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 6, contra §4 (Stack)

**Evidência.** A Lei 6: *"O Audit Log é **append-only** e não é editável por nenhum papel,
incluindo Super Admin."* O §4 define a persistência: PostgreSQL 16. O §10 trata cifragem de
segredos, e nada mais sobre integridade.

Em PostgreSQL, "append-only" obtido por permissão de papel (`REVOKE UPDATE, DELETE`) protege
contra o **usuário da aplicação**, não contra quem detém a credencial de dono do schema, a
credencial de superusuário, ou acesso ao volume de dados. A Lei 6 diz "nenhum papel,
incluindo Super Admin" — e "Super Admin" é papel da aplicação, mas o texto pretende afirmar
uma propriedade do registro, não do sistema de permissões.

**Cenário de falha.** Um incidente envolve ação indevida de um administrador. O Audit Log é
a única prova. A defesa — interna ou judicial — pergunta o que impediria esse administrador,
que também tem acesso ao banco, de alterar a linha. A resposta, hoje, é "a aplicação não
oferece essa função". Isso não sustenta um registro probatório, que é exatamente o propósito
declarado da Lei 6.

**Impacto.** A lei está escrita como garantia e entrega uma convenção. Custa pouco agora e
muito depois: retroagir integridade sobre um log já existente exige âncora externa que não
existirá.

**Correção exigida.** A Lei 6 deve nomear um mecanismo, não apenas a intenção. Opções, em
ordem crescente de custo: encadeamento por hash (cada registro carrega o hash do anterior,
tornando a alteração detectável); publicação periódica do hash-raiz em armazenamento WORM ou
fora do banco; escrita espelhada em sink append-only externo. A decisão pertence ao ADR-007,
que hoje cobre "separação Audit Log / Case Timeline" mas não integridade.

---

### [MAJOR-02] O `01-BUILDER.md` afirma um endpoint de API que não existe — violando a Lei 1 dentro do próprio conjunto de prompts

**Arquivo:** `docs/prompts/01-BUILDER.md` §7.4
**Lei/dimensão violada:** Lei 1; dimensão 4.2

**Evidência.** O texto instrui o Builder a pesquisar: *"API do Manager (auth, **endpoints de
alertas**/agentes/regras)"*.

Baixei a especificação OpenAPI oficial da *tag* fixa `v4.14.7`
(`api/api/spec/spec.yaml`, 20.062 linhas) e enumerei todos os *paths* declarados.
**Nenhum contém a palavra `alert`.** O único caminho próximo, `/events`, é de **entrada** —
injeta eventos no Wazuh, não lê alertas.

Alertas do Wazuh existem no **Wazuh Indexer** (OpenSearch, índices `wazuh-alerts-*`) e em
`alerts.json` no disco do manager. Não na API do Manager.

**Cenário de falha.** O Builder segue a instrução, procura o endpoint, e tem dois caminhos:
descobrir que não existe (custo: tempo) ou — o risco real — assumir que existe e desenhar o
conector `WazuhConnector` em torno de um `GET /alerts` imaginário, com paginação e filtros
inventados. A Fase 9 quebra inteira. É o modo de falha que a Lei 1 foi escrita para impedir,
presente no documento que ensina a Lei 1.

**Impacto.** Além do retrabalho: a correção muda arquitetura. O adaptador Wazuh precisa
falar com **dois sistemas, com dois modelos de autenticação** — Manager API (porta 55000,
JWT de 900s) e Indexer (porta 9200, credencial própria). Isso afeta ADR-001, ADR-008, o
Health Center (Lei 12 — são duas fontes de saúde, não uma) e a gestão de credenciais.

**Correção exigida.** Corrigir a redação do `01-BUILDER.md` §7.4 para separar *"API do
Manager (auth, agentes, regras, resposta ativa)"* de *"Wazuh Indexer (alertas, índices,
autenticação)"*, e registrar em ADR-001 que o conector Wazuh é duplo por necessidade.

---

### [MAJOR-03] A Lei 11 e o ADR-004 (Sigma) colidem, e nada na constituição resolve

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 11, contra Lei 2 / ADR-004

**Evidência.** A Lei 11: *"Linhas de comando são coletadas mas passam por **redação de
padrões sensíveis** antes do envio."*

A Lei 2 adota **Sigma** como formato de regra de detecção. A maioria das regras Windows de
alto valor do SigmaHQ casa em subcadeias de `CommandLine` — é o campo mais usado do corpus.

Verificado: o Sysmon Event ID 1 registra *"process creation with **full command line** for
both current and parent processes"* (doc oficial, 2026-09-10).

A constituição não diz **onde** a redação ocorre em relação à detecção, nem **o que** a
redação preserva.

**Cenário de falha.** O Collector reda a linha de comando antes do envio, como a Lei 11
manda. O evento chega ao Poseidon com `CommandLine` parcialmente mascarado. A regra Sigma
que procura `-enc` seguido de base64, ou `-NoProfile -W Hidden`, ou uma credencial passada
por argumento, não casa mais. A detecção falha **em silêncio** — nenhum erro, nenhum log,
apenas ausência de alerta. É o pior modo de falha possível num SOC, e a Lei 12 não o pega:
a telemetria está chegando normalmente.

**Impacto.** Duas leis corretas isoladamente produzem, juntas, cegueira silenciosa. E a
tensão é real, não resolúvel por redação mais esperta: a mesma cadeia que revela a senha
revela o ataque.

**Correção exigida.** A constituição precisa decidir a ordem e o contrato. A resolução que
recomendo avaliar no ADR-004 e ADR-005: **detectar antes de redigir, persistir depois**.
A linha íntegra existe em memória no endpoint o tempo necessário para avaliação; o que vai
para o banco é a versão redigida mais um hash da original mais o marcador de que houve
redação. Seja qual for a escolha, ela precisa estar no texto, porque hoje um Builder pode
implementar qualquer uma das duas ordens e ambas parecem conformes.

Ressalva de honestidade que também deve entrar no texto: a Lei 11 se chama "O Collector não
coleta segredos", mas o Sysmon já **escreveu** a linha de comando completa no Event Log do
endpoint antes de o Collector existir. A redação protege o banco do Poseidon, não o
endpoint. A EULA da Sysinternals reconhece isso explicitamente ("Sensitive Information").
O título da lei promete mais do que o mecanismo entrega.

---

### [MAJOR-04] A Fase 5 depende de software que o Poseidon não pode redistribuir

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §7 (Fase 5 e nota sobre o Defender)

**Evidência.** A constituição fixa: *"Telemetria de endpoint no laboratório vem de
**Sysmon** + Windows Security Log + log operacional do Defender Antivírus local — **tudo
gratuito e sem tenant**."*

"Gratuito" está correto. "Livre para distribuir" não foi afirmado — e é o que importa.
Sysinternals Software License Terms (https://live.sysinternals.com/Eula.txt), em "Scope of
License", *"you may not"*:

> *"publish the software for others to copy; rent, lease or lend the software; transfer the
> software or this agreement to any third party; or **use the software for commercial
> software hosting services**."*

**Cenário de falha.** A Fase 5 entrega o Collector Agent com um instalador que traz o
Sysmon junto, porque é o que torna a instalação de um passo. Isso é "publish the software
for others to copy" e "transfer the software to a third party". O defeito só aparece quando
alguém de fora do time instala o produto — ou seja, quando já é caro.

**Impacto.** Restringe a forma de entrega da Fase 5. E a cláusula *"commercial software
hosting services"* tem alcance estratégico: **inviabiliza uma oferta SaaS do Poseidon que
dependa de Sysmon nos endpoints monitorados**. Isso não é detalhe de empacotamento; é uma
restrição no modelo de negócio, tomada por omissão.

**Correção exigida.** Registrar no ADR-005: (a) o Poseidon **não empacota** o Sysmon;
entrega um `sysmonconfig.xml` recomendado — configuração é obra própria — e instruções de
instalação; (b) responder se SaaS está no horizonte, porque a resposta muda a dependência.
O ADR-005 deve ainda **nomear e recusar conscientemente** a alternativa de consumir ETW
diretamente no agente Go, que não tem essa restrição. Não estou recomendando ETW — não
verifiquei cobertura nem exigência de PPL. Estou dizendo que a alternativa precisa constar
como considerada, sob pena de o ADR falhar o critério "as alternativas foram consideradas de
verdade".

---

### [MAJOR-05] Identidade do agente: nenhuma lei, nenhuma fase, e a constituição a chama de irreversível

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 9 e §9.3

**Evidência.** A Lei 9 exige que o agente valide, antes de executar: *"assinatura,
destinatário correto, expiração, nonce não reutilizado, capacidade habilitada na política
local"*. E o §9.3 lista, entre as decisões que exigem parar e perguntar ao humano:
*"esquema de identidade do agente"*.

Não existe, em nenhuma lei nem em nenhuma fase do roadmap: como o agente é **inscrito**
(enrollment); como recebe sua identidade inicial; **contra qual chave** valida a assinatura
da Lei 9; como essa chave é **distribuída**; como é **rotacionada**; como um agente é
**revogado** e o que acontece com ações já emitidas para ele.

O §4 menciona "mTLS" — que resolve autenticação de transporte, não autoria de ação. São
camadas diferentes: mTLS diz "este agente é o agente 102"; a Lei 9 exige "esta ordem foi
assinada por quem podia emiti-la".

**Cenário de falha.** Um endpoint comprometido é desprovisionado. O atacante já extraiu o
material de identidade do agente. Sem revogação, ele continua sendo um agente válido:
recebe ações, reporta telemetria falsa, e — se `NETWORK_RESTORE` estiver entre as
capacidades, e está — pode desfazer isolamentos. Esta é a pergunta 4.3 do `02-AUDITOR.md`
("Agente revogado continua aceitando ordens?"), e hoje a constituição não tem resposta.

**Impacto.** É a lacuna mais perigosa entre as ausências, porque a Lei 9 **depende** dela
para significar alguma coisa e a constituição **já sabe** que a decisão é irreversível.

**Correção exigida.** ADR-005 ou um ADR próprio deve cobrir ciclo de vida completo da
identidade do agente: enrollment (com que segredo inicial e com que janela), emissão,
rotação, revogação, e comportamento do agente diante de material expirado ou revogado. A
Fase 5 não deve ser planejada sem isso decidido.

---

### [MAJOR-06] Retenção de dados: o Auditor é mandado caçá-la, e não existe lei nem fase que a crie

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §7; `02-AUDITOR.md` §7.14

**Evidência.** O `02-AUDITOR.md` §7.14 lista entre as armadilhas que devo procurar
ativamente: *"**Retenção sem limite** — evento e evidência crescem para sempre e o disco
acaba no pior momento possível."*

Procurei na constituição por política de retenção, ILM, cotas por fonte, descarte, ou
limites de crescimento. Não há nada — nem lei, nem fase. Fase 12 é "Evidence Locker + chain
of custody" (guardar, não descartar); Fase 15 é "Production Readiness", genérica.

Isto é estrutural, não cosmético: a Lei 5 obriga a **preservar o evento bruto** de todo
evento, e o §3 aponta OpenSearch como destino. Preservação obrigatória sem política de
descarte tem exatamente um desfecho.

**Cenário de falha.** O OpenSearch enche. A ingestão para. Pela Lei 12 o Health Center
sinaliza — bem — mas a plataforma está cega e o disco não se desfaz sozinho. A correção sob
pressão é apagar índices manualmente, o que destrói a cadeia de custódia da Fase 12 e o
valor probatório da Lei 6.

**Impacto.** É a causa mais comum de morte de SOC auto-hospedado, e atinge simultaneamente
as Leis 5, 6 e 12.

**Correção exigida.** Retenção precisa existir como decisão de arquitetura antes de a
ingestão existir — não depois. No mínimo: política por classe de dado (evento bruto, evento
normalizado, alerta, caso, auditoria, evidência), com prazos distintos; ILM configurado
desde a Fase 4; cota por fonte; e a regra de que **o Audit Log e a evidência de caso têm
retenção própria, mais longa, e nunca são descartados pela mesma política dos eventos**.
Candidato natural a ADR-008.

---

### [MAJOR-07] Atualização do agente em campo não tem fase

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §4 e §7

**Evidência.** O agente é *"binário estático único, sem runtime externo"*, serviço Windows
nativo, com capacidade de isolar máquinas. Não há, no roadmap, fase que trate de como esse
binário é atualizado no parque.

"Binário estático único" agrava: não há gerenciador de pacotes para carregar a atualização.

**Cenário de falha.** Vulnerabilidade encontrada no agente na Fase 14 (Hardening). Existem
N agentes instalados, cada um com poder de isolar seu host. Não há canal de atualização
projetado, então ele é improvisado sob pressão de segurança — e um canal de atualização
improvisado é, funcionalmente, o `POST /agent/execute` que a Lei 8 proíbe, com outro nome.

**Impacto.** A pressão de improvisar um atualizador é a rota mais provável para a violação
da Lei 8 em todo o projeto, justamente porque chega disfarçada de correção de segurança.

**Correção exigida.** Fase própria, ou escopo explícito da Fase 5, cobrindo: canal de
atualização, verificação de assinatura do pacote, *rollback*, atualização escalonada, e o
que acontece se um agente ficar para trás. Deve ser tratado com o mesmo rigor da Lei 9 —
porque é a mesma superfície.

---

### [MAJOR-08] A persistência do isolamento através de um reboot é indefinida — e a escolha é irreversível

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 10

**Evidência.** A Lei 10 exige snapshot, dead-man's-switch, exceções e teste em VM. Não diz o
que deve acontecer com um endpoint isolado que **reinicia**.

A escolha de mecanismo decide isso, e as duas opções são opostas — verificado na
documentação oficial do Windows Filtering Platform
(https://learn.microsoft.com/en-us/windows/win32/fwp/object-management):

> *"**Dynamic** — … Dynamic objects live until they are deleted **or the owning session
> terminates**."* — e a sessão termina *"when the client calls FwpmEngineClose0 **or the
> client process terminates**"*.
>
> *"**Persistent** — Persistent objects are created by passing the appropriate
> FWPM_*_FLAG_PERSISTENT flag … Persistent objects live until they are deleted."*

Ou seja: filtro **dinâmico** cai quando o agente morre ou a máquina reinicia — falha-aberto.
Regra persistente (incluindo `netsh advfirewall`) sobrevive a ambos — falha-fechado.

**Cenário de falha, nas duas direções.**
Falha-aberto: analista isola host com ransomware; o atacante reinicia a máquina; o
isolamento cai; a propagação continua.
Falha-fechado: um defeito isola indevidamente uma máquina; o agente morre ou é removido; a
máquina fica permanentemente sem rede, recuperável só fisicamente — exatamente o desfecho
que a Lei 10 declara querer evitar.

**Impacto.** Não existe escolha segura por omissão. Deixar indefinido significa que o
mecanismo escolhido na Fase 8 decide o comportamento sem que ninguém tenha decidido, e o
protocolo do agente é irreversível na prática (§9.3).

**Correção exigida.** A Lei 10 deve ganhar um item explícito sobre o comportamento através
de reboot, e o ADR-006 deve escolher o mecanismo à luz dessa decisão. Ver
`[OBSERVATION-03]` para o insumo técnico que recomendo levar à decisão.

---

### [MAJOR-09] As Leis 5 e 9 dependem do relógio do endpoint, e não há modelo de confiança de relógio

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Leis 5 e 9

**Evidência.** A Lei 5 define `event_time` como *"quando aconteceu no endpoint/fonte"*. A
Lei 9 exige `issued_at` / `expires_at`, e que o agente valide expiração **antes de
executar**. O Sysmon grava em UTC (verificado), o que ajuda no fuso mas não na confiança.

Ambas dependem do relógio de uma máquina que, no cenário de uso, pode estar sob controle de
um atacante com privilégio local — o mesmo privilégio necessário para instalar o Sysmon.

A constituição não menciona *skew*, sincronização, detecção de salto, nem ancoragem no
relógio do servidor.

**Cenário de falha.**
*Relógio atrasado:* o agente aceita uma ação já expirada, porque `expires_at` ainda está no
"futuro" segundo ele. A proteção de expiração da Lei 9 é anulada; sobra o nonce — cuja
persistência através de reinício do agente também não está especificada.
*Relógio adiantado:* eventos chegam com `event_time` no futuro, envenenando a Case Timeline
(Lei 6) e a detecção de ordem fora de sequência (dimensão 4.4).

**Impacto.** Duas leis assumem uma premissa que o modelo de ameaça do produto contradiz.

**Correção exigida.** A Lei 5 deve exigir que o Poseidon registre **ambos** os tempos e a
**diferença observada** entre relógio do endpoint e do servidor na ingestão, tratando *skew*
acima de um limiar como sinal (Lei 12), não como ruído. A Lei 9 deve declarar que a
expiração é avaliada contra uma base de tempo que o endpoint não controla sozinho — por
exemplo, prazo relativo ancorado no instante de recebimento — e que o armazenamento de
nonces sobrevive a reinício do agente.

---

### [MAJOR-10] O §11 transforma exclusões permanentes em prazo, e licencia multi-tenant por acidente

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §11

**Evidência.** O §11 lista o que está *"explicitamente fora do MVP"*:

> NDR · UEBA · **multi-tenant** · IA tomando ação autônoma · resposta automática sem
> aprovação humana · agentes Linux/macOS · correlação avançada com ML · marketplace de
> integrações · chat entre IAs

E conclui: *"Proposta de qualquer um desses itens **antes da Fase 13** deve ser recusada
pelo Auditor como desvio de escopo."*

A condição temporal converte uma exclusão de escopo em prazo de carência. Pela letra, a
partir da Fase 13 nada disso é mais desvio — inclusive **multi-tenant**, que não aparece em
nenhuma fase do roadmap e que é a mais irreversível da lista: separação de tenant não se
adiciona a um modelo de dados maduro sem reescrever a camada de acesso inteira.

Há ainda uma ambiguidade interna: o §11 proíbe *"resposta automática sem aprovação humana"*
sem qualquer ressalva, enquanto a Fase 13 se chama *"Policy Engine / SOAR semi-automático"*.
"Semi-automático" não está definido em lugar nenhum.

**Cenário de falha.** Na Fase 13 alguém propõe multi-tenant citando o §11 como autorização.
Eu, como Auditor, não tenho base textual para recusar — a constituição diz que a partir da
Fase 13 deixou de ser desvio.

**Impacto.** Baixo hoje, alto e irreversível na Fase 13. É defeito de redação com
consequência arquitetural.

**Correção exigida.** Separar a lista em duas: **exclusões permanentes do produto** (onde
multi-tenant, NDR e UEBA devem entrar, ou sair para um roadmap declarado) e **itens adiados
para a Fase 13+** (onde cabe o SOAR semi-automático). E definir "semi-automático": o mínimo
é "toda ação que toque um endpoint exige aprovação humana registrada", que é o que as Leis 9
e 10 já implicam.

---

### [MAJOR-11] A Lei 5 não exige versão de schema no evento persistido

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Lei 5

**Evidência.** A Lei 5 enumera os campos obrigatórios de todo evento. Não há
`schema_version` nem equivalente.

O padrão a ser adotado evolui: OCSF saiu de 1.4 (2025-02-05) para **1.9.0 (2026-08-03)** —
cinco versões menores em dezenove meses, cadência aproximadamente trimestral (verificado na
API de releases do `ocsf/ocsf-schema`). ECS está em **9.5.0 (2026-08-04)**.

**Cenário de falha.** Eventos gravados sob OCSF 1.9 convivem no mesmo índice com eventos
gravados sob 1.12. Um campo mudou de tipo entre as versões. Nada no documento diz sob qual
versão ele foi escrito, então a desambiguação passa a ser inferida pela data de ingestão —
que é frágil e quebra em *reprocessamento*, justamente o cenário do Event Replay Lab
(Fase 11).

**Impacto.** Com Lei 5 obrigando preservação do bruto e sem retenção definida
(`[MAJOR-06]`), os eventos antigos ficam para sempre. Versão de schema é o que os mantém
interpretáveis.

**Correção exigida.** Acrescentar à Lei 5 a exigência de versão do schema no evento
persistido — o OCSF já oferece `metadata.version` para isso, coerente com `[BLOCKER-01]`.

---

### [MAJOR-12] Rotação de credenciais de integração não tem mecanismo nem fase

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §10

**Evidência.** O §10 determina: *"Credenciais de integração são cifradas em repouso com
envelope encryption e chave mestra fora do banco."* Cobre armazenamento. Não cobre
**rotação** — nem da credencial, nem da chave mestra — nem revogação, nem o que acontece com
operações em curso durante a troca.

Isto interage diretamente com `[BLOCKER-03]`: a credencial da API do Wazuh é equivalente a
execução de código na frota. Uma credencial dessa potência sem procedimento de rotação é
dívida de segurança com juros.

**Cenário de falha.** Suspeita de vazamento da credencial do Wazuh. Não há caminho
projetado para rotacioná-la sem interromper a ingestão, e a chave mestra do envelope nunca
foi rotacionada desde a Fase 1. A resposta ao incidente vira mudança de arquitetura sob
pressão.

**Correção exigida.** ADR-008 (ou o ADR de gestão de segredos) deve cobrir rotação de
credencial de integração e da chave mestra, com dupla-chave durante a transição, e
registrar a rotação no Audit Log (Lei 6). O Health Center (Lei 12) deve sinalizar
credencial próxima da expiração — ausência de sinal aqui é o mesmo defeito que a Lei 12
combate.

---

### [MINOR-01] O protocolo de gate trava quando a auditoria não encontra nada

**Arquivo:** `docs/prompts/02-AUDITOR.md` §5; `docs/prompts/README.md`

**Evidência.** O `02-AUDITOR.md` §5 determina que o `05-VERDICT.md` é escrito *"somente
depois do `04-REMEDIATION.md` do Builder, e depois de você reverificar cada correção"*. O
`04-REMEDIATION.md` é a resposta do Builder aos achados. Se não há achados, não há o que
responder, e pela letra o veredito nunca pode ser emitido.

**Correção exigida.** Uma frase no §5: quando o `03-AUDIT-REPORT.md` não contém BLOCKER nem
MAJOR, o Builder registra ciência dos MINOR/OBSERVATION e o Auditor emite o veredito
diretamente. (O §2.3 do `02-AUDITOR.md` já exige, nesse caso, a declaração explícita do que
foi e do que não foi verificado — o que preserva o rigor.)

---

### [MINOR-02] A Fase 0 não tem conjunto de artefatos de gate definido

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §6

**Evidência.** O §6 estabelece seis artefatos por fase, incluindo `02-BUILD-REPORT.md`
("como testar, comando de demonstração") e a *Definition of Done* com testes, migrações e
`gitleaks`. A Fase 0 não produz código: não há o que testar, migrar ou demonstrar. O
protocolo não prevê essa fase, embora a prescreva.

Sintoma prático: este documento é um `03-AUDIT-REPORT.md` de uma fase sem `02-BUILD-REPORT`
correspondente, e tive de decidir sozinho como adaptar a tabela de severidade.

**Correção exigida.** Definir no §6 o conjunto reduzido da Fase 0 — `00-RESEARCH.md`,
ADRs propostos, `03-AUDIT-REPORT.md`, `04-REMEDIATION.md`, `05-VERDICT.md` — e marcar
explicitamente quais itens da *Definition of Done* não se aplicam.

---

### [MINOR-03] O §4 comprime autenticação a ponto de omitir as decisões que importam

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §4

**Evidência.** *"JWT (access+refresh) com argon2id e TOTP"* — argon2id é função de hash de
senha, TOTP é segundo fator; nenhum dos dois é propriedade de um JWT. A linha junta três
decisões independentes e omite as duas que geram defeito: **estratégia de revogação** de
token e **identidade estável do ator** através do *refresh*.

A segunda importa diretamente para a Lei 6: se o Audit Log registra o ator por um
identificador derivado do token, a renovação pode fragmentar a trilha de um mesmo humano.

**Correção exigida.** ADR-007 deve separar: hash de senha (argon2id), segundo fator (TOTP),
formato e tempo de vida de token, revogação, e o identificador de ator usado no Audit Log —
que deve ser o do sujeito, nunca o do token.

---

### [MINOR-04] `sighting` é tratado como SDO; é um SRO

**Arquivo:** `docs/prompts/01-BUILDER.md` §7.4

**Evidência.** O texto pede pesquisa sobre *"STIX 2.1: objetos relevantes (indicator,
observed-data, malware, threat-actor, campaign, relationship, **sighting**)"*, enumerando
`sighting` junto aos SDOs.

Na especificação OASIS (STIX 2.1, OASIS Standard aprovado em 2021-06-10), `sighting` é um
**STIX Relationship Object** — um dos dois definidos, ao lado de `relationship` — descrito
como servindo para *"capture cases where an entity has 'seen' an SDO"*.

A distinção não é acadêmica: SRO tem propriedades próprias (`sighting_of_ref`,
`where_sighted_refs`, `observed_data_refs`, `count`, `first_seen`, `last_seen`) que são,
quase literalmente, o modelo de observação exigido pela **Lei 7**. Tratá-lo como SDO leva a
inventar um "IOCObservation" paralelo — que é o que a Lei 2 proíbe.

**Correção exigida.** Corrigir a redação e registrar no ADR-003 que a observação da Lei 7 é
materializada como `sighting` (SRO), com `confidence` na escala comum do STIX (0–100).

---

### [MINOR-05] A DRL 1.1 impõe um requisito de schema que nenhuma lei contempla

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` — Leis 2 e 7

**Evidência.** As regras do SigmaHQ são licenciadas sob **Detection Rule License 1.1**
(verificado no `LICENSE` de `SigmaHQ/sigma`; a *especificação* Sigma é domínio público, as
*regras* não). A DRL 1.1 diz:

> *"If you **use** the Rules (including in modified form) **on data**, **messages based on
> matches with the Rules must retain** … identification of the author(s) ('author' field) of
> the Rule…"*

Ou seja: **o alerta gerado precisa carregar o autor da regra**. Atribuição no repositório
não satisfaz a cláusula.

Obrigação análoga vem do ATT&CK, cujo `LICENSE.txt` exige reproduzir o aviso de copyright da
MITRE em qualquer cópia usada para fins comerciais.

**Correção exigida.** ADR-004 registra a obrigação e o modelo de alerta reserva campo para
atribuição de autoria da regra. Encaixa bem na Lei 7, que já exige proveniência para
veredito de reputação — é o mesmo princípio aplicado à detecção.

---

### [MINOR-06] `arq` é fixado no stack sem ADR, ainda em 0.x

**Arquivo:** `docs/prompts/00-CONSTITUTION.md` §4

**Evidência.** O §4 determina *"workers com ARQ"*. Verificado em 2026-09-20: `arq` está em
**0.28.0** (PyPI, publicado 2026-04-16), MIT, 3.014 estrelas, repositório ativo mas com
cadência de release baixa e **ainda sem 1.0**.

Não é achado de qualidade do projeto — `arq` é competente e adequado ao stack async. É
achado de processo: o §4 diz *"Desvios exigem ADR"*, mas a escolha original também é uma
decisão não-óbvia, e a constituição exige ADR para decisões não-óbvias.

**Correção exigida.** ADR curto registrando a escolha e as alternativas consideradas
(Celery, Dramatiq, TaskIQ), e o que dispararia reconsideração.

---

### [OBSERVATION-01] LGPD não aparece na constituição

O `02-AUDITOR.md` §8.6 me manda apontar *"LGPD sobre telemetria de endpoint de
funcionários"*. A constituição não menciona proteção de dados pessoais.

Telemetria de endpoint de funcionários em território brasileiro é tratamento de dado
pessoal: nome de usuário, host, linhas de comando, DNS consultado, arquivos acessados. A
Lei 11 trata do que é sensível **do ponto de vista de segurança** (credenciais), não do
ponto de vista de **privacidade**.

Não sou a fonte de interpretação jurídica e não vou fingir que sou. Registro que faltam três
decisões: base legal do tratamento, prazo de retenção do dado pessoal (que conversa com
`[MAJOR-06]`) e como responder a pedido de titular. Merece ao menos um ADR de posição — e
cai na Condição de Parada §9.2.

### [OBSERVATION-02] O SDK do OTX está parado e o produto mudou de marca

`AlienVault-OTX/OTX-Python-SDK`: último push em **2024-05-09** — cerca de dois anos e quatro
meses. O produto migrou de AlienVault para **LevelBlue**. A página `otx.alienvault.com/api`
é renderizada por JavaScript, o que impede verificação automatizada da documentação.

Os endpoints (`/api/v1/pulses/subscribed`, `/api/v1/pulses/events`) e o header
(`X-OTX-API-KEY`) foram lidos direto do código do SDK. **Os limites de taxa não foram
verificados** — o SDK trata `429`, logo existem, mas nenhum número deve ser codificado. Os
**termos de uso quanto a armazenar e reexibir IOCs de terceiros também não foram
verificados**, e isso é Condição de Parada §9.2 antes da Fase 6.

Sugestão para a Fase 6: tratar OTX como *um* provedor atrás do contrato de CTI, nunca como
sua fundação.

### [OBSERVATION-03] Sessão dinâmica do WFP como failsafe nativo — insumo para ADR-006

Documentação oficial do Windows Filtering Platform
(https://learn.microsoft.com/en-us/windows/win32/fwp/object-management):

> *"Any objects added during a dynamic session are automatically deleted when the session
> ends."* — e a sessão termina *"when the client calls FwpmEngineClose0 **or the client
> process terminates**."*

Isso dá um dead-man's-switch **implementado pelo sistema operacional**: se o Collector
travar, for morto ou desinstalado, o isolamento cai sozinho — sem depender de temporizador,
de relógio (o que também ataca `[MAJOR-09]`) ou de contato com o servidor. É estruturalmente
mais robusto que um timer dentro do processo que pode ser justamente o que falhou.

Contrapartida, já registrada em `[MAJOR-08]`: filtro dinâmico não sobrevive a reboot. Não
recomendo mecanismo — a decisão depende da resposta sobre reboot, que é do humano. Registro
porque o ADR-006 deve avaliá-lo explicitamente, e porque ele muda a Lei 10.2 de "timer que
esperamos que funcione" para "propriedade do SO".

**Não verificado:** privilégio necessário para `FwpmEngineOpen0`; interação com perfis do
Windows Defender Firewall; exceção de saída quando o servidor está atrás de DNS dinâmico
(armadilha 7.3 do `02-AUDITOR.md`). Tudo isso exige VM descartável na Fase 8.

### [OBSERVATION-04] Ler `wazuh-alerts-*` reintroduz o molde do Wazuh pela camada de consulta

Decorre de `[MAJOR-02]`. Como os alertas só existem no Wazuh Indexer, o adaptador vai
consultar índices `wazuh-alerts-*` com o **schema de índice do Wazuh**. A Lei 4 protege o
modelo de evento; não protege a camada de consulta.

Sugestão: manter a tradução do formato de alerta do Wazuh **inteiramente dentro do adapter**,
com uma bateria de *fixtures* de alertas reais como contrato — de modo que uma mudança de
schema entre versões do Wazuh quebre um teste, e não a produção.

### [OBSERVATION-05] Não use "o ECS foi doado ao OTel, logo está morto" como argumento no ADR-002

A página oficial da Elastic sobre ECS e OpenTelemetry descreve a doação de abril de 2023
como *"a directional decision for the evolution of both standards rather than a single event
that merged both schemas into a single standard"*. **Não há anúncio de sunset nessa
página.** ECS publicou **v9.5.0 em 2026-08-04**, um dia depois do OCSF 1.9.0.

Registro isto preventivamente porque é o atalho retórico mais provável a favor do OCSF, e
ele não se sustenta na fonte. Se o ADR-002 escolher OCSF, que escolha por mérito verificável
— e há vários: cobertura nativa de `detection_finding`, `remediation_activity`, extensão
`win` para registro do Windows, e `metadata.loggers` para cadeia de ingestão.

### [OBSERVATION-06] O ferramental Python do OCSF é fraco, e isso é custo recorrente

Verificado em 2026-09-20: `ocsf/ocsf-validator` (12 estrelas, push 2026-07-29);
`ocsf/ocsf-lib-py` (16 estrelas, **push em 2025-07-07**). Para um backend Python/Pydantic v2,
isso significa que os modelos OCSF serão escritos e mantidos à mão, contra um schema que
publica versão a cada trimestre.

Este é o argumento honesto **contra** OCSF, e ele precisa aparecer na seção "Consequências"
do ADR-002. Um ADR-002 que escolha OCSF sem contabilizar esse custo falha o critério do
§8.4 do `02-AUDITOR.md` ("as consequências foram mapeadas?"), e eu o apontarei.

### [OBSERVATION-07] O agente do Wazuh 5.x é AGPL-3.0

`wazuh/wazuh-agent` contém o texto verbatim da AGPL-3.0. O agente **hoje distribuído**
(4.14.7, de `wazuh/wazuh`) é GPLv2 — o repositório AGPL está marcado *"Work in progress …
not functional and is not compatible with the official release version"* e não tem releases.

Não é problema agora. É vigilância para o ADR-001, que deve registrar licença **por
componente e por versão**, não uma linha só dizendo "Wazuh é GPLv2". A AGPL-3.0 tem cláusula
de uso em rede que a GPLv2 não tem.

### [OBSERVATION-08] A classe 1008 do OCSF está grafada errada no próprio schema

`event_log_actvity` — falta o "i". Verificado em `https://schema.ocsf.io/api/classes`
(1.9.0). Geração de código a partir do schema vai carregar o erro; corrigi-lo silenciosamente
quebra compatibilidade com o schema oficial. Decidir e documentar, não "consertar".

### [OBSERVATION-09] O Sysmon fixa o piso de sistema operacional do laboratório

Documentação oficial (2026-09-10): *"Runs on: Client: **Windows 11 and higher**. Server:
**Windows Server 2019 and higher**."* Define o escopo das VMs da Fase 5 e da Fase 8.

Nota adicional: eventos 3 (rede), 7 (ImageLoad) e 10 (ProcessAccess) são **desligados por
padrão**, e a doc alerta que 7 e 10 geram volume alto. A configuração base do Poseidon deve
tratar volume como requisito de projeto — o que reforça `[MAJOR-06]`.

### [OBSERVATION-10] Não use `/mitre/*` do Wazuh como fonte de ATT&CK

A API do Wazuh expõe `/mitre/techniques`, `/mitre/tactics`, `/mitre/groups`,
`/mitre/software`, `/mitre/mitigations`, `/mitre/references`. É conveniente e é armadilha:
consumir ATT&CK dali acopla a taxonomia do Poseidon ao ciclo de release de um fornecedor.

Fonte correta: `mitre-attack/attack-stix-data` (STIX 2.1), **v19.2 de 2026-08-05**,
versionado pelo próprio Poseidon. Cadência de ~duas versões maiores por ano — o Poseidon
precisa de estratégia de atualização de ATT&CK, incluindo o que acontece com técnicas
depreciadas já referenciadas em casos fechados.

### [OBSERVATION-11] Recuperação de desastre não aparece em nenhuma fase

O `02-AUDITOR.md` §8.6 me manda apontar. A constituição descreve três repositórios de estado
— PostgreSQL, OpenSearch e Object Storage — com consistência **entre** eles (a evidência no
object storage é referenciada pelo caso no PostgreSQL, e o `raw_reference` da Lei 5 aponta
do normalizado para o bruto). Não há menção a backup, restauração, ou à consistência de um
restore parcial.

Um restore que recupere o PostgreSQL mas não o Object Storage produz casos com cadeia de
custódia quebrada — que é exatamente o que a Fase 12 existe para garantir. Merece constar do
ADR-008, ainda que a implementação fique para a Fase 15.

---

## Avaliação dos ADRs propostos (§8.4 e §8.5 do `02-AUDITOR.md`)

Os oito ADRs ainda não foram escritos. Avalio a **formulação** proposta em
`01-BUILDER.md` §7.5.

| ADR | Formulação | Reversível? | Parecer |
|---|---|---|---|
| **001** Papel do Wazuh e licenciamento | **Insuficiente** | Parcialmente | Precisa cobrir licença **por componente e por versão** (`[OBSERVATION-07]`), a cláusula de *derived works*, a inexistência de endpoint de alertas (`[MAJOR-02]`) e o Active Response como superfície de execução (`[BLOCKER-03]`). Como está, decidiria "usamos Wazuh" sem decidir nada do que custa. |
| **002** OCSF ou ECS | **Adequada, mas contaminada** | **Não** | A Lei 5 já pré-decide nomes de campo (`[BLOCKER-01]`), e a Lei 4 não é exequível na ordem atual (`[BLOCKER-02]`). Resolver os dois **antes** de escrever o ADR-002. Deve decidir também: extensão `win`, política de versão do schema (`[MAJOR-11]`) e custo de ferramental (`[OBSERVATION-06]`). |
| **003** CTI com STIX 2.1 | **Boa** | Sim | Ajustar `sighting` para SRO (`[MINOR-04]`). Mapear a Lei 7 diretamente em `sighting` em vez de criar entidade paralela. Citar o OS de 2021, não o Errata CSD de 2025. |
| **004** Sigma como formato canônico | **Incompleta** | Sim | Faltam três decisões: como Sigma e as regras XML do Wazuh coexistem (o Wazuh não consome Sigma); a obrigação de atribuição da DRL 1.1 (`[MINOR-05]`); e a colisão com a redação da Lei 11 (`[MAJOR-03]`). |
| **005** Collector Agent | **Insuficiente** | **Não** (protocolo e identidade) | Falta o ciclo de vida da identidade do agente (`[MAJOR-05]`), atualização em campo (`[MAJOR-07]`) e a restrição de redistribuição do Sysmon (`[MAJOR-04]`). "transporte, buffer, identidade" trata identidade como item de lista; é o mais caro dos três. |
| **006** Protocolo de ações | **Boa, mas incompleta** | **Não** | Falta o comportamento do isolamento através de reboot (`[MAJOR-08]`) e o modelo de confiança de relógio (`[MAJOR-09]`). Deve avaliar explicitamente a sessão dinâmica do WFP (`[OBSERVATION-03]`). |
| **007** Auth, RBAC, Audit/Timeline | **Incompleta** | Parcialmente | Falta o mecanismo de integridade do Audit Log (`[MAJOR-01]`) e a identidade estável de ator através do *refresh* (`[MINOR-03]`). |
| **008** Persistência | **Incompleta** | **Não** (formato persistido) | Falta retenção e cotas (`[MAJOR-06]`), rotação de credenciais (`[MAJOR-12]`) e consistência de restore entre os três repositórios (`[OBSERVATION-11]`). |

**Sobre as duas decisões que a constituição chama de irreversíveis:**

- **ADR-001** — o projeto **não** tem informação suficiente para decidir hoje. Faltam duas
  respostas jurídicas (§9.2): empacotamento do Wazuh no compose, e termos de uso do OTX. A
  parte técnica está levantada e é suficiente; a jurídica não é minha nem do Builder.
- **ADR-002** — o projeto **não** tem informação suficiente, mas por outro motivo: pela
  Lei 4, decidir o padrão exige tê-lo exercitado contra duas fontes, e nenhuma existe.
  É possível **decidir o padrão** agora com o que está levantado
  (`03-AUDIT-RESEARCH.md` §3); **não** é possível congelar o modelo. Enquanto
  `[BLOCKER-01]` e `[BLOCKER-02]` estiverem abertos, o ADR-002 nasce contaminado.

---

## Verificações realizadas sem achado

Isto delimita o que uma eventual aprovação cobre.

- **Lei 3** (não forkar o `wazuh-dashboard`) — consistente com o §3 e com o §4. Verifiquei
  que `wazuh-dashboard` é Apache-2.0 e `wazuh-dashboard-plugins` é GPL-2.0; a proibição da
  Lei 3 é arquitetural, não jurídica, e continua correta pelo motivo declarado (quebra a
  cada upgrade do upstream). Nenhum arquivo do `wazuh-dashboard` existe no repositório.
- **Lei 7** (IOC com proveniência) — tecnicamente sólida e diretamente mapeável em STIX 2.1
  `sighting`. Nenhuma inconsistência interna. Ver `[MINOR-04]` e `[MINOR-05]`, que são
  complementos, não defeitos da lei.
- **Lei 12** (o SOC monitora a si mesmo) — internamente coerente e bem justificada. A
  formulação "ausência de dados é tratada como sinal, não como silêncio" é precisa. Sem
  achado, com a ressalva de que ela **não** pega o modo de falha de `[MAJOR-03]` — detecção
  degradada com telemetria saudável — o que não é defeito da Lei 12, mas limite dela.
- **§3, Pipeline de ingestão** — `SOURCE → ADAPTER → NORMALIZER → VALIDATOR → ENRICHER →
  CORRELATOR` e a regra "nenhum `if source == 'wazuh'` fora do adapter" são corretos e
  verificáveis mecanicamente em auditoria futura por `grep`.
- **§3, Regra de nomenclatura de contrato** (`get_alert()` vs `get_wazuh_alert()`) — clara e
  auditável.
- **§4, escolha de Go para o agente** — a justificativa apresentada (binário assinável, sem
  runtime, serviço Windows nativo, footprint) é tecnicamente correta. `bbolt` verificado:
  MIT, ativo (push 2026-09-15). Sem achado.
- **§4, transporte outbound com polling** — a justificativa (NAT, proxy, e funcionar durante
  o próprio isolamento) é correta e bem pensada. O defeito em `[BLOCKER-04]` não está no
  transporte: está na Lei 10 não reconhecer o que o transporte implica.
- **§6, Definition of Done** — os nove itens são verificáveis e não têm brecha óbvia. O item
  "teste que só verifica 'não lançou exceção' não conta" é a formulação certa.
- **§8, tabela de severidade** — coerente. "BLOCKER reprova, sem exceção" e "MAJOR reprova
  salvo aceite humano registrado" dão a assimetria correta.
- **§9, Condições de Parada** — as seis são bem escolhidas. Usei a §9.2 três vezes nesta
  sessão; funcionaram como projetadas.
- **§10, ADR imutável com `Supersedes`** — correto, e é o que viabiliza a opção 1 de
  `[BLOCKER-02]`.
- **`README.md`, sinais de degradação do processo** — os cinco sinais são bem escolhidos, em
  particular *"`NÃO VERIFICADO` sumindo dos relatórios sem que nada tenha sido verificado"*.
  A sugestão de trocar os papéis entre as IDEs por uma fase é boa contramedida.
- **Separação Builder/Auditor** — sem contradição entre `01-BUILDER.md` §5 e
  `02-AUDITOR.md` §6. As três respostas (ACEITO/CONTESTO/ADIADO) e o dever de admitir erro
  no veredito estão simétricos.
- **Versões e licenças verificadas sem problema:** OCSF 1.9.0 (Apache-2.0); ECS 9.5.0
  (Apache-2.0); STIX 2.1 (OASIS Standard, 2021-06-10) e `cti-python-stix2` (BSD-3);
  especificação Sigma (domínio público) e `pySigma` + backend OpenSearch (LGPL, ativos);
  ATT&CK v19.2 (licença MITRE permite uso comercial com aviso de copyright); `bbolt` (MIT);
  `arq` (MIT — ver `[MINOR-06]`, que é de processo, não de licença).

---

## Não verificado

Onde esta auditoria tem buraco. O humano precisa ver isto antes de dar peso ao que está
acima.

1. **Nenhuma dimensão de código foi exercida.** Segurança (4.3), Correção (4.4), Qualidade
   de teste (4.5) e Operabilidade (4.8) não foram auditadas, porque não há código. Esta
   auditoria **não afirma nada** sobre a implementação futura.
2. **Nada jurídico foi verificado.** Reportei texto de licença lido na fonte. Não sou fonte
   de interpretação. As três perguntas jurídicas em aberto — empacotamento do Wazuh, termos
   do OTX, LGPD — continuam abertas.
3. **IDs de evento do Defender Antivírus (1116/1117) vieram de fontes secundárias.** Não
   consegui confirmação em `learn.microsoft.com` nesta sessão. Marcado `NÃO VERIFICADO` no
   levantamento; não deve virar código sem confirmação.
4. **O formato do alerta do Wazuh não foi examinado campo a campo.** Confirmei apenas onde
   ele **não** está (a API do Manager). O conteúdo de `wazuh-alerts-*` é insumo obrigatório
   da Fase 9 e continua em aberto.
5. **Rate limits não verificados** para Wazuh Manager API, OTX, VirusTotal e AbuseIPDB.
6. **TAXII 2.1, VirusTotal API v3, AbuseIPDB v2 e MISP não foram pesquisados** nesta rodada.
   A Lei 2 cita TAXII 2.1 e eu não o verifiquei.
7. **Nada sobre o agente Go foi verificado na prática:** bibliotecas de Windows Event Log,
   viabilidade de WFP sem CGO, privilégios necessários, assinatura de binário. O
   `[OBSERVATION-03]` vem da documentação da Microsoft, **não** de teste.
8. **Nenhum teste em VM descartável foi executado.** Nada nesta auditoria substitui o
   requisito 4 da Lei 10.
9. **`cloud` e `osint` aparecem como `required` em `base_event`** na API do schema OCSF.
   Suspeito de artefato de renderização com perfis aplicados. **Não confirmei.**
10. **Não li o `00-RESEARCH.md` do Builder**, por desenho. A comparação entre as duas
    pesquisas é a próxima etapa e pode produzir achados que nenhum dos dois documentos tem
    sozinho.

---

## Resumo para decisão

| Severidade | Quantidade |
|---|---|
| BLOCKER | 4 |
| MAJOR | 12 |
| MINOR | 6 |
| OBSERVATION | 11 |

**A Fase 0 não deve receber `PASS`** enquanto os quatro BLOCKER estiverem abertos. Todos os
quatro são de redação da constituição ou de ordem do roadmap — **nenhum exige código para
ser resolvido**, e todos ficam dez vezes mais caros depois da Fase 3.

Os três itens que considero mais urgentes, nesta ordem:

1. **`[BLOCKER-02]`** — a ordem do roadmap contra a Lei 4. É a decisão que precisa ser
   tomada primeiro, porque `[BLOCKER-01]` e o ADR-002 dependem dela.
2. **`[BLOCKER-01]`** — a Lei 5 precisa ser reescrita antes de o ADR-002 ser escrito, ou o
   modelo de evento nasce com dois vocabulários.
3. **`[BLOCKER-03]`** — o alcance da Lei 8. É o único achado com consequência direta de
   segurança em produção, e a resposta é barata hoje: uma frase na lei e uma restrição no
   conector.

Seis perguntas estão abertas para o humano na seção 12 do
`docs/gates/FASE-00/03-AUDIT-RESEARCH.md`. Quatro delas são Condições de Parada §9.2 ou
§9.3 — não são minhas nem do Builder para decidir.
