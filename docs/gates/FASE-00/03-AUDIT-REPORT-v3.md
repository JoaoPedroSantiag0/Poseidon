# Auditoria — Fase 0 · Rodada 3

**Data:** 2026-09-20
**Auditor:** Auditor
**Base:** `00-CONSTITUTION.md` **v2.1** · `04-REMEDIATION.md` do Builder (19.761 bytes,
11:41) · `docs/adr/ADR-001.md` a `ADR-008.md` e `TEMPLATE.md` (10:45–10:47) ·
`00-RESEARCH.md` revisado pelo Builder às 11:42 (23.488 bytes)

Três partes:

- **Parte I** — a v2.1 fecha `BLOCKER-05`, `BLOCKER-06` e `BLOCKER-07`, ou os move?
- **Parte II** — julgamento da contestação do Builder ao `MAJOR-03`.
- **Parte III** — auditoria dos oito ADRs, que nunca entraram em escopo.

Numeração contínua da fase. Rodadas 1 e 2 produziram `BLOCKER-01` a `07`, `MAJOR-01` a `17`,
`MINOR-01` a `08`, `OBSERVATION-01` a `13`. Esta rodada abre `BLOCKER-08` a `11`,
`MAJOR-18` a `23`, `MINOR-09` a `11` e `OBSERVATION-14` a `16`.

---

## Método

1. Releitura integral da v2.1, comparando cláusula a cláusula com a v2.0.
2. Para cada BLOCKER: confirmar se a correção exigida entrou **e depois procurar o defeito
   que a nova redação cria**. A v2.0 fechou três e criou dois; tratei a v2.1 com a mesma
   premissa.
3. Para o `MAJOR-03`: reconstruir o argumento do Builder na fonte primária — especificação
   de modificadores do Sigma — em vez de julgá-lo por plausibilidade. Julguei separadamente
   cada uma das três afirmações dele, porque duas se sustentam e uma não.
4. Para os ADRs: ler cada um contra a constituição **vigente**, contra o `04-REMEDIATION.md`
   que promete conteúdo neles, e contra as verificações de schema das rodadas anteriores.

Fontes primárias novas desta rodada, consultadas em **2026-09-20**:
`SigmaHQ/sigma-specification`, arquivo `specification/sigma-appendix-modifiers.md`
(**versão 2.1.0, release 2025-08-02**); e `schema.ocsf.io/api/objects/metadata` para
confirmar `metadata.version`.

---

# PARTE I — A emenda v2.1

## Quadro-resumo

| ID | Assunto | Veredito | Resíduo |
|---|---|---|---|
| **BLOCKER-05** | Fase 3 modelava contra fonte única | ✅ **FECHADO** na lei | `MINOR-09`, `MAJOR-18` |
| **BLOCKER-06** | Expiração sem integridade | ⚠️ **FECHADO para o caso que eu descrevi**; reabre no reboot → **`BLOCKER-08`** | — |
| **BLOCKER-07** | ETW fixado sem verificação | ✅ **FECHADO** | `MAJOR-19`, `MAJOR-20` |

Dois de três fechados de forma limpa. O terceiro foi fechado contra o cenário que eu
apresentei e permanece aberto contra um cenário que eu não havia apresentado — e que a
própria decisão falha-fechado torna obrigatório considerar.

Esta emenda é **substancialmente melhor** que a anterior: criou um defeito, não dois, e
nenhum por descuido de redação. O `BLOCKER-08` existe porque o problema é genuinamente
difícil, não porque o texto foi apressado.

---

## BLOCKER-05 — ✅ FECHADO na lei

A Lei 4 agora exige **dois corpora**, nomeados e obrigatórios:

> *"1. **Alertas reais do Wazuh** … 2. **Telemetria bruta de endpoint** — ETW e Security Log
> capturados de uma máquina real, antes do Collector existir, com um script descartável."*

E acrescenta a justificativa que faltava:

> *"Um corpus só não cumpre a Lei 4: modelaria contra fonte única, apenas trocando o Wazuh
> pelo Sysmon como molde. São **duas naturezas diferentes de dado** — alerta já interpretado
> por um motor de terceiro versus telemetria bruta de sistema operacional — e é justamente a
> tensão entre elas que expõe as premissas escondidas do normalizador."*

Isso é mais preciso que a correção que eu havia pedido. Eu pedi simetria de contagem; a
emenda deu simetria de **natureza**, que é o que realmente exercita o normalizador. Achado
fechado.

### [MINOR-09] O roadmap não acompanhou a Lei 4

O §7 continua com a anotação da v2.0:

```
Fase 3   Event Model PROVISÓRIO  ← decide o padrão; exercita contra corpus gravado do Wazuh (Lei 4)
```

Singular, e nomeando só o Wazuh. A Lei 4 diz dois. A lei é mais específica e prevalece, mas
o roadmap é o que se lê ao planejar a fase, e edição pela metade é o mecanismo pelo qual
uma lei e o cronograma que a executa divergem em silêncio.

**Correção:** `← decide o padrão; exercita contra os dois corpora gravados (Lei 4)`.

### [MAJOR-18] O corpus de telemetria vem de "uma máquina real" e colide com as Leis 11 e 13 e com o §10

**Arquivo:** `00-CONSTITUTION.md` — Lei 4, item 2

A lei manda capturar ETW e Security Log *"de uma máquina real, antes do Collector existir,
com um script descartável"*. Três problemas, todos decorrentes de "real" e de "antes do
Collector existir":

1. **Não há pipeline de redação.** O Collector — que é quem implementa a redação da Lei 11
   — por definição ainda não existe. O script descartável captura tudo em claro. Um corpus
   de Security 4688 contém linhas de comando, e linhas de comando contêm credenciais: é
   exatamente a premissa que justifica a Lei 11.
2. **§10 e a Definition of Done.** O §10 determina *"Segredos: nunca no repositório"*, e a
   DoD exige *"`gitleaks` limpo; nenhum segredo no repositório ou no histórico"*. Um corpus
   versionado com linhas de comando reais de uma máquina real é candidato direto a reprovar
   a própria DoD da Fase 3.
3. **Lei 13 / LGPD.** A Lei 13 acabou de declarar que o Poseidon trata dado pessoal com
   finalidade declarada, minimização e prazo. Telemetria de uma máquina real — nomes de
   usuário, logons, DNS consultado, arquivos abertos — é dado pessoal de quem usa aquela
   máquina. Um corpus permanente no repositório é a antítese de minimização.

**Cenário de falha.** O corpus é capturado da máquina de desenvolvimento, commitado em
`lab/corpus/`, e no primeiro `gitleaks` da Fase 3 o gate reprova — no melhor caso. No pior,
não reprova, porque uma senha posicional num `net use` não casa com nenhuma regra do
`gitleaks`, e o repositório passa a carregar credencial real de uma pessoa real,
permanentemente, no histórico do git.

**Correção exigida.** Trocar "máquina real" por **VM de laboratório dedicada, com atividade
sintética gerada para o fim de exercitar o normalizador**, e declarar que o corpus: (a) é
gerado, não colhido de uso humano; (b) passa por redação antes de ser versionado, ainda que
manual; (c) tem manifesto de proveniência, conforme `MAJOR-13` da rodada 2. Isso preserva
integralmente o valor do corpus — o normalizador não sabe se o `powershell.exe` foi digitado
por uma pessoa ou por um script — e elimina os três problemas de uma vez.

---

## BLOCKER-06 — ⚠️ Fechado contra o cenário apresentado; reaberto pelo reboot

A v2.1 reescreveu os itens 3 e 4 da Lei 10 exatamente como eu pedi, e com melhor redação:

> *"3. **A expiração é o objeto de ação assinado da Lei 9, persistido íntegro** — nunca um
> timestamp solto derivado dele. … Quem restaura **verifica a assinatura antes de
> restaurar**; falha na verificação mantém o isolamento (falha-fechado) e gera sinal de
> severidade alta…"*
>
> *"4. **A base de tempo não pode ser o relógio de parede do host isolado.** Mínimo: relógio
> monotônico desde a aplicação, imune a salto de relógio; divergência entre monotônico e
> relógio de parede é sinal (Lei 12)."*

O ataque que eu descrevi — editar o registro de expiração, ou adiantar o relógio — está
fechado. O item 5 separa corretamente **falha** do agente (watchdog cobre) de **remoção
deliberada** (não é cobrível localmente, vai para o item 6), e o item 6 qualifica a
recuperação como obrigatoriamente local e proíbe canal remoto. Todos os resíduos que eu
havia apontado como `MAJOR-15` e `MAJOR-16` foram absorvidos.

Mas o item 4 tem um pressuposto que a decisão falha-fechado torna falso.

### [BLOCKER-08] O relógio monotônico não sobrevive ao reboot que a falha-fechado exige que o isolamento sobreviva

**Arquivo:** `00-CONSTITUTION.md` — Lei 10, item 4 contra o preâmbulo da Lei 10
**Lei/dimensão violada:** Lei 10 (contrato de isolamento); dimensões 4.1 e 4.4

**Evidência.** Duas cláusulas da mesma lei:

> Preâmbulo: *"o isolamento é **falha-fechado** — **sobrevive ao reboot da máquina** e à
> morte do agente."*
>
> Item 4: *"Mínimo: relógio **monotônico desde a aplicação**, imune a salto de relógio."*

Um relógio monotônico mede tempo decorrido desde o **boot**. Ele **zera no boot**, em
qualquer sistema operacional. É essa propriedade que o torna imune a salto de relógio — e é
a mesma propriedade que o torna inútil através de um reboot.

Sequência: isolamento aplicado em T0 com expiração de 12 horas. Monotônico começa a contar.
Em T0+1h a máquina reinicia — seja por ação do atacante, seja por atualização, seja por
queda de energia. O isolamento sobrevive, como a lei exige. O contador monotônico não: ele
recomeça do zero, e não há nenhum registro confiável de quanto tempo já decorreu.

O watchdog fica com exatamente duas opções, e a lei não escolhe nenhuma:

| Opção | Consequência |
|---|---|
| Reancorar no relógio de parede | O item 4 é abandonado no exato momento em que importa, e o `BLOCKER-06` reabre: o atacante reinicia a máquina e adianta o relógio |
| Nunca expirar após reboot | O isolamento vira permanente. É o cenário do preâmbulo da própria Lei 10: *"um erro transforma a máquina em algo que só se recupera fisicamente"* |

**Cenário de falha.** O atacante no host contido não precisa adulterar nada assinado. Ele
reinicia a máquina — operação trivial e indistinguível de manutenção legítima — e em
seguida manipula o relógio. Se o watchdog reancorou no relógio de parede, a expiração é
alcançada imediatamente e a rede volta. Nenhuma assinatura foi quebrada, nenhum arquivo foi
editado, e o evento registrado é "expiração alcançada".

**Impacto.** É o mesmo impacto do `BLOCKER-06`, por um caminho que a correção do
`BLOCKER-06` não cobre — e o reboot não é um caso de borda: é a primeira coisa que se faz
numa máquina que perdeu a rede.

**Correção exigida.** Existe uma solução limpa, e ela está disponível **justamente porque**
o item 2 fixou isolamento seletivo, que preserva o canal do Poseidon:

1. A expiração é **tempo absoluto no objeto assinado** — como o item 3 já determina — e a
   referência de tempo autoritativa é o **servidor**, não o host.
2. **Após cada boot, o watchdog reancora o tempo contactando o Control Plane** pelo canal
   que o isolamento seletivo mantém aberto. Só depois de reancorar ele pode decidir
   expirar. Monotônico continua valendo **dentro** de cada sessão de boot.
3. **Se não conseguir reancorar, mantém o isolamento** — falha-fechado, coerente com o item
   3 — e gera sinal. A saída, nesse caso, é o item 6: recuperação local. Que é exatamente
   para isso que ele existe.
4. Relógio de parede retrocedendo em relação ao `issued_at` do objeto assinado é
   adulteração detectada, tratada como o item 3 já manda.

Isto fecha o caminho do reboot sem inventar mecanismo novo: usa o canal que a lei já
garante, a assinatura que a lei já exige, e o comportamento falha-fechado que a lei já
escolheu.

---

## BLOCKER-07 — ✅ FECHADO

A v2.1 fez o que eu pedi e foi além do que eu pedi. A §4 deixou de afirmar e passou a
declarar origem por campo:

> *"**Esta troca tem custo, e o custo é declarado aqui, não descoberto na Fase 5.** O
> provedor `Microsoft-Windows-Kernel-Process` **não entrega linha de comando de forma
> confiável**, nem linha de comando do processo pai, nem hashes, nem GUID de processo imune
> a reúso de PID."*

Com tabela de origem por campo: linha de comando vem do **Security 4688**, com a GPO como
*"requisito de implantação declarado"* e ausência tratada como degradação de saúde pela
Lei 12; hashes calculados pelo Collector, com custo de I/O e corrida com exclusão assumidos;
linha de comando do pai derivada de árvore de processos em memória.

E o parágrafo que eu não esperava e que é o melhor da emenda:

> *"O provedor `Microsoft-Windows-Threat-Intelligence`, que traria paridade real, exige
> processo **PPL com atributo Antimalware**, o que exige driver **ELAM** co-assinado pela
> Microsoft. … **Paridade plena com um EDR comercial exige componente em modo kernel
> assinado — esse é o custo estratégico da decisão de SaaS, e fica registrado como dívida
> conhecida, não como surpresa futura.**"*

Isso é a Lei 1 aplicada a uma limitação estratégica em vez de a um endpoint. Achado fechado.

Dois resíduos, ambos consequência da correção, nenhum fatal.

### [MAJOR-19] A criação de processo passa a vir de duas fontes e ninguém declara quem as junta

**Arquivo:** `00-CONSTITUTION.md` §4, tabela de origem por campo

A tabela cria uma situação nova: **um mesmo evento de criação de processo chega por dois
caminhos independentes** — ETW `Kernel-Process` (sem linha de comando) e Security 4688 (com
linha de comando, sem linha de comando do pai). A §4 diz de onde vem cada campo e não diz
**quem os une em um evento**, nem o que acontece quando só um dos dois chega.

Isso não é detalhe de implementação: é decisão de arquitetura, porque a junção precisa de
chave de correlação e de janela de tempo, e as duas fontes não compartilham identificador
natural — ETW traz `ProcessId` e a chave única de processo; 4688 traz `NewProcessId` em
hexadecimal e o `SubjectLogonId`. Relógios e ordenação também diferem.

**Cenário de falha.** Sob carga, o 4688 chega 200 ms depois do evento ETW correspondente. A
janela de junção é curta demais e o evento é emitido sem linha de comando; ou é longa demais
e dois `cmd.exe` iniciados no mesmo segundo trocam de linha de comando entre si. O segundo
caso é pior: produz atribuição **errada**, e uma detecção atribuída ao processo errado é
pior que detecção ausente — manda o analista investigar a árvore errada.

E há o caso assimétrico: com a GPO desligada, chega ETW e nunca chega 4688. A Lei 12 sinaliza
a ausência, o que é correto — mas a junção precisa decidir se emite o evento incompleto ou
se o segura esperando um par que nunca virá.

**Correção exigida.** ADR-005 declara: a chave de junção, a janela, o comportamento quando
só uma das fontes chega, e o que é emitido nesse caso. E — importante para a Lei 5 — se o
evento resultante tem **um** `raw_reference` ou **dois**, porque ele passa a ter dois
eventos brutos de origem.

### [MAJOR-20] A árvore de processos em memória não sobrevive ao reinício do agente

**Arquivo:** `00-CONSTITUTION.md` §4 — linha de comando do pai

*"linha de comando do pai | derivada de árvore de processos mantida em memória pelo
agente"*. Uma estrutura em memória tem três lacunas conhecidas, nenhuma mencionada:

1. **Cold start.** Quando o agente inicia — instalação, atualização, reboot, crash — todos
   os processos já em execução são desconhecidos. Seus filhos nascem com pai sem linha de
   comando. Em um servidor que fica meses no ar, os pais de longa duração são justamente os
   serviços que mais importam.
2. **Reúso de PID.** A §4 reconhece que o ETW não dá GUID imune a reúso, e é exatamente o
   que uma árvore indexada por PID precisa. Um PID reciclado atribui ao filho a linha de
   comando de um processo morto.
3. **Teto de memória.** A árvore cresce com o número de processos vivos e precisa de
   política de descarte, que a §4 não menciona — e o ADR-005 promete `< 40MB` de RAM.

**Correção exigida.** ADR-005 declara o comportamento de cold start (o mais honesto é emitir
o campo como ausente, nunca como vazio, para que a Lei 12 possa medir a cobertura), a chave
de identidade de processo usada em vez do PID puro, e o teto da estrutura.

---

# PARTE II — Julgamento da contestação ao MAJOR-03

## O que foi contestado

O Builder respondeu ao `MAJOR-03` com **CONTESTO** à solução que propus e **ACEITO** à
existência do problema, e sustentou três afirmações:

1. Executar Sigma no endpoint é inviável — footprint, segundo motor de detecção, e
   contraria a arquitetura de referência, que centraliza detecção no Core/OpenSearch.
2. Regras Sigma de alto valor procuram ferramentas e padrões de ataque (`powershell -enc`,
   `-NoProfile`, `Invoke-Expression`, `vssadmin delete shadows`, `certutil -urlcache`), e
   *"nenhum desses comandos representa segredos de usuários"*; argumentos de evasão *"nunca
   coincidem com regexes de credenciais e trafegam íntegros"*.
3. O Collector calcula SHA-256 da linha de comando original antes da redação e o envia como
   `metadata.command_line_hash`; *"regras Sigma e correlações de IOCs baseadas no hash
   completo continuam funcionando perfeitamente"*.

## Veredito: **MANTIDO em parte, ACEITO em parte**

Julguei as três separadamente porque elas não têm o mesmo valor.

### Afirmação 1 — **ACEITO. Ele está certo e eu estava errado.**

Minha redação do `MAJOR-03` dizia: *"A resolução que recomendo avaliar no ADR-004 e ADR-005:
**detectar antes de redigir, persistir depois**."*

Ele demonstrou que isso exige um motor Sigma no endpoint, o que contraria o §3 da
constituição — que centraliza correlação no Core — e a meta de footprint do agente. Ele está
certo, e a objeção arquitetural é a correta: um segundo motor de detecção no endpoint criaria
duas populações de regras com ciclos de vida distintos, que é precisamente o defeito que eu
apontei para a coexistência Sigma/Wazuh na rodada 1.

**Retiro a solução que propus.** O achado nunca dependeu dela — eu havia escrito *"seja qual
for a escolha, ela precisa estar no texto"* — mas a recomendação específica estava errada e
fica registrado que estava.

### Afirmação 2 — **ACEITO em parte. Verdadeira para o conjunto que ele lista, falsa como regra geral.**

Ele tem razão no essencial: `powershell -enc`, `-NoProfile`, `vssadmin delete shadows`,
`certutil -urlcache` não são segredos, e uma redação bem construída não os toca. Esse é um
ponto legítimo e desmonta a versão ingênua do meu achado, que tratava "redação" e "perda de
detecção" como sinônimos.

Mas a afirmação *"nunca coincidem com regexes de credenciais"* é sobre um conjunto de
regexes que ninguém escreveu ainda, e a especificação do Sigma contradiz a generalização em
dois pontos concretos e verificáveis.

**Fonte:** `SigmaHQ/sigma-specification`, `specification/sigma-appendix-modifiers.md`,
versão **2.1.0**, release **2025-08-02**.

**(a) Falso negativo na detecção — o modificador `base64offset`.** A especificação define:

> *"`base64offset`: If a value might appear somewhere in a base64-encoded string the
> representation might change depending on the position of the value in the overall
> string."*

É o modificador que existe para casar conteúdo **dentro** do blob base64 de um
`powershell -enc`. Ele opera sobre a cadeia base64 inteira. Ora: credenciais em linha de
comando aparecem com frequência **posicionalmente**, sem flag que as anuncie —
`net use \\srv\share P@ssw0rd /user:x`, `mysql -uroot -pSenha` sem espaço. Para capturá-las,
a redação precisa de heurística de **entropia ou comprimento**, que é como se detecta token
sem prefixo. E uma heurística de entropia sobre uma linha de comando acerta, em primeiro
lugar, o blob base64 de um `-enc`.

A tensão real não é "flags de evasão versus regexes de credencial". É: **redação estreita
ancorada em flags** deixa passar credencial posicional — e viola a Lei 11 enquanto parece
funcionar. **Redação ampla por entropia** cumpre a Lei 11 e come exatamente o campo que o
`base64offset` precisa. Não dá para ter as duas integralmente, e a contestação não reconhece
o trade-off.

**(b) Falso negativo na redação — o modificador `windash`.** A especificação define:

> *"`windash`: Creates all possible permutations of the `-`, `/`, `–` (en dash), `—` (em
> dash), and `―` (horizontal bar) characters. Windows command line flags can often be
> indicated by both characters."*

O Sigma carrega esse modificador porque flags no Windows aparecem como `-p`, `/p`, `–p`,
`—p`, `―p`, e porque o casamento é **case-insensitive por padrão** (*"Default Sigma behavior
is case-insensitive matching"*). O exemplo da contestação — `--password=secret` → `[REDACTED]`
— é uma única grafia. Um regex `--password=\S+` não pega `/PASSWORD:`, `-Password `,
`–password=`. O resultado é a pior combinação possível: a credencial vaza para o banco
(Lei 11 violada) e o log de redação diz que funcionou.

Em outras palavras, o próprio corpus de conhecimento do Sigma documenta que o espaço de
grafias de flag no Windows é grande o bastante para exigir um modificador dedicado. A
redação enfrenta o mesmo espaço, na direção inversa, e a contestação assume que ele é
pequeno.

**(c) Falso positivo — sobre-redação.** Não mencionado na contestação. `-p` é flag de
porta em `docker run -p 8080:80`, de prompt em `xcopy /p`. `-pass` casa o início de
`-PassThru` do PowerShell. Um regex ganancioso dentro de um bloco de script do PowerShell
mutila a cadeia no meio, e regras Sigma que casam no bloco inteiro deixam de casar. Cada
sobre-redação é uma detecção perdida em silêncio.

**Nada disso invalida a solução dele.** Invalida a afirmação de que o problema não existe. A
redação semântica ancorada em flags é a direção certa; o que falta é o reconhecimento de que
ela tem taxa de erro nas duas direções, e de que essa taxa precisa ser **medida**, não
assumida.

### Afirmação 3 — **MANTIDO. Tecnicamente incorreta.**

> *"Regras Sigma e correlações de IOCs baseadas no hash completo continuam funcionando
> perfeitamente sem expor o segredo em claro no banco."*

Isto é falso, e é o motivo pelo qual o achado não pode ser fechado.

**Todo modificador de string do Sigma é posicional ou de codificação.** Da especificação
2.1.0, seção "Generic Modifiers" e "String Modifiers", os que se aplicam a um campo de texto
como linha de comando são:

`startswith` · `endswith` · `contains` · `re` · `cased` · `all` · `windash` ·
`base64` · `base64offset` · `utf16le` · `utf16be` · `utf16` · `wide`

Não existe um modificador de igualdade sobre hash, e não poderia existir com utilidade: um
SHA-256 é resistente a pré-imagem e tem efeito avalanche. `contains` sobre um hash não tem
significado — alterar um byte da entrada muda todo o dígito. **Nenhuma regra Sigma existente
casa em `metadata.command_line_hash`, e nenhuma regra Sigma futura pode casar**, a não ser
por igualdade exata com um hash pré-computado.

E igualdade exata sobre linha de comando completa tem valor próximo de zero na prática,
porque linhas de comando são quase únicas: contêm caminhos de perfil de usuário, nomes de
arquivo temporário, GUIDs, PIDs, portas. O hash de
`powershell.exe -enc <blob>` é diferente para cada blob — e o blob é diferente a cada
execução do mesmo ataque.

O que o hash **de fato** oferece: detecção de adulteração da linha redigida, agrupamento de
execuções byte a byte idênticas, e prova de que a redação ocorreu. São propriedades úteis e
valem a pena manter — mas são propriedades de **integridade**, não de **detecção**. Apresentá-lo
como preservação de capacidade Sigma é a afirmação que mantenho como incorreta.

Um substituto que **funcionaria** e que recomendo avaliar no ADR-004: além do hash da linha
inteira, emitir a linha redigida **preservando comprimento e classe de caractere** dos
trechos removidos (p. ex. `[REDACTED:12]`), mais um hash **do segmento redigido isoladamente**.
Isso mantém regras posicionais funcionando sobre tudo que não foi redigido, permite correlação
por segredo repetido entre hosts sem expor o segredo, e torna a redação mensurável.

## O agravamento pelo BLOCKER-07 — e um achado novo

O `BLOCKER-07` mudou a origem da linha de comando de Sysmon EID 1 para **Security 4688**.
Isso piora o `MAJOR-03` em três frentes, e revela uma quarta que é mais grave que o achado
original.

1. **Cobertura condicional.** Sem a GPO, não há linha de comando nenhuma. A Lei 12 sinaliza,
   o que é correto — mas significa que a discussão de redação só se aplica quando a GPO está
   ligada, e a Fase 5 precisa funcionar nos dois estados.
2. **Sem linha de comando do pai.** O 4688 não a fornece. Ela vem da árvore em memória
   (`MAJOR-20`), e a constituição não diz se o que a árvore guarda é a linha **redigida** ou
   a **original**. Se for a redigida, o erro de redação se propaga para todo descendente.
3. **A redação deixou de proteger o endpoint, e agora é explícito.** O Windows escreve o
   4688 com a linha de comando **em claro no Security Log do próprio host**, antes de o
   Collector ler. A Lei 11 se chama *"O Collector não coleta segredos"* e o que ela entrega é
   *"o Poseidon não persiste segredos"*. Eu havia apontado isso na rodada 1; com o 4688 não é
   mais interpretação, é o mecanismo.

### [BLOCKER-09] A Lei 5 obriga a preservar o bruto; a Lei 11 obriga a redigir antes do envio. O evento bruto carrega a credencial.

**Arquivos:** `00-CONSTITUTION.md` — Lei 5 contra Lei 11; `docs/adr/ADR-008.md` §2.3
**Lei/dimensão violada:** Lei 11 (e Lei 13); dimensões 4.1 e 4.3

**Evidência.** As duas cláusulas, literais:

> Lei 5: *"o **evento bruto original é preservado e nunca sobrescrito** pela versão
> normalizada."*
>
> Lei 11: *"Linhas de comando são coletadas mas passam por **redação de padrões sensíveis
> antes do envio**."*

E onde o bruto vive, segundo o ADR-008 §2.3:

> *"Arquivos brutos compactados de eventos que geram o `raw_reference` (Lei 5)"* —
> no **Object Storage**, isto é, no servidor.

Para o bruto estar no servidor, ele precisa ser **enviado**. As duas leis se encontram
exatamente aí, e são incompatíveis:

| Se… | Então… |
|---|---|
| O bruto é enviado íntegro, como a Lei 5 exige | A credencial em claro do 4688 chega ao Object Storage do Poseidon. **Lei 11 violada**, e a Lei 13 junto — é dado pessoal sensível em repouso, num produto SaaS |
| O bruto é redigido antes do envio, como a Lei 11 exige | Não é bruto. **Lei 5 violada**: o "evento original preservado" foi sobrescrito pela versão tratada, e a capacidade forense que a Lei 5 existe para garantir é fictícia |

A contestação do Builder discute a **linha de comando normalizada** e não toca no **evento
bruto**, que é onde o problema é mais duro — porque no normalizado há a opção de redigir com
perda controlada, e no bruto, por definição, não há.

**Cenário de falha.** Um analista abre um caso, clica em "ver evento original" para checar a
linha de comando completa — que é a razão de a Lei 5 existir — e lê a senha do administrador
de domínio, em claro, na interface do Poseidon. Em um produto SaaS, essa senha está no
Object Storage do provedor, retida pela política de retenção de evidências, que o
`04-REMEDIATION.md` propõe como *"mínimo 1 ano"*.

**Impacto.** É a materialização exata da frase da Lei 11: *"Uma plataforma de segurança que
agrega credenciais é um alvo, não uma defesa."* E atinge a decisão de SaaS, porque o
operador passa a custodiar credenciais de seus clientes sem ter decidido isso.

**Correção exigida.** A constituição precisa resolver a colisão explicitamente. A resolução
que recomendo avaliar — e desta vez ela não exige motor de detecção no endpoint:

1. **"Bruto" passa a significar "bruto após redação de credencial, com redação registrada".**
   A Lei 5 troca *"nunca sobrescrito"* por *"nunca sobrescrito pela versão **normalizada**,
   e a única transformação admitida antes da preservação é a redação da Lei 11, que é
   registrada no próprio evento"*.
2. O evento bruto carrega o **inventário da redação**: quantos segmentos, em que posições,
   com que regra, e o hash de cada segmento. A cadeia de custódia deixa de ser "o texto
   original" e passa a ser "o texto original menos N segmentos identificados, com prova de
   quais eram".
3. Em nenhuma hipótese o segmento removido é enviado.

Isso preserva o que a Lei 5 realmente protege — a impossibilidade de o normalizador destruir
evidência em silêncio — e cumpre a Lei 11 literalmente. Mas é **emenda de constituição**,
não decisão de ADR: as duas leis estão em conflito no texto vigente e nenhum Builder pode
cumprir as duas.

## Resolução formal do MAJOR-03

| Afirmação do Builder | Veredito |
|---|---|
| Sigma no endpoint é inviável; a solução do Auditor estava errada | **ACEITO** — eu estava errado, e retiro a recomendação |
| Redação semântica ancorada em credenciais preserva flags de evasão | **ACEITO em parte** — correto para o conjunto listado; a generalização não se sustenta (`base64offset`, `windash`, sobre-redação) |
| SHA-256 preserva capacidade de detecção Sigma | **MANTIDO** — tecnicamente incorreto; nenhum modificador do Sigma opera sobre hash |

**`MAJOR-03` permanece ABERTO**, com escopo redefinido: não é mais "onde redigir", que o
Builder resolveu bem. É **"qual é a taxa de erro da redação, nas duas direções, e quem a
mede"** — mais o `BLOCKER-09`, que a contestação não alcançou.

**Para fechar:** (a) corrigir a afirmação sobre o SHA-256 no ADR-005, mantendo o hash pelo
que ele de fato serve; (b) especificar a redação preservando posição e comprimento, com
inventário; (c) exigir, na Fase 5, um **conjunto de teste de redação** — linhas com
credenciais em todas as grafias de flag que o `windash` enumera, e linhas de ataque conhecidas
que não podem ser tocadas — com métrica de falso negativo e falso positivo no relatório da
fase; (d) resolver o `BLOCKER-09` por emenda.

---

# PARTE III — Auditoria dos oito ADRs

## Quadro geral

| ADR | Assunto | Estado | Achado principal |
|---|---|---|---|
| 001 | Papel e licenciamento do Wazuh | ⚠️ desatualizado | `MINOR-11` — não incorpora as travas da Lei 8 |
| 002 | OCSF vs. ECS | ❌ **BLOCKER** | `BLOCKER-10` — reintroduz o envelope revogado; classes erradas |
| 003 | CTI com STIX 2.1 | ✅ sólido | o melhor dos oito |
| 004 | Sigma canônico | ⚠️ | `MAJOR-22` — classe depreciada; Lei 13 ausente |
| 005 | Collector Agent | ⚠️ | `MAJOR-23` — Sysmon, sem revogação, conformidade falsa com a Lei 10 |
| 006 | Protocolo de ações | ❌ **BLOCKER** | `BLOCKER-11` — contradiz frontalmente a Lei 10 v2.1 |
| 007 | Auth, RBAC, Audit Log | ⚠️ | não contém o encadeamento por hash que a remediação prometeu |
| 008 | Persistência | ⚠️ | não contém retenção, rotação nem DR que a remediação prometeu |

### [OBSERVATION-14] A causa é sistêmica: os oito ADRs são anteriores a duas emendas

Todos os ADRs foram gravados entre 10:45 e 10:47. A constituição foi emendada para v2.0 e
depois v2.1, e o `04-REMEDIATION.md` é de 11:41. Nenhum ADR foi tocado desde.

Isso explica a maioria dos achados desta parte, e o diagnóstico importa: **não são erros de
julgamento do Builder, são artefatos dessincronizados.** O `TEMPLATE.md` ainda lista doze
leis quando a constituição tem treze (`MINOR-10`), e os ADRs que citam a Lei 8 e a Lei 10
citam a redação v1.0.

Mas a dessincronia não é inócua: o §6 exige ADR para cada decisão não-óbvia, e os ADRs são o
que o humano vai ler para decidir. Um ADR que descreve uma lei revogada não é neutro — ele
propõe ativamente uma arquitetura proibida.

**Sugestão de processo:** o §10 já determina que ADR é imutável e que decisão revista cria
novo ADR com `Supersedes`. Como estes ainda estão em `Status: Proposed` e nunca foram
aceitos, revisá-los no lugar é legítimo. Mas o §6 deveria dizer que **emenda constitucional
dispara revisão obrigatória dos ADRs que citam as leis alteradas** — hoje nada dispara.

---

### ADR-001 — Papel do Wazuh

Tecnicamente correto no essencial. Incorpora o achado do `wazuh-indexer-plugins` AGPL-3.0
que ele mesmo levantou, decide corretamente por cluster OpenSearch próprio, e a leitura de
que consumo por rede não é obra derivada está alinhada com o texto da licença.

Duas falhas.

### [MINOR-11] O ADR-001 não contém as travas do conector Wazuh que a Lei 8 exige

O `04-REMEDIATION.md` [BLOCKER-03] afirma: *"O ADR-001 e o ADR-006 refletirão essas travas."*
Futuro. O ADR-001 não menciona o prefixo `!`, `agents_list`, `upgrade_custom`, derivação de
`arguments`, nem o RBAC restrito — que a Lei 8 v2.1 lista como proibições constitucionais
nominais. Também não registra que a credencial da API do Wazuh equivale a execução de código
na frota, que é a consequência arquitetural mais importante do ADR.

Menor: cita a licença pelo branch `master` e cobre Wazuh 4.x sem mencionar a linha 5.x
AGPL-3.0 (`OBSERVATION-07` da rodada 1, respondida com "acolhido" e não refletida aqui); e o
checklist de conformidade afirma *"Lei 4 — Wazuh entra na Fase 9 como segunda fonte"*, o que
a Lei 4 v2.1 já não descreve — há corpus do Wazuh na Fase 3.

---

### ADR-002 — OCSF

### [BLOCKER-10] O ADR-002 reintroduz o envelope que a emenda 2.0 revogou, e mapeia três classes inexistentes ou depreciadas

**Arquivo:** `docs/adr/ADR-002.md` §2.2 e §2.1
**Lei/dimensão violada:** Lei 2 e Lei 5; dimensão 4.2 e 4.6

**Evidência — parte 1, o envelope.** O ADR-002 §2.2 especifica, literalmente:

```json
{
  "event_time": "...", "ingestion_time": "...", "source": "collector-agent",
  "source_event_id": "SYS-00048192", "raw_reference": "s3://...",
  "correlation_id": "corr-uuid-987",
  "ocsf_class_uid": 1007,
  "ocsf_data": { ... }
}
```

É exatamente o artefato que o `BLOCKER-01` descreveu e que a emenda 2.0 eliminou da Lei 5:
seis nomes inventados, sem namespace `poseidon.*`, com o objeto OCSF **aninhado dentro** de
um envelope caseiro. A Lei 5 v2.1 diz, em negrito: *"Esta lei enuncia requisitos semânticos,
não nomes de campo. Os nomes concretos são os do padrão adotado no ADR-002 — inventá-los aqui
violaria a Lei 2."* O ADR-002 é o documento que deveria fornecer os nomes do padrão, e
fornece os inventados.

Pior: aninhar OCSF em `ocsf_data` significa que **nenhum consumidor de OCSF lê eventos do
Poseidon sem desembrulhar um formato proprietário**, o que anula a interoperabilidade que o
próprio §4 do ADR lista como consequência positiva.

O `04-REMEDIATION.md` [BLOCKER-01] já registra o mapeamento certo — *"`time`,
`metadata.logged_time`, `metadata.product`, `metadata.original_event_uid`, `raw_data`,
`metadata.correlation_uid`"* — e diz *"O ADR-002 será atualizado"*. Não foi.

**Evidência — parte 2, as classes.** O ADR-002 §2.1 mapeia:

| ADR-002 diz | Verificado em `schema.ocsf.io` (2026-09-20) |
|---|---|
| `Class 1004 (Registry Activity)` | 1004 é `memory_activity`. Registro não existe no núcleo: `win/registry_key_activity` **201001** e `win/registry_value_activity` **201002**, na extensão `win` |
| `Class 3001 (Authentication)` | 3001 é `account_change`, **depreciada desde 1.9.0** (→ `user_management`). Authentication é **3002** |
| `Class 2001 (Security Finding)` | **depreciada desde 1.1.0** → `detection_finding` (2004) e classes irmãs |
| `OCSF na versão v1.3.0+` | versão corrente **1.9.0** (2026-08-03) |

Os três erros foram documentados na rodada 2 com evidência da API do schema. O
`00-RESEARCH.md` foi revisado às 11:42; o ADR-002 não.

**Cenário de falha.** A Fase 3 implementa os modelos Pydantic conforme o ADR: um envelope
proprietário com OCSF aninhado, classes 1004/3001/2001. Na Fase 9, o congelamento acontece
sobre um schema que o OCSF depreciou em duas classes e que nenhuma ferramenta OCSF lê. A
Lei 2 foi cumprida no nome e violada no resultado.

**Impacto.** É o formato persistido — a camada que o próprio §9.3 da constituição classifica
como irreversível — e o `BLOCKER-01` reabre no artefato que o implementa, depois de ter sido
fechado no artefato que o governa.

**Correção exigida.** Reescrever o §2 do ADR-002: (a) eliminar o envelope; usar os campos
OCSF nativos que o `03-AUDIT-RESEARCH.md` §3.5 mapeia conceito a conceito; (b) corrigir as
classes para `1007`, `1001`, `4001`, `4003`, **`3002`**, **`2004`**, e declarar a adoção da
extensão `win` para registro; (c) fixar a versão de referência em **1.9.0** e incluir
`metadata.version`, que é `required` no OCSF — confirmei na API do schema, e a resposta do
Builder ao `MAJOR-11` está tecnicamente correta neste ponto; (d) incluir a categoria 7
(Remediation), que é argumento a favor do OCSF e não aparece; (e) avaliar `py-ocsf-models`,
conforme a correção que fiz ao meu próprio `OBSERVATION-06`.

Menor, mas sintomático: o §4 do ADR diz *"Fase 5 exercita contra Sysmon e Security Log"* —
Sysmon saiu do produto — e o §1 cita a Lei 5 pelos nomes de campo revogados.

---

### ADR-003 — STIX 2.1 · o mais sólido dos oito

### [OBSERVATION-16] ADR-003 não tem achado estrutural

Trata `sighting` corretamente como SRO com `sighting_of_ref`, `where_sighted_refs`,
`first_seen`, `last_seen`, `count`; mapeia a Lei 7 diretamente em STIX em vez de criar
entidade paralela — que era o risco que meu `MINOR-04` apontava; exige `source`,
`confidence`, `observed_at` e `raw_payload` em toda ingestão; e o modelo híbrido
relacional/JSONB é a escolha certa pelas razões que ele dá. Cita o OASIS Standard, não o
Errata.

Duas lacunas pequenas: o checklist de conformidade não inclui a **Lei 13**, que exige ADR de
termos de uso antes de qualquer feed de CTI entrar em produção — e o ADR-003 é o documento
que introduz feeds; e `cti_sightings` tem `event_reference` onde o STIX tem
`observed_data_refs`, o que é extensão legítima mas deveria estar sob `poseidon.*` e
declarada como tal.

---

### ADR-004 — Sigma

### [MAJOR-22] O ADR-004 gera alertas numa classe depreciada e não implementa a Lei 13

**Arquivo:** `docs/adr/ADR-004.md` §2.3 e §5

§2.3: *"O casamento de uma query de detecção gerará um evento OCSF `Class 2001 (Security
Finding)`"*. Depreciada desde OCSF 1.1.0. O destino correto para detecção é
`detection_finding` (**2004**).

E o ADR-004 **não menciona licenciamento**. A Lei 13 v2.1 determina que todo alerta gerado
por regra do SigmaHQ *"carrega o autor da regra no próprio alerta"*, porque a DRL 1.1 exige
que *"messages based on matches with the Rules must retain identification of the author(s)"*.
O ADR-004 é o único lugar onde essa obrigação vira campo de dados, e ele não a tem. O
`04-REMEDIATION.md` responde ao `MINOR-05` dizendo que o alerta *"reterá o campo do autor no
payload do evento (`Class 2001 - Security Finding`)"* — repetindo a classe errada e sem que o
ADR registre nada.

Também ausentes: a licença **LGPL-2.1/3.0** do `pySigma` e dos backends, que é decisão de
licença própria e não é coberta pela Lei 13; e a coexistência com as regras XML do Wazuh —
o Wazuh não consome Sigma, então o Poseidon terá duas populações de detecção com ciclos de
vida distintos, e o ADR-004 não diz quem é dono de qual. Menor: cita `sigmahq.io` como
especificação, quando a normativa é `SigmaHQ/sigma-specification` **v2.1.0**.

---

### ADR-005 — Collector Agent

### [MAJOR-23] O ADR-005 descreve o agente da v1.0 e declara conformidade com uma lei que ele não cumpre mais

**Arquivo:** `docs/adr/ADR-005.md` §1, §5

O §1 diz que o agente coleta *"telemetria profunda (Sysmon, Security Log, Defender AV)"*.
Sysmon saiu do produto na v2.0. Não há ETW em lugar nenhum do ADR — nem provedores, nem
biblioteca, nem a junção com o 4688 (`MAJOR-19`), nem a árvore de processos (`MAJOR-20`),
nem a dependência da GPO. O ADR-005 é justamente o documento que a §4 da constituição delega
para resolver essas três coisas: *"decisão e consequências no ADR-005"*.

O §5 declara: *"[x] Lei 10 — Arquitetura compatível com dead-man's-switch e isolamento com
exceção de saída."* O dead-man's-switch por perda de contato **foi removido da Lei 10 na
v2.0**, precisamente porque era incompatível com o transporte. O checklist afirma conformidade
com uma cláusula revogada.

O §2.4 tem enrollment com Ed25519 e CSR — bom — mas **não tem revogação**. O
`04-REMEDIATION.md` [MAJOR-05] promete CRL verificada em cada handshake mTLS; não está aqui.
E `MAJOR-07` (atualização do agente em campo) foi respondido com *"será incorporado como
requisito da Fase 5"*, e não aparece nem no ADR-005 nem no roadmap.

O §2.5 é a redação da Lei 11, objeto da Parte II: precisa da correção sobre o SHA-256, do
inventário de redação, e do conjunto de teste com métrica.

---

### ADR-006 — Protocolo de ações

### [BLOCKER-11] O ADR-006 especifica o failsafe que a Lei 10 v2.1 proíbe, em todos os pontos

**Arquivo:** `docs/adr/ADR-006.md` §2.4 e §4
**Lei/dimensão violada:** Lei 10; dimensões 4.1 e 4.3

O ADR-006 é um bom documento para a constituição v1.0. Contra a v2.1, ele contradiz cada um
dos sete itens da Lei 10 que tratam de failsafe.

| ADR-006 §2.4 diz | Lei 10 v2.1 determina |
|---|---|
| *"**Dead-Man's-Switch:** Um timer autônomo (**goroutine dedicada**) monitora o contato com o servidor"* | Item 5: watchdog **independente do processo do agente**. Uma goroutine é o processo do agente — é o componente que pode ter morrido |
| *"Se o agente ficar sem comunicar heartbeat por mais de `dead_man_timeout_minutes`… **reverte automaticamente** o firewall"* | O gatilho por perda de contato **foi removido na v2.0**, por ser incompatível com o transporte outbound. Item 3: o gatilho é a **expiração assinada** |
| `"parameters": { "dead_man_timeout_minutes": 30 }` no objeto de ação | Item 3: a expiração **é o objeto assinado**, não um parâmetro de timeout |
| *"quatro travas simultâneas"* | São **sete** requisitos na v2.1 |
| §4: *"**Garantia de que nenhuma máquina ficará isolada permanentemente** em caso de pane do servidor ou queda da rota de rede"* | O preâmbulo decide o oposto: **falha-fechado**, *"a contenção vale mais que a conveniência de recuperação"* |
| Ausente | Item 4: base de tempo não pode ser o relógio de parede do host |
| Ausente | Item 6: recuperação fora de banda **local**, documentada e testada; canal remoto proibido |
| Ausente | Item 5: qual componente é a fonte da verdade quando agente e watchdog discordam |

**Cenário de falha.** O ADR-006 está em `Status: Proposed` e é o documento que o humano lê
para decidir o protocolo de resposta. Aprovado como está, a Fase 8 implementa um failsafe
falha-**aberto** dentro do processo do agente — que é literalmente o desenho que os
`BLOCKER-04` e `BLOCKER-06` eliminaram, e que a decisão registrada do humano em 2026-09-20
reverteu.

**Impacto.** É o subsistema que isola máquinas. Um ADR aprovado por inércia aqui desfaz três
rodadas de auditoria e a decisão explícita do humano.

**Correção exigida.** Reescrever o §2.4 contra os sete itens da Lei 10 v2.1, incluindo:
nomear o watchdog (item 5) e reconhecer que, se ele verifica assinatura Ed25519 antes de
restaurar, **ele é um segundo binário assinado com criptografia, não uma tarefa agendada
trivial**; declarar a fonte da verdade entre agente e watchdog; especificar a recuperação
local do item 6; e resolver o `BLOCKER-08` — o comportamento da base de tempo através do
reboot. O §4 precisa trocar a consequência "nenhuma máquina ficará isolada permanentemente"
pela consequência real, que é a inversa e é a decidida.

Um ponto a favor: a rejeição da Alternativa B (*"failsafe centralizado no servidor"*) continua
correta, mas por motivo agora diferente — não é que o failsafe tenha de ser local, é que a
**autoridade** é do servidor e a **execução** é local, com o canal do isolamento seletivo
ligando os dois.

---

### ADR-007 — Auth, RBAC, Audit Log

Sólido no desenho: Argon2id por RFC 9106, TOTP por RFC 6238, refresh rotacionado em cookie
`HttpOnly`/`SameSite=Strict`/`Secure`, papéis com separação entre quem solicita e quem aprova
ação (o que sustenta o `requested_by`/`approved_by` da Lei 9), e a tabela comparando Audit
Log e Case Timeline é boa e cumpre a Lei 6 na parte estrutural.

**Mas não contém a correção que a remediação promete para o `MAJOR-01`.** O
`04-REMEDIATION.md` declara ACEITO e diz: *"O ADR-007 incluirá a especificação de
encadeamento criptográfico por hash… `previous_record_hash`… espelhamento assíncrono para
WORM"*. O ADR-007 tem apenas *"Triggers no PostgreSQL bloqueando `UPDATE` e `DELETE`"* e
*"Envio paralelo **opcional** para syslog/WORM"*.

Isso é precisamente o mecanismo que o `MAJOR-01` identificou como insuficiente: trigger
protege contra o usuário da aplicação, não contra quem tem a credencial de dono do schema —
que é o cenário que a Lei 6 nomeia ao dizer *"nenhum papel, incluindo Super Admin"*. E
"opcional" não satisfaz uma lei.

Também ausentes, embora prometidos ao `MINOR-03`: denylist de JWT em Redis para logoff
imediato, e a declaração de que o identificador de ator no Audit Log é o `user_id` imutável.
**`MAJOR-01` permanece aberto.**

---

### ADR-008 — Persistência

Bem fundamentado. A divisão em três camadas é a correta, as razões para rejeitar
"tudo em OpenSearch" e "tudo em PostgreSQL" são técnicas e honestas, e o registro de hash e
tamanho no PostgreSQL para artefatos do Object Storage é a base certa de cadeia de custódia.

Três promessas da remediação não estão nele:

| Prometido em `04-REMEDIATION.md` | Estado no ADR-008 |
|---|---|
| `MAJOR-06` — ISM com Hot 7d / Warm 30d / Cold 90d, e **retenção estendida separada para Audit Log e evidências** | Só *"rollover por tamanho (ex: 50GB) e retenção temporal por camadas (Hot, Warm, Cold/Delete)"*, sem prazos e **sem a segregação**, que é o ponto do achado |
| `MAJOR-12` — rotação de credenciais com chave dupla | Ausente |
| `OBSERVATION-11` — consistência de restore entre os três repositórios | Ausente |
| `MINOR-06` — registrar a escolha do `arq` e alternativas | Ausente |

**`MAJOR-06`, `MAJOR-12` e `OBSERVATION-11` permanecem abertos.**

E um ponto que o ADR-008 introduz e que interage com o `BLOCKER-09`: §2.3 coloca no Object
Storage *"Arquivos brutos compactados de eventos que geram o `raw_reference`"*. É onde a
credencial em claro do 4688 vai parar.

---

## [MAJOR-21] A remediação declara ACEITO o que os artefatos não contêm

**Arquivo:** `docs/gates/FASE-00/04-REMEDIATION.md`

O `01-BUILDER.md` §5 define **ACEITO** como *"o que foi corrigido, **em quais arquivos**, com
qual teste cobrindo"* — descrição de fato consumado. O `04-REMEDIATION.md` marca 11 de 12
MAJOR como ACEITO, e a maioria em tempo futuro, apontando para ADRs que já existiam em disco
uma hora antes e que não contêm o conteúdo prometido.

| Achado | Remediação promete | Está no arquivo? |
|---|---|---|
| `MAJOR-01` | encadeamento por hash no ADR-007 | ❌ |
| `MAJOR-05` | CRL no ADR-005 | ❌ (enrollment sim, revogação não) |
| `MAJOR-06` | ISM e segregação de retenção no ADR-008 | ⚠️ parcial |
| `MAJOR-07` | atualização do agente na Fase 5 | ❌ |
| `MAJOR-09` | TTL relativo e `clock_skew` no protocolo | ❌ (ADR-006 mantém `expires_at` absoluto) |
| `MAJOR-11` | `metadata.version` no ADR-002 | ❌ |
| `MAJOR-12` | rotação com chave dupla no ADR-008/001 | ❌ |
| `MINOR-03` | denylist JWT e `user_id` imutável no ADR-007 | ❌ |
| `MINOR-06` | `arq` e alternativas no ADR-008 | ❌ |
| `OBSERVATION-11` | DR no ADR-008 | ❌ |

Os quatro BLOCKER e os `MAJOR-02`, `04`, `08`, `10` são exceção legítima: apontam para
mudanças reais na constituição e no `01-BUILDER.md`, feitas pelo humano, e verifiquei que
estão lá. `MINOR-04` também foi entregue — o ADR-003 tem `cti_sightings` como SRO.

**Por que isso importa e não é formalismo.** O razão de achados é o que diz ao humano o que
está resolvido. Com dez itens marcados ACEITO sem entrega, o razão afirma que o passivo caiu
de doze MAJOR para um, quando na prática caiu para dez abertos com plano escrito. No
`05-VERDICT.md` eu teria de reverificar cada correção — e não há o que reverificar.

**Correção exigida.** Nada de reescrever a substância: as resoluções propostas são, na
maioria, tecnicamente boas, e várias eu endosso explicitamente. O que muda é o rótulo.
Itens cuja correção ainda não existe em arquivo não são ACEITO — são **ADIADO com item de
backlog**, que é a terceira resposta que o `01-BUILDER.md` já oferece, ou ACEITO depois de
os ADRs serem atualizados. A segunda opção é a melhor, porque a maior parte do trabalho é
uma passada de revisão nos oito ADRs, não engenharia nova.

### [MINOR-10] O `TEMPLATE.md` de ADR tem checklist de doze leis

`docs/adr/TEMPLATE.md` §5 lista Leis 1 a 12. A constituição tem **treze** desde a v2.0, e a
Lei 13 é a que impõe obrigações de schema — atribuição de autor de regra, aviso do ATT&CK,
ADR de termos de feed, LGPD. Todo ADR criado a partir deste template nasce sem verificar a
lei que mais gera requisito de dado. Os enunciados das Leis 5, 8 e 10 no template também são
os da v1.0.

---

## Verificações realizadas sem achado

- **Lei 10 v2.1, itens 1, 2, 3, 5, 6 e 7** — internamente coerentes, e os itens 5 e 6
  resolvem exatamente o que eu havia apontado como `MAJOR-15` e `MAJOR-16`. O único defeito
  é a base de tempo do item 4 através do reboot (`BLOCKER-08`).
- **Lei 4 v2.1** — a justificativa das "duas naturezas diferentes de dado" é tecnicamente
  correta e melhor que a correção que eu havia pedido.
- **§4 v2.1, tabela de origem por campo e parágrafo sobre PPL/ELAM** — não encontrei erro
  factual. A afirmação sobre `Microsoft-Windows-Threat-Intelligence` exigir PPL Antimalware
  e, por consequência, driver ELAM co-assinado, confere com o que se sabe da plataforma.
- **§11 v2.1** — a separação entre "Adiado — cabe depois da Fase 13" e "Vedado — não é
  questão de prazo" fecha o `MINOR-08` da rodada 2, e a redação *"só por emenda explícita
  desta constituição, que teria de enfrentar o motivo pelo qual foram vedados"* é a
  formulação certa.
- **`metadata.version` do OCSF** — consultei `schema.ocsf.io/api/objects/metadata`: existe e
  é `required`. A resposta do Builder ao `MAJOR-11` está correta; o problema é só não estar
  no ADR-002.
- **ADR-003** — sem achado estrutural (ver `OBSERVATION-16`).
- **ADR-007, §2.1 e §2.2** — mecanismos de autenticação e modelo de papéis corretos e bem
  fundamentados em RFC. O achado é sobre integridade do Audit Log, não sobre autenticação.
- **ADR-008, §2.1 a §2.4 e §3** — divisão de camadas e rejeição das alternativas corretas.
- **ADR-005, §2.1 a §2.3** — Go, serviço via SCM, transporte outbound com mTLS, `bbolt` com
  teto e política FIFO com evento `BUFFER_OVERFLOW_DROP` registrado: correto, e o evento de
  descarte atende à Lei 12 de forma que eu havia cobrado na dimensão 4.8.
- **ADR-006, §2.1 a §2.3** — capacidades fechadas por `switch` sobre enum, validação de
  destinatário, assinatura Ed25519, expiração e nonce em `bbolt`, máquina de estados
  completa: cumprem as Leis 8 e 9. O `BLOCKER-11` é sobre o §2.4, não sobre estes.

---

## Não verificado

1. **`Microsoft-Windows-Kernel-Network`** — nomeado na §4 v2.1 como fonte de eventos de rede.
   Não verifiquei existência, cobertura nem paridade com Sysmon EID 3.
2. **Comportamento real do relógio monotônico do Windows através de reboot e de hibernação**
   no contexto do `BLOCKER-08`. O raciocínio vale para qualquer relógio monotônico por
   definição; não medi o comportamento específico de `QueryUnbiasedInterruptTime` nem o do
   runtime do Go.
3. **Taxa real de falso negativo e falso positivo da redação por regex.** Meu argumento é
   estrutural, apoiado na especificação do Sigma. **Nenhum número foi medido** — e o ponto
   central do meu voto na Parte II é justamente que ninguém mediu.
4. **Viabilidade da junção ETW × 4688** (`MAJOR-19`) — descrevi o problema; não testei
   janelas nem chaves.
5. **Nada em VM.** Nenhuma verificação desta rodada tocou máquina, isolamento, watchdog, WFP
   ou ETW em execução.
6. **`00-RESEARCH.md` revisado às 11:42** — li o original de 10:46 para a rodada 2 e
   auditei os ADRs nesta. **Não reli a versão revisada**, então não afirmo se as correções de
   classe OCSF entraram nela. O ADR-002, que é o que decide, não as tem.
7. **Nada jurídico.** DRL 1.1, LGPD, licenças LGPL do pySigma: reportei texto e consequência
   técnica.

---

## Resumo para decisão

| | Rodada 1 | Rodada 2 | Rodada 3 |
|---|---|---|---|
| BLOCKER abertos ao fim | 4 | 3 | **4** |

**Abertos agora:**

| ID | Achado | Onde |
|---|---|---|
| `BLOCKER-08` | Monotônico não sobrevive ao reboot que a falha-fechado exige | Constituição, Lei 10 item 4 |
| `BLOCKER-09` | Lei 5 × Lei 11: o evento bruto carrega a credencial | Constituição, Leis 5 e 11 |
| `BLOCKER-10` | ADR-002 reintroduz o envelope revogado e usa classes erradas | `docs/adr/ADR-002.md` |
| `BLOCKER-11` | ADR-006 especifica o failsafe que a Lei 10 v2.1 proíbe | `docs/adr/ADR-006.md` |

A leitura importa: **a v2.1 é uma boa emenda.** Fechou dois dos três BLOCKER de forma limpa,
fechou os quatro MAJOR residuais da rodada 2, e o parágrafo sobre PPL/ELAM é o melhor
exemplo de Lei 1 que este projeto produziu — declarar uma limitação estratégica antes de
descobri-la. O `BLOCKER-08` é dificuldade genuína, não descuido.

Os outros dois BLOCKER não vêm da emenda: vêm de os ADRs nunca terem sido auditados nem
atualizados. `BLOCKER-10` e `BLOCKER-11` são o `BLOCKER-01` e o `BLOCKER-04` sobrevivendo
nos documentos que a constituição delega para implementá-los. Corrigir a lei e não corrigir
o ADR que a executa deixa o defeito exatamente onde ele produz código.

Ordem que eu recomendaria:

1. **`BLOCKER-11` e `BLOCKER-10`** — são revisão de texto contra leis já decididas, sem
   decisão nova. Baratos, e enquanto existirem, um "sim" do humano a esses ADRs desfaz três
   rodadas.
2. **`BLOCKER-09`** — exige emenda, porque duas leis vigentes são mutuamente incumpríveis e
   nenhum Builder pode resolver isso sozinho. Toca a decisão de SaaS: define se o operador
   custodia credenciais de clientes.
3. **`BLOCKER-08`** — a correção que proponho usa o canal que o isolamento seletivo já
   garante, e não inventa mecanismo.
4. **`MAJOR-21`** — reclassificar as dez promessas, ou entregá-las na revisão dos ADRs. É a
   opção melhor: o trabalho é uma passada de revisão, não engenharia nova.

Sobre o `MAJOR-03`: o Builder ganhou a parte em que estava certo — minha solução era
arquiteturalmente errada e retirei. Perdeu a parte em que generalizou: o SHA-256 não preserva
capacidade Sigma, e nenhum modificador da especificação 2.1.0 opera sobre hash. O achado
segue aberto com escopo novo — medir a taxa de erro da redação — e produziu o `BLOCKER-09`,
que é mais grave que ele.
