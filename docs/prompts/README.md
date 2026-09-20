# Como operar as duas IAs

## Pré-requisito

**As duas IDEs devem abrir `D:\PoseidonProject`.** Elas não conversam por rede — conversam
pelo sistema de arquivos. Se uma delas estiver em outra pasta, o protocolo de gate quebra
e você vira o carteiro manual entre as duas.

## Bootstrap

Cole isto na IDE que será o **Builder**:

```
Você é o Architect/Builder do projeto Poseidon.

Leia, nesta ordem e por inteiro, antes de qualquer outra ação:
  docs/prompts/00-CONSTITUTION.md
  docs/prompts/01-BUILDER.md

Depois execute a seção "Sua primeira ação nesta sessão" do 01-BUILDER.md.
Não escreva código de aplicação na Fase 0.
```

Cole isto na IDE que será o **Auditor**:

```
Você é o Auditor do projeto Poseidon.

Leia, nesta ordem e por inteiro, antes de qualquer outra ação:
  docs/prompts/00-CONSTITUTION.md
  docs/prompts/02-AUDITOR.md

Depois execute a seção "Sua primeira ação nesta sessão" do 02-AUDITOR.md.
Você não escreve código de produção.
```

No começo de **toda sessão nova**, repita o bootstrap. Contexto de IDE não sobrevive ao
fechamento, e a constituição precisa estar dentro da janela de contexto para valer alguma
coisa.

## O ciclo

```
1. Builder    → 00-RESEARCH.md      (pesquisa, com fontes citadas)
2. Builder    → 01-PLAN.md          → PARA, você aprova o plano
3. Builder    → implementa + testa
4. Builder    → 02-BUILD-REPORT.md  → PARA
5. você avisa o Auditor que a fase está pronta
6. Auditor    → 03-AUDIT-REPORT.md
7. você avisa o Builder que há auditoria
8. Builder    → 04-REMEDIATION.md   (ACEITO / CONTESTO / ADIADO, item a item)
9. Auditor    → reverifica → 05-VERDICT.md  (PASS ou FAIL)
10. PASS → tag v0.XX.0 → próxima fase
    FAIL → volta ao passo 8
```

Você é o único gatilho entre 4↔5 e 6↔7. É trabalho de duas mensagens por ciclo, e é o que
mantém as duas IAs sincronizadas sem que uma atropele a outra.

## Seus dois pontos de decisão

**Passo 2** — aprovar o plano. É aqui que você corrige rumo barato. Plano errado
implementado com perfeição continua errado.

**Passo 9** — aceitar ou não um MAJOR como dívida. Só você pode. BLOCKER não é negociável
nem por você: se for mesmo aceitável, então a constituição está errada e deve ser emendada
explicitamente — não contornada no caso particular.

## Quando emendar a constituição

Ela não é sagrada. Mas emenda é ato deliberado: você edita `00-CONSTITUTION.md`, sobe a
versão, registra o motivo, e avisa as duas IAs na próxima sessão. O que não pode é uma
lei ser contornada em silêncio dentro de um gate — é assim que projeto de segurança
apodrece sem ninguém perceber.

## Sinais de que o processo está degradando

- Auditor aprovando fases sem achado, repetidamente
- Builder aceitando todos os achados sem nunca contestar
- Relatórios de gate encurtando ao longo das fases
- `NÃO VERIFICADO` sumindo dos relatórios sem que nada tenha sido verificado
- Você parando de ler os planos antes de aprovar

Qualquer um desses significa que as duas IAs viraram uma só, com passos a mais. Se
acontecer, troque os papéis entre as IDEs por uma fase — a que auditava passa a construir.
Perspectiva nova costuma reencontrar o que a familiaridade apagou.
