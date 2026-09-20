# ADR-009 — Escopo do produto e papel do motor de detecção

> **Rodada de decisão dedicada.** Todo o resto está congelado até esta decisão sair.
> Em particular: **não consertar `BLOCKER-10`, `11`, `12` e `14`** — são passadas de revisão
> nos ADRs, e parte deles será reescrita de qualquer forma dependendo do resultado aqui.
>
> Aberta em 2026-09-20 pelo humano.

---

## 1. A pergunta

Não é "qual SIEM é melhor". É **qual produto o Poseidon é**.

A intenção original do humano, nas palavras dele:

> *"SIEM + CTI = Poseidon. Em outros termos: Wazuh + conjunto inteligente de APIs = projeto."*

Ao longo da Fase 0 o escopo cresceu: o Poseidon ganhou Collector próprio, modelo de evento
próprio, Response Control Plane, engenharia de detecção com Sigma e cofre de evidências.
Cada passo foi defensável isoladamente. O resultado acumulado é uma plataforma completa na
qual o Wazuh passou a ser **redundante** — e é dessa redundância que vem a fricção
documentada em três rodadas de auditoria: dois agentes no endpoint, dois formatos de
detecção, dois caminhos de resposta, dois caminhos de credencial, dois clientes de API.

**A tarefa desta rodada é decidir qual dos quatro produtos abaixo o Poseidon é.** A escolha
do motor de detecção é consequência disso, não causa.

---

## 2. As quatro opções

### Opção A — SIEM de terceiro + CTI (a visão original)

O Poseidon é a **camada de inteligência, investigação e integração** sobre um SIEM que ele
não escreve. Sem Collector próprio, sem Response Control Plane próprio, sem modelo de evento
próprio no MVP.

```
Wazuh (ou outro SIEM)  →  detecta
Poseidon               →  CTI, enriquecimento, entidades, timeline,
                          Investigation Workspace, Integration Hub, UX
```

### Opção B — Plataforma completa, Wazuh como motor

O estado atual da arquitetura. Collector próprio, modelo de evento próprio, resposta própria,
e o Wazuh como uma fonte entre outras.

### Opção C — Plataforma completa, stack permissiva

Mesmo escopo do B, trocando o Wazuh por componentes Apache-2.0:
**OpenSearch Security Analytics** (motor de detecção, Sigma nativo) + **osquery**
(FIM, inventário, estado de configuração) + Collector próprio.

### Opção B′ — Wazuh como serviço de detecção, **sem agente Wazuh no endpoint**

Proposta do humano em 2026-09-20. **Um único agente no endpoint — o do Poseidon.** A
telemetria entra no Wazuh pela fronteira de ingestão do Poseidon, não por um agente Wazuh.

```
Endpoint
  └─ Poseidon Collector          (único agente instalado)
       └─ Poseidon Ingestion     ← a REDAÇÃO da Lei 11 acontece aqui
            ├─→ Poseidon Core    (modelo de evento próprio)
            └─→ Wazuh Manager    (formato compatível, via syslog remoto)
                   └─ decoders + regras → alertas → Indexer → Poseidon puxa
```

O Wazuh deixa de ser infraestrutura de agentes e vira **serviço de detecção que o Poseidon
chama**.

**O que isto resolve, se for viável:**

| Problema | Por quê |
|---|---|
| `MAJOR-26` — dois agentes no endpoint | passa a haver um só |
| **As sete obrigações da D-005** | você nunca distribui código do Wazuh. Hospedar GPLv2 não é distribuição, e o GPLv2 não tem cláusula de rede |
| Risco do agente 5.x virar AGPL-3.0 | você não usa o agente deles |
| `BLOCKER-13` — custódia de credencial | a redação acontece no Poseidon **antes** do Wazuh. O Wazuh nunca vê credencial |
| `BLOCKER-03` — Active Response como superfície | sem agente Wazuh no endpoint não existe caminho de execução do Wazuh |
| Maior perda da opção C | você **mantém** a biblioteca de decoders e regras do Wazuh |

**O que custa, e é preciso ser honesto:**

Os módulos **FIM, SCA/CIS, rootcheck e coleta de inventário** rodam **no agente** do Wazuh,
não no manager. Sem o agente, você não os tem — teria de construí-los no Collector ou usar
osquery. É a mesma perda da opção C para essas capacidades específicas, com a diferença de
que aqui você preserva o motor de regras.

**O que precisa ser verificado antes de qualquer entusiasmo:**

1. **O decoder `windows_eventchannel` dispara em evento injetado?** As regras do Wazuh para
   Windows dependem do envelope que o agente produz (`data.win.eventdata.*`,
   `data.win.system.eventID`, `location: EventChannel`). Se o Collector emitir o mesmo
   envelope, as regras devem casar — **isto é a hipótese central da opção B′ e não está
   verificada.** Se falhar, B′ entrega o manager sem o valor dele.
2. **Syslog remoto suporta o volume e o formato?** Limite de tamanho de mensagem,
   enquadramento, TCP vs UDP, TLS, perda sob carga.
3. **`POST /events` da API:** limites de taxa reais, maturidade, se é caminho suportado para
   produção ou só para integração e teste. A spec v4.14.7 declara o path; a documentação é
   escassa.
4. **Atribuição de endpoint nos alertas.** Alertas do Wazuh carregam `agent.id`,
   `agent.name`, `agent.ip`. Em evento ingerido por syslog, quem é o agente? Se for sempre o
   manager (`000`), o Poseidon precisa de outro caminho para amarrar o alerta ao endpoint de
   origem — e isso afeta o Investigation Workspace inteiro.
5. **Acoplamento de formato.** O Collector passaria a emitir formato Wazuh. Isso deve ficar
   confinado a um **adapter de saída** na fronteira, nunca no modelo interno do Collector,
   sob pena de violar a Lei 4 pela porta dos fundos.
6. **Syscollector e detecção de vulnerabilidade:** o casamento com CVE é feito no manager a
   partir do inventário que o agente envia. Se o Collector emitir inventário em formato
   syscollector, a detecção de vulnerabilidade do Wazuh volta a funcionar? **Verificar** —
   se sim, recupera uma das perdas listadas acima.

**Avalie B′ contra os mesmos dez critérios da seção 5, junto com A, B e C.**

---

## 3. O que já está verificado — não repesquisar

Resultados de três rodadas. Use como insumo; conteste apenas com fonte primária.

| Fato | Fonte | Rodada |
|---|---|---|
| `wazuh/wazuh` (manager + agente 4.x) é **GPLv2**; `wazuh/wazuh-agent` (5.x, WIP) é **AGPL-3.0**; indexer e dashboard **Apache-2.0**; `wazuh-indexer-plugins` **AGPL-3.0** | arquivos LICENSE | 1 e 2 |
| A API do Manager (55000) **não serve alertas**; eles vivem no Indexer (9200), índices `wazuh-alerts-*` | spec OpenAPI v4.14.7 | 1 |
| Active Response: prefixo `!` pula a lista de permissões; `agents_list` default `'*'` atinge a frota; `extra_args` sem escape no caminho moderno; `upgrade_custom` instala WPK arbitrário | código-fonte v4.14.7 | 1 |
| O Wazuh **não consome Sigma** — regras XML próprias | spec + docs | 2 |
| O agente Wazuh coleta linha de comando e **não faz redação nenhuma** | `00-RESEARCH.md` §2.1.3 | 3 |
| EULA do Sysinternals veda *"commercial software hosting services"* → Sysmon fora do produto | `live.sysinternals.com/Eula.txt` | 1 |
| `Microsoft-Windows-Kernel-Process` **não entrega linha de comando confiável**; ela vem do Security 4688, que exige GPO desligada por padrão | Microsoft Learn | 2 e 3 |
| `Microsoft-Windows-Threat-Intelligence` exige PPL com atributo Antimalware, que exige driver ELAM co-assinado pela Microsoft | Microsoft Learn | 3 |
| OCSF corrente é **1.9.0**; classe 2001 depreciada desde 1.1.0 → usar `detection_finding` (2004); registro do Windows só na extensão `win` | `schema.ocsf.io/api/*` | 2 |
| VirusTotal API pública: *"must not be used in commercial products or services"*. AbuseIPDB gratuito: *"may not use Free plans for commercial purposes"* | docs oficiais | 3 |
| OpenSearch Security Analytics é **Apache-2.0**, tem **suporte nativo a Sigma**, detectores para Windows/Linux/rede/nuvem e motor de correlação desde a 2.7 | docs OpenSearch | 3 |
| osquery é **Apache-2.0**, multiplataforma, com FIM via `file_events` e inventário | docs osquery | 3 |

---

## 4. Decisões do humano que continuam valendo

Leia `docs/DECISOES-DO-HUMANO.md` por inteiro. As que mais pesam aqui:

- **D-002 — o Poseidon tem ambição de SaaS.** Qualquer opção precisa funcionar como serviço
  operado por você para terceiros. Licença que restringe oferta gerenciada está fora.
- **D-005 — hoje o Poseidon fornece o Wazuh ao cliente.** Esta decisão **está em revisão
  nesta rodada** e pode ser revogada pelo resultado. Trate-a como hipótese, não premissa.

---

## 5. Critérios de decisão

Avalie cada opção contra todos. Não pontue: descreva a consequência concreta.

1. **Entrega do MVP** — quanto tempo até o primeiro vertical slice funcionando de ponta a
   ponta, com um endpoint real?
2. **Diferenciação** — o que o produto oferece que o motor sozinho não oferece? Se a resposta
   for fraca, a opção é ruim, por melhor que seja tecnicamente.
3. **Licenciamento sob SaaS** — obrigações de redistribuição, cláusulas de rede, restrição a
   serviço gerenciado. Por componente, com o arquivo LICENSE lido.
4. **Custódia de dado pessoal** — por onde a linha de comando do cliente trafega e onde ela
   repousa. Quem é custodiante em cada opção. (`BLOCKER-09`, `BLOCKER-13`)
5. **Superfície de execução** — quantos caminhos de execução no endpoint o produto comanda, e
   se a Lei 8 alcança todos. (`BLOCKER-03`)
6. **Duplicação** — quantos agentes no endpoint, quantos formatos de detecção, quantos
   caminhos de resposta, quantos clientes de API.
7. **Dependência estratégica** — o que acontece se o fornecedor mudar licença, ritmo ou
   direção. O agente Wazuh 5.x indo para AGPL-3.0 é o caso concreto.
8. **Maturidade** — o que se perde em biblioteca de decoders, SCA/CIS, detecção de
   vulnerabilidade, rootcheck, e quanto custa reconstruir cada um.
9. **Posicionamento comercial** — "baseado em Wazuh" comunica algo que as outras opções não
   comunicam. Isso tem valor e precisa aparecer na conta.
10. **Reversibilidade** — dá para começar por uma e migrar? A que custo?

---

## 6. O que precisa ser verificado e ainda não foi

Nenhuma destas tem resposta no repositório. Marque `NÃO VERIFICADO` o que não conseguir
confirmar em fonte primária — a Lei 1 vale integralmente.

**Sobre OpenSearch Security Analytics:**
- Cobertura real da especificação Sigma: suporte integral ou subconjunto? Quais modificadores
  e correlações não funcionam?
- Quais log types e detectores vêm prontos, e quais exigem mapeamento manual
- Motor de correlação: o que ele faz e o que não faz
- Limitações operacionais conhecidas, escala, maturidade
- Como ele se relaciona com o Alerting plugin e o que isso implica para o Response Plane

**Sobre osquery:**
- Cobertura comparada ao Wazuh para FIM, SCA/CIS e detecção de vulnerabilidade
- O que o osquery **não** faz que o agente Wazuh faz
- Modelo de gerenciamento de frota em escala, e se exige componente adicional
- Se a coleta de `file_events` no Windows tem paridade com Linux/macOS

**Sobre a opção A especificamente:**
- Se o Poseidon **não** tiver Collector próprio, de onde vem a telemetria de endpoint para o
  Investigation Workspace?
- O `BLOCKER-13` desaparece de fato, ou só muda de dono, se o cliente hospedar o próprio
  Wazuh?
- Qual é o MVP da opção A, em uma lista de telas e capacidades?
- A opção A ainda comporta as Fases 8 a 13 do roadmap no futuro, ou fecha portas?

**Transversal:**
- Alternativas que nenhum dos dois papéis pesquisou até agora e que podem caber: **MISP**
  (citado no §3 da constituição e nunca pesquisado), Suricata, Zeek, Fleet, Velociraptor.
  Verificar licença antes de qualquer entusiasmo.

---

## 7. Entregáveis

| Arquivo | Autor |
|---|---|
| `docs/gates/ADR-009/01-RESEARCH-BUILDER.md` | Builder |
| `docs/gates/ADR-009/02-RESEARCH-AUDITOR.md` | Auditor — **independente, sem ler o do Builder** |
| `docs/gates/ADR-009/03-COMPARACAO.md` | Auditor, depois de ler os dois |
| `docs/gates/ADR-009/04-RECOMENDACAO.md` | Builder, uma recomendação com consequências |

O humano decide. Nenhum dos dois papéis fecha esta decisão.

---

## 8. Regra desta rodada

**Não recomende por elegância técnica.** A opção A é a menos sofisticada das quatro e pode
muito bem ser a certa, porque entrega antes e porque a diferenciação do produto nunca esteve
no motor de detecção — esteve na camada de investigação e inteligência acima dele.

A pergunta que fecha esta rodada é: **qual opção coloca um analista investigando um incidente
real mais cedo, sem criar uma classe de problema que a gente já sabe que vai doer?**
