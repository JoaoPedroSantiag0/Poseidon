# Decisões registradas do humano

> Decisões que **não são do Builder nem do Auditor**. Elas resolvem Condições de Parada
> (§9 da constituição) e têm a mesma precedência que o texto constitucional.
>
> Nenhum ADR pode contradizer uma decisão aqui. ADR que dependa de uma delas deve citá-la.

---

## D-001 · Sem tenant Microsoft 365 com Defender for Endpoint
**Data:** 2026-09-20 · **Afeta:** roadmap, ADR-001

O humano não possui tenant licenciado. O Defender for Endpoint sai do caminho crítico e vira
contrato `EDRConnector` testado com respostas gravadas, entregue desabilitado.

---

## D-002 · O Poseidon tem ambição de SaaS
**Data:** 2026-09-20 · **Afeta:** §4, §11, Lei 13, ADR-005, ADR-008

Consequências já incorporadas à constituição:
- Sysmon fora do produto (EULA Sysinternals veda *commercial software hosting services*)
- Telemetria via ETW + Windows Event Log, com a origem de cada campo declarada na §4
- Multi-tenancy não construída no MVP, mas o modelo de dados carrega tenant desde a Fase 2
- LGPD aplicável: o Poseidon é operador de dados pessoais

---

## D-003 · Isolamento é falha-fechado
**Data:** 2026-09-20 · **Afeta:** Lei 10, ADR-006

Sobrevive ao reboot e à morte do agente. Consequência: o failsafe não mora no agente —
expiração é o objeto assinado da Lei 9, base de tempo monotônica, recuperação fora de banda
obrigatoriamente local. Isolamento total fora do MVP.

---

## D-004 · CTI externo: consultar, não acumular acervo de terceiro
**Data:** 2026-09-20 · **Afeta:** Fase 6, ADR-003, Lei 13

O Poseidon **não constrói base própria a partir do acervo de fontes externas** (pulses,
listas de IOC, descrições de terceiros).

O Poseidon **persiste as próprias observações**: *"consultei o IOC X em T, a fonte S
respondeu R"*, e *"vi o IOC X no host Y do cliente Z em T"*. Isso é fato próprio, satisfaz a
Lei 7 e não é derivado do acervo alheio.

**Motivo, e é estratégico antes de ser jurídico:** o acervo de terceiro é comprável por
qualquer concorrente; o histórico de avistamentos dos seus clientes não é. O ativo que
compõe com o tempo é o segundo.

### Restrições verificadas em 2026-09-20 — insumo obrigatório do planejamento de custo

| Fonte | Situação para produto comercial |
|---|---|
| **VirusTotal**, API pública | *"must not be used in commercial products or services"*; proíbe republicar/redistribuir material do serviço. **Exige API premium paga** |
| **AbuseIPDB**, plano gratuito | *"You may not use Free plans for commercial purposes"*. **Exige plano Basic ou superior** |
| **abuse.ch** (MalwareBazaar/URLhaus/ThreatFox) | Declarado *"100% free for commercial and non-commercial usage"* sob uso justo. Há menção a licença de desenvolvedor para acesso comercial à API — **NÃO VERIFICADO em detalhe** |
| **OTX / LevelBlue** | Não encontrada proibição categórica de uso comercial. **Termos integrais NÃO VERIFICADOS** |

Fontes consultadas em 2026-09-20: `docs.virustotal.com/reference/getting-started`,
`docs.virustotal.com/docs/historic-terms-of-service`, `abuseipdb.com/legal`,
`abuse.ch`, `bazaar.abuse.ch/faq`.

**Consequência de roadmap:** VirusTotal e AbuseIPDB estavam previstos para a V1 em tier
gratuito. **Não podem entrar assim.** Ou entram pagos — custo recorrente que precisa constar
do modelo de negócio agora — ou a V1 usa abuse.ch e OTX, e os dois primeiros ficam para
quando houver receita. Decisão pertence ao ADR-003.

---

## D-005 · O Poseidon fornece o Wazuh ao cliente
**Data:** 2026-09-20 · **Afeta:** ADR-001, Fase 9, empacotamento

O Poseidon hospeda o manager e entrega o agente Wazuh aos endpoints do cliente. Isso é
**redistribuição de software GPLv2** — permitida, com obrigações estritas:

1. **Dois artefatos separados, sempre.** O instalador do Poseidon **nunca** empacota o
   agente Wazuh dentro de si. O `LICENSE` do `wazuh/wazuh` nomeia explicitamente
   *"includes/integrates Wazuh into a proprietary executable installer"* como obra
   derivada. Entregar lado a lado, como pacotes distintos, não cai nessa leitura.
2. **Oferta de código-fonte** para a release exata distribuída, apontando o tag upstream.
3. **Preservar avisos de copyright e o texto da licença** nos artefatos do Wazuh.
4. **Nenhuma restrição adicional** sobre as partes do Wazuh — o EULA do Poseidon não pode
   proibir o cliente de redistribuir o agente Wazuh.
5. **Não modificar o agente Wazuh.** Se for modificado, as modificações *a ele* são GPLv2 e
   devem ser publicadas.
6. **O Collector do Poseidon permanece com zero código derivado do Wazuh.** Ele é o que
   torna o repositório do Poseidon privado sem conflito.
7. **Marca:** "Wazuh" é marca de terceiro; nenhuma comunicação do Poseidon pode sugerir
   endosso ou origem comum.

**Alerta de horizonte:** o agente da linha 5.x (`wazuh/wazuh-agent`) é **AGPL-3.0**, que tem
a cláusula de rede (§13) que o GPLv2 não tem. Migrar para ele **invalida esta análise** e
exige novo ADR antes de qualquer adoção.

**Ressalva:** as leituras acima são de texto de licença, não parecer jurídico. Antes de
vender, um advogado precisa ver os itens 1, 4 e 7.
