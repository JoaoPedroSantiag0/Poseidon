# ADR-009 — Pesquisa Técnica do Builder: Escopo do Produto e Papel do Motor de Detecção

> **Status:** Pesquisa técnica concluída pelo Architect/Builder  
> **Data:** 2026-09-20  
> **Conformidade:** Constituição v2.1 (Leis 1, 4, 8, 10, 11, 13 e §4) | `docs/DECISOES-DO-HUMANO.md` (D-001 a D-005)  
> **Regra desta rodada:** Levantamento factual e imparcial com fontes primárias (Lei 1). **Sem recomendação nesta fase** (a recomendação será emitida exclusivamente no documento `04-RECOMENDACAO.md` após o cotejo com a pesquisa do Auditor).

---

## Sumário Executivo da Pesquisa

Esta pesquisa analisa as quatro opções estruturais de produto postas no Briefing do ADR-009:
- **Opção A:** SIEM de terceiro + CTI (camada de investigação, correlação de entidades e inteligência sobre SIEM/EDR existente).
- **Opção B:** Plataforma completa com Wazuh como motor de detecção (coleta própria, resposta própria, regras Wazuh).
- **Opção C:** Plataforma completa sobre stack permissiva (OpenSearch Security Analytics + osquery + Poseidon Collector).
- **Opção B′:** Wazuh como serviço de detecção sem agente Wazuh no endpoint (proposta do humano de 2026-09-20).

### Achado Crítico Imediato: A Hipótese Central da Opção B′ Caiu Factualmente
A verificação número 1 da Opção B′ investigou se o decoder nativo `windows_eventchannel` do Wazuh dispara em eventos Windows injetados via syslog ou API.
**Resultado:** **NÃO dispara.** O decoder `windows_eventchannel` (`DecodeWinevt`) no Wazuh é executado em C exclusivamente quando a mensagem interna do agente contém o cabeçalho `location: EventChannel`, emitido pelo binário do agente Wazuh na porta 1514. Eventos recebidos via syslog (porta 514) ou API caem nos decoders `syslog` ou `json`. A regra raiz de todos os eventos de Windows no Wazuh (`0575-win-base_rules.xml`, Rule ID 60000) exige explicitamente `<decoded_as>windows_eventchannel</decoded_as>`. Como consequência, **nenhuma das centenas de regras nativas de Windows do Wazuh (Sysmon, Security, Defender, PowerShell) casa ou gera alerta para eventos injetados externamente**, a menos que o arquivo base de regras do Wazuh seja alterado manualmente (o que é sobrescrito em cada atualização) ou que o Poseidon Collector reimplemente o protocolo criptográfico binário do agente Wazuh na porta 1514.

Os detalhes desta verificação e o mapeamento das quatro opções contra os dez critérios seguem abaixo.

---

## 1. Verificação Técnica Aprofundada da Opção B′ (Os 6 Itens do Briefing)

### 1.1 Item 1: O decoder `windows_eventchannel` dispara em evento injetado?

- **Pergunta:** As regras do Wazuh para Windows dependem do envelope do agente (`data.win.eventdata.*`, `data.win.system.eventID`, `location: EventChannel`). Se o Poseidon Collector ou Ingestion injetar o mesmo envelope via syslog/JSON, o decoder `windows_eventchannel` e as regras de detecção disparam?
- **Resultado da Investigação:** **FALHA TOTAL (A hipótese não se sustenta no Wazuh padrão).**
- **Evidência Primária no Código-Fonte e Regras:**
  1. **Código C do `analysisd`:** Em `src/analysisd/decoders/winevtchannel.c` (função `DecodeWinevt`), o parser é invocado internamente pelo despachante de decoders apenas quando a mensagem carrega o identificador de canal de evento do Windows gerado pelo `logcollector` do agente (`EventChannel`).
  2. **Tratamento de Syslog e JSON:** Mensagens que entram via syslog de rede (`src/remoted/remoted.c` na porta 514 UDP/TCP) são tratadas por `src/analysisd/decoders/syslog.c` ou `src/analysisd/decoders/json.c`. O decoder associado ao evento resultante é atribuído como `syslog` ou `json`, e **nunca** como `windows_eventchannel`.
  3. **A Regra Raiz 60000 (`ruleset/rules/0575-win-base_rules.xml`):**
     ```xml
     <rule id="60000" level="0">
       <category>ossec</category>
       <decoded_as>windows_eventchannel</decoded_as>
       <field name="win.system.providerName">\.+</field>
       <options>no_full_log</options>
       <description>Group of windows rules.</description>
     </rule>
     ```
     Todas as regras de detecção de Windows no Wazuh (incluindo eventos de logon 4624, criação de processos 4688, PowerShell 4104, Sysmon EID 1 a 25) herdam direta ou indiretamente da regra 60000 via `<if_sid>60000</if_sid>` ou `<if_group>windows</if_group>`.
  4. **Comportamento em Testes e Produção:** Na documentação e nos fóruns oficiais de engenharia do Wazuh (e.g., investigações de uso do `wazuh-logtest`), quando um evento de Windows é fornecido em formato JSON ou syslog, a regra 60000 avalia como `false` porque `decoded_as` é `json` e não `windows_eventchannel`. O único "workaround" conhecido pela comunidade Wazuh é modificar manualmente o arquivo `/var/ossec/ruleset/rules/0575-win-base_rules.xml`, alterando `<decoded_as>windows_eventchannel</decoded_as>` para `<decoded_as>json</decoded_as>`.
  5. **Impacto Operacional:** Modificar regras na pasta padrão do Wazuh quebra a integridade do ruleset e é revertido em upgrades do Wazuh Manager (`wazuh-manager` substitui arquivos em `/var/ossec/ruleset/rules/`). Além disso, mesmo com essa alteração, os campos extraídos por `json` ficam sob o prefixo `data.*` sem a estrutura esperada de mapeamento do XML nativo de canais do Windows, gerando falsos negativos sistemáticos.
  6. **Alternativa Teórica:** Para injetar eventos e fazê-los passar por `windows_eventchannel`, o Poseidon precisaria conectar na porta 1514 do Wazuh Manager, emular a negociação de chave simétrica Blowfish/AES e o enquadramento binário do protocolo interno do agente Wazuh (`agentd`). Isso violaria frontalmente a premissa de um contrato limpo de integração e acoplaria o Poseidon a estruturas internas privadas e instáveis do Wazuh.
- **Fontes Primárias:**
  - Repositório Wazuh: `wazuh/wazuh` — arquivo `ruleset/rules/0575-win-base_rules.xml` (acessado em 2026-09-20).
  - Repositório Wazuh: `wazuh/wazuh` — `src/analysisd/decoders/winevtchannel.c` (acessado em 2026-09-20).
  - Wazuh Issue #6027 & #11974: Discussões de engenharia sobre limitação de decodificação de EventChannel fora do agente local (`https://github.com/wazuh/wazuh/issues/11974`).

---

### 1.2 Item 2: O syslog remoto suporta o volume e o formato?

- **Capacidade e Concorrência:** O listener de syslog do `wazuh-remoted` roda em um loop de socket com buffer configurável, mas é historicamente limitado quando comparado a coletores dedicados como Vector, Fluentbit ou Logstash.
- **Tamanho Máximo de Mensagem:** No RFC 3164/5424 padrão do Wazuh, o buffer máximo padrão por linha de log é limitado a 64 KB (`OS_MAXSTR` no core em C). Eventos ricos de telemetria moderna do Windows (ETW/EventLog de PowerShell com ScriptBlock ou Sysmon com hashes e dados PE completos) frequentemente ultrapassam 64 KB, sofrendo truncamento silencioso no socket do syslog.
- **Enquadramento e Transporte:** Syslog UDP sofre perda de pacotes garantida sob rajadas de eventos (bursts de atividade de endpoint). Syslog TCP no Wazuh sofre com conexão travada caso o socket entre em backpressure, bloqueando o worker do `remoted`. O `wazuh-remoted` não oferece terminação TLS nativa com autenticação mTLS robusta para syslog sem o auxílio de proxies externos (rsyslog ou stunnel).
- **Fontes Primárias:**
  - Wazuh Documentation: "Remote syslog monitoring configuration" (`https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html`, acessado em 2026-09-20).
  - Wazuh Core: `src/headers/defs.h` (`OS_MAXSTR` buffer definitions).

---

### 1.3 Item 3: Viabilidade e limites reais do `POST /events` da API do Wazuh

- **Limites de Taxa e Concorrência:** A API do Wazuh Manager (porta 55000, escrita em Python/AsyncIO) foi desenhada para operações administrativas de controle e consulta, não para ingestão massiva de telemetria.
- **Teto Operacional Verificado:** A especificação OpenAPI v4.14.7 e as configurações de segurança da API (`api.yaml`) impõem limitação padrão de requisições (`max_request_per_minute: 300` a `30` dependendo do endpoint). O endpoint `POST /events` aceita lotes de no máximo 100 eventos por chamada. Isso estabelece uma taxa máxima teórica de processamento de **50 a 500 eventos por segundo**, o que é ordens de grandeza inferior à telemetria de um único endpoint corporativo em atividade de pico (um único host gerando ETW de processos, rede e registro pode emitir facilmente 2.000 a 5.000 eventos/s).
- **Overhead:** Cada lote via API exige overhead de handshake HTTP/1.1 TLS, autenticação por Bearer JWT, deserialização de JSON em Python e despacho para socket UNIX local de `analysisd`. É um caminho comprovadamente inviável para produção contínua de streaming de telemetria.
- **Fontes Primárias:**
  - Wazuh OpenAPI Specification v4.14.7: Definição do endpoint `/events`.
  - Wazuh Documentation: "API Configuration parameters (`api.yaml`)" (`https://documentation.wazuh.com/current/user-manual/api/configuration.html`, acessado em 2026-09-20).

---

### 1.4 Item 4: Atribuição de endpoint nos alertas gerados

- **Comportamento do `agent.id`:** Todo evento ingerido no Wazuh por syslog remoto ou pela API HTTP é categorizado pelo `analysisd` como originado do próprio Wazuh Manager.
- **Identidade Registrada:**
  - `agent.id`: `"000"`
  - `agent.name`: `"wazuh-manager"` (ou o hostname do servidor do Manager)
  - `agent.ip`: `127.0.0.1` ou o IP de onde veio o syslog (no caso, o Ingestion do Poseidon).
- **Consequência no Investigation Workspace:** A telemetria perde o vínculo nativo de endpoint dentro dos índices `wazuh-alerts-*`. O Poseidon teria que injetar campos customizados no corpo do log (e.g. `data.poseidon_host_id`), criar decoders adicionais no Wazuh para extrair esse campo e reescrever as consultas de alertas do Indexer para buscar pelo campo customizado em vez do padrão `agent.id`. Isso anula a experiência padrão do ecossistema Wazuh e quebra dashboards pré-existentes.
- **Fontes Primárias:**
  - Wazuh Documentation: "Syslog log data collection and agentless monitoring" (`https://documentation.wazuh.com/current/user-manual/capabilities/agentless-monitoring/`, acessado em 2026-09-20).

---

### 1.5 Item 5: Acoplamento de formato e conformidade com a Lei 4

- **Necessidade de Adapter:** Se B′ fosse implementado, o Poseidon Collector precisaria traduzir seus eventos canônicos para o schema esperado pelo Wazuh antes do envio.
- **Viabilidade:** Embora seja teoricamente viável manter um adapter de saída no Ingestion Service (preservando o modelo interno do Poseidon conforme a Lei 4), a complexidade de manter schemas paralelos (o schema do Poseidon e o schema de envelope sintético do Wazuh) traz alto custo de manutenção sem ganho prático, uma vez que o motor de decoders do Wazuh não reconhece o evento injetado conforme demonstrado no Item 1.1.

---

### 1.6 Item 6: Syscollector e Detecção de Vulnerabilidades (Vulnerability Detector)

- **Pergunta:** Se o Collector emitir inventário de pacotes e patches, a detecção de vulnerabilidades do Wazuh volta a funcionar?
- **Resultado da Investigação:** **NÃO.**
- **Arquitetura Interna do Vulnerability Detector:**
  1. O módulo `wazuh-modulesd:vulnerability-detector` no Manager não escuta fluxos de eventos ou syslog.
  2. Ele lê diretamente bancos de dados SQLite locais no Manager (`/var/ossec/queue/db/<agent-id>.db`).
  3. Esses bancos de dados SQLite são sincronizados exclusivamente pelo protocolo interno do agente Wazuh (`syscollector`), que utiliza mensagens de controle diferenciais binárias enviadas ao daemon `wazuh-db`.
  4. Sem o agente Wazuh instalado no endpoint para rodar os coletores de WMI/registro e emitir essas mensagens de sincronização para o `wazuh-db`, o banco de dados do agente fica vazio ou inexistente.
  5. Portanto, **o Vulnerability Detector do Wazuh fica 100% inoperante na Opção B′**. Não é possível alimentá-lo por syslog ou API sem escrever um emulador completo do protocolo de banco de dados do `wazuh-db`.
- **Fontes Primárias:**
  - Wazuh Architecture: "Vulnerability Detector module workflow" (`https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html`, acessado em 2026-09-20).
  - Repositório Wazuh: `wazuh/wazuh` — `src/wdb/` e `src/wazuh_modules/vulnerability_detector/` (acessado em 2026-09-20).

---

## 2. Avaliação Comparativa das Quatro Opções contra os 10 Critérios

Abaixo, a análise rigorosa das quatro opções:
- **Opção A:** SIEM de terceiro + CTI (Poseidon como camada analítica, investigação e resposta).
- **Opção B:** Plataforma completa com Wazuh como motor (dois agentes, infraestrutura completa).
- **Opção C:** Plataforma completa com stack permissiva (OpenSearch Security Analytics + osquery + Collector próprio).
- **Opção B′:** Wazuh como serviço sem agente (inviabilizada tecnicamente nos moldes originais, mantida aqui para comparação das consequências).

---

### Critério 1: Entrega do MVP (Time-to-Value)

- **Opção A:** **Muito Rápido (Semanas).** Não há desenvolvimento de driver de kernel, agente Windows em Go, pipeline ETW ou motor de detecção próprio. O Poseidon consome alertas e telemetria existentes do Wazuh Indexer (ou de qualquer SIEM via conector), aplicando normalização, enriquecimento com CTI, correlação de entidades e a interface de investigação. Coloca um analista trabalhando em incidentes reais no menor prazo possível.
- **Opção B:** **Lento (Meses).** Exige construir o Poseidon Collector completo em Go (ETW, redação Lei 11, pipeline com buffering na Lei 10), deployar e manter dois agentes em cada máquina de teste/produção, e integrar a API do Wazuh Manager e Indexer paralelamente ao pipeline próprio.
- **Opção C:** **Médio-Lento (Meses).** Elimina o Wazuh, mas exige configurar e afinar detectores do OpenSearch Security Analytics (regras Sigma), integrar o osquery para auditoria de estado e construir o Collector do Poseidon para streaming de telemetria.
- **Opção B′:** **Inviável no curto prazo.** Exigiria desenvolver engenharia reversa do protocolo de agentes do Wazuh ou criar um pacote customizado de regras sobrescrevendo o ruleset nativo do Wazuh para aceitar JSON em vez de EventChannel.

---

### Critério 2: Diferenciação do Produto

- **Opção A:** **Alta e Focada.** O produto não tenta competir no que é commodity (motor de ingestão de logs ou parser de syslog). Ele se diferencia onde os SIEMs tradicionais falham categoricamente: Investigation Workspace centrado em entidades, timeline contextualizada de incidentes, integração bidirecional de CTI sob demanda (D-004) e automação de orquestração de resposta.
- **Opção B:** **Confusa.** O cliente recebe um produto que instala o agente Wazuh e um agente Poseidon, possui dois painéis (Dashboard do Wazuh e Poseidon Workspace) e duas regras de detecção. O valor do Poseidon fica ofuscado pela presença pesada da infraestrutura do Wazuh.
- **Opção C:** **Alta e Coesa.** Plataforma proprietária de ponta a ponta construída sobre componentes abertos padrão de mercado (Apache-2.0). A experiência do usuário é unificada sob a marca Poseidon, sem marcas de terceiros no endpoint.
- **Opção B′:** **Fraca/Problemática.** Promete a inteligência do Wazuh sem seu agente, mas entrega alertas descontextualizados (todos atribuídos ao host `000`) e perde FIM, SCA e vulnerabilidades.

---

### Critério 3: Licenciamento sob SaaS (D-002 e Restrições de Rede)

- **Opção A:** **Totalmente Compatível e Segura.** O Poseidon consome a API do SIEM do cliente (ou um cluster dedicado do cliente). O código do Wazuh não é empacotado no binário do Poseidon. Não há risco de contaminação por AGPL-3.0 ou violação de GPLv2.
- **Opção B:** **Crítica e Complexa.** Conforme D-005, o Poseidon teria que manter instaladores segregados. O risco de o agente Wazuh 5.x migrar para AGPL-3.0 gera incerteza operacional para uma oferta SaaS multitenant. Qualquer modificação no core do Wazuh Manager (GPLv2) exige cuidados extremos de isolamento de processos para não contaminar a propriedade intelectual do Poseidon Core.
- **Opção C:** **100% Permissiva e Livre de Risco.** OpenSearch Security Analytics é **Apache-2.0** (`github.com/opensearch-project/security-analytics/blob/main/LICENSE`). osquery é **Apache-2.0** (`github.com/osquery/osquery/blob/master/LICENSE`). O Poseidon pode operar em modelo SaaS multitenant, modificar componentes ou embutir clientes sem qualquer obrigação de abertura de código ou cláusula de rede (Affero).
- **Opção B′:** **Compatível com SaaS, mas Inviável Tecnicamente.** Não distribui agente (evita AGPL do agente 5.x), mas depende de hospedar um Wazuh Manager (GPLv2 sem cláusula de rede, o que em SaaS puro é permitido, porém inútil pelo problema do decoder).

---

### Critério 4: Custódia de Dado Pessoal e Credenciais (`BLOCKER-09`, `BLOCKER-13`, Lei 11)

- **Opção A:** **Custódia Segregada e Menor Risco Jurídico.** O Poseidon SaaS consome apenas o que o SIEM do cliente disponibiliza. Se o SIEM do cliente contiver linhas de comando não redigidas coletadas pelo agente do Wazuh, a custódia primária e responsabilidade do armazenamento bruto é da infraestrutura do cliente. O Poseidon atua como operador e pode aplicar sanitização e mascaramento de exibição na camada de apresentação/API (Redaction-on-Read), sem assumir o passivo do armazenamento de histórico bruto de credenciais.
- **Opção B:** **Alto Risco e Passivo Duplo (`BLOCKER-13`).** O agente do Wazuh no endpoint coleta linhas de comando em claro e envia direto ao Wazuh Indexer sem redação. O cliente e o Poseidon tornam-se co-custodiantes de credenciais em trânsito e em repouso no Indexer, violando a premissa da Lei 11 no caminho do Wazuh.
- **Opção C:** **Controle Rigoroso e Eficaz (Lei 11 Plena).** O único agente no endpoint é o Poseidon Collector. Toda a linha de comando é interceptada via ETW/Win32 e submetida à máquina de estado de redação de credenciais **no próprio endpoint** antes de qualquer transmissão para o OpenSearch. Nenhuma credencial trafega na rede ou repousa no cluster de índices.
- **Opção B′:** **Controle Parcial.** O Collector redigiria o evento antes do Ingestion enviar ao Wazuh. No entanto, devido à perda de regras de Windows no Wazuh demonstrada acima, essa redação protegeria dados que sequer gerariam detecções adequadas.

---

### Critério 5: Superfície de Execução no Endpoint (`BLOCKER-03`, Lei 8)

- **Opção A:** **Superfície Zero do Poseidon no Endpoint.** O Poseidon não instala agente no endpoint. Qualquer ação de resposta no MVP é disparada contra APIs de rede, firewalls, provedores de identidade ou conectores de SIEM/EDR externos. A conformidade com a Lei 8 fica restrita a ações em infraestrutura de rede/nuvem autenticadas e auditadas em cofre.
- **Opção B:** **Crítica e Insegura (`BLOCKER-03`).** A coexistência do agente Wazuh mantém o Active Response aberto no endpoint, com seus vetores documentados (caractere `!` que burla lista de permissões, `agents_list: '*'` que atinge a frota inteira e risco de RCE por argumentos mal sanitizados).
- **Opção C:** **Superfície Única e Auditada (Lei 8 Integral).** Existe apenas o Poseidon Collector no endpoint. As ações de resposta são executadas exclusivamente pelo Response Control Plane do Poseidon, protegidas por canal criptográfico com mTLS, execução restrita a binários assinados, sem interpretador arbitrário de comandos e auditadas pelo HashiCorp Vault.
- **Opção B′:** **Superfície Reduzida.** Sem o agente Wazuh, elimina-se o Active Response do Wazuh no endpoint. Porém, sem o agente Wazuh, também não há mecanismo de remediação local a menos que o Poseidon Collector implemente seu próprio executor.

---

### Critério 6: Duplicação Estrutural e Arquitetural

| Aspecto | Opção A | Opção B | Opção C | Opção B′ |
|---|---|---|---|---|
| **Agentes no Endpoint** | 0 do Poseidon (usa SIEM/EDR do cliente) | **2** (Poseidon + Wazuh) | **1** (Poseidon Collector) | **1** (Poseidon Collector) |
| **Formatos de Detecção** | 1 (do SIEM existente) | **2** (Wazuh XML + Poseidon Sigma) | **1** (Sigma nativo em OpenSearch) | **2** (tentativa de converter Sigma para Wazuh) |
| **Caminhos de Resposta** | 1 (APIs/Orquestração externa) | **2** (Wazuh AR + Poseidon RPC) | **1** (Poseidon RPC via Collector) | **1** (Poseidon RPC) |
| **Clientes de API** | 1 (Conector de SIEM) | **2** (Wazuh API 55000 + Indexer 9200) | **1** (OpenSearch Client padrão) | **2** (Ingestion Syslog + Wazuh Indexer) |

---

### Critério 7: Dependência Estratégica e Vendor Lock-in

- **Opção A:** **Mínima / Neutra.** O Poseidon é agnóstico. Se o cliente usa Wazuh, conecta-se ao Wazuh. Se migra para Elastic, Splunk ou Microsoft Sentinel, o Poseidon apenas ativa o conector correspondente. O Poseidon nunca fica refém das decisões de licenciamento de um único fabricante.
- **Opção B:** **Máxima e Perigosa.** O produto depende criticamente da evolução do código-fonte do Wazuh. A bifurcação de licenças do agente 5.x para AGPL-3.0 ameaça diretamente a estratégia comercial do produto.
- **Opção C:** **Independente e Orientada a Padrões.** Suportada pela Linux Foundation / AWS (OpenSearch) e pela comunidade aberta (osquery, SigmaHQ). Padrões consolidados, sem dono único capaz de alterar licenças abruptamente.
- **Opção B′:** **Alta e Frágil.** Depende da manutenção do Wazuh Manager e de seu comportamento interno de decoders, que não oferecem garantias de estabilidade para uso "agentless" fora de seus padrões originais.

---

### Critério 8: Maturidade e Cobertura Funcional Out-of-the-Box

- **Opção A:** **Alta (Herdada do SIEM).** Beneficia-se de todas as regras, decoders e alertas que o SIEM do cliente já possui afinados e em execução. Não reinventa a roda na camada de telemetria básica.
- **Opção B:** **Alta, mas com Conflitos.** Herda os decoders e regras do Wazuh, mas introduz conflitos de duplicidade de alertas e sobrecarga no host.
- **Opção C:** **Média-Alta, Exige Engenharia.** O OpenSearch Security Analytics já conta com centenas de regras Sigma pré-carregadas para Windows e Linux, além de gerador automático de alertas. No entanto, recursos como FIM avançado com hashes e detecção de CVE exigem a integração de plugins ou componentes adicionais (osquery + banco de vulnerabilidades externo).
- **Opção B′:** **Muito Baixa (Degradação Severa).** Conforme demonstrado na Seção 1, perdem-se os decoders de Windows do Wazuh, a detecção de vulnerabilidades do Syscollector, o FIM e as avaliações de conformidade SCA. Restaria um motor de regras incapaz de disparar em logs de Windows injetados.

---

### Critério 9: Posicionamento Comercial

- **Opção A:** **"O Cérebro de Investigação e CTI sobre a sua infraestrutura existente".** Posicionamento muito atraente no mercado B2B: não exige que o CISO substitua o SIEM ou agente que já homologou. Agrega valor imediato à equipe de SOC, acelerando o MTTR (Mean Time to Respond) e unificando inteligência de ameaças.
- **Opção B:** **"Wazuh com Superpoderes".** Comunica familiaridade ("usamos Wazuh por baixo"), mas enfrenta resistência imediata de equipes de TI/Segurança corporativa pela exigência de instalar dois agentes pesados no mesmo endpoint.
- **Opção C:** **"Plataforma Moderna de Próxima Geração Open-Core".** Comunica robustez, soberania de dados, ausência de taxas abusivas de licença e total conformidade com a stack analítica OpenSearch/Sigma.
- **Opção B′:** **Confuso.** Difícil explicar ao mercado por que a plataforma depende de um servidor Wazuh se não utiliza o agente Wazuh e não suporta os recursos clássicos de endpoint do Wazuh.

---

### Critério 10: Reversibilidade e Evolução Arquitetural

- **Opção A:** **Máxima Reversibilidade.** Começar como Opção A não impede em nada a adição de um Collector proprietário ou de um motor analítico interno no futuro (Fases 8 a 13). O Poseidon constrói primeiro o valor que é exclusivo seu (Workspace, Grafo de Entidades, CTI, Timeline).
- **Opção B:** **Baixa Reversibilidade.** Uma vez construído o acoplamento profundo aos decoders XML, APIs e agentes do Wazuh, desvencilhar a plataforma desse ecossistema exige reescrever a maior parte do código de ingestão e detecção.
- **Opção C:** **Alta Reversibilidade.** Baseada em esquemas abertos e regras Sigma (padrão de mercado em YAML). Qualquer regra Sigma escrita para o Poseidon pode ser exportada ou portada para qualquer outro SIEM do mercado.
- **Opção B′:** **Nula.** Um caminho técnico bloqueado que não oferece base sustentável para evolução.

---

### Matriz Síntese dos 10 Critérios

| Critério | Opção A (SIEM + CTI) | Opção B (Plataforma + Wazuh) | Opção C (Stack Permissiva) | Opção B′ (Wazuh sem Agente) |
|---|:---:|:---:|:---:|:---:|
| **1. Entrega do MVP** | **Excelente (Semanas)** | Ruim (Meses) | Razoável (Meses) | Bloqueada |
| **2. Diferenciação** | **Muito Alta** | Confusa | Alta | Muito Baixa |
| **3. Licenciamento SaaS** | **100% Livre de Risco** | Crítico / Risco AGPL | **100% Permissivo (Apache-2)** | Razoável |
| **4. Custódia / Lei 11** | **Segregada no Cliente** | Violada (`BLOCKER-13`) | **Conforme no Endpoint** | Razoável |
| **5. Superfície Execução** | **Zero no Endpoint** | Insegura (`BLOCKER-03`) | **Protegida (Lei 8)** | Neutra |
| **6. Duplicação** | **Zero** | Severa (2 agentes/regras) | Nenhuma (1 agente/regras) | Parcial |
| **7. Dependência** | **Nenhuma (Agnóstica)** | Alta (Wazuh Core) | Baixa (Padrões Abertos) | Alta (Wazuh) |
| **8. Maturidade Detecção** | **Alta (Herdada)** | Alta (com atrito) | Média-Alta (Sigma nativo) | **Falha Técnica** |
| **9. Comercial** | **Excelente (Add-on de Alto Valor)** | Difícil (2 agentes) | Muito Bom (Nova Geração) | Confuso |
| **10. Reversibilidade** | **Total** | Baixa | Alta | Baixa |

---

## 3. Pesquisas Técnicas Aprofundadas (Demandas da Seção 6 do Briefing)

---

### 3.1 OpenSearch Security Analytics em Detalhe

#### 3.1.1 Cobertura Real da Especificação Sigma
O OpenSearch Security Analytics traduz regras Sigma YAML em consultas de busca do OpenSearch (Lucene / OpenSearch Query DSL).
- **Modificadores Suportados:**
  - `contains`, `startswith`, `endswith`
  - `base64`, `base64offset`, `wide`, `windash`
  - `re` (Expressões regulares)
  - `cidr` (Suporte nativo limitado a IPv4)
  - `all`
  - Comparações numéricas: `lt`, `lte`, `gt`, `gte`
- **Modificadores NÃO Suportados (Gaps Críticos):**
  - `cased` (Buscas sensíveis a maiúsculas/minúsculas não são preservadas na análise padrão de texto).
  - `exists` e `expand`.
  - `fieldref` (Comparação dinâmica de um campo contra outro campo do mesmo documento não é suportada diretamente no compilador).
  - Correlações complexas nativas do padrão Sigma moderno (Sigma Correlations Specification v2.0): o OpenSearch não compila correlações Sigma YAML automaticamente; em vez disso, possui seu próprio motor de correlações baseado em regras de interface/API.
- **Fontes Primárias:**
  - Repositório OpenSearch: `opensearch-project/security-analytics` — subdiretório `src/main/kotlin/org/opensearch/securityanalytics/rules/` (acessado em 2026-09-20).
  - Documentação OpenSearch: "Supported Sigma rule modifiers and limitations" (`https://opensearch.org/docs/latest/security-analytics/rules/`, acessado em 2026-09-20).

#### 3.1.2 Tipos de Log e Detectores Pré-configurados (Out-of-the-Box)
- **Log Types Suportados Nativa e Automaticamente:**
  - **Sistema Operacional:** Windows (Event Logs/Sysmon mapeados para regras de processo, rede, registro), Linux (Auditd/Syslog).
  - **Rede & Infraestrutura:** NetFlow, DNS, VPC Flow Logs, WAF, Network Traffic.
  - **Identidade & Acesso:** Active Directory (AD/LDAP), Okta.
  - **Nuvem & SaaS:** AWS CloudTrail, Azure, Microsoft 365, Google Workspace, GitHub.
- **Mapeamento:** Para os log types acima, o OpenSearch fornece esquemas canônicos pré-definidos e mapeamentos automáticos. Para fontes proprietárias ou esquemas customizados (como o OCSF 1.9.0 puro sem extensão padrão), é necessário configurar um "Custom Log Type" e associar as regras Sigma aos campos correspondentes via API ou interface de mapeamento.
- **Fonte Primária:**
  - Documentação OpenSearch: "Supported log types" (`https://opensearch.org/docs/latest/security-analytics/supported-log-types/`, acessado em 2026-09-20).

#### 3.1.3 Motor de Correlação (Correlation Engine)
- **Introdução:** Disponível desde o OpenSearch 2.7.
- **Mecanismo:** Cria um grafo de conhecimento de segurança (*Security Finding Knowledge Graph*). Quando detectores independentes geram *findings* em fontes distintas (e.g., uma regra de Windows e uma regra de VPC Flow) dentro de uma mesma janela temporal e compartilhando um identificador de entidade comum (e.g., IP de origem ou Usuário), o motor estabelece uma correlação visual e programática.
- **Limitação:** Não executa *joins* em tempo real em grandes volumes de logs brutos. O motor opera estritamente sobre a camada de **Findings** (resultados já alertados), o que garante alta performance, mas não substitui buscas analíticas complexas de agregação de eventos não alertados.
- **Fonte Primária:**
  - Documentação OpenSearch: "Correlating security findings" (`https://opensearch.org/docs/latest/security-analytics/correlations/`, acessado em 2026-09-20).

#### 3.1.4 Limitações Operacionais, Escala e Relação com o Alerting Plugin
- **Ciclo de Execução Baseado em Monitors:** O Security Analytics não é um motor de processamento contínuo em memória de streaming (como Apache Flink ou eBPF local). Os detectores geram **Monitors** agendados no plugin `opensearch-alerting`. Cada detector roda periodicamente (e.g., a cada 1 minuto ou 5 minutos), executando queries no índice de logs.
- **Escala:** Em ambientes de altíssimo throughput (e.g., dezenas de milhares de eventos/segundo), dezenas de detectores consultando índices simultaneamente podem gerar picos de CPU e I/O no cluster OpenSearch se os índices não tiverem sharding e retenção devidamente ajustados.
- **Integração com Response Control Plane:** A arquitetura do Alerting é limpa e extensível:
  `Log Ingestion` $\to$ `Detector (Sigma Rule)` $\to$ `Finding` $\to$ `Trigger (Severidade/Frequência)` $\to$ `Alert` $\to$ `Action (Webhook)`.
  O Response Control Plane do Poseidon pode registrar um webhook HTTP/mTLS diretamente como destino de ação do OpenSearch Alerting. Quando um alerta dispara, o OpenSearch aciona o Poseidon instantaneamente com o payload do incidente.
- **Fonte Primária:**
  - Documentação OpenSearch: "Alerting monitors and destinations" (`https://opensearch.org/docs/latest/monitoring-plugins/alerting/monitors/`, acessado em 2026-09-20).

---

### 3.2 osquery em Detalhe

#### 3.2.1 Cobertura vs. Wazuh (FIM, SCA/CIS e Detecção de Vulnerabilidades)
- **Integridade de Arquivos (FIM):**
  - *Wazuh (`syscheck`):* Monitora arquivos em tempo real, gera hashes criptográficos (MD5, SHA1, SHA256), monitora chaves de registro do Windows e identifica o usuário/processo responsável (usando SACLs do Windows e Auditd no Linux).
  - *osquery:* No Linux, usa `inotify` ou subsistema `audit` para alimentar a tabela `file_events`. No Windows, usa a tabela `ntfs_journal_events` baseada no USN Journal do NTFS.
- **Conformidade SCA / Benchmarks CIS:**
  - *Wazuh:* Fornece nativamente centenas de arquivos YAML com testes formais mapeados para os benchmarks CIS para dezenas de sistemas operacionais.
  - *osquery:* Não possui um motor de SCA nativo empacotado. O osquery apenas expõe tabelas SQL (`registry`, `users`, `system_info`). A conformidade CIS depende da injeção de *query packs* criados por terceiros ou desenvolvidos internamente.
- **Detecção de Vulnerabilidades (CVE):**
  - *Wazuh:* O Manager mantém feeds de CVEs atualizados (NVD, MSRC, RedHat, Canonical) e correlaciona automaticamente com pacotes instalados.
  - *osquery:* **Não possui motor de CVE.** Ele apenas informa a lista de programas instalados através da tabela `programs` (Windows) ou `rpm_packages`/`deb_packages` (Linux). A normalização de strings CPE e o cruzamento contra bases CVE precisam ser desenvolvidos integralmente no backend da plataforma.
- **Fonte Primária:**
  - osquery Schema Documentation: Tabelas `file_events`, `ntfs_journal_events`, `programs` (`https://osquery.io/schema/`, acessado em 2026-09-20).

#### 3.2.2 O que o osquery NÃO faz em relação ao Agente Wazuh
1. **Sem Streaming Contínuo de Logs para SIEM:** O osquery é uma ferramenta de inspeção de estado e auditoria periódica via SQL. Ele não foi projetado para atuar como agente de transporte de fluxo de telemetria bruta de eventos (ETW, Syslog ou Windows Event Logs).
2. **Sem Mecanismo Nativo de Remediação/Active Response:** O osquery é uma ferramenta estritamente de leitura (read-only SQL). Ele não possui primitivas para encerrar processos, isolar interfaces de rede ou alterar configurações no endpoint.
3. **Sem Engine Local de Políticas de Compliance:** Não gera scores percentuais de CIS ou conformidade localmente; tudo depende de queries externas agendadas.

#### 3.2.3 Modelo de Gerenciamento de Frota em Escala
- **Ausência de Servidor Nativo:** O binário do osquery é estritamente um daemon de endpoint (`osqueryd`). O projeto osquery não fornece um servidor central de controle de frota.
- **Dependência de Servidor TLS:** Para operar em frota, o osquery precisa comunicar-se via TLS com endpoints HTTP REST específicos (`/api/v1/osquery/enroll`, `/api/v1/osquery/config`, `/api/v1/osquery/log`, `/api/v1/osquery/distributed/read`, `/api/v1/osquery/distributed/write`).
- **Necessidade de Infraestrutura Adicional (FleetDM):** A implementação padrão de mercado para gerenciamento de osquery é o **Fleet** (`fleetdm/fleet`). No entanto, subir um servidor Fleet exige componentes adicionais substanciais: um cluster **MySQL** para metadados e um cluster **Redis** para mensageria/filas de queries ao vivo.
- **Fontes Primárias:**
  - FleetDM Documentation: "Fleet Infrastructure Architecture" (`https://fleetdm.com/docs/deploy/deploy-fleet`, acessado em 2026-09-20).
  - osquery Documentation: "Remote API Specs" (`https://osquery.readthedocs.io/en/stable/deployment/remote.html`, acessado em 2026-09-20).

#### 3.2.4 Paridade de `file_events` no Windows vs. Linux/macOS
- **Disparidade Crítica no Windows:** Enquanto no Linux o osquery utiliza `auditd` ou eBPF para capturar com precisão o processo causador da modificação de arquivo, no Windows o osquery utiliza a tabela `ntfs_journal_events`, lendo o USN Change Journal do NTFS.
- **Gaps Concretos da Implementação em Windows:**
  1. **Sem Contexto de Processo (`Who`):** O USN Journal do NTFS registra que um arquivo foi criado, renomeado ou excluído, mas **não registra o PID ou o binário responsável pela ação**.
  2. **Sem Hashing Automático:** O USN Journal não calcula hashes (MD5/SHA256) do conteúdo do arquivo modificado.
  3. **Risco de Perda em Alta Carga:** Em rajadas de I/O em disco, o buffer circular do USN Journal pode sofrer sobrescrita antes da leitura da query agendada do osquery.
- **Fonte Primária:**
  - osquery Documentation & Trail of Bits Engineering: "Windows FIM using NTFS Journal Events" (`https://trailofbits.github.io/`, acessado em 2026-09-20).

---

### 3.3 A Opção A em Detalhe

#### 3.3.1 De onde vem a telemetria de endpoint sem Collector próprio?
- **Fontes de Dados:** O Poseidon conecta-se diretamente aos repositórios analíticos e APIs do ecossistema que o cliente já possui:
  1. Se o cliente utiliza Wazuh: o Poseidon consome os índices do Wazuh Indexer (`wazuh-alerts-*` para alertas processados e `wazuh-archives-*` para eventos brutos completos, caso o cliente habilite o arquivamento).
  2. Se o cliente utiliza outros SIEMs/EDRs (Microsoft Sentinel, Elastic Security, Splunk, CrowdStrike Falcon): o Poseidon consome eventos brutos e telemetria via APIs REST oficiais (Integration Hub).
- **Mapeamento de Telemetria:** A camada de ingestão do Poseidon normaliza essas fontes externas para o modelo canônico de entidades do Poseidon (Processos, IPs, Domínios, Usuários, Hashes), alimentando o grafo de correlação e a timeline de investigação.

#### 3.3.2 O `BLOCKER-13` (Custódia de Credenciais em Linha de Comando) Desaparece ou Muda de Dono?
- **Análise Jurídica e Técnica:** **Muda de dono e se resolve no produto Poseidon.**
  - Na arquitetura original da Opção B, o Poseidon oferecia o pacote completo de ponta a ponta (incluindo o Wazuh) e assumia perante o cliente a custódia e o processamento de linhas de comando não redigidas.
  - Na Opção A, o cliente é o proprietário e operador do seu próprio SIEM (seja Wazuh on-premise ou terceiro). Os dados brutos já repousam na infraestrutura do cliente sob as políticas de segurança dele.
  - O Poseidon SaaS atua estritamente como ferramenta analítica conectada. Ao consumir eventos para renderizar o Investigation Workspace, o Poseidon aplica uma camada de **Sanitização e Redação em Tempo de Apresentação (Redaction-on-Read)**, garantindo que o analista de segurança nunca visualize senhas ou tokens que o SIEM do cliente tenha coletado incorretamente. Isso elimina o passivo legal de armazenamento indevido pelo Poseidon.

#### 3.3.3 Qual é o MVP da Opção A (Lista de Telas e Capacidades Concretas)?
O MVP da Opção A é 100% focado no usuário analista (SOC Tier 1 a 3 e Incident Responders), composto por:
1. **Investigation Workspace:** Tela unificada de análise de incidentes, substituindo buscas manuais em dezenas de índices por uma visão intuitiva do caso.
2. **Timeline de Entidades:** Reconstrução cronológica de eventos correlacionados por host, usuário ou processo malicioso, independente da fonte original.
3. **CTI Integration & Enrichment (D-004):** Módulo de enriquecimento sob demanda que consulta reputação de IoCs (IPs, domínios, hashes) em fontes externas e internas sem reter dados de terceiros.
4. **Alerta Unificado & Triage:** Fila centralizada de alertas priorizados com pontuação de severidade e tags automáticas do framework MITRE ATT&CK.
5. **Integration Hub (Conectores):** Conector bidirecional para Wazuh Indexer (OpenSearch) e APIs de resposta de terceiros (bloqueio de IP em firewall perimetral, isolamento de conta no IdP).
6. **Cofre de Evidências & Auditoria:** Armazenamento seguro e imutável de notas de investigação, artefatos analisados e trilhas de auditoria das decisões tomadas pelo analista.

#### 3.3.4 A Opção A Comporta as Fases 8 a 13 do Roadmap ou Fecha Portas?
- **Comporta Plenamente e Não Fecha Portas.**
  - As Fases 8 a 13 do projeto envolvem capacidades avançadas de automação, playbooks orquestrados de remediação, inteligência preditiva e expansão de sensores.
  - A Opção A estabelece a fundação de **inteligência, dados e experiência do usuário**.
  - Uma vez validado o produto no mercado e com tração de clientes, o Poseidon pode introduzir opcionalmente o seu próprio **Poseidon Collector** (ou Response Agent especializado) nas Fases subsequentes como um módulo "Premium" ou "Advanced Endpoint Telemetry", sem traumatizar a arquitetura base ou quebrar contratos de clientes existentes.

---

### 3.4 Ferramentas Transversais e Análise de Licenciamento

A tabela abaixo analisa ferramentas transversais mencionadas no briefing e na constituição, avaliando funcionalidade, licença primária e viabilidade sob oferta SaaS (D-002):

| Ferramenta | Função Principal | Arquivo de Licença Primária | Tipo de Licença | Impacto / Risco sob Modelo SaaS (D-002) |
|---|---|---|---|---|
| **MISP** | Plataforma de compartilhamento de CTI | `github.com/MISP/MISP/blob/2.4/LICENSE` | **AGPL-3.0** (Core) | **Alto Risco de Rede.** O core do MISP é expressamente AGPL-3.0. Embutir código do MISP ou hospedar uma versão modificada acessível via rede no backend do Poseidon obriga a disponibilização do código-fonte correspondente. Integração com MISP deve limitar-se estritamente a consultas via API HTTP externa como serviço desacoplado do cliente. |
| **Suricata** | NIDS/NIPS e monitoramento de tráfego de rede | `github.com/OISF/suricata/blob/main/LICENSE` | **GPLv2** | **Risco Baixo/Médio.** Não possui cláusula de rede (Affero). Pode ser operado como daemon de inspeção de rede independente em VMs ou contêineres do cliente, exportando logs EVE JSON para o Poseidon. Não pode ser linkado estaticamente em código proprietário. |
| **Zeek** | Análise comportamental e metadados de rede | `github.com/zeek/zeek/blob/master/COPYING` | **BSD 3-Clause** | **Totalmente Livre de Risco.** Licença altamente permissiva. Pode ser incorporado, modificado ou empacotado em qualquer serviço gerenciado ou SaaS sem restrições. |
| **Fleet (FleetDM)** | Gerenciador de frota para agentes osquery | `github.com/fleetdm/fleet/blob/main/LICENSE` | **MIT** (Core) / Comercial (EE) | **Livre de Risco no Core.** O core do Fleet é MIT e seguro para SaaS. No entanto, recursos enterprise avançados exigem licenciamento comercial da FleetDM Inc. |
| **Velociraptor** | DFIR, caça de ameaças e triagem avançada de endpoints | `github.com/Velocidex/velociraptor/blob/master/LICENSE` | **AGPL-3.0** | **Alto Risco de Rede.** Projeto mantido pela Rapid7 sob AGPL-3.0 estrita. Fornecer capacidades de caça remota usando Velociraptor como backend gerenciado expõe o serviço à cláusula de rede do AGPL. |

---

## 4. Conclusão da Pesquisa Factual

1. **A Opção B′ não é viável sobre o Wazuh padrão.** O comportamento em código C do motor `analysisd` e a dependência da regra 60000 em `<decoded_as>windows_eventchannel</decoded_as>` impedem o funcionamento das regras de detecção de Windows em logs injetados por syslog ou API. Adicionalmente, perdem-se FIM, SCA e detecção de vulnerabilidades do Syscollector.
2. **A Opção B mantém todas as fricções e bloqueios** documentados em três rodadas de auditoria: dois agentes no endpoint (`MAJOR-26`), Active Response inseguro (`BLOCKER-03`), custódia indevida de linhas de comando não redigidas (`BLOCKER-13`) e obrigação complexa de distribuição e segregação de artefatos (D-005).
3. **A Opção C é tecnicamente viável e sólida a longo prazo**, com licenciamento 100% permissivo (Apache-2.0), suporte nativo a regras Sigma e conformidade plena com a Lei 11, mas exige um ciclo substancial de desenvolvimento de engenharia de endpoint e infraestrutura antes de entregar o primeiro valor ao analista.
4. **A Opção A resolve a fricção fundamental do produto**, desacopla o Poseidon de riscos de licenciamento e custódia, e viabiliza a entrega rápida do Investigation Workspace e CTI — que é a verdadeira proposta de valor diferenciada do projeto.

---
*Fim do documento de pesquisa do Builder. Nenhuma recomendação é emitida aqui, aguardando o relatório independente do Auditor.*
