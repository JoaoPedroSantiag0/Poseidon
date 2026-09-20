# POSEIDON CTI — Análise Competitiva de Plataformas de Threat Intelligence

> **Documento:** `docs/research/competitive-analysis.md`  
> **Status:** Aprovado para Phase 0 (Research & Foundation)  
> **Classificação:** Arquitetura Estratégica & Engenharia CTI  
> **Data:** 2026-09-20  

---

## 1. Sumário Executivo & Escopo de Benchmark

O objetivo deste documento é analisar de forma crítica as principais plataformas de **Cyber Threat Intelligence (CTI)** do mercado global — tanto open-source e comunitárias quanto comerciais de nível enterprise —, identificando seus modelos conceituais, padrões arquiteturais, limitações estruturais e práticas recomendadas.

Essa análise serve como base analítica para a concepção do **POSEIDON**, garantindo que a plataforma não seja apenas um repositório passivo de IOCs (Indicator of Compromise CRUD), mas uma plataforma analítica de alta fidelidade focada em:
* **Proveniência rigorosa e auditável** (*"Intelligence without provenance is only an assertion"*);
* **Distinção estrita entre Observables (fatos) e Indicators (lógica de detecção/hipóteses)**;
* **Cálculo de Risco Explicável e Decomponível** em oposição a "scores de caixa-preta";
* **Separação matemática entre Risco (impacto/probabilidade de ameaça) e Confiança (certeza analítica/corroboração)**;
* **Orquestração resiliente de enriquecimento** com governança de quotas, rate-limits e circuit-breaking;
* **Modelagem de Knowledge Graph e Temporal Intelligence (Sightings e Decay)**.

---

## 2. Análise Detalhada das Plataformas

### 2.1 OpenCTI (Luatix / Filigran)
* **Propósito & Posicionamento:** Plataforma unificada de gestão de CTI open-source/open-core, orientada a conhecimento operacional, tático e estratégico.
* **Modelo de Dados:** 100% nativo em **STIX 2.1**. Todas as entidades internas são mapeadas como STIX Domain Objects (SDOs), STIX Cyber-observable Objects (SCOs) ou STIX Relationship Objects (SROs).
* **Arquitetura Técnica:**
  * Backend em Node.js / TypeScript com GraphQL API.
  * Storage primário: OpenSearch / Elasticsearch para busca full-text e indexação de entidades.
  * Graph Engine / Cache: Redis + TypeDB (historicamente Grakn) migrado para arquitetura híbrida de search index com links relacionais.
  * Mensageria: RabbitMQ para ingestão assíncrona e conectores desacoplados.
  * Frontend: React + Material-UI, suporte a grafos interativos (Cytoscape / Three.js).
* **Pontos Fortes:**
  * Conformidade estrita e rigorosa com a ontologia STIX 2.1.
  * Ecossistema robusto de conectores modulares via Python (`pycti`).
  * Capacidade avançada de visualização de grafos de conhecimento, matrizes MITRE ATT&CK e timelines.
  * Gestão granular de marcações (TLP, PAP, marcações de confiabilidade).
* **Limitações & Dívidas Técnicas:**
  * Alto consumo de recursos computacionais (exige clusters pesados de OpenSearch, Redis, RabbitMQ e Node.js mesmo para bases moderadas).
  * Enriquecimento em tempo real síncrono é lento; depende inteiramente de workers assíncronos que podem acumular filas gigantescas (*lag* de ingestão).
  * O cálculo de risco unificado é limitado; foca muito na agregação ontológica e delega o score para atributos de fornecedores sem algoritmo unificado e explicável de pontuação com decay dinâmico.
  * Complexidade operacional extrema de setup e manutenção.

---

### 2.2 MISP (Malware Information Sharing Platform)
* **Propósito & Posicionamento:** Plataforma comunitária pioneira para compartilhamento e colaboração de inteligência sobre ameaças e incidentes de segurança.
* **Modelo de Dados:** Modelo proprietário centrado em **Eventos** e **Atributos**:
  * Evento (incidente, campanha, report) $\rightarrow$ Atributos (IPs, hashes, domínios, emails).
  * Objetos MISP (abstrações compostas para agrupar atributos, como `file`, `network-connection`).
  * Taxonomias e Galáxias (mapeamentos semânticos para ATT&CK, threat actors, ferramentas).
  * Warninglists (mecanismo essencial de detecção de falsos positivos e infraestrutura benigna conhecida).
* **Arquitetura Técnica:**
  * Backend em PHP (CakePHP framework) com MySQL / MariaDB.
  * Cache & Pub/Sub: Redis e ZeroMQ para distribuição de eventos entre instâncias.
  * Python integration via PyMISP.
* **Pontos Fortes:**
  * De facto standard para partilha e feeds multilaterais entre CSIRTs, CERTs nacionais, ISACs e agências militares.
  * Sincronização peer-to-peer descentralizada entre instâncias MISP com controle refinado de distribuição (community, sharing groups).
  * Warninglists maduras que evitam disparos contra DNS públicos, CDNs e RFC1918.
* **Limitações & Dívidas Técnicas:**
  * Modelo de dados legado não-nativo STIX 2.1 (conversão via stix2/misp-stix apresenta perdas semânticas frequentes).
  * Arquitetura monolítica em PHP de difícil extensão para pipelines modernos de streaming e grafos massivos.
  * Interface visual árida, com curva de aprendizado íngreme para analistas menos técnicos.
  * Capacidades fracas de correlação temporal automática e inferência em grafo sem plugins externos.

---

### 2.3 ThreatConnect
* **Propósito & Posicionamento:** Threat Intelligence Platform (TIP) enterprise combinando CTI com orquestração de segurança (SOAR light / Playbooks).
* **Modelo de Dados:** Threat Graph proprietário modelado em Indicators (IOCs atômicos) vs. Groups (Adversaries, Campaigns, Incidents, Signatures, TTPs).
* **Arquitetura Técnica:**
  * Java enterprise core com Postgres, Elasticsearch e microserviços.
  * CAL (Collective Analytics Layer): infraestrutura em nuvem que correlaciona anonimamente telemetria de clientes globais.
  * Engine de Playbooks (BPMN gráfico) para automação de triagem.
* **Pontos Fortes:**
  * O CAL fornece agregação multi-tenant global para medir a frequência de observação de um IOC.
  * Fortes fluxos de automação nativa (Playbooks visuais com disparo orientado a eventos de CTI).
  * Atribuição estruturada de infraestrutura e threat actors.
* **Limitações & Dívidas Técnicas:**
  * Solução proprietária de custo proibitivo para pequenas e médias operações.
  * O modelo analítico é fortemente acoplado aos módulos de automação SOAR, sobrecarregando a plataforma para times que buscam puramente inteligência e investigação forense.

---

### 2.4 Recorded Future
* **Propósito & Posicionamento:** Plataforma de inteligência preditiva e externa (Open Source Intelligence / Deep & Dark Web / Technical Telemetry).
* **Modelo de Dados:** Intelligence Graph centrado em **Intelligence Cards** para entidades (IP, Domain, Hash, Vulnerability, Actor, Company).
* **Arquitetura Técnica:**
  * Pipeline massivo de Natural Language Processing (NLP) e Machine Learning sobre feeds de notícias, fóruns da dark web, repositórios de código e feeds de telemetria.
  * Motor de pontuação dinâmica de risco de 0 a 99 baseado em **Risk Rules** declarativas.
* **Pontos Fortes:**
  * **Risk Rules Explicáveis:** O analista consegue ver exatamente quais regras contribuíram para o score (ex: `+20 observado em C2 recente`, `+15 citado em fórum de ransomware`, `-10 ausência de atividade há mais de 30 dias`).
  * Intelligence Cards fornecem uma experiência de UX de referência para analistas: resumo imediato dos fatos, timeline, entidades relacionadas e evidências em um único painel.
  * Cobertura extensiva de vulnerabilidades (CVSS vs. Exploitability real em wild).
* **Limitações & Dívidas Técnicas:**
  * Produto totalmente fechado (SaaS exclusivo).
  * Incapaz de rodar on-premises ou em infraestrutura privada controlada pelo cliente.
  * Quotas estritas de consumo e custo elevado por seat/API.

---

### 2.5 Anomali (ThreatStream / Match)
* **Propósito & Posicionamento:** Gestão e normalização em larga escala de feeds heterogêneos de IOCs com foco em distribuição rápida para SIEM/firewalls.
* **Modelo de Dados:** Catálogo de indicadores associados a inteligência de parceiros (Anomali App Store).
* **Pontos Fortes:**
  * Alta capacidade de desduplicação de feeds de alto volume.
  * Integração nativa de exportação para switches, firewalls e SIEMs legados.
* **Limitações & Dívidas Técnicas:**
  * Foco excessivo em "volume de IOCs" sem contexto investigativo profundo.
  * Frequentemente atua apenas como um "tubo de ingestão", sem capacidade avançada de exploração de grafos e hipóteses analíticas.

---

### 2.6 Google Threat Intelligence (Mandiant + VirusTotal)
* **Propósito & Posicionamento:** Combinação da telemetria global de arquivos do VirusTotal com a inteligência humana de frontline da Mandiant e a infraestrutura de telemetria da Google Cloud.
* **Modelo de Dados:** Mandiant Threat Advantage (MTA) integrado com o grafo relacional do VirusTotal v3.
* **Pontos Fortes:**
  * Qualidade inigualável de atribuição de Threat Actors (UNC/APT groups) derivados de incident response em tempo real.
  * Integração com IA generativa (Gemini in SecOps) para sumarização técnica de relatórios e busca contextual.
* **Limitações & Dívidas Técnicas:**
  * Licenciamento premium restritivo; uso da Public API do VirusTotal é estritamente proibido para integrações comerciais e corporativas.

---

### 2.7 VirusTotal (Enterprise & VT Graph)
* **Propósito & Posicionamento:** Mecanismo líder global de análise multiscanner de arquivos, URLs, domínios e IPs, com histórico passivo de DNS e grafos de relação.
* **Modelo de Dados:** Objetos VT v3 (`analyses`, `file`, `domain`, `ip_address`, `url`, `graph`).
* **Pontos Fortes:**
  * Maior base histórica do mundo de hashes de malware e detecções por 70+ engines de antivírus.
  * VT Graph permite visualizar a relação binária entre arquivos baixados, executáveis que criaram o arquivo e IPs de C2 contatados.
* **Limitações & Dívidas Técnicas:**
  * Distinção rígida entre **Public API** (4 req/min, 500 req/dia, restrita a pesquisa pessoal não-comercial) e **Premium API** (comercial, com Hunting, Livehunt e sem limites restritivos de concorrência). A arquitetura do Poseidon precisa isolar as duas variantes de forma transparente.

---

## 3. Matriz Comparativa Estrutural

| Dimensão / Capacidade | OpenCTI | MISP | ThreatConnect | Recorded Future | VirusTotal Ent. | POSEIDON (Proposta de Valor) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Padrão de Ontologia** | STIX 2.1 nativo | Proprietário (Events/Attrs) | Proprietário | Proprietário | VT v3 JSON:API | **STIX 2.1 interoperável + Modelo Canônico Relacional/Grafo** |
| **Distinção Observable vs. Indicator** | Sim (SCO vs SDO) | Parcial (Objetos) | Fraca | Fraca | Não (Apenas entidades) | **Estrita & Obrigatória (SCO observável factual vs SDO indicador contextual)** |
| **Rastreamento de Proveniência** | Alto (Markings/Authors) | Médio (Org/Source) | Alto | Alto | Médio | **Absoluto (Source, URL, Retrieved_at, Payload Hash, Transformation History)** |
| **Risk Score Explicável** | Médio | Inexistente (Score livre) | Médio | **Excelente (Rules)** | Parcial (Detections count) | **100% Explicável (Regras aditivas/subtrativas com decay e mitigadores)** |
| **Separação Risco vs. Confiança** | Parcial | Não | Parcial | Não | Não | **Total (Risco = Potencial Malicioso; Confiança = Nível de Certeza/Corroboração)** |
| **Temporalidade & Sightings** | Bom | Médio (Sighting básico) | Bom | Excelente | Bom (Passive DNS) | **Sightings contínuos com timeline unificada e decaimento temporal configurável** |
| **Knowledge Graph** | Nativo (Cytoscape/3D) | Plugins externos | Nativo | Cartões de Relação | VT Graph nativo | **Nativo com profundidade ajustável (1-5), temporalidade e filtros por TTP/Actor** |
| **Workspace de Investigação & Hipótese** | Reports/Workspaces | Event Discussion | Playbooks/Cases | Intelligence Cards | Workspaces | **Workspace de Investigação com Engine de Hipóteses (Evidência A Favor vs Contra)** |
| **Detecção de Falsos Positivos** | Manual | Warninglists maduras | CAL | Rules | Crowdsourced | **Warninglists automáticas + CDN/Cloud Detection + Override auditado** |
| **Isolamento de Fontes Gratuitas vs Pagas** | Conectores externos | Feeds | Conectores | Fechado | N/A | **Framework de Conectores com gestão de Quota, Rate Limit e Circuit Breaker** |
| **SSRF & Proteção de Rede** | Depende do host | Depende do host | Nativo | SaaS | SaaS | **Firewall interno anti-SSRF com validação estrita de IP/DNS/Metadata** |
| **Auditabilidade & Imutabilidade** | Sim (Audit stream) | Sim (Event logs) | Sim | Fechado | Parcial | **Trilha de auditoria criptográfica e imutabilidade de payload original** |

---

## 4. Oportunidades Arquiteturais & Diretrizes para o Poseidon

A partir do benchmark com as plataformas existentes, foram identificados os seguintes direcionadores estratégicos para o Poseidon:

1. **Evitar o "Complexo de Frankenstein" do OpenCTI:**
   * O OpenCTI sofre com dependência de 5 tecnologias pesadas simultâneas (OpenSearch + Redis + RabbitMQ + TypeDB/Postgres + Node.js).
   * O Poseidon adotará uma arquitetura concisa e de alto desempenho baseada em:
     * **Python 3.12+ (FastAPI)** com tipagem estrita (Pydantic v2);
     * **PostgreSQL** com suporte a JSONB, índices de busca full-text e tabelas relacionais com integridade referencial forte;
     * **Redis** como cache de baixa latência e controle atômico de rate limiting;
     * Background Workers desacoplados para ingestão e enriquecimento assíncrono.
2. **Superar o modelo arcaico do MISP:**
   * O Poseidon não utilizará esquemas de dados genéricos não-tipados. Adotaremos contratos canônicos estritos para cada tipo de IOC (IPv4, IPv6, Domain, URL, Hash, ASN, CVE, etc.) garantindo validação em tempo de ingestão.
3. **Adotar o modelo de "Intelligence Card" e "Risk Rules" do Recorded Future:**
   * Nenhum score será gerado como caixa-preta.
   * A interface do Poseidon apresentará um **Intelligence Card** padrão ouro que responde imediatamente: *O quê, De onde veio, Quando ocorreu, Quem está associado, Qual a evidência factual e Qual o nível de confiança*.
4. **Respeito rigoroso aos Termos das Fontes:**
   * Separar formalmente conectores Comunitários (ex: ThreatFox, URLhaus, MalwareBazaar, AbuseIPDB, GreyNoise v3 Community) de conectores Premium/Comerciais (VirusTotal Premium, Shodan Enterprise, etc.), com controle de quotas, mitigação de abusos e prevenção de bloqueios de API.
