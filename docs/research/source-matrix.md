# POSEIDON CTI — Matriz Técnica de Fontes de Inteligência

> **Documento:** `docs/research/source-matrix.md`  
> **Status:** Aprovado para Phase 0 (Research & Foundation)  
> **Classificação:** Arquitetura de Conectores & Governança de Dados  
> **Data:** 2026-09-20  

---

## 1. Diretrizes de Integração & Governança de Fontes

O Poseidon foi projetado sob o princípio fundamental:
> *"Intelligence without provenance is only an assertion."*

Para assegurar conformidade jurídica, integridade técnica e alta disponibilidade da plataforma, nenhuma fonte externa é tratada como genérica. Cada fonte é integrada através de um **Connector Dedicado** subordinado ao `Source Connector Framework` do Poseidon.

### Categorias de Acesso e Licenciamento
* **FREE:** Acesso público e irrestrito sem necessidade de credenciais (sob termos de Fair Use).
* **COMMUNITY:** Acesso comunitário gratuito mediante registro simples de conta / emissão de Auth-Key.
* **FREE_WITH_ACCOUNT:** Nível gratuito fornecido por empresa comercial com limites de taxa (rate limits) e restrições sobre redistribuição ou uso corporativo.
* **TRIAL:** Acesso temporário de demonstração com credenciais dedicadas.
* **PAID:** Acesso pago/comercial via API key com SLA garantido e cotas elevadas.
* **ENTERPRISE:** Acesso corporativo com suporte dedicado, endpoints privados, contratos SLA e direitos estendidos de armazenamento/distribuição.
* **INTERNAL:** Telemetria interna corporativa ou sensores locais do Poseidon.

---

## 2. Matriz Técnica Comparativa de Fontes

| Fonte / Fornecedor | Categoria / Acesso | Autenticação | Modelo Comercial & Licença | Limites de Taxa (Rate Limits) & Cotas | Tipos de IOC Suportados | Capacidades Suportadas | Formato API / Protocolo | Prioridade de Implementação |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **abuse.ch ThreatFox** | `COMMUNITY` | Header `Auth-Key: <token>` (gratuito via portal auth.abuse.ch) | Gratuito sob Fair Use para fins de pesquisa/defesa. Uso comercial intensivo requer API comercial Spamhaus/abuse.ch. | Fair Use. Recomenda-se backoff exponencial e intervalo mínimo de 1-2s entre requisições automáticas. | IPv4, IPv6, Domain, URL, Hash (MD5, SHA1, SHA256) | Lookup, Search, Feeds recentes, Tags, Malware Families | REST POST JSON (`https://threatfox-api.abuse.ch/api/v1/`) | **Fase 3 (P1 - Core Free)** |
| **abuse.ch URLhaus** | `COMMUNITY` | Header `Auth-Key: <token>` (portal auth.abuse.ch) | Gratuito sob Fair Use. Uso comercial exige assinatura comercial Spamhaus. | Fair Use. Dumps completos restritos a intervalos definidos (ex: hourly/daily). | URL, Domain, IPv4, SHA256 (payloads) | Lookup URL/Host, Feeds de URLs ativas, Payloads maliciosos | REST POST/GET JSON (`https://urlhaus-api.abuse.ch/v1/`) | **Fase 3 (P1 - Core Free)** |
| **abuse.ch MalwareBazaar** | `COMMUNITY` | Header `Auth-Key: <token>` (portal auth.abuse.ch) | Gratuito sob Fair Use comunitário. Redistribuição comercial requer plano Spamhaus. | Fair Use. Download de amostras binárias restrito a analistas credenciados. | SHA256, SHA1, MD5, TLSH, ImpHash | Hash lookup, Malware family search, YARA rules, Tags, Code signing metadata | REST POST JSON (`https://mb-api.abuse.ch/api/v1/`) | **Fase 3 (P1 - Core Free)** |
| **AbuseIPDB** | `FREE_WITH_ACCOUNT` (Free Tier Individual) | Header `Key: <api_key>` | Gratuito para uso individual/pesquisa. Planos comerciais (Basic, Premium, Enterprise) para equipes. | Free: 1.000 checks/dia, 100 block checks/dia, 5 bulk reports/dia. Reports do mesmo IP limitados a 1 a cada 15 min. | IPv4, IPv6 | IP Reputation, Abuse Confidence Score, Categories, Country, ISP, Domain, Recent Reports | REST GET/POST JSON (`https://api.abuseipdb.com/api/v2/`) | **Fase 3 (P1 - Core Free)** |
| **GreyNoise (Community v3)** | `FREE_WITH_ACCOUNT` (Community) | Header `key: <api_key>` (exige email corporativo para chave estável) ou unauthenticated limitado | Dados comunitários para triagem de ruído de internet e scanners benignos (RIOT). Uso comercial intensivo requer assinatura Enterprise. | 50 buscas por semana no plano gratuito consolidado (Visualizer + API). Endpoints v2 descontinuados (EOL 2026). Retorno HTTP 429 ao estourar cota. | IPv4 | IP Classification (benign, malicious, unknown), Noise detection, RIOT (benign business infra), Tags, Actor, Last Seen | REST GET JSON (`https://api.greynoise.io/v3/community/{ip}`) | **Fase 3 (P1 - Core Free)** |
| **VirusTotal (Public API)** | `FREE_WITH_ACCOUNT` (Public) | Header `x-apikey: <api_key>` | **Estritamente não-comercial.** Termos de Serviço proíbem expressamente uso em produtos corporativos/comerciais ou compartilhamento de resultados em painéis coletivos. | 4 requisições / minuto. 500 requisições / dia. 15.500 requisições / mês. Retorno HTTP 429 estrito. | File Hash (MD5, SHA1, SHA256), URL, Domain, IPv4 | Multi-engine AV detections, Sandbox reports resumidos, Names/Aliases | REST GET/POST JSON:API v3 (`https://www.virustotal.com/api/v3/`) | **Fase 3 (P1 - Flag `VIRUSTOTAL_PUBLIC` com aviso legal explícito)** |
| **VirusTotal (Premium Enterprise)** | `ENTERPRISE` | Header `x-apikey: <api_key>` | Comercial enterprise. Permite integração em plataformas CTI corporativas, automação e SLA garantido. | Customizado por contrato (ex: 100+ req/min, milhões/ano). Suporte a Livehunt, Retrohunt, VT Graph. | Hash, URL, Domain, IPv4, SSL Certs, YARA Rules | Full Hunting, Graph relations, Behavioral Sandbox, Passive DNS, Download de binários | REST GET/POST JSON:API v3 (`https://www.virustotal.com/api/v3/`) | **Fase 8 (P2 - Premium Connectors)** |
| **AlienVault OTX** | `FREE_WITH_ACCOUNT` | Header `X-OTX-API-KEY: <key>` | Gratuito com registro comunitário. Licença sob termos AT&T Cybersecurity/LevelBlue. | 1.000 requisições / hora (sujeito a variação conforme termos vigentes). | IPv4, IPv6, Domain, Hostname, File Hash, CVE, URL | Pulses de ameaças comunitárias, Malicious Indicators, Passive DNS, GeoIP | REST GET JSON (`https://otx.alienvault.com/api/v1/`) | **Fase 3 (P1.5 - Comunitária Estendida)** |
| **MITRE ATT&CK (Enterprise v16)** | `FREE` (Open Source) | Nenhuma (Acesso público via GitHub / MITRE CDN) | Licença Apache 2.0 / Creative Commons Attribution 4.0 International. | Ilimitado (armazenamento local via sincronização periódica de bundle STIX). | Techniques, Sub-techniques, Tactics, Mitigations, Groups, Software | Matriz de TTPs, Mapeamento de Adversários e Malware, Relações estruturadas | Bundle STIX 2.1 JSON (`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`) | **Fase 6 (P1 - Matriz ATT&CK Nativa)** |
| **Shodan** | `PAID` / `FREE_WITH_ACCOUNT` (Limitado) | Query Param / Header `key: <api_key>` | Conta gratuita oferece 100 query credits/mês. Licenças pagas (Member, Professional, Enterprise) necessárias para telemetria contínua. | Conforme plano (ex: 1 req/segundo na API standard). | IPv4, IPv6, Domain, SSL Certificate, Banner Hash | Open Ports, Services, Banners, Vulnerabilities detectadas, SSL Fingerprints, C2 identification | REST GET JSON (`https://api.shodan.io/`) | **Fase 8 (P2 - Premium Connectors)** |
| **Censys Search** | `PAID` / `FREE_WITH_ACCOUNT` (Community) | HTTP Basic Auth (`API_ID:API_SECRET`) | Plano Community oferece 250 créditos/mês para uso individual. Uso corporativo exige plano Teams/Enterprise. | Conforme créditos e plano contratado. | IPv4, Domain, Certificate SHA256 | Host infrastructure, Ports, Software services, TLS Certificates, ASNs | REST GET/POST JSON v2 (`https://search.censys.io/api/v2/`) | **Fase 8 (P2 - Premium Connectors)** |
| **SecurityTrails** | `PAID` / `FREE_WITH_ACCOUNT` (50 queries/mês) | Header `APIKEY: <key>` | Gratuito estritamente para avaliação (50 queries/mês). Planos pagos para histórico corporativo de DNS/WHOIS. | 50 requisições/mês (Free). Planos pagos a partir de 1.000 queries/mês. | Domain, IPv4, Subdomains, IP Historic | Historical DNS (A, AAAA, MX, NS, SOA, TXT), Subdomain enumeration, Reverse IP/WHOIS | REST GET JSON (`https://api.securitytrails.com/v1/`) | **Fase 8 (P2 - Premium Connectors)** |
| **STIX / TAXII 2.1 Feeds** (CISA, CERTs) | `FREE` / `ENTERPRISE` | Basic Auth, Token ou Nenhuma (públicos) | Padrão aberto OASIS STIX/TAXII. Conformidade com termos de cada coleção. | Conforme servidor TAXII de origem. | SDOs, SCOs e SROs completos (STIX 2.1) | Ingestão contínua de coleções, feeds automatizados com polling incremental | TAXII 2.1 HTTP HTTPS REST (`application/taxii+json;version=2.1`) | **Fase 9 (P2 - Interoperabilidade)** |

---

## 3. Gestão e Políticas de Rate Limit no Poseidon

### 3.1 Arquitetura de Governança de Quotas
Para evitar bloqueios de API, estouro de custos ou consumo indevido de limites por requisições desnecessárias:

1. **Token Bucket & Leaky Bucket por Fonte e Endpoint:**
   * Cada conector possui uma especificação estrita de vazão (ex: AbuseIPDB = máx 1 req/s; VirusTotal Public = 4 req/min = 1 req a cada 15s).
   * O Poseidon enfileira chamadas de enriquecimento respeitando o *tick interval* configurado.
2. **Respeito a Cabeçalhos HTTP de Rate Limit:**
   * O engine inspeciona automaticamente `Retry-After`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
   * Se um `HTTP 429 Too Many Requests` for recebido:
     * O conector transita seu status para `RATE_LIMITED`.
     * Aplica-se **Exponential Backoff com Full Jitter**.
     * Nenhuma requisição adicional é enviada à fonte até o esgotamento do tempo estipulado.
3. **Deduplicação de Requisições Simultâneas (SingleFlight / Coalescing):**
   * Se 10 analistas ou 10 tarefas de background solicitarem enriquecimento para o mesmo hash `e3b0c44...` no mesmo segundo, o Poseidon executa apenas **uma** requisição externa e distribui a resposta canônica para todas as chamadas aguardando.
4. **Cache Multinível com TTL Inteligente por Tipo de Dado:**
   * **File Hashes:** TTL longo (24h a 7 dias) — o conteúdo de um hash não muda; apenas o score de novas detecções pode evoluir.
   * **IP Addresses:** TTL médio (6h a 12h) — endereços IP sofrem rotatividade (DHCP, cloud, C2 hosting efêmero).
   * **Domains / FQDNs:** TTL médio (4h a 8h) — resoluções de Fast-Flux e C2 dinâmico exigem renovação regular.
   * **URLs:** TTL curto (2h a 4h) — campanhas de phishing e drops maliciosos são frequentemente neutralizados em poucas horas.

---

## 4. Política de Tratamento de Termos de Uso e Propriedade Intelectual

1. **Aviso Legal Visível de Modalidade:**
   * Na interface administrativa do Poseidon, ao configurar VirusTotal, o sistema exibirá uma chave seletora obrigatória:
     * `[ ] VIRUSTOTAL_PUBLIC (Pesquisa não-comercial / restrição de 4 req/min)`
     * `[ ] VIRUSTOTAL_PREMIUM (Licença corporativa / acesso comercial)`
2. **Preservação de Atribuição de Origem:**
   * Os dados de feeds e lookups nunca serão apresentados como "Descoberta proprietária do Poseidon".
   * A entidade armazena o `source_id`, `source_name`, `source_url` e `license_type` de forma indelével.
3. **Não-armazenamento de Binários sem Autorização:**
   * A plataforma consome e indexa metadados (hashes, assinaturas, YARA, PE headers), mas não fará download automático de executáveis suspeitos sem configuração explícita e aprovação do analista em ambiente isolado.
