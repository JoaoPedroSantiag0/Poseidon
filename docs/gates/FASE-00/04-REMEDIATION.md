# Remediação — Fase 00: Arquitetura Fundacional e Governança

**Autor:** Architect / Builder  
**Data:** 2026-09-20  
**Referência:** `docs/gates/FASE-00/03-AUDIT-REPORT.md`  
**Base Constitucional:** `docs/prompts/00-CONSTITUTION.md` (Emenda v2.0)  
**Status:** Respostas Submetidas à Auditoria  

---

## 1. Resumo Executivo da Remediação

O relatório de auditoria `03-AUDIT-REPORT.md` realizou uma análise adversária de alto valor sobre a Constituição v1.0 e as premissas da Fase 0. Quatro achados foram classificados como **BLOCKER**, doze como **MAJOR**, seis como **MINOR** e onze como **OBSERVATION**.

Com a promulgação da **Emenda Constitucional v2.0** pelo Humano em 2026-09-20 e com as decisões registradas (o Poseidon possui ambição de **SaaS**, e o isolamento de rede é **falha-fechado**), todos os quatro BLOCKERs foram sanados diretamente no texto constitucional.

| Categoria | Total | ACEITO | CONTESTO | ADIADO |
|---|:---:|:---:|:---:|:---:|
| **BLOCKER** | 4 | 4 | 0 | 0 |
| **MAJOR** | 12 | 11 | 1 | 0 |
| **MINOR** | 6 | 6 | 0 | 0 |
| **OBSERVATION** | 11 | 11 (Ciência/Acolhido) | 0 | 0 |

---

## 2. Respostas aos BLOCKERs

### [BLOCKER-01] A Lei 5 inventa schema — que a Lei 2 proíbe — e decide o ADR-002 antes dele existir
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O achado procede plenamente. A fixação de nomes rígidos em código na Lei 5 contradizia a Lei 2 e geraria um envelope redundante sobre o OCSF/ECS.
- **Onde foi corrigido:** Na **Constituição v2.0**, a Lei 5 foi reescrita para declarar **requisitos semânticos e conceituais** (tempo do evento, tempo de ingestão, origem, ID na origem, referência ao bruto, correlação), estabelecendo que a nomenclatura concreta pertencerá ao padrão adotado no ADR-002 (OCSF) e que extensões usarão o namespace `poseidon.*`. O ADR-002 será atualizado para refletir o schema formal do OCSF 1.9 (`time`, `metadata.logged_time`, `metadata.product`, `metadata.original_event_uid`, `raw_data`, `metadata.correlation_uid`).

---

### [BLOCKER-02] A Lei 4 é inexequível na ordem em que o roadmap está escrito
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O achado identificou com precisão cirúrgica a contradição entre a Lei 4 ("exercitado contra no mínimo duas fontes") e a Fase 3 (onde nenhuma fonte real existia ainda).
- **Onde foi corrigido:** Na **Constituição v2.0**, a Lei 4 e o Roadmap (§7) separaram formalmente:
  1. **Decidir o padrão (Fase 3):** O padrão é decidido no ADR-002 e o modelo nasce marcado como `PROVISÓRIO`, exercitado compulsoriamente contra um **corpus gravado de alertas reais do Wazuh** capturados em container de laboratório.
  2. **Congelar o modelo (Fase 9):** O congelamento só ocorre após o Wazuh entrar como segunda fonte real heterogênea em produção, mediante ADR específico (`Supersedes: ADR-002`).
  3. Fases 4 a 8 mantêm migrações de dados estritamente reversíveis.

---

### [BLOCKER-03] A Lei 8 protege o agente que escrevemos e ignora o agente que comandamos
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** A evidência levantada pelo Auditor no código-fonte do Wazuh v4.14.7 (`framework/wazuh/core/active_response.py` e `active_response_controller.py`) comprovou brechas estruturais de terceiros: prefixo `!` ignora lista de comandos, `agents_list: '*'` por padrão atinge toda a frota, e `PUT /agents/upgrade_custom` permite upload de binário WPK arbitrário.
- **Onde foi corrigido:** Na **Constituição v2.0**, a Lei 8 foi estendida para abranger **todo caminho de execução que o Poseidon comanda** (próprio ou de terceiros). O conector Wazuh agora possui proibições constitucionais explícitas:
  - Nunca envia comando com prefixo `!`;
  - Nunca omite `agents_list`;
  - Nunca invoca `upgrade_custom`;
  - Nunca deriva `arguments` de entrada do usuário;
  - A credencial da API do Wazuh é formalmente reconhecida como equivalente a execução de código na frota e tratada com o nível de segurança de chave de assinatura. O ADR-001 e o ADR-006 refletirão essas travas.

---

### [BLOCKER-04] Isolamento total é incompatível com o dead-man's-switch e com o transporte escolhido
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** Com transporte exclusivamente outbound por polling, o isolamento total impede o agente de pollar o servidor. Consequentemente, um dead-man's-switch dispararia desfazendo o isolamento após N minutos, gerando falsa expectativa de contenção ao analista.
- **Onde foi corrigido:** O Humano deliberou que o isolamento é **falha-fechado** e determinou:
  1. **Isolamento total está FORA do MVP** (Constituição v2.0, Lei 10 e §11). No MVP existe exclusivamente **isolamento seletivo** (mantendo o canal do Poseidon, DNS e gestão).
  2. O failsafe não mora dentro do processo do agente (que pode estar morto), mas sim em um **watchdog independente do sistema operacional** (tarefa/serviço nativo) associado a uma **expiração absoluta persistida em disco**.
  3. Exigência de caminho de recuperação fora de banda testado antes de produção.

---

## 3. Respostas aos MAJORs

### [MAJOR-01] A Lei 6 exige uma propriedade que o stack escolhido não consegue garantir
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O Auditor tem razão ao apontar que regras de permissão no PostgreSQL (`REVOKE UPDATE, DELETE`) protegem contra o usuário da aplicação, mas não contra adulteração por quem possui credenciais de banco de dados ou acesso físico aos volumes.
- **Resolução:** O ADR-007 incluirá a especificação de **encadeamento criptográfico por hash (hash chaining)**: cada registro de auditoria conterá o hash SHA-256 do registro imediatamente anterior (`previous_record_hash`) e a assinatura do bloco, tornando qualquer mutação em banco detectável imediatamente. Além disso, espelhamento assíncrono para armazenamento WORM/Object Storage imutável será integrado na Fase 12.

---

### [MAJOR-02] O `01-BUILDER.md` afirma um endpoint de API que não existe
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O texto do `01-BUILDER.md` §7.4 induzia à busca de alertas na API do Manager (porta 55000). A pesquisa técnica já havia comprovado que alertas residem unicamente no Wazuh Indexer (porta 9200) e em `alerts.json`.
- **Resolução:** O `01-BUILDER.md` §7.4 foi corrigido na v2.0 para distinguir *"API do Manager (auth, agentes, regras, resposta ativa — ela não serve alertas)"* e *"Wazuh Indexer (alertas, índices, autenticação própria)"*. O conector Wazuh é projetado como duplo por necessidade no ADR-001.

---

### [MAJOR-03] A Lei 11 e o ADR-004 (Sigma) colidem, e nada na constituição resolve
- **Posicionamento:** **CONTESTO (a solução proposta de detectar no endpoint antes de redigir)** / **ACEITO (a necessidade de harmonizar redação e detecção)**
- **Fundamentação Técnica da Contestação:**
  O Auditor sugere como resolução *"detectar antes de redigir, persistir depois"*. Essa abordagem exigiria portar e executar um motor completo de regras Sigma compiladas **dentro do Collector Agent** no endpoint.
  Essa solução é inviável e prejudicial por três razões técnicas:
  1. O Collector Agent em Go foi projetado para ter footprint mínimo (<40MB de RAM, binário estático enxuto, sem interpretador complexo de regras). Executar compilação e matching de centenas de regras Sigma no endpoint violaria a meta de performance e criaria um segundo motor de detecção paralelo ao backend;
  2. A arquitetura de referência da Constituição centraliza a correlação e detecção no **Poseidon Core / OpenSearch** (Seção 3 e Seção 4);
  3. Regras Sigma que detectam comandos maliciosos de alto valor procuram ferramentas e padrões de ataque (`powershell -enc`, `-NoProfile`, `Invoke-Expression`, `vssadmin delete shadows`, `certutil -urlcache`), e **nenhum desses comandos representa segredos de usuários**. Eles não são objeto de redação de credenciais!
- **Solução Técnica Adotada:**
  A redação da Lei 11 é estritamente **semântica e focada em credenciais**:
  1. A redação no Collector Agent mascara **valores de argumentos de autenticação** (ex: substitui `net use ... /user:x secret123` por `net use ... /user:x [REDACTED]`, ou `--password=secret` por `--password=[REDACTED]`), mas **preserva intactos os nomes das flags, switches, caminhos de binários e comandos invocados**;
  2. Argumentos de evasão de defesa (`-enc`, `-W Hidden`) nunca coincidem com regexes de credenciais e trafegam íntegros para detecção pelo Sigma;
  3. Adicionalmente, o Collector calcula um hash criptográfico (SHA-256) da linha de comando original antes da redação e o envia como metadado (`metadata.command_line_hash`). Regras Sigma e correlações de IOCs baseadas no hash completo continuam funcionando perfeitamente sem expor o segredo em claro no banco.

---

### [MAJOR-04] A Fase 5 depende de software que o Poseidon não pode redistribuir
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** A EULA da Sysinternals veda expressamente *"publish the software for others to copy"* e *"use the software for commercial software hosting services"*, tornando a redistribuição do Sysmon inviável para uma oferta SaaS do Poseidon.
- **Onde foi corrigido:** Na **Constituição v2.0 (§4)**, o Humano aprovou a substituição definitiva: a fonte primária de telemetria do Collector Agent é o **consumo direto de ETW** (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-DNS-Client` e equivalentes) e **Windows Event Log via `wevtapi.dll`** sem CGO. O Sysmon permanece exclusivamente como ferramenta de laboratório para validação cruzada de cobertura, e o instalador do Poseidon jamais o empacota.

---

### [MAJOR-05] Identidade do agente: nenhuma lei, nenhuma fase, e a constituição a chama de irreversível
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O ciclo de vida da identidade do agente (enrollment, rotação e revogação) é crítico para impedir o uso de credenciais extraídas de máquinas desprovisionadas ou comprometidas.
- **Resolução:** O ADR-005 definirá o protocolo completo:
  1. **Enrollment:** Token temporário de uso único (*bootstrap token*) provisionado pelo administrador; o agente gera um par Ed25519 local e envia um Certificate Signing Request (CSR); o servidor assina e emite certificado de identidade mTLS com UUID fixo;
  2. **Revogação:** Lista de revogação de certificados (CRL) mantida no servidor e verificada em cada handshake mTLS;
  3. **Validação de Ordens:** Despacho de ações (Lei 9) é assinado pela chave privada do Control Plane; o agente valida contra a chave pública da CA interna recebida no enrollment. Se um agente for revogado no servidor, suas conexões são rejeitadas e novas ordens cessam imediatamente.

---

### [MAJOR-06] Retenção de dados: o Auditor é mandado caçá-la, e não existe lei nem fase que a crie
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** A preservação obrigatória do evento bruto (Lei 5) sem política formal de ciclo de vida e descarte levaria inevitavelmente ao esgotamento do armazenamento.
- **Resolução:** O ADR-008 incluirá:
  1. Política de **Index State Management (ISM)** no OpenSearch com transição por fases (Hot: 7 dias; Warm: 30 dias; Cold: 90 dias; Delete/Archive para Object Storage);
  2. Segregação de políticas: telemetria efêmera possui retenção configurável (padrão 90 dias); **Audit Log e evidências forenses vinculadas a Casos possuem retenção estendida mandatória (mínimo 1 ano / regulatório) e nunca são descartadas pelas regras de telemetria geral**;
  3. Alertas de saturação de disco integrados ao Health Center (Lei 12).

---

### [MAJOR-07] Atualização do agente em campo não tem fase
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** Atualizar agentes em campo é superfície de altíssimo risco que, se improvisada, equivaleria a um vetor de execução arbitrária.
- **Resolução:** O ciclo de atualização do agente será incorporado como requisito da Fase 5 (arquitetura) e da Fase 14 (hardening). O protocolo obedecerá às mesmas travas da Lei 9: pacote de atualização distribuído como binário compilado único, assinado com a chave da CA do Poseidon, verificado por hash SHA-256 e assinatura antes de substituir o executável do serviço via troca atômica com rollback automático em caso de falha de inicialização.

---

### [MAJOR-08] A persistência do isolamento através de um reboot é indefinida
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O Auditor demonstrou que sessões dinâmicas do WFP caem no reboot (falha-aberto), enquanto regras persistentes sobrevivem (falha-fechado).
- **Onde foi corrigido:** O Humano decidiu formalmente que o isolamento é **falha-fechado** (Constituição v2.0, Lei 10): a contenção de um incidente sobrevive ao reboot da máquina e à morte do agente. O mecanismo (regras persistentes do WFP/Windows Firewall) mantém o bloqueio seletivo até que a expiração gravada em disco seja alcançada pelo watchdog ou haja comando autenticado de restauração.

---

### [MAJOR-09] As Leis 5 e 9 dependem do relógio do endpoint, e não há modelo de confiança de relógio
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** Um atacante com privilégios locais pode manipular o relógio do sistema para forçar aceitação de ordens expiradas ou distorcer cronologia de eventos.
- **Resolução:**
  1. **Ações de Resposta:** A expiração da ação não dependerá unicamente do relógio absoluto do endpoint: o payload transporta um tempo de vida relativo (*TTL em segundos*) e o servidor afere o *clock skew* no handshake mTLS; os nonces executados persistem em `bbolt` com proteção anti-replay independente do relógio;
  2. **Ingestão de Eventos:** O pipeline de ingestão armazena o `event_time` original do endpoint, o `ingestion_time` do servidor e o `clock_skew_delta`. Desvios significativos (> 60s) disparam alerta no Health Center (Lei 12).

---

### [MAJOR-10] O §11 transforma exclusões permanentes em prazo, e licencia multi-tenant por acidente
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** O §11 v1.0 gerava ambiguidade ao sugerir que itens fora do MVP estariam liberados a partir da Fase 13.
- **Onde foi corrigido:** Na **Constituição v2.0 (§11)**:
  - Isolamento total foi categoricamente excluído do MVP;
  - A seção **"Multi-tenancy: não construída, mas não impedida"** foi inserida: a operação no MVP é single-tenant, mas entidades de dados carregam a coluna `tenant_id` desde a Fase 2 para que a transição futura para SaaS não exija reescrita destrutiva de banco de dados.

---

### [MAJOR-11] A Lei 5 não exige versão de schema no evento persistido
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** Mudanças de versão de schemas (OCSF 1.4 -> 1.9) tornam logs históricos ininterpretáveis caso a versão do modelo não esteja explicitada no registro.
- **Resolução:** Todo evento normalizado persistido carregará obrigatoriamente o metadado de versão do schema (campo nativo `metadata.version` do OCSF). Incorporado nos requisitos do ADR-002.

---

### [MAJOR-12] Rotação de credenciais de integração não tem mecanismo nem fase
- **Posicionamento:** **ACEITO**
- **Fundamentação e Correção:** A credencial do Wazuh Manager e de outras fontes de integração equivale a acesso privilegiado e exige ciclo de vida formal.
- **Resolução:** O ADR-008 e ADR-001 definirão o ciclo de rotação com suporte a chave dupla (período de overlap onde a credencial antiga e nova são aceitas simultaneamente). O Health Center emitirá alertas preventivos antes do vencimento de segredos.

---

## 4. Respostas aos MINORs

- **[MINOR-01] O protocolo de gate trava quando a auditoria não encontra nada:**
  - **Posicionamento:** **ACEITO**. Protocolo ajustado: na ausência de BLOCKER e MAJOR, o Builder registra ciência em `04-REMEDIATION.md` e o Auditor emite o veredito `PASS` diretamente com as ressalvas aplicáveis.
- **[MINOR-02] A Fase 0 não tem conjunto de artefatos de gate definido:**
  - **Posicionamento:** **ACEITO**. Na Fase 0 (pesquisa e decisão), o `02-BUILD-REPORT.md` e os testes de código de produção não se aplicam; o gate encerra-se com a entrega do `04-REMEDIATION.md`, da pesquisa complementar de ETW e dos ADRs propostos para decisão do Humano.
- **[MINOR-03] O §4 comprime autenticação a ponto de omitir decisões que importam:**
  - **Posicionamento:** **ACEITO**. O ADR-007 distinguirá hash de senha (Argon2id), segundo fator (TOTP), emissão/revogação de JWTs (com denylist em Redis para logoff imediato) e a estabilidade do identificador de usuário (`user_id` imutável, nunca derivado de hash de sessão) no Audit Log.
- **[MINOR-04] `sighting` é tratado como SDO; é um SRO:**
  - **Posicionamento:** **ACEITO**. Na especificação OASIS STIX 2.1, `sighting` é formalmente um *Relationship Object* (SRO). O ADR-003 mapeará a observação da Lei 7 exatamente como SRO `sighting` vinculado ao SDO `indicator`.
- **[MINOR-05] A DRL 1.1 impõe um requisito de schema que nenhuma lei contempla:**
  - **Posicionamento:** **ACEITO**. A nova **Lei 13 da Constituição v2.0** foi criada especificamente para contemplar essa exigência: todo alerta disparado por regra do SigmaHQ reterá o campo do autor no payload do evento (`Class 2001 - Security Finding`).
- **[MINOR-06] `arq` é fixado no stack sem ADR, ainda em 0.x:**
  - **Posicionamento:** **ACEITO**. O ADR-008 documentará formalmente a escolha do `arq` e as alternativas avaliadas (Celery, TaskIQ), justificando seu uso pelo suporte nativo a `asyncio`/Redis e baixo overhead.

---

## 5. Ciência e Acolhimento das OBSERVATIONs

Registramos ciência formal e alinhamento com as 11 observações técnicas levantadas pelo Auditor:
- **[OBSERVATION-01] (LGPD):** Acolhido integralmente na **Lei 13 da Constituição v2.0**. O Poseidon é classificado como operador de dados pessoais com minimização e retenção controladas desde o design.
- **[OBSERVATION-02] (SDK OTX / LevelBlue):** Acolhido. O conector CTI consumirá diretamente os endpoints REST da API via HTTP client assíncrono padrão, sem acoplamento ao SDK em desuso.
- **[OBSERVATION-03] (Sessão dinâmica WFP):** Analisado. Como o isolamento é falha-fechado por decisão do Humano, regras dinâmicas puras não atendem; utilizaremos regras persistentes associadas a watchdog de SO.
- **[OBSERVATION-04] (Molde Wazuh via Indexer):** Acolhido. O adapter da Fase 9 confinará toda tradução de campos dentro de sua fronteira com testes contra fixtures gravadas.
- **[OBSERVATION-05] (Argumentação ECS vs OCSF):** Acolhido. OCSF será defendido por méritos técnicos verificáveis e governança neutra, sem argumentos falaciosos sobre o status do ECS.
- **[OBSERVATION-06] (Ferramental Python OCSF):** Acolhido. Assumimos no ADR-002 o custo de manutenção de schemas manuais em Pydantic v2.
- **[OBSERVATION-07] (Wazuh 5.x AGPL):** Acolhido. Reforça a decisão de isolamento absoluto via API de rede.
- **[OBSERVATION-08] (Typo classe 1008 OCSF):** Acolhido e mapeado.
- **[OBSERVATION-09] (Piso SO Sysmon):** Superado pela mudança para ETW nativo (§4).
- **[OBSERVATION-10] (ATT&CK via Wazuh):** Acolhido. O Poseidon utilizará diretamente o repositório oficial STIX 2.1 do MITRE ATT&CK.
- **[OBSERVATION-11] (Disaster Recovery entre os 3 stores):** Acolhido e incluído como requisito arquitetural no ADR-008.
