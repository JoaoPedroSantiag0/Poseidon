# POSEIDON CTI — Padrão Master de Qualidade Visual & Experiência do Usuário (UI/UX)

> **Documento:** `docs/ui/visual-quality-standard.md`  
> **Status:** Ativo / Normativo  
> **Classificação:** Diretriz de Engenharia de Frontend & Design System  
> **Data:** 2026-09-20  

---

## 1. Princípio Fundamental

O **POSEIDON** não deve se parecer com:
* Um CRUD administrativo genérico;
* Um dashboard SaaS de marketing;
* Um template comercial genérico de componentes;
* Uma aplicação acadêmica ou experimental;
* Uma tela de administração de banco de dados (ex: phpMyAdmin);
* Um clone visual estrito de MISP ou OpenCTI.

A identidade visual do Poseidon deve transmitir com sobriedade e sofisticação:
$$\textbf{Cyber Threat Intelligence Platform} + \textbf{Investigation Console} + \textbf{Intelligence Operations}$$

A qualidade visual e de interação é tratada como **requisito funcional de engenharia**, e não mero adorno estético.

---

## 2. Paleta Cromática Institucional & Níveis de Superfície

Para criar profundidade visual tridimensional sem depender de sombras difusas exageradas, a interface adota **quatro camadas fundamentais de superfície escura** combinadas com acentos semânticos de alta fidelidade:

```
[ BASE CANVAS: #080c14 ] (Deep Void Blue)
    └── [ SURFACE: #0f172a ] (Cartões primários, modais, painéis laterais)
          └── [ ELEVATED: #1e293b ] (Headers, toolbars, dropdowns, inputs)
                └── [ BORDER: #334155 / #475569 ] (Linhas finas de definição 1px)
```

| Token Semântico | Valor Hexadecimal | Função Operacional |
| :--- | :--- | :--- |
| `--poseidon-base` | `#080c14` | Plano de fundo global da aplicação |
| `--poseidon-surface` | `#0f172a` | Fundo de contêineres de dados, cartões e painéis analíticos |
| `--poseidon-elevated` | `#1e293b` | Superfície elevada para toolbars, inputs e cabeçalhos de tabela |
| `--poseidon-border` | `#334155` | Delimitação sutil de elementos e divisores |
| `--poseidon-border-light` | `#475569` | Bordas ativas em hover e estados de foco |
| `--poseidon-cyan` | `#38bdf8` | **Interação primária:** links, elementos selecionados, dados técnicos |
| `--poseidon-cyan-dark` | `#0284c7` | Estados de hover e gradientes secundários |
| `--poseidon-gold` | `#f59e0b` | **Inteligência crítica:** Threat Actors de alto perfil, status premium, destaque analítico |
| `--poseidon-gold-dark` | `#d97706` | Badges de alta severidade e ênfase tática |
| `--poseidon-critical` | `#ef4444` | Risco crítico (> 75), infraestrutura C2 ativa confirmada |
| `--poseidon-high` | `#f97316` | Risco alto (50-74), tráfego malicioso detectado |
| `--poseidon-medium` | `#eab308` | Risco moderado / atividade suspeita sob análise |
| `--poseidon-benign` | `#10b981` | Infraestrutura benigna verificada (RIOT / CDNs corporativas) |
| `--poseidon-neutral` | `#64748b` | Observável puro sem evidência de abuso / sem dados |

> [!CAUTION]
> **Regra de Ouro do Dourado:** O acento Gold (`#f59e0b`) **NUNCA** deve dominar a tela. Ele deve ser reservado exclusivamente para asserções de alta prioridade, atores confirmados e inteligência estratégica. O sistema deve parecer um console operacional militar de alta precisão, não um tema dourado chamativo.

---

## 3. Diretrizes de Tipografia Técnica

Para garantir a leitura rápida e sem ambiguidade de dados de telemetria forense:
* **Indicadores Técnicos em Fonte Monoespaçada:**
  * Endereços IPv4 e IPv6;
  * Hashes criptográficos (MD5, SHA1, SHA256, SHA512);
  * Domínios e FQDNs;
  * Identificadores CVE (`CVE-2024-38077`);
  * Timestamps em UTC (`2026-09-20 14:02:18 UTC`);
  * Família de fontes: `JetBrains Mono, Menlo, Monaco, Consolas, monospace`.
* **Corpo de Texto e Rótulos Analíticos:**
  * Fonte sem serifa de alta legibilidade (`Inter, system-ui, sans-serif`).
  * Altura de linha ajustada para evitar fadiga em sessões prolongadas de investigação.

---

## 4. Arquitetura dos Componentes Críticos

### 4.1 Intelligence Card
O componente central de visualização de indicadores responde em menos de 3 segundos:
1. **O que é:** Valor canônico, tipo do artefato (SCO) e marcação TLP.
2. **Qual a ameaça:** Risk Score numérico (0 a 100), label explicativo e barra visual.
3. **Qual a certeza:** Confidence Score (LOW / MEDIUM / HIGH) baseado em consenso.
4. **Quem está envolvido:** Família de malware associada e Threat Actor atribuído.
5. **Quando aconteceu:** Primeira e última observação cronológica e contagem de sightings.
6. **Por que acreditamos:** Lista completa e transparente de contribuidores (+/-).

### 4.2 Visualização de Risco Não-Dependente de Cores (Acessibilidade)
Nunca confiar exclusivamente em cores (`vermelho = ruim`, `verde = bom`):
* Todo indicador exibe o valor numérico exato ($87/100$);
* Rótulo textual explícito (`CRITICAL`, `HIGH`, `MEDIUM`, `BENIGN`);
* Indicador de tendência (`+12 pts nas últimas 24h` ou `-6 pts por decaimento`);
* Tooltip com os contribuidores matemáticos transparentes.

### 4.3 Sistema de Indicadores de Estado (Status System)
Todo estado do sistema combina:
$$\textbf{Ícone} + \textbf{Rótulo Textual} + \textbf{Cor Padronizada} + \textbf{Tooltip Explicativo}$$
* `CONNECTED`: Ponto verde pulsante + ícone de check + status de latência.
* `RATE_LIMITED`: Ícone de ampulheta + cor âmbar + aviso de *backoff* ativo.
* `AUTH_FAILED`: Ícone de chave bloqueada + cor vermelha + alerta de credencial inválida.
* `QUOTA_EXCEEDED`: Ícone de medidor esgotado + cor laranja + percentual consumido.
* `NOT_CONFIGURED`: Ícone neutro cinza + instrução de configuração direta.

### 4.4 Estados de Carregamento Progressivo (Skeletons)
* **Proibição de spinners genéricos centralizados:** Em vez de uma tela vazia com *"Carregando..."*, utilizar **Skeletons pulsantes** no exato formato da tabela, cartão ou grafo.
* **Enriquecimento Conector por Conector:** Apresentar feedback progressivo em tempo real à medida que cada API externa responde (`ThreatFox ✓`, `AbuseIPDB ✓`, `GreyNoise ⟳`, etc.).

### 4.5 Estados Vazios e de Erro Ação-Orientados
* **Empty State:** Informa claramente *o que está vazio*, *por que não há dados* e fornece uma ação direta (ex: `[ Disparar Enriquecimento Manual ]`).
* **Error State:** Traduz falhas técnicas para linguagem humana e acionável, com botão explícito de `[ Tentar Novamente ]`.

### 4.6 Command Palette (`Ctrl + K`) & Reconhecimento de IOCs
* Acesso global via teclado (`Ctrl + K` / `Cmd + K`).
* Reconhecimento automático do padrão inserido pelo analista:
  * Ao digitar `185.220.101.5` $\rightarrow$ *"IPv4 detectado"* com atalhos para:
    * `[ Enter ] Buscar no Banco Canônico`
    * `[ Shift + Enter ] Enriquecer em Tempo Real`
    * `[ Ctrl + I ] Abrir no Workspace de Investigação`

---

## 5. Microinterações & Diretrizes de Movimento

* **Duração Padrão:** Transições suaves de **150ms a 250ms** (`cubic-bezier(0.4, 0, 0.2, 1)`).
* **Finalidade Estrita:** Animações servem exclusivamente para guiar o foco visual, confirmar conclusão de processos de background ou indicar expansão de dados contextuais.
* **Proibição de Efeitos Supérfluos:** Rejeição formal de efeitos de "hacker movie" (chuva de código verde, caveiras animadas, terminal verde fluorescente, neon excessivo ou elementos piscando ininterruptamente).

---

## 6. Lista de Verificação de Qualidade Visual (Visual QA Gate)

Antes de considerar qualquer tela concluída, o desenvolvedor deve auditar:

- [ ] **Hierarquia Visual:** Elementos primários, secundários e terciários estão visualmente distinguidos?
- [ ] **Alinhamento & Grid:** O alinhamento espacial segue múltiplos consistentes de 4px e 8px?
- [ ] **Tipografia Técnica:** IPs, hashes, domínios e CVEs estão em fonte monoespaçada?
- [ ] **Contraste & Acessibilidade:** Os contrastes de texto sobre as superfícies escuras atendem à norma WCAG AA?
- [ ] **Não-Dependência de Cor:** Todos os estados e scores possuem rótulo textual e ícone correspondente?
- [ ] **Loading Skeletons:** A transição de carregamento utiliza skeletons estruturados?
- [ ] **Empty States:** Telas sem dados possuem explicação humana e botão de ação acionável?
- [ ] **Error States:** Falhas exibem a causa técnica simplificada e botão de retry?
- [ ] **Responsividade:** A tela funciona perfeitamente de 1280px a 2560px sem quebras de layout ou overflow horizontal?
- [ ] **Microinterações Discretas:** Transições entre 150ms e 250ms sem animações supérfluas?
