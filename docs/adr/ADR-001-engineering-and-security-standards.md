# ADR-001: Adoção do Padrão Tripartite de Engenharia, Qualidade Visual & Segurança Operacional

* **Status:** Aprovado
* **Data:** 2026-09-20
* **Decisores:** Time de Engenharia e Arquitetura Poseidon
* **Contexto:** Definição dos fundamentos arquiteturais e padrões de qualidade para a plataforma CTI.

---

## Contexto do Problema

Plataformas legadas de Cyber Threat Intelligence frequentemente sofrem com quatro vícios arquiteturais graves:
1. Tratam indicadores como registros estáticos em bancos de dados sem rastreabilidade bidirecional de proveniência;
2. Misturam fatos empíricos com hipóteses analíticas e pontuações de caixa-preta;
3. Dependem de interfaces CRUD genéricas e visualmente áridas que desaceleram o analista em momentos críticos de incidente;
4. Falham catastroficamente quando APIs externas ficam offline, aplicam rate-limits ou alteram seus formatos de resposta.

---

## Decisão

Adotamos a **Especificação Tripartite do Poseidon**:
* **PROMPT 01 (Produto & Arquitetura):** O que construir (STIX 2.1, Observable vs Indicator, Proveniência, Risk Score explicável, Conectores modulares).
* **PROMPT 02 (Qualidade Visual & UX):** Como construir visualmente (Design System com Blue Graphite, Cyan e Gold, Intelligence Cards, Command Palette Ctrl+K, Skeletons progressivos, estados de erro humanos).
* **PROMPT 03 (Excelência em Engenharia & Segurança):** Como construir corretamente e provar que funciona (Definition of Done estrita, pirâmide de testes com testes de falha deliberada, proteção anti-SSRF de camada de rede, Correlation IDs ponta a ponta e taxonomia unificada de erros).

---

## Consequências e Impacto Operacional

### Positivas:
* Eliminação de "verdades mágicas" ou asserções não fundamentadas em evidências.
* Alta resiliência operacional: falhas ou bloqueios de fontes externas degradam apenas o conector correspondente, mantendo o Poseidon 100% operacional.
* Rastreabilidade total de ponta a ponta através de `X-Correlation-ID` e logs estruturados em JSON.
* Prevenção ativa de vazamentos e ataques SSRF através do firewall de DNS e validação de rotas privadas.

### Negativas / Custos de Engenharia:
* Maior tempo investido em testes e cobertura de cenários de falha antes da liberação de cada conector.
* Necessidade de manter contratos e validação estrita de esquemas em todas as entradas de terceiros.
