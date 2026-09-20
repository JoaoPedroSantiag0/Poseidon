# Auditoria — Fase XX: [Nome da Fase]

**Autor:** Auditor / Researcher  
**Data:** AAAA-MM-DD  
**Base Commit:** `<hash>`  
**Status:** Auditado  

---

## 1. Escopo Auditado

- **Commits / Arquivos Analisados:** [Lista ou range de commits]
- **O que Ficou Fora e Justificativa:** [Escopo não coberto na auditoria]

## 2. Método e Fontes Consultadas

- **Testes e Ferramentas Executadas:** [pytest, mypy strict, ruff, gitleaks, curl manual, etc.]
- **Documentação Oficial Verificada:**
  - [URL Oficial 1] (consultado em AAAA-MM-DD)
  - [URL Oficial 2] (consultado em AAAA-MM-DD)
- **Profundidade por Dimensão:** [Tempo e esforço alocados em conformidade constitucional, segurança, veracidade de API, concorrência, etc.]

## 3. Achados

### [BLOCKER-01] [Título Objetivo]
- **Arquivo:** `backend/app/...:linha`
- **Lei / Dimensão Violada:** Lei X — [Nome da Lei]
- **Evidência:** [Código, log de teste, documentação oficial]
- **Cenário de Falha:** Dado X, Quando Y, Resulta em Z
- **Impacto:** [Efeito prático para o operador, sistema ou endpoint]
- **Correção Exigida:** [Critério objetivo para encerramento do achado]

### [MAJOR-01] [Título Objetivo]
- **Arquivo:** `backend/app/...:linha`
- **Lei / Dimensão Violada:** ...
- **Evidência:** ...
- **Cenário de Falha:** ...
- **Impacto:** ...
- **Correção Exigida:** ...

### [MINOR-01] [Título Objetivo]
- **Arquivo:** `...`
- **Descrição:** ...
- **Sugestão:** ...

### [OBSERVATION-01] [Título Objetivo]
- **Contexto:** ...
- **Risco Futuro / Dívida:** ...

## 4. Verificações Realizadas sem Achado

[Lista explícita do que foi checado e passou com sucesso, delimitando a garantia da auditoria.]

## 5. Não Verificado

[O que o Auditor não conseguiu verificar objetivamente e por quê.]
