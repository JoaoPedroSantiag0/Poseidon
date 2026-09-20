# Plano — Fase XX: [Nome da Fase]

**Autor:** Architect / Builder  
**Data:** AAAA-MM-DD  
**Status:** Proposto | Aprovado pelo Humano | Rejeitado  

---

## 1. Objetivo da Fase em uma Frase

[Definição sucinta e sem ambiguidade do que esta fase entrega.]

## 2. Critérios de Aceite

No formato obrigatório: *Dado [contexto inicial], Quando [ação ou evento executado], Então [resultado verificável esperado]*.

- [ ] **AC-01:** Dado ..., Quando ..., Então ...
- [ ] **AC-02:** Dado ..., Quando ..., Então ...
- [ ] **AC-03:** Dado ..., Quando ..., Então ...

## 3. Arquivos a Criar e Alterar

| Ação (NOVO/ALTERAR/DELETAR) | Caminho do Arquivo | Propósito e Responsabilidade |
|---|---|---|
| NOVO | `backend/...` | ... |
| ALTERAR | `...` | ... |

## 4. Modelo de Dados e Migrações

- **Entidades Afetadas:** [Tabelas PostgreSQL, índices OpenSearch, etc.]
- **Migrações Alembic:** [Descrição dos scripts de upgrade e downgrade]
- **Estratégia de Reversibilidade:** [Como o downgrade preserva ou descarta dados com segurança]

## 5. Contratos de API

- **Novos Endpoints:** [Método, path, parâmetros, schemas Pydantic de entrada/saída]
- **Endpoints Alterados:** [Mudanças de contrato ou breaking changes]
- **Autenticação e RBAC Exigido:** [Permissões necessárias para cada rota]

## 6. Riscos e Mitigações

| Risco Identificado | Severidade / Probabilidade | Estratégia de Mitigação |
|---|---|---|
| [Risco 1] | Alta / Média | [Mitigação detalhada] |

## 7. O que Explicitamente Fica de Fora

[Lista de funcionalidades, atalhos ou escopos adiados para fases futuras ou fora do MVP.]

## 8. Comando de Demonstração Previsto

```bash
# Uma linha documentada que comprova o funcionamento da fase
```
