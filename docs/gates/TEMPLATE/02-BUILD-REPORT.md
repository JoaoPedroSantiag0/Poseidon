# Relatório de Construção — Fase XX: [Nome da Fase]

**Autor:** Architect / Builder  
**Data:** AAAA-MM-DD  
**Base Commit:** `<hash>`  
**Status:** Pronto para Auditoria  

---

## 1. O que foi Entregue

Mapeamento de entrega contra os critérios de aceite definidos no `01-PLAN.md`:

| Critério de Aceite | Status (Entregue / Parcial / Não Entregue) | Evidência / Teste Correspondente |
|---|---|---|
| **AC-01** | Entregue | `tests/...::test_xyz` |
| **AC-02** | Entregue | `tests/...::test_abc` |

## 2. Desvios do Plano e Justificativa

> [!IMPORTANT]
> Este é o item mais crítico do relatório. Qualquer discrepância em relação ao `01-PLAN.md` deve ser documentada aqui com justificativa técnica.

- **Desvio 1:** [O que mudou e por quê]
- **Desvio 2:** [O que mudou e por quê]

## 3. Como Executar e Testar

### Pré-requisitos
- [Dependências, variáveis de ambiente, serviços necessários]

### Execução dos Testes Automatizados
```bash
# Comando de teste
pytest tests/... -v
```

### Comando de Demonstração Funcionando
```bash
# Uma linha documentada que prova a fase funcionando de ponta a ponta
```

## 4. Cobertura de Testes e Limitações

- **Cobertura Geral:** XX%
- **Caminhos de Erro Testados:** [Lista de testes de casos de borda e falha]
- **O que Deliberadamente Não Foi Testado e Justificativa:** [Ex: mocks de serviços externos inviáveis no ambiente local]

## 5. Dívida Técnica Assumida

- [Dívida 1 com item de backlog associado]

## 6. Itens "NÃO VERIFICADO" que Permanecem

- [Itens cuja confirmação empírica ou documental não foi possível]

## 7. Focos Sugeridos para a Auditoria

> [!TIP]
> Pontos onde o próprio Builder possui dúvidas ou recomenda atenção minuciosa do Auditor.

- [Ponto de atenção 1]
- [Ponto de atenção 2]
