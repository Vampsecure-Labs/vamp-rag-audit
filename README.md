# vamp-rag-audit

  <img src="https://github.com/Vampsecure-Labs/vamp-rag-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>

**RAG and agentic AI security auditor** — VampSecure Labs · VampSecure Studios

Auditor de seguridad activo para sistemas de Retrieval-Augmented Generation (RAG) e IA agéntica.
Detecta indirect prompt injection, context poisoning, data exfiltration, embedding attacks,
context window overflow y retrieval manipulation.

**Para uso exclusivo en pruebas de penetración autorizadas.**

---

## Instalación

```bash
pip install vamp-rag-audit
```

O desde el repositorio:

```bash
pip install .
```

## Uso

```bash
# Auditoría básica contra un endpoint RAG/LLM
vamp-rag-audit probe http://localhost:8080/api/query

# Con API key
vamp-rag-audit probe http://api.example.com/chat --api-key sk-xxx

# Extraer endpoints desde spec OpenAPI
vamp-rag-audit probe --spec openapi.yaml

# Output JSON para integración CI/CD
vamp-rag-audit probe http://localhost:8080/api/query --format json

# Generar informe HTML
vamp-rag-audit probe http://localhost:8080/api/query --output informe.html

# Ejecutar solo checks específicos
vamp-rag-audit probe http://localhost:8080/api/query --checks RAG-001 RAG-002 RAG-003

# Filtrar por severidad mínima
vamp-rag-audit probe http://localhost:8080/api/query --severity HIGH
```

## Checks incluidos

| ID      | Severidad | Descripción |
|---------|-----------|-------------|
| RAG-001 | CRITICAL  | Indirect Prompt Injection vía contexto recuperado |
| RAG-002 | CRITICAL  | Context Poisoning con Unicode Tags invisibles |
| RAG-003 | HIGH      | Data Exfiltration por manipulación de retrieval |
| RAG-004 | HIGH      | Context Window Overflow |
| RAG-005 | HIGH      | Source Attribution Bypass |
| RAG-006 | MEDIUM    | Retrieval Query Injection (SQL/NoSQL) |
| RAG-007 | MEDIUM    | Agentic Tool Invocation vía documento inyectado |
| RAG-008 | MEDIUM    | Metadata Poisoning |
| RAG-009 | LOW       | Information Disclosure vía Embeddings |
| RAG-010 | LOW       | Missing Input Sanitization (XSS/HTML) |

## OWASP LLM Top 10 2025 — Mapping

- LLM01 Prompt Injection → RAG-001, RAG-002, RAG-004, RAG-005, RAG-006, RAG-008
- LLM06 Sensitive Information Disclosure → RAG-003, RAG-009
- LLM07 Insecure Plugin Design → RAG-007
- LLM08 Excessive Agency → RAG-005
- LLM09 Misinformation / Insecure Output → RAG-010

## Exit codes

- `0` — Sin hallazgos CRITICAL/HIGH
- `1` — Hallazgos detectados
- `2` — Error de ejecución

## Licencia

AGPL-3.0-only · © VampSecure Studios — VampSecure Labs Security Research Division
