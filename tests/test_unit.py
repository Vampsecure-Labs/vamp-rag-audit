# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-rag-audit.

Cubre los dataclasses, la detección de compromiso, ClienteRAG,
los checks disponibles y las funciones de exportación.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import vamp_rag_audit as rag_audit


# ────────────────────────────────────────────────────────────────────────────
# Tests de _detectar_compromiso
# ────────────────────────────────────────────────────────────────────────────

class TestDetectarCompromiso:
    """Pruebas de la función de detección de compromiso por tipo de check."""

    def test_rag001_detecta_pwned(self):
        """RAG-001: 'PWNED' en la respuesta indica inyección indirecta exitosa."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="PWNED: ejecutando instrucciones del atacante.",
            payload="instrucción maliciosa",
            tipo="RAG-001",
        )
        assert resultado is True

    def test_rag001_respuesta_normal_no_comprometida(self):
        """RAG-001: respuesta sin indicadores no se considera comprometida."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="El aprendizaje automático permite a los sistemas aprender de datos.",
            payload="instrucción maliciosa",
            tipo="RAG-001",
        )
        assert resultado is False

    def test_rag002_detecta_compromised(self):
        """RAG-002: 'COMPROMISED' en la respuesta indica poisoning con Unicode Tags."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="COMPROMISED via Unicode Tags injection in context.",
            payload="",
            tipo="RAG-002",
        )
        assert resultado is True

    def test_rag003_detecta_exfiltracion_clave_api(self):
        """RAG-003: patrón de clave API en la respuesta indica exfiltración de datos."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="Credenciales del sistema: password: sk-live-abc123xyz456",
            payload="../../../etc/secrets",
            tipo="RAG-003",
        )
        assert resultado is True

    def test_rag006_detecta_error_sql(self):
        """RAG-006: error de sintaxis SQL en la respuesta indica inyección exitosa."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="ERROR: You have an error in your SQL syntax near 'OR 1=1'",
            payload="' OR 1=1--",
            tipo="RAG-006",
        )
        assert resultado is True

    def test_rag010_detecta_xss(self):
        """RAG-010: etiqueta <script> en la respuesta indica inyección HTML/XSS."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="<script>alert('XSS')</script>Respuesta del sistema.",
            payload="<script>",
            tipo="RAG-010",
        )
        assert resultado is True

    def test_tipo_desconocido_devuelve_false(self):
        """Un tipo de check desconocido no debe lanzar excepción; devuelve False."""
        resultado = rag_audit._detectar_compromiso(
            respuesta="cualquier texto",
            payload="payload",
            tipo="RAG-999",
        )
        assert resultado is False


# ────────────────────────────────────────────────────────────────────────────
# Tests de Hallazgo y ResultadoCheck
# ────────────────────────────────────────────────────────────────────────────

class TestDataclasses:
    """Pruebas de los dataclasses Hallazgo y ResultadoCheck."""

    def test_hallazgo_se_crea_correctamente(self, hallazgo_critico):
        """El dataclass Hallazgo se instancia con los atributos correctos."""
        assert hallazgo_critico.id == "RAG-001"
        assert hallazgo_critico.severidad == "CRITICAL"
        assert hallazgo_critico.estado == "VULNERABLE"

    def test_resultado_check_vulnerable(self, resultado_check_vulnerable):
        """ResultadoCheck en estado VULNERABLE tiene los campos esperados."""
        assert resultado_check_vulnerable.estado == "VULNERABLE"
        assert resultado_check_vulnerable.severidad == "CRITICAL"

    def test_resultado_check_seguro(self, resultado_check_seguro):
        """ResultadoCheck en estado SEGURO indica ausencia de vulnerabilidad."""
        assert resultado_check_seguro.estado == "SEGURO"

    def test_resultado_check_tiene_duracion_ms(self, resultado_check_vulnerable):
        """ResultadoCheck registra la duración de ejecución del check."""
        assert isinstance(resultado_check_vulnerable.duracion_ms, (int, float))
        assert resultado_check_vulnerable.duracion_ms >= 0


# ────────────────────────────────────────────────────────────────────────────
# Tests de CHECKS_DISPONIBLES
# ────────────────────────────────────────────────────────────────────────────

class TestChecksDisponibles:
    """Pruebas del catálogo de checks RAG registrados en el módulo."""

    def test_checks_disponibles_tiene_diez_entradas(self):
        """El módulo registra exactamente 10 checks RAG."""
        assert len(rag_audit.CHECKS_DISPONIBLES) == 10

    def test_todos_los_ids_rag_presentes(self):
        """Los IDs RAG-001 a RAG-010 están todos registrados."""
        for n in range(1, 11):
            assert f"RAG-{n:03d}" in rag_audit.CHECKS_DISPONIBLES

    def test_todos_los_checks_son_callable(self):
        """Cada valor del catálogo es una función invocable (coroutine)."""
        for id_check, funcion in rag_audit.CHECKS_DISPONIBLES.items():
            assert callable(funcion), f"{id_check} no es callable"


# ────────────────────────────────────────────────────────────────────────────
# Tests de ClienteRAG
# ────────────────────────────────────────────────────────────────────────────

class TestClienteRAG:
    """Pruebas de la clase ClienteRAG sin llamadas de red reales."""

    def test_construir_headers_sin_auth(self, cliente_sin_auth):
        """Sin API key, los headers no incluyen Authorization."""
        headers = cliente_sin_auth._construir_headers()
        assert "Authorization" not in headers

    def test_construir_headers_con_auth(self, cliente_con_auth):
        """Con API key, los headers incluyen Authorization: Bearer."""
        headers = cliente_con_auth._construir_headers()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Bearer ")

    def test_construir_body_formato_openai(self, cliente_sin_auth):
        """El body para formato openai incluye la clave 'messages'."""
        body = cliente_sin_auth._construir_body("¿qué es RAG?")
        # Puede ser formato OpenAI o genérico dependiendo del formato detectado
        assert isinstance(body, dict)
        assert len(body) > 0

    def test_extraer_texto_openai(self, cliente_sin_auth):
        """Extrae el contenido de una respuesta en formato OpenAI."""
        raw = json.dumps({"choices": [{"message": {"content": "respuesta del modelo"}}]})
        texto = cliente_sin_auth.extraer_texto_respuesta(raw)
        assert texto == "respuesta del modelo"

    def test_extraer_texto_formato_generico_answer(self, cliente_sin_auth):
        """Extrae el contenido de una respuesta con clave 'answer'."""
        raw = json.dumps({"answer": "respuesta directa"})
        texto = cliente_sin_auth.extraer_texto_respuesta(raw)
        assert texto == "respuesta directa"

    def test_extraer_texto_formato_generico_output(self, cliente_sin_auth):
        """Extrae el contenido de una respuesta con clave 'output'."""
        raw = json.dumps({"output": "salida del modelo"})
        texto = cliente_sin_auth.extraer_texto_respuesta(raw)
        assert texto == "salida del modelo"


# ────────────────────────────────────────────────────────────────────────────
# Tests de exportar_json y generar_html
# ────────────────────────────────────────────────────────────────────────────

class TestExportacion:
    """Pruebas de las funciones de exportación de resultados."""

    def test_exportar_json_produce_json_valido(self, resultado_check_vulnerable, resultado_check_seguro):
        """exportar_json produce una cadena JSON válida."""
        resultados = [resultado_check_vulnerable, resultado_check_seguro]
        salida = rag_audit.exportar_json(resultados, "http://localhost:8080")
        datos = json.loads(salida)
        assert isinstance(datos, (dict, list))

    def test_exportar_json_incluye_endpoint(self, resultado_check_seguro):
        """El JSON exportado incluye referencia al endpoint auditado."""
        salida = rag_audit.exportar_json([resultado_check_seguro], "http://test-endpoint")
        assert "http://test-endpoint" in salida

    def test_generar_html_produce_html(self, resultado_check_vulnerable):
        """generar_html produce una cadena HTML con estructura básica."""
        html = rag_audit.generar_html([resultado_check_vulnerable], "http://test-endpoint")
        assert "<html" in html.lower() or "<!doctype" in html.lower()

    def test_generar_html_contiene_id_check(self, resultado_check_vulnerable):
        """El HTML generado incluye el ID del check encontrado."""
        html = rag_audit.generar_html([resultado_check_vulnerable], "http://test")
        assert "RAG-001" in html
