"""
core/common.py
----------------
Estructura de datos común que usan TODOS los mecanismos del laboratorio,
y utilidades para medir tiempo / memoria de cada operación.

Cada mecanismo (hash, cifrado, MAC, firma, KDF, intercambio de llaves...)
devuelve un objeto `OperationResult` con los siete campos que pide la
práctica:

    inputs             -> mensaje, contraseña, secreto compartido, etc.
    components         -> llaves, IV, nonce, contador, sal, etiqueta, firma, certificado...
    secret_info        -> lo que NUNCA debe salir de quien lo generó
    public_info        -> lo que SÍ puede viajar por el canal (lo que Alice envía a Bob)
    outputs            -> texto cifrado, huella, etiqueta, firma, clave derivada...
    property_provided  -> confidencialidad / autenticación / integridad / establecimiento de llaves
    resources          -> tiempo de ejecución, tamaño de entrada/salida, memoria observada
    usage_conditions   -> reglas / tamaños / parámetros necesarios para que sea seguro
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time
import tracemalloc


@dataclass
class OperationResult:
    mechanism: str
    inputs: Dict[str, Any] = field(default_factory=dict)
    components: Dict[str, Any] = field(default_factory=dict)
    secret_info: Dict[str, Any] = field(default_factory=dict)
    public_info: Dict[str, Any] = field(default_factory=dict)
    outputs: Dict[str, Any] = field(default_factory=dict)
    property_provided: str = ""
    resources: Dict[str, Any] = field(default_factory=dict)
    usage_conditions: List[str] = field(default_factory=list)
    accepted: Optional[bool] = None   # solo aplica a operaciones de verificación/descifrado en Bob
    notes: str = ""

    def pretty(self) -> str:
        lines = [f"=== {self.mechanism} ==="]
        if self.property_provided:
            lines.append(f"Propiedad proporcionada : {self.property_provided}")
        if self.accepted is not None:
            lines.append(f"Resultado               : {'ACEPTADO' if self.accepted else 'RECHAZADO'}")
        for title, d in (("Entradas", self.inputs),
                         ("Componentes", self.components),
                         ("Info. SECRETA (no viaja)", self.secret_info),
                         ("Info. PÚBLICA (sí viaja)", self.public_info),
                         ("Salidas", self.outputs)):
            if d:
                lines.append(f"-- {title} --")
                for k, v in d.items():
                    lines.append(f"   {k}: {_shorten(v)}")
        if self.resources:
            lines.append("-- Recursos --")
            for k, v in self.resources.items():
                lines.append(f"   {k}: {v}")
        if self.usage_conditions:
            lines.append("-- Condiciones de uso --")
            for c in self.usage_conditions:
                lines.append(f"   * {c}")
        if self.notes:
            lines.append(f"Notas: {self.notes}")
        return "\n".join(lines)


def _shorten(v: Any, maxlen: int = 64) -> str:
    s = v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
    return s if len(s) <= maxlen else s[:maxlen] + f"...(+{len(s)-maxlen} chars)"


class Measure:
    """Context manager que mide tiempo de ejecución y memoria pico (tracemalloc)
    de una operación. Se usa dentro de cada mecanismo para llenar 'resources'.

    LIMITACIÓN IMPORTANTE (se exige declararla en la práctica):
    tracemalloc solo contabiliza la memoria asignada por objetos Python.
    Las bibliotecas criptográficas de este proyecto (el paquete `cryptography`)
    hacen la mayor parte de su trabajo en código nativo de OpenSSL (C), por lo
    que esas asignaciones NO quedan reflejadas aquí. El valor de memoria debe
    leerse como una cota inferior / aproximación, nunca como el consumo real total.
    """

    def __enter__(self):
        tracemalloc.start()
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.elapsed_ms = (time.perf_counter() - self._t0) * 1000
        current, peak = tracemalloc.get_traced_memory()
        self.peak_bytes = peak
        tracemalloc.stop()
        return False

    def as_dict(self, input_size: int = None, output_size: int = None) -> Dict[str, Any]:
        d = {
            "tiempo_ejecucion_ms": round(self.elapsed_ms, 4),
            "memoria_pico_python_bytes": self.peak_bytes,
            "memoria_nota": "Medida solo con tracemalloc (objetos Python); "
                             "no incluye asignaciones nativas de OpenSSL/libcrypto.",
        }
        if input_size is not None:
            d["tamano_entrada_bytes"] = input_size
        if output_size is not None:
            d["tamano_salida_bytes"] = output_size
        return d
