"""
channel.py
----------
Simula el canal de comunicacion entre Alice y Bob.

Reglas de diseno (exigidas por la practica):
  * Eve SOLO puede ver lo que Alice puso en el canal (los campos "publicos":
    texto cifrado, IV/nonce, etiquetas, firmas, certificados, llaves PUBLICAS...).
  * Eve NUNCA recibe automaticamente llaves privadas/secretas. Si se quiere
    demostrar que pasa cuando una llave se filtra, hay que llamar
    explicitamente a `Channel.escenario_fuga_de_llave(...)`, que queda
    registrado de forma separada y visible en el log como "FUGA EXPLICITA".
  * Eve puede, en el "modo laboratorio", modificar/sustituir/reenviar lo que
    hay en el canal antes de que llegue a Bob.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List
import copy


@dataclass
class ChannelEvent:
    kind: str                  # "envio", "manipulacion_eve", "reenvio_eve", "FUGA_EXPLICITA_DE_LLAVE"
    payload_publico: Dict[str, Any]
    actor: str
    detalle: str = ""


class Channel:
    def __init__(self):
        self.log: List[ChannelEvent] = []
        self.last_payload: Dict[str, Any] = {}

    # ---- Alice ----
    def alice_send(self, public_payload: Dict[str, Any], detalle: str = "") -> None:
        """Alice solo puede poner en el canal lo que es PUBLICO por diseno del mecanismo
        (OperationResult.public_info). Nunca se le pasan aqui llaves privadas."""
        self.last_payload = copy.deepcopy(public_payload)
        self.log.append(ChannelEvent("envio", self.last_payload, "Alice", detalle))

    # ---- Eve: observacion pasiva (siempre disponible) ----
    def eve_observe(self) -> Dict[str, Any]:
        """Eve ve exactamente los mismos bytes publicos que hay en el canal. Nada mas."""
        return copy.deepcopy(self.last_payload)

    # ---- Eve: acciones activas de laboratorio ----
    def eve_tamper(self, field: str, new_value: Any, detalle: str = "") -> None:
        """Eve modifica/sustituye un campo PUBLICO del ultimo mensaje en el canal
        (ej. voltear un byte del cifrado, sustituir una llave publica, sustituir un certificado)."""
        if field in self.last_payload:
            old = self.last_payload[field]
            self.last_payload[field] = new_value
            self.log.append(ChannelEvent("manipulacion_eve", copy.deepcopy(self.last_payload), "Eve",
                                          detalle or f"Eve modifico el campo '{field}'"))

    def eve_replay(self, detalle: str = "Eve reenvia un mensaje valido capturado antes") -> Dict[str, Any]:
        """Eve simplemente vuelve a enviar (sin modificar) un payload que ya vio pasar."""
        self.log.append(ChannelEvent("reenvio_eve", copy.deepcopy(self.last_payload), "Eve", detalle))
        return copy.deepcopy(self.last_payload)

    # ---- Bob ----
    def bob_receive(self) -> Dict[str, Any]:
        return copy.deepcopy(self.last_payload)

    # ---- Escenario SEPARADO y EXPLICITO de fuga de llave privada/secreta ----
    def escenario_fuga_de_llave(self, nombre_llave: str, valor) -> None:
        """OJO: este metodo representa un escenario de laboratorio aparte, en el que se
        asume deliberadamente que una llave secreta/privada quedo expuesta (por mala
        practica, malware, error de configuracion, etc.). No ocurre nunca automaticamente;
        debe invocarse de forma explicita, y queda marcado en el log como tal."""
        self.log.append(ChannelEvent(
            "FUGA_EXPLICITA_DE_LLAVE",
            {nombre_llave: valor},
            "Eve (escenario separado)",
            "ESCENARIO EXPLICITO: se asume que esta llave secreta se filtro por una causa externa "
            "al protocolo (no por una debilidad criptografica). Esto NO sucede en los demas escenarios.",
        ))

    def print_log(self):
        for i, ev in enumerate(self.log, 1):
            print(f"[{i}] ({ev.actor}) {ev.kind}: {ev.detalle}")
