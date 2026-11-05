"""
core/mac.py
-----------
Codigos de Autenticacion de Mensajes (MAC): HMAC-SHA256 y CMAC-AES.

Un MAC usa una llave SECRETA compartida para producir una etiqueta que
prueba dos cosas a la vez: integridad (el mensaje no cambio) y
autenticacion de origen (solo quien tiene la llave pudo haberla generado).
A diferencia de un hash simple, Eve NO puede recalcular una etiqueta
valida aunque conozca el mensaje, porque no tiene la llave.
"""
import hmac
import hashlib
import os
from cryptography.hazmat.primitives import cmac as crypto_cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from .common import OperationResult, Measure


def hmac_sha256_sign(message: bytes, key: bytes = None) -> OperationResult:
    key = key or os.urandom(32)
    with Measure() as m:
        tag = hmac.new(key, message, hashlib.sha256).digest()

    return OperationResult(
        mechanism="HMAC-SHA256",
        inputs={"mensaje": message},
        components={"llave_HMAC": key, "etiqueta_32B": tag},
        secret_info={"llave_HMAC": key},
        public_info={"mensaje": message, "etiqueta": tag},
        outputs={"etiqueta": tag},
        property_provided="Integridad + Autenticacion de origen (NO confidencialidad: el "
                           "mensaje normalmente viaja en claro junto con la etiqueta).",
        resources=m.as_dict(input_size=len(message), output_size=len(tag)),
        usage_conditions=[
            "La llave debe tener al menos 256 bits de entropia y mantenerse secreta.",
            "Comparar etiquetas con comparacion de tiempo constante (hmac.compare_digest) para "
            "evitar ataques de temporizacion.",
            "Si se necesita tambien confidencialidad, combinar con cifrado usando el patron "
            "Encrypt-then-MAC (cifrar primero, luego autenticar el cifrado).",
        ],
    )


def hmac_sha256_verify(message: bytes, tag: bytes, key: bytes) -> OperationResult:
    with Measure() as m:
        expected = hmac.new(key, message, hashlib.sha256).digest()
        accepted = hmac.compare_digest(expected, tag)

    return OperationResult(
        mechanism="Verificacion HMAC-SHA256",
        inputs={"mensaje_recibido": message, "etiqueta_recibida": tag},
        components={"llave_HMAC (privada de Bob)": key},
        secret_info={"llave_HMAC": key},
        property_provided="Integridad + Autenticacion de origen.",
        resources=m.as_dict(input_size=len(message)),
        accepted=accepted,
        notes="" if accepted else "La etiqueta recalculada no coincide: el mensaje fue modificado "
                                   "en transito, o fue generado por alguien sin la llave correcta.",
    )


def cmac_aes_sign(message: bytes, key: bytes = None) -> OperationResult:
    key = key or os.urandom(16)
    with Measure() as m:
        c = crypto_cmac.CMAC(algorithms.AES(key))
        c.update(message)
        tag = c.finalize()

    return OperationResult(
        mechanism="CMAC-AES-128",
        inputs={"mensaje": message},
        components={"llave_AES_128": key, "etiqueta_16B": tag},
        secret_info={"llave_AES_128": key},
        public_info={"mensaje": message, "etiqueta": tag},
        outputs={"etiqueta": tag},
        property_provided="Integridad + Autenticacion de origen (construido a partir de un cifrado "
                           "por bloques en vez de un hash, a diferencia de HMAC).",
        resources=m.as_dict(input_size=len(message), output_size=len(tag)),
        usage_conditions=[
            "Util cuando ya se dispone de una implementacion de AES y se prefiere no depender de "
            "una funcion hash aparte.",
            "Igual que HMAC: la llave debe ser secreta y la verificacion debe hacerse en tiempo constante.",
        ],
    )


def cmac_aes_verify(message: bytes, tag: bytes, key: bytes) -> OperationResult:
    accepted = True
    note = ""
    with Measure() as m:
        try:
            c = crypto_cmac.CMAC(algorithms.AES(key))
            c.update(message)
            c.verify(tag)
        except Exception:
            accepted = False
            note = "La etiqueta CMAC no es valida: el mensaje fue modificado o la llave no coincide."

    return OperationResult(
        mechanism="Verificacion CMAC-AES-128",
        inputs={"mensaje_recibido": message, "etiqueta_recibida": tag},
        components={"llave_AES_128 (privada de Bob)": key},
        secret_info={"llave_AES_128": key},
        property_provided="Integridad + Autenticacion de origen.",
        resources=m.as_dict(input_size=len(message)),
        accepted=accepted,
        notes=note,
    )
