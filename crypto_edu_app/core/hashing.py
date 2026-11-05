"""
core/hashing.py
----------------
Apartado 1 del menu: "cifrados sin uso de llaves"
  - Funciones hash criptograficas (SHA-256)
  - Construccion esponja y salida extensible / XOF (SHAKE-128 / SHAKE-256)

Ninguno de estos dos mecanismos usa una llave: cualquiera (incluida Eve)
puede calcular la misma huella si conoce el mensaje. Por eso NO ofrecen
confidencialidad; solo sirven para verificar integridad cuando se
transmiten por un canal confiable, o como pieza interna de otros
mecanismos (HMAC, KDF, firmas, etc.).
"""
import hashlib
from .common import OperationResult, Measure


def sha256_hash(message: bytes) -> OperationResult:
    with Measure() as m:
        digest = hashlib.sha256(message).digest()

    return OperationResult(
        mechanism="Funcion hash criptografica (SHA-256)",
        inputs={"mensaje": message},
        components={},  # sin llave, sin IV, sin nonce: no necesita componentes secretos
        secret_info={},  # no hay nada que proteger: el mensaje puede ser publico o no, pero
                          # el algoritmo no usa ningun secreto interno
        public_info={"huella_sha256": digest},
        outputs={"huella_sha256": digest, "tamano_salida_bits": 256},
        property_provided="Integridad (deteccion de cambios) SI el valor hash llega por un "
                           "canal/medio confiable; NO proporciona confidencialidad ni autenticacion "
                           "de origen por si sola.",
        resources=m.as_dict(input_size=len(message), output_size=len(digest)),
        usage_conditions=[
            "SHA-256 es resistente a colisiones y a preimagen con el estado del arte actual.",
            "NUNCA debe usarse sola para proteger contrasenas (es demasiado rapida: "
            "permite probar miles de millones de intentos por segundo). Usar una KDF (Scrypt/Argon2).",
            "El valor hash debe llegar al receptor por un canal cuya integridad este garantizada "
            "de otra forma (ej. HTTPS, o publicado junto con una firma digital).",
        ],
    )


def shake_xof(message: bytes, output_len_bytes: int = 32, variant: str = "shake_256") -> OperationResult:
    """Construccion esponja de Keccak usada como funcion de salida extensible (XOF).

    A diferencia de SHA-256 (salida fija de 32 bytes), SHAKE permite pedir
    tantos bytes de salida como se necesiten, "exprimiendo" la esponja.
    """
    with Measure() as m:
        if variant == "shake_128":
            h = hashlib.shake_128(message)
        else:
            h = hashlib.shake_256(message)
        out = h.digest(output_len_bytes)

    return OperationResult(
        mechanism=f"Construccion esponja / XOF ({variant.upper().replace('_','-')})",
        inputs={"mensaje": message, "longitud_salida_pedida_bytes": output_len_bytes},
        components={"tasa_absorcion/capacidad": "fijas por el algoritmo (no configurables por el usuario)"},
        secret_info={},
        public_info={"salida_xof": out},
        outputs={"salida_xof": out, "tamano_salida_bytes": len(out)},
        property_provided="Integridad / huella de longitud variable. Sigue sin llave: no da "
                           "confidencialidad ni autenticacion por si sola. Es la base interna de "
                           "mecanismos modernos como KMAC o de generadores de mascara.",
        resources=m.as_dict(input_size=len(message), output_size=len(out)),
        usage_conditions=[
            "La seguridad contra colisiones de una salida de N bytes es como maximo min(N,32) bytes "
            "efectivos de resistencia (para SHAKE-256), por eso para 256 bits de seguridad se piden "
            "al menos 32 bytes de salida.",
            "Util para derivar varias subclaves de distinta longitud a partir de un mismo secreto "
            "(a diferencia de un hash de salida fija).",
        ],
    )
