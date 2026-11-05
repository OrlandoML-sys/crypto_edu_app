"""
core/symmetric.py
------------------
Apartado 2 del menu: "cifrados simetricos"
  - Cifrado simetrico por bloques     -> AES-128 en modo CBC
  - Cifrado por flujo (stream cipher) -> ChaCha20
  - (bonus, se usa en los ataques)    -> AES-GCM: cifrado AUTENTICADO, para comparar
                                          contra CBC sin autenticar

Alice y Bob comparten la MISMA llave simetrica de antemano (se asume ya
distribuida, p. ej. mediante un intercambio de llaves -> ver core/asymmetric.py).
Esa llave jamas debe viajar por el canal que observa Eve.
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from .common import OperationResult, Measure


# ---------------------------------------------------------------- AES-CBC --
def aes_cbc_encrypt(message: bytes, key: bytes = None) -> OperationResult:
    key = key or os.urandom(16)          # AES-128
    iv = os.urandom(16)

    with Measure() as m:
        padder = sympadding.PKCS7(128).padder()
        padded = padder.update(message) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        ciphertext = enc.update(padded) + enc.finalize()

    return OperationResult(
        mechanism="Cifrado simetrico por bloques (AES-128-CBC)",
        inputs={"mensaje": message},
        components={"llave_AES_128": key, "IV_16B": iv, "relleno": "PKCS7"},
        secret_info={"llave_AES_128": key},
        public_info={"IV_16B": iv, "texto_cifrado": ciphertext},
        outputs={"texto_cifrado": ciphertext},
        property_provided="Confidencialidad UNICAMENTE. CBC por si solo NO protege integridad: "
                           "un atacante puede alterar bytes del cifrado y, salvo que rompa el "
                           "relleno del ultimo bloque, Bob 'descifrara' datos corruptos sin ninguna alerta.",
        resources=m.as_dict(input_size=len(message), output_size=len(ciphertext)),
        usage_conditions=[
            "El IV debe ser impredecible y NUNCA reutilizarse con la misma llave.",
            "La llave debe mantenerse secreta; si Eve la obtiene, pierde toda confidencialidad (ver "
            "escenario explicito de fuga de llaves).",
            "NO usar CBC solo para datos donde la integridad importe: combinar con un MAC (Encrypt-then-MAC) "
            "o usar un modo AEAD como AES-GCM.",
        ],
    )


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> OperationResult:
    accepted = True
    plaintext = b""
    note = ""
    with Measure() as m:
        try:
            dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            padded = dec.update(ciphertext) + dec.finalize()
            unpadder = sympadding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except Exception as e:
            accepted = False
            note = f"Error al descifrar/quitar relleno: {e}. " \
                   "OJO: esto NO es un mecanismo de integridad disenado; solo detecta " \
                   "manipulaciones que por casualidad rompen el formato del relleno del ultimo bloque."

    r = OperationResult(
        mechanism="Descifrado AES-128-CBC",
        inputs={"texto_cifrado": ciphertext, "IV_16B": iv},
        components={"llave_AES_128 (privada de Bob, ya compartida)": key},
        secret_info={"llave_AES_128": key},
        outputs={"mensaje_recuperado": plaintext} if accepted else {},
        property_provided="Confidencialidad (si la llave/IV son correctos). SIN garantia de integridad.",
        resources=m.as_dict(input_size=len(ciphertext)),
        accepted=accepted,
        notes=note,
    )
    return r


# -------------------------------------------------------------- ChaCha20 --
def chacha20_encrypt(message: bytes, key: bytes = None) -> OperationResult:
    key = key or os.urandom(32)
    nonce = os.urandom(16)  # 4 bytes contador (en 0) + 12 bytes nonce, segun implementacion de 'cryptography'

    with Measure() as m:
        enc = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor()
        ciphertext = enc.update(message) + enc.finalize()

    return OperationResult(
        mechanism="Cifrado por flujo (ChaCha20)",
        inputs={"mensaje": message},
        components={"llave_256bits": key, "nonce_128bits(incluye_contador)": nonce},
        secret_info={"llave_256bits": key},
        public_info={"nonce": nonce, "texto_cifrado": ciphertext},
        outputs={"texto_cifrado": ciphertext},
        property_provided="Confidencialidad unicamente (como CBC, sin autenticacion). Un cifrado de "
                           "flujo genera un 'keystream' pseudoaleatorio y lo combina con XOR: cualquier "
                           "bit que Eve voltee en el cifrado voltea EXACTAMENTE ese mismo bit en el "
                           "texto claro recuperado, sin error ni aviso.",
        resources=m.as_dict(input_size=len(message), output_size=len(ciphertext)),
        usage_conditions=[
            "El par (llave, nonce) JAMAS debe repetirse: reutilizar un nonce con la misma llave "
            "rompe por completo la confidencialidad (permite recuperar el XOR de dos mensajes).",
            "No proporciona integridad: en la practica se usa casi siempre dentro de un AEAD "
            "(ChaCha20-Poly1305), nunca 'pelado' como aqui, que es solo con fines didacticos.",
        ],
    )


def chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> OperationResult:
    with Measure() as m:
        dec = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
    return OperationResult(
        mechanism="Descifrado ChaCha20",
        inputs={"texto_cifrado": ciphertext, "nonce": nonce},
        components={"llave_256bits (privada de Bob)": key},
        secret_info={"llave_256bits": key},
        outputs={"mensaje_recuperado": plaintext},
        property_provided="Confidencialidad. SIN integridad: Bob no tiene forma de saber si el "
                           "'mensaje_recuperado' es el original o uno modificado por Eve.",
        resources=m.as_dict(input_size=len(ciphertext)),
        accepted=True,  # un cifrado de flujo SIEMPRE "acepta": no hay verificacion posible
        notes="ChaCha20 solo nunca rechaza nada: no tiene mecanismo de verificacion. "
              "Esa es precisamente la leccion del escenario 'cifrado sin autenticacion'.",
    )


# --------------------------------------------------------------- AES-GCM --
def aes_gcm_encrypt(message: bytes, key: bytes = None, associated_data: bytes = b"") -> OperationResult:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = key or os.urandom(32)
    nonce = os.urandom(12)

    with Measure() as m:
        aesgcm = AESGCM(key)
        ct_and_tag = aesgcm.encrypt(nonce, message, associated_data)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    return OperationResult(
        mechanism="Cifrado autenticado AES-256-GCM (AEAD)",
        inputs={"mensaje": message, "datos_asociados_AAD": associated_data},
        components={"llave_256bits": key, "nonce_96bits": nonce, "etiqueta_autenticacion_128bits": tag},
        secret_info={"llave_256bits": key},
        public_info={"nonce": nonce, "texto_cifrado": ciphertext, "etiqueta": tag,
                      "datos_asociados_AAD": associated_data},
        outputs={"texto_cifrado": ciphertext, "etiqueta": tag},
        property_provided="Confidencialidad + Integridad + Autenticacion de origen (si la llave es secreta), "
                           "todo en una sola operacion (AEAD = Authenticated Encryption with Associated Data).",
        resources=m.as_dict(input_size=len(message), output_size=len(ciphertext)),
        usage_conditions=[
            "El nonce de 12 bytes JAMAS debe repetirse con la misma llave: reutilizarlo en GCM es "
            "catastrofico (permite falsificar etiquetas y recuperar texto claro).",
            "Los AAD (datos asociados) se autentican pero NO se cifran: usarlos para cabeceras publicas "
            "que deban llegar integras (ej. remitente, numero de secuencia).",
            "Cualquier bit modificado en texto_cifrado, nonce o AAD hace que la verificacion falle "
            "por completo al descifrar (ver escenario 'cifrado autenticado').",
        ],
    )


def aes_gcm_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes,
                     associated_data: bytes = b"") -> OperationResult:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    accepted = True
    plaintext = b""
    note = ""
    with Measure() as m:
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, associated_data)
        except InvalidTag:
            accepted = False
            note = "Etiqueta de autenticacion invalida: el mensaje fue modificado (o la llave/nonce/AAD " \
                   "no coinciden). AES-GCM RECHAZA el mensaje completo; no entrega texto claro parcial."

    return OperationResult(
        mechanism="Verificacion/Descifrado AES-256-GCM",
        inputs={"texto_cifrado": ciphertext, "etiqueta": tag, "nonce": nonce, "AAD": associated_data},
        components={"llave_256bits (privada de Bob)": key},
        secret_info={"llave_256bits": key},
        outputs={"mensaje_recuperado": plaintext} if accepted else {},
        property_provided="Confidencialidad + Integridad + Autenticacion.",
        resources=m.as_dict(input_size=len(ciphertext)),
        accepted=accepted,
        notes=note,
    )
