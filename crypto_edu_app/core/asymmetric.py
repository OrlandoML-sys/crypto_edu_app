"""
core/asymmetric.py
-------------------
Apartado 3 del menu: "cifrados asimetricos"
  - Cifrado de clave publica      -> RSA-2048 + OAEP
  - Firmas digitales              -> ECDSA sobre curva P-256
  - Intercambio de llaves         -> ECDH sobre curva P-256

En todos los casos Eve puede ver y usar libremente las llaves PUBLICAS
(se asume que viajan por el canal o se publican); jamas debe tener
acceso a las llaves PRIVADAS salvo en el escenario explicito de fuga.
"""
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes, serialization
from .common import OperationResult, Measure


# --------------------------------------------------- Cifrado de clave publica (RSA-OAEP) --
def rsa_generate_keypair(key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def rsa_oaep_encrypt(message: bytes, public_key) -> OperationResult:
    with Measure() as m:
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
        )
    pub_bytes = public_key.public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)

    return OperationResult(
        mechanism="Cifrado de clave publica (RSA-2048-OAEP)",
        inputs={"mensaje": message},
        components={"llave_publica_RSA_de_Bob_DER": pub_bytes},
        secret_info={},  # Alice no tiene ningun secreto aqui: solo usa la llave PUBLICA de Bob
        public_info={"llave_publica_de_Bob": pub_bytes, "texto_cifrado": ciphertext},
        outputs={"texto_cifrado": ciphertext},
        property_provided="Confidencialidad: solo quien tiene la llave PRIVADA de Bob puede descifrar. "
                           "No requiere que Alice y Bob compartan ningun secreto de antemano.",
        resources=m.as_dict(input_size=len(message), output_size=len(ciphertext)),
        usage_conditions=[
            "RSA-OAEP solo puede cifrar mensajes PEQUENOS (unos 190 bytes con 2048 bits + SHA-256): "
            "para mensajes largos se usa 'cifrado hibrido' (RSA cifra una llave simetrica, y esa "
            "llave simetrica con AES cifra el mensaje real).",
            "Usar SIEMPRE el relleno OAEP; el relleno 'de libro de texto' (RSA sin relleno) es inseguro.",
            "Es ~1000x mas lento que el cifrado simetrico: no se usa para cifrar datos masivos.",
        ],
    )


def rsa_oaep_decrypt(ciphertext: bytes, private_key) -> OperationResult:
    accepted = True
    plaintext = b""
    note = ""
    with Measure() as m:
        try:
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None),
            )
        except Exception as e:
            accepted = False
            note = f"Fallo al descifrar: {e}"

    return OperationResult(
        mechanism="Descifrado RSA-2048-OAEP",
        inputs={"texto_cifrado": ciphertext},
        components={"llave_privada_RSA (de Bob, NUNCA sale de Bob)": "***oculta***"},
        secret_info={"llave_privada_RSA": "***oculta, solo Bob la tiene***"},
        outputs={"mensaje_recuperado": plaintext} if accepted else {},
        property_provided="Confidencialidad.",
        resources=m.as_dict(input_size=len(ciphertext)),
        accepted=accepted,
        notes=note,
    )


# -------------------------------------------------------------- Firmas digitales (ECDSA) --
def ecdsa_generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def ecdsa_sign(message: bytes, private_key) -> OperationResult:
    with Measure() as m:
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    return OperationResult(
        mechanism="Firma digital (ECDSA P-256 + SHA-256)",
        inputs={"mensaje": message},
        components={"llave_privada_de_Alice (NUNCA sale de Alice)": "***oculta***", "firma": signature},
        secret_info={"llave_privada_ECDSA": "***oculta, solo Alice la tiene***"},
        public_info={"mensaje": message, "firma": signature},
        outputs={"firma": signature},
        property_provided="Autenticacion de origen + Integridad + NO-REPUDIO (a diferencia de un MAC, "
                           "un tercero puede verificar la firma con la llave PUBLICA de Alice sin "
                           "necesitar ningun secreto compartido, y Alice no puede negar haberla firmado).",
        resources=m.as_dict(input_size=len(message), output_size=len(signature)),
        usage_conditions=[
            "La llave privada de firma JAMAS debe salir del firmante ni reutilizarse para otro fin.",
            "El valor aleatorio 'k' interno de ECDSA debe ser unico e impredecible por firma: "
            "reutilizar k (o usar un generador debil) PERMITE RECUPERAR LA LLAVE PRIVADA completa.",
            "La llave publica debe distribuirse de forma autenticada (ver PKI), si no Eve puede "
            "sustituirla por la suya y firmar mensajes haciendose pasar por Alice.",
        ],
    )


def ecdsa_verify(message: bytes, signature: bytes, public_key) -> OperationResult:
    from cryptography.exceptions import InvalidSignature
    accepted = True
    note = ""
    with Measure() as m:
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            accepted = False
            note = "La firma no es valida para este mensaje: fue modificado despues de firmarse, " \
                   "o no fue firmado por el duenio de esta llave publica."

    pub_bytes = public_key.public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    return OperationResult(
        mechanism="Verificacion de firma ECDSA",
        inputs={"mensaje_recibido": message, "firma_recibida": signature},
        components={"llave_publica_de_Alice_DER": pub_bytes},
        secret_info={},
        public_info={"llave_publica_de_Alice": pub_bytes},
        property_provided="Autenticacion de origen + Integridad + No-repudio.",
        resources=m.as_dict(input_size=len(message)),
        accepted=accepted,
        notes=note,
    )


# ------------------------------------------------------- Intercambio de llaves (ECDH) --
def ecdh_generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def ecdh_derive_shared(my_private_key, peer_public_key, who: str = "") -> OperationResult:
    with Measure() as m:
        shared = my_private_key.exchange(ec.ECDH(), peer_public_key)
        # El secreto crudo de ECDH NO debe usarse directo como llave: se pasa por un KDF (HKDF)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as _h
        session_key = HKDF(algorithm=_h.SHA256(), length=32, salt=None,
                            info=b"ecdh-sesion").derive(shared)

    peer_pub_bytes = peer_public_key.public_bytes(serialization.Encoding.DER,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
    return OperationResult(
        mechanism=f"Intercambio de llaves Diffie-Hellman sobre curvas elipticas (ECDH) [{who}]",
        inputs={},
        components={"llave_publica_del_otro_participante_DER": peer_pub_bytes,
                     "mi_llave_privada_efimera": "***oculta, nunca se transmite***"},
        secret_info={"secreto_compartido_crudo": shared, "llave_de_sesion_derivada": session_key},
        public_info={"mi_llave_publica_efimera": "(se envia al otro participante, ver 'components' del otro lado)"},
        outputs={"llave_de_sesion_derivada": session_key},
        property_provided="Establecimiento de una llave simetrica compartida SIN transmitirla jamas "
                           "por el canal (ni siquiera cifrada). Solo quienes combinan su llave privada "
                           "con la publica del otro llegan al mismo secreto.",
        resources=m.as_dict(output_size=len(session_key)),
        usage_conditions=[
            "ECDH 'puro' (sin autenticar) es vulnerable a un ataque de intermediario (Man-in-the-Middle): "
            "si Eve sustituye las llaves publicas en transito, puede establecer una llave de sesion "
            "distinta con Alice y otra con Bob, y quedar en medio relevando/leyendo todo (ver demo).",
            "Para evitarlo, las llaves publicas deben autenticarse (firmarlas, o certificarlas via PKI).",
            "Usar llaves efimeras (una pareja nueva por sesion) da 'forward secrecy': si una llave "
            "de sesion se filtra despues, las sesiones pasadas siguen seguras.",
        ],
    )
