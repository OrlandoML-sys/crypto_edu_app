"""
core/kdf.py
-----------
Derivaciones de claves (KDF).

Dos usos distintos que la practica pide distinguir:
 1) Derivar una llave a partir de una CONTRASENA humana (lenta a proposito,
    para encarecer los ataques de diccionario/fuerza bruta): PBKDF2, Scrypt.
 2) Derivar una o varias llaves a partir de un SECRETO YA ALEATORIO de alta
    entropia (p. ej. la salida de un intercambio Diffie-Hellman): HKDF,
    que es rapida a proposito porque el secreto de entrada ya es fuerte.
"""
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .common import OperationResult, Measure


def pbkdf2_derive(password: bytes, salt: bytes = None, iterations: int = 600_000,
                   length: int = 32) -> OperationResult:
    salt = salt or os.urandom(16)
    with Measure() as m:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
        key = kdf.derive(password)

    return OperationResult(
        mechanism="PBKDF2-HMAC-SHA256",
        inputs={"contrasena": password, "iteraciones": iterations},
        components={"sal_16B": salt, "iteraciones": iterations},
        secret_info={"contrasena": password, "llave_derivada": key},
        public_info={"sal": salt},  # la sal SI puede ser publica
        outputs={"llave_derivada": key},
        property_provided="Establecimiento de una llave simetrica a partir de una contrasena, "
                           "encareciendo (con 'iteraciones') los ataques de diccionario/fuerza bruta.",
        resources=m.as_dict(input_size=len(password), output_size=len(key)),
        usage_conditions=[
            "La sal debe ser aleatoria y distinta por usuario/registro (evita tablas arcoiris).",
            "OWASP 2023+ recomienda >= 600,000 iteraciones para PBKDF2-HMAC-SHA256.",
            "PBKDF2 es barato de acelerar en hardware (GPU/ASIC) comparado con Scrypt/Argon2: "
            "preferir estos ultimos cuando sea posible.",
        ],
    )


def scrypt_derive(password: bytes, salt: bytes = None, n: int = 2**14, r: int = 8, p: int = 1,
                   length: int = 32) -> OperationResult:
    salt = salt or os.urandom(16)
    with Measure() as m:
        kdf = Scrypt(salt=salt, length=length, n=n, r=r, p=p)
        key = kdf.derive(password)

    return OperationResult(
        mechanism="Scrypt",
        inputs={"contrasena": password, "parametros_costo": {"N": n, "r": r, "p": p}},
        components={"sal_16B": salt, "N": n, "r": r, "p": p},
        secret_info={"contrasena": password, "llave_derivada": key},
        public_info={"sal": salt},
        outputs={"llave_derivada": key},
        property_provided="Establecimiento de llave a partir de contrasena, con costo deliberado "
                           "en TIEMPO *y* MEMORIA (el parametro N obliga a usar ~128*N*r bytes de RAM), "
                           "lo que encarece mucho los ataques paralelizados en GPU/ASIC frente a PBKDF2.",
        resources=m.as_dict(input_size=len(password), output_size=len(key)),
        usage_conditions=[
            "N debe ser potencia de 2; valores tipicos interactivos: N=2^14..2^17, r=8, p=1.",
            "Memoria aproximada requerida ~= 128 * N * r bytes (con N=2^14, r=8 son ~16 MB por intento).",
            "Es precisamente ese costo de memoria lo que hace a Scrypt mas caro de atacar que SHA-256 "
            "directo o que PBKDF2 con el mismo numero de iteraciones (ver demo de ataque de diccionario).",
        ],
    )


def hkdf_derive(shared_secret: bytes, info: bytes = b"sesion", length: int = 32,
                 salt: bytes = None) -> OperationResult:
    salt = salt if salt is not None else os.urandom(16)
    with Measure() as m:
        hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
        key = hk.derive(shared_secret)

    return OperationResult(
        mechanism="HKDF-SHA256",
        inputs={"secreto_compartido": shared_secret, "info_contexto": info},
        components={"sal": salt, "info": info},
        secret_info={"secreto_compartido": shared_secret, "llave_derivada": key},
        public_info={"sal": salt, "info": info},
        outputs={"llave_derivada": key},
        property_provided="Expande/'blanquea' un secreto YA aleatorio (p. ej. salida de Diffie-Hellman) "
                           "en una o varias llaves independientes para distintos usos (cifrado, MAC...).",
        resources=m.as_dict(input_size=len(shared_secret), output_size=len(key)),
        usage_conditions=[
            "NO usar HKDF directamente sobre una contrasena humana: es rapida a proposito, no ofrece "
            "ningun costo contra diccionario (para eso esta Scrypt/PBKDF2/Argon2).",
            "Usar un 'info' distinto por cada llave que se derive del mismo secreto, para separar "
            "criptograficamente sus usos (ej. 'cifrado' vs 'autenticacion').",
        ],
    )
