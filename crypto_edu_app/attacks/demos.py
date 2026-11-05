"""
attacks/demos.py
-----------------
Implementa los NUEVE escenarios de la tabla de la practica. Cada funcion
`escenario_*` regresa (resumen_texto, datos) y puede usarse tanto desde
demo_cli.py (modo texto) como desde la GUI (boton de cada panel de Eve).
"""
import os
import time
import hashlib

from core import hashing, symmetric, mac, kdf, asymmetric, pki
from channel import Channel

# Un diccionario de contrasenas pequeno, SOLO con fines didacticos.
WORDLIST = ["123456", "password", "qwerty", "letmein", "admin", "bienvenido",
            "contrasena", "iloveyou", "monkey", "dragon", "futbol", "mexico2024",
            "correcthorse", "hunter2", "P@ssw0rd!", "estudiante"]


# ----------------------------------------------------------- 1. Contrasena debil --
def escenario_contrasena_debil(contrasena_real: str = "P@ssw0rd!") -> dict:
    target_hash = hashlib.sha256(contrasena_real.encode()).hexdigest()

    t0 = time.perf_counter()
    intentos = 0
    encontrada = None
    for palabra in WORDLIST:
        intentos += 1
        if hashlib.sha256(palabra.encode()).hexdigest() == target_hash:
            encontrada = palabra
            break
    elapsed = (time.perf_counter() - t0) * 1000

    resumen = (
        f"Escenario: Contrasena debil (ataque de diccionario contra SHA-256 directo)\n"
        f"Huella objetivo (SHA-256): {target_hash}\n"
        f"Intentos probados: {intentos}/{len(WORDLIST)}  |  Tiempo total: {elapsed:.3f} ms "
        f"(~{elapsed/max(intentos,1):.5f} ms/intento)\n"
        f"Resultado: {'CONTRASENA ENCONTRADA -> ' + encontrada if encontrada else 'no estaba en el diccionario'}\n"
        f"Aprendizaje: Eve NO 'descifro' el hash (SHA-256 no se puede invertir); recreo el mismo calculo "
        f"que hizo el sistema y comparo resultados. 'Adivinar por fuerza bruta/diccionario' es un ataque "
        f"totalmente distinto, y mucho mas rapido de ejecutar, a 'romper criptograficamente' el algoritmo."
    )
    return {"resumen": resumen, "intentos": intentos, "tiempo_ms": elapsed, "encontrada": encontrada}


# ----------------------------------------------------- 2. Derivacion de contrasenas --
def escenario_derivacion_contrasenas(contrasena_real: str = "P@ssw0rd!") -> dict:
    salt = os.urandom(16)

    # Ataque de diccionario vs SHA-256 directo (sin sal, solo para comparar costo)
    target_sha = hashlib.sha256(contrasena_real.encode()).hexdigest()
    t0 = time.perf_counter()
    for palabra in WORDLIST:
        hashlib.sha256(palabra.encode()).hexdigest()
    t_sha_total = (time.perf_counter() - t0) * 1000

    # Ataque de diccionario vs Scrypt (con los mismos parametros que usaria el sistema real)
    scrypt_result = kdf.scrypt_derive(contrasena_real.encode(), salt=salt, n=2**14, r=8, p=1)
    target_scrypt = scrypt_result.outputs["llave_derivada"]
    t0 = time.perf_counter()
    for palabra in WORDLIST:
        kdf.scrypt_derive(palabra.encode(), salt=salt, n=2**14, r=8, p=1)
    t_scrypt_total = (time.perf_counter() - t0) * 1000

    factor = t_scrypt_total / t_sha_total if t_sha_total > 0 else float("inf")
    resumen = (
        f"Escenario: Derivacion de contrasenas (SHA-256 directo vs Scrypt, mismo diccionario de "
        f"{len(WORDLIST)} palabras)\n"
        f"Tiempo total probando el diccionario completo contra SHA-256 directo : {t_sha_total:.3f} ms\n"
        f"Tiempo total probando el diccionario completo contra Scrypt (N=2^14) : {t_scrypt_total:.3f} ms\n"
        f"Scrypt fue ~{factor:.0f}x mas lento de atacar con el mismo diccionario.\n"
        f"Aprendizaje: los PARAMETROS DE COSTO (iteraciones en PBKDF2; N,r,p en Scrypt) multiplican "
        f"directamente el trabajo que Eve debe invertir POR CADA intento del diccionario; con SHA-256 "
        f"'pelado' ese costo es practicamente nulo."
    )
    return {"resumen": resumen, "t_sha_ms": t_sha_total, "t_scrypt_ms": t_scrypt_total, "factor": factor}


# ----------------------------------------------------- 3. Cifrado sin autenticacion --
def escenario_cifrado_sin_autenticacion(mensaje: bytes = b"Transferir 100 pesos a Bob, cuenta 001") -> dict:
    enc = symmetric.aes_cbc_encrypt(mensaje)
    key, iv = enc.components["llave_AES_128"], enc.components["IV_16B"]
    ciphertext = bytearray(enc.outputs["texto_cifrado"])

    # Eve voltea un byte del PRIMER bloque (no el ultimo, para no romper el relleno PKCS7
    # y que el "ataque" pase completamente desapercibido para la verificacion de Bob).
    idx = 3
    ciphertext[idx] ^= 0xFF
    dec = symmetric.aes_cbc_decrypt(bytes(ciphertext), key, iv)

    resumen = (
        "Escenario: Cifrado SIN autenticacion (AES-CBC)\n"
        f"Mensaje original            : {mensaje!r}\n"
        f"Bob 'descifra' sin error?   : {'SI (accepted=True)' if dec.accepted else 'NO'}\n"
        f"Mensaje que Bob obtiene     : {dec.outputs.get('mensaje_recuperado')!r}\n"
        "Aprendizaje: el cifrado por si solo NO garantiza deteccion de modificaciones. Bob no recibe "
        "ningun error ni alerta; simplemente obtiene datos distintos a los que Alice envio, y los "
        "trata como legitimos a menos que el mensaje tenga ademas un mecanismo de integridad."
    )
    return {"resumen": resumen, "accepted": dec.accepted,
             "original": mensaje, "recuperado": dec.outputs.get("mensaje_recuperado")}


# --------------------------------------------------------- 4. Cifrado autenticado --
def escenario_cifrado_autenticado(mensaje: bytes = b"Transferir 100 pesos a Bob, cuenta 001") -> dict:
    enc = symmetric.aes_gcm_encrypt(mensaje, associated_data=b"cuenta:001")
    key, nonce, tag, aad = (enc.components["llave_256bits"], enc.components["nonce_96bits"],
                              enc.components["etiqueta_autenticacion_128bits"], mensaje and b"cuenta:001")
    ciphertext = bytearray(enc.outputs["texto_cifrado"])
    ciphertext[0] ^= 0xFF  # Eve voltea un solo byte del cifrado

    dec = symmetric.aes_gcm_decrypt(bytes(ciphertext), tag, key, nonce, associated_data=aad)

    resumen = (
        "Escenario: Cifrado AUTENTICADO (AES-GCM) con el mismo tipo de manipulacion\n"
        f"Mensaje original          : {mensaje!r}\n"
        f"Bob acepta el mensaje?    : {'SI' if dec.accepted else 'NO -> RECHAZADO'}\n"
        f"Detalle                   : {dec.notes}\n"
        "Aprendizaje: la verificacion DEBE fallar (y falla) ante cualquier bit alterado del cifrado, "
        "del nonce o de los datos asociados. A diferencia de CBC solo, GCM detecta la manipulacion "
        "y Bob rechaza el mensaje completo en vez de usar datos corruptos."
    )
    return {"resumen": resumen, "accepted": dec.accepted}


# ------------------------------------------------------------------- 5. HMAC/CMAC --
def escenario_mac_sin_llave(mensaje: bytes = b"Orden de compra #4521: 10 unidades") -> dict:
    signed = mac.hmac_sha256_sign(mensaje)
    key = signed.components["llave_HMAC"]
    tag = signed.outputs["etiqueta"]

    mensaje_alterado = mensaje.replace(b"10", b"99")  # Eve NO conoce la llave
    verif_alterado = mac.hmac_sha256_verify(mensaje_alterado, tag, key)
    verif_original = mac.hmac_sha256_verify(mensaje, tag, key)

    resumen = (
        "Escenario: HMAC/CMAC - Eve modifica el mensaje SIN conocer la llave\n"
        f"Mensaje original  : {mensaje!r}  -> verificacion: {'ACEPTADO' if verif_original.accepted else 'RECHAZADO'}\n"
        f"Mensaje alterado  : {mensaje_alterado!r}  -> verificacion: "
        f"{'ACEPTADO' if verif_alterado.accepted else 'RECHAZADO'}\n"
        "Aprendizaje: sin la llave, Eve no puede recalcular una etiqueta valida para el mensaje "
        "modificado; la etiqueta original deja de ser valida y Bob rechaza el mensaje."
    )
    return {"resumen": resumen, "accepted_alterado": verif_alterado.accepted}


# --------------------------------------------------------------- 6. Firma digital --
def escenario_firma_digital(mensaje: bytes = b"Autorizo el pago de la factura #778") -> dict:
    priv, pub = asymmetric.ecdsa_generate_keypair()
    firmado = asymmetric.ecdsa_sign(mensaje, priv)
    firma = firmado.outputs["firma"]

    mensaje_alterado = mensaje.replace(b"778", b"779")
    verif_alterado = asymmetric.ecdsa_verify(mensaje_alterado, firma, pub)
    verif_original = asymmetric.ecdsa_verify(mensaje, firma, pub)

    resumen = (
        "Escenario: Firma digital - se modifica un mensaje firmado\n"
        f"Verificacion con mensaje original : {'ACEPTADA' if verif_original.accepted else 'RECHAZADA'}\n"
        f"Verificacion con mensaje alterado : {'ACEPTADA' if verif_alterado.accepted else 'RECHAZADA'}\n"
        "Aprendizaje: la firma deja de verificarse ante CUALQUIER cambio en el mensaje, incluso sin "
        "conocer la llave privada de Alice; esto se debe a que la firma cubre criptograficamente "
        "el contenido completo (via su huella hash)."
    )
    return {"resumen": resumen, "accepted_alterado": verif_alterado.accepted}


# --------------------------------------------- 7. Acuerdo de llaves sin autenticar --
def escenario_mitm_intercambio_llaves() -> dict:
    """Simula un Diffie-Hellman/ECDH SIN AUTENTICAR donde Eve, en medio del canal,
    sustituye las llaves publicas de Alice y de Bob por las suyas propias."""
    alice_priv, alice_pub = asymmetric.ecdh_generate_keypair()
    bob_priv, bob_pub = asymmetric.ecdh_generate_keypair()
    eve_priv_A, eve_pub_A = asymmetric.ecdh_generate_keypair()  # llave que Eve usa frente a Alice
    eve_priv_B, eve_pub_B = asymmetric.ecdh_generate_keypair()  # llave que Eve usa frente a Bob

    # Alice cree que envia su llave publica a Bob, pero Eve la intercepta y envia la SUYA a Bob.
    # Bob cree que envia su llave publica a Alice, pero Eve la intercepta y envia la SUYA a Alice.
    secreto_alice_cree_compartir_con_bob = asymmetric.ecdh_derive_shared(alice_priv, eve_pub_B, "Alice<->'Bob'")
    secreto_bob_cree_compartir_con_alice = asymmetric.ecdh_derive_shared(bob_priv, eve_pub_A, "Bob<->'Alice'")
    secreto_eve_con_alice = asymmetric.ecdh_derive_shared(eve_priv_B, alice_pub, "Eve<->Alice")
    secreto_eve_con_bob = asymmetric.ecdh_derive_shared(eve_priv_A, bob_pub, "Eve<->Bob")

    llave_alice = secreto_alice_cree_compartir_con_bob.outputs["llave_de_sesion_derivada"]
    llave_eve_con_alice = secreto_eve_con_alice.outputs["llave_de_sesion_derivada"]
    llave_bob = secreto_bob_cree_compartir_con_alice.outputs["llave_de_sesion_derivada"]
    llave_eve_con_bob = secreto_eve_con_bob.outputs["llave_de_sesion_derivada"]

    coincide_con_alice = llave_alice == llave_eve_con_alice
    coincide_con_bob = llave_bob == llave_eve_con_bob
    alice_y_bob_comparten_llave = llave_alice == llave_bob

    resumen = (
        "Escenario: Acuerdo de llaves (ECDH) SIN autenticacion, con Eve sustituyendo valores publicos\n"
        f"Llave de Alice == llave de Bob (lo que ambos CREEN compartir)?  {alice_y_bob_comparten_llave}\n"
        f"Llave de Alice == llave que Eve establecio con Alice?            {coincide_con_alice}\n"
        f"Llave de Bob   == llave que Eve establecio con Bob?              {coincide_con_bob}\n"
        "Aprendizaje: Alice y Bob NUNCA llegan a compartir la misma llave entre ellos; cada uno "
        "establece, sin saberlo, una llave DISTINTA con Eve. Eve puede descifrar, leer, re-cifrar y "
        "reenviar todo el trafico sin que ninguno lo note. Un acuerdo de llaves necesita autenticar "
        "a los participantes (firmar las llaves publicas, o usar certificados/PKI) para impedir esto."
    )
    return {"resumen": resumen, "mitm_exitoso": coincide_con_alice and coincide_con_bob
             and not alice_y_bob_comparten_llave}


# ------------------------------------------------------------ 8. Repeticion de mensajes --
def escenario_repeticion_mensajes() -> dict:
    """Un mensaje AUTENTICADO (HMAC) sigue siendo vulnerable a REPETICION si el
    receptor no lleva un control de mensajes ya vistos (nonce/contador/timestamp)."""
    mensaje = b"Transferir 500 pesos de Alice a Bob"
    firmado = mac.hmac_sha256_sign(mensaje)
    key, tag = firmado.components["llave_HMAC"], firmado.outputs["etiqueta"]

    ch = Channel()
    ch.alice_send({"mensaje": mensaje, "etiqueta": tag}, detalle="Alice autoriza UNA transferencia")

    # Bob procesa el mensaje la primera vez: legitimo.
    primera_vez = mac.hmac_sha256_verify(mensaje, tag, key)

    # Eve simplemente reenvia (replay) el mismo mensaje capturado, intacto y con etiqueta valida.
    repetido = ch.eve_replay("Eve reenvia la misma transferencia ya autorizada")
    segunda_vez = mac.hmac_sha256_verify(repetido["mensaje"], repetido["etiqueta"], key)

    # Receptor SIN control de repeticion: acepta ambas (aunque la etiqueta sea criptograficamente valida)
    receptor_vulnerable_acepta_ambas = primera_vez.accepted and segunda_vez.accepted

    # Receptor CON control de repeticion (numero de secuencia visto una sola vez)
    vistos = set()
    def receptor_con_control(msg_id):
        if msg_id in vistos:
            return False
        vistos.add(msg_id)
        return True
    ids_simulados = [1]  # el mismo mensaje llega "dos veces" con el mismo identificador
    primero_ok = receptor_con_control(ids_simulados[0])
    segundo_ok = receptor_con_control(ids_simulados[0])

    resumen = (
        "Escenario: Repeticion de mensajes (replay) sobre un mensaje autenticado con HMAC\n"
        f"Etiqueta HMAC del mensaje reenviado sigue siendo valida? "
        f"{'SI' if segunda_vez.accepted else 'NO'}\n"
        f"Receptor SIN control de repeticion -> acepta la transferencia repetida? "
        f"{receptor_vulnerable_acepta_ambas}\n"
        f"Receptor CON control (numero de secuencia / nonce ya visto) -> 1ra vez: {primero_ok}, "
        f"2da vez (repetida): {segundo_ok}\n"
        "Aprendizaje: la autenticacion por si sola (HMAC, CMAC, firma) prueba que el mensaje es "
        "genuino y no fue alterado, pero NO dice nada sobre si ya se proceso antes. Se necesitan "
        "controles adicionales (numeros de secuencia, nonces de un solo uso, marcas de tiempo con "
        "ventana de validez) para impedir que un mensaje valido capturado se reenvie con exito."
    )
    return {"resumen": resumen, "vulnerable_sin_control": receptor_vulnerable_acepta_ambas,
             "protegido_con_control": primero_ok and not segundo_ok}


# ------------------------------------------------------------------------- 9. PKI --
def escenario_pki_ca_no_confiable() -> dict:
    ca_confiable_priv, ca_confiable_cert = pki.build_ca("CA Confiable de la Universidad")
    ca_atacante_priv, ca_atacante_cert = pki.build_ca("CA del Atacante (no confiable)")  # Eve controla esta CA

    bob_priv, bob_pub = asymmetric.ecdsa_generate_keypair()

    # Caso legitimo: certificado de Bob emitido por la CA confiable
    cert_legitimo = pki.issue_certificate(ca_confiable_priv, ca_confiable_cert, "bob@servidor.edu", bob_pub)
    verif_legitimo = pki.verify_certificate(cert_legitimo.outputs["certificado"], [ca_confiable_cert])

    # Caso de ataque: Eve emite un certificado para "bob@servidor.edu" usando SU PROPIA CA no confiable
    cert_falso = pki.issue_certificate(ca_atacante_priv, ca_atacante_cert, "bob@servidor.edu", bob_pub)
    verif_falso = pki.verify_certificate(cert_falso.outputs["certificado"], [ca_confiable_cert])  # Bob solo confia en la CA real

    resumen = (
        "Escenario: PKI - se presenta un certificado de una CA NO confiable\n"
        f"Certificado emitido por la CA confiable  -> Bob lo acepta? {verif_legitimo.accepted}\n"
        f"Certificado emitido por la CA del atacante (mismo 'sujeto': bob@servidor.edu) "
        f"-> Bob lo acepta? {verif_falso.accepted}\n"
        f"Motivo del rechazo: {verif_falso.notes}\n"
        "Aprendizaje: aunque el certificado falso tenga el mismo 'nombre' de sujeto y una firma "
        "VALIDA (valida respecto a la CA del atacante), el receptor debe rechazarlo porque esa CA "
        "no esta en su almacen de confianza. La seguridad de la PKI depende por completo de que "
        "lista de CAs decide confiar cada receptor."
    )
    return {"resumen": resumen, "legitimo_aceptado": verif_legitimo.accepted,
             "falso_rechazado": not verif_falso.accepted}


def run_all() -> str:
    funcs = [
        escenario_contrasena_debil,
        escenario_derivacion_contrasenas,
        escenario_cifrado_sin_autenticacion,
        escenario_cifrado_autenticado,
        escenario_mac_sin_llave,
        escenario_firma_digital,
        escenario_mitm_intercambio_llaves,
        escenario_repeticion_mensajes,
        escenario_pki_ca_no_confiable,
    ]
    out = []
    for f in funcs:
        r = f()
        out.append(r["resumen"])
        out.append("-" * 90)
    return "\n".join(out)
