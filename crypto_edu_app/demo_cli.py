# -*- coding: utf-8 -*-
"""
demo_cli.py
-----------
Corre TODOS los mecanismos del laboratorio (sin necesidad de pantalla/GUI) y
las 9 demostraciones de ataque, imprimiendo el informe tecnico completo:
entradas, componentes, info. secreta vs publica, salidas, propiedad
proporcionada, recursos consumidos y condiciones de uso de cada uno.

Util para:
  - Generar evidencia de "operaciones correctas y pruebas con datos modificados".
  - Generar evidencia de "al menos un ataque de diccionario y simulaciones de manipulacion".
  - Correrlo en un servidor/CI sin entorno grafico (a diferencia de gui/app.py).

Uso:
    python3 demo_cli.py            # corre todo e imprime en pantalla
    python3 demo_cli.py > reporte_evidencias.txt   # guarda la evidencia en un archivo
"""
import os

from core import hashing, symmetric, mac, kdf, asymmetric, pki
from attacks import demos


def seccion(titulo):
    print("\n" + "#" * 100)
    print("#  " + titulo)
    print("#" * 100)


def main():
    mensaje = b"Transferir 100 pesos a Bob, cuenta 001"
    contrasena = b"P@ssw0rd!"

    seccion("1. CIFRADOS SIN USO DE LLAVES")
    print(hashing.sha256_hash(mensaje).pretty())
    print()
    print(hashing.shake_xof(mensaje, 32).pretty())

    seccion("2. CIFRADOS SIMETRICOS")
    enc = symmetric.aes_cbc_encrypt(mensaje)
    print(enc.pretty())
    print()
    print(symmetric.aes_cbc_decrypt(enc.outputs["texto_cifrado"], enc.components["llave_AES_128"],
                                     enc.components["IV_16B"]).pretty())

    enc2 = symmetric.chacha20_encrypt(mensaje)
    print()
    print(enc2.pretty())
    print()
    print(symmetric.chacha20_decrypt(enc2.outputs["texto_cifrado"], enc2.components["llave_256bits"],
                                      enc2.components["nonce_128bits(incluye_contador)"]).pretty())

    enc3 = symmetric.aes_gcm_encrypt(mensaje, associated_data=b"cuenta:001")
    print()
    print(enc3.pretty())
    print()
    print(symmetric.aes_gcm_decrypt(enc3.outputs["texto_cifrado"], enc3.outputs["etiqueta"],
                                     enc3.components["llave_256bits"], enc3.components["nonce_96bits"],
                                     b"cuenta:001").pretty())

    m1 = mac.hmac_sha256_sign(mensaje)
    print()
    print(m1.pretty())
    print()
    print(mac.hmac_sha256_verify(mensaje, m1.outputs["etiqueta"], m1.components["llave_HMAC"]).pretty())

    m2 = mac.cmac_aes_sign(mensaje)
    print()
    print(m2.pretty())
    print()
    print(mac.cmac_aes_verify(mensaje, m2.outputs["etiqueta"], m2.components["llave_AES_128"]).pretty())

    print()
    print(kdf.pbkdf2_derive(contrasena).pretty())
    print()
    print(kdf.scrypt_derive(contrasena).pretty())
    print()
    print(kdf.hkdf_derive(os.urandom(32)).pretty())

    seccion("3. CIFRADOS ASIMETRICOS")
    bob_priv, bob_pub = asymmetric.rsa_generate_keypair()
    enc4 = asymmetric.rsa_oaep_encrypt(mensaje, bob_pub)
    print(enc4.pretty())
    print()
    print(asymmetric.rsa_oaep_decrypt(enc4.outputs["texto_cifrado"], bob_priv).pretty())

    alice_priv_sig, alice_pub_sig = asymmetric.ecdsa_generate_keypair()
    firma = asymmetric.ecdsa_sign(mensaje, alice_priv_sig)
    print()
    print(firma.pretty())
    print()
    print(asymmetric.ecdsa_verify(mensaje, firma.outputs["firma"], alice_pub_sig).pretty())

    a_priv, a_pub = asymmetric.ecdh_generate_keypair()
    b_priv, b_pub = asymmetric.ecdh_generate_keypair()
    print()
    print(asymmetric.ecdh_derive_shared(a_priv, b_pub, "Alice").pretty())
    print()
    print(asymmetric.ecdh_derive_shared(b_priv, a_pub, "Bob").pretty())

    ca_priv, ca_cert = pki.build_ca()
    bob_pki_priv, bob_pki_pub = asymmetric.ecdsa_generate_keypair()
    cert_r = pki.issue_certificate(ca_priv, ca_cert, "bob@laboratorio.edu", bob_pki_pub)
    print()
    print(cert_r.pretty())
    print()
    print(pki.verify_certificate(cert_r.outputs["certificado"], [ca_cert]).pretty())

    seccion("4. LAS NUEVE DEMOSTRACIONES DE ATAQUE / MANIPULACION (incluye ataque de diccionario)")
    print(demos.run_all())

    seccion("FIN DEL REPORTE")
    print("Para la interfaz interactiva con los paneles de Alice, Bob y Eve, ejecutar:  python3 main.py")


if __name__ == "__main__":
    main()
