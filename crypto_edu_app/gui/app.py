# -*- coding: utf-8 -*-
"""
gui/app.py
----------
Interfaz grafica (Tkinter) del laboratorio Alice / Bob / Eve.

Estructura visual (igual que el diagrama de la practica):

        [ Eve: observa / manipula el canal ]
   [ Alice: emisor ]  <---canal--->  [ Bob: receptor ]
        [ Log / Informe tecnico de cada operacion ]

Reglas respetadas en el codigo:
  * Lo unico que Eve puede observar/alterar por defecto es lo que esta en
    `channel.last_payload` (los campos PUBLICOS del mecanismo).
  * Las llaves secretas/privadas viven en `self.session` (equivalente a
    "ya se compartieron de forma segura antes", o "nunca salen de su dueno")
    y NUNCA se copian al canal.
  * La fuga de llaves es un boton SEPARADO y con dialogo de confirmacion
    explicito ("Escenario de laboratorio aparte").
"""
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import hashing, symmetric, mac, kdf, asymmetric, pki
from channel import Channel
from attacks import demos

MECANISMOS = [
    ("hash",        "sin_llaves", "1.1 Funcion hash criptografica (SHA-256)"),
    ("sponge",      "sin_llaves", "1.2 Construccion esponja / salida extensible (SHAKE-256)"),
    ("block",       "simetrico",  "2.1 Cifrado simetrico por bloques (AES-128-CBC)"),
    ("stream",      "simetrico",  "2.2 Cifrado por flujo (ChaCha20)"),
    ("aead",        "simetrico",  "2.extra Cifrado AUTENTICADO (AES-256-GCM)"),
    ("mac_hmac",     "simetrico",  "2.3a Codigo de autenticacion de mensajes (HMAC-SHA256)"),
    ("mac_cmac",     "simetrico",  "2.3b Codigo de autenticacion de mensajes (CMAC-AES)"),
    ("kdf_pbkdf2",   "simetrico",  "2.4a Derivacion de llaves (PBKDF2)"),
    ("kdf_scrypt",   "simetrico",  "2.4b Derivacion de llaves (Scrypt)"),
    ("kdf_hkdf",     "simetrico",  "2.4c Derivacion de llaves (HKDF)"),
    ("pke",         "asimetrico", "3.1 Cifrado de clave publica (RSA-2048-OAEP)"),
    ("sig",         "asimetrico", "3.2 Firma digital (ECDSA P-256)"),
    ("kex",         "asimetrico", "3.3 Intercambio de llaves (ECDH)"),
    ("pki",         "asimetrico", "3.4 Infraestructura de clave publica (PKI)"),
]
CATEGORIA_LABEL = {
    "sin_llaves": "Cifrados SIN uso de llaves",
    "simetrico": "Cifrados SIMETRICOS",
    "asimetrico": "Cifrados ASIMETRICOS",
}


class CryptoLabApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Laboratorio de Primitivas Criptograficas - Alice, Bob y Eve")
        self.geometry("1180x760")
        self.channel = Channel()
        self.session = {}
        self.current_alice_result = None
        self._build_menu()
        self._build_layout()
        self.regenerate_session()

    # ------------------------------------------------------------ setup --
    def _build_menu(self):
        menubar = tk.Menu(self)
        for cat_id, cat_label in CATEGORIA_LABEL.items():
            m = tk.Menu(menubar, tearoff=0)
            for mid, cat, label in MECANISMOS:
                if cat == cat_id:
                    m.add_command(label=label, command=lambda mid=mid: self.select_mechanism(mid))
            menubar.add_cascade(label=cat_label, menu=m)
        sesion_menu = tk.Menu(menubar, tearoff=0)
        sesion_menu.add_command(label="Generar nuevo material criptografico de sesion",
                                 command=self.regenerate_session)
        sesion_menu.add_command(label="Correr las 9 demostraciones de ataque (consola)",
                                 command=self.run_all_demos_popup)
        menubar.add_cascade(label="Sesion", menu=sesion_menu)
        self.config(menu=menubar)

    def _build_layout(self):
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=4)
        ttk.Label(top, text="Mecanismo activo:", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.mech_var = tk.StringVar()
        self.mech_combo = ttk.Combobox(top, textvariable=self.mech_var, state="readonly", width=70,
                                        values=[label for _, _, label in MECANISMOS])
        self.mech_combo.pack(side="left", padx=6)
        self.mech_combo.bind("<<ComboboxSelected>>", self._on_combo_select)
        self.mech_combo.current(0)
        self.mech_id = MECANISMOS[0][0]

        # ---- Eve (arriba, centro) ----
        eve_frame = ttk.LabelFrame(self, text="🕵  EVE  —  observadora / atacante del canal")
        eve_frame.pack(fill="x", padx=8, pady=4)
        self.eve_view = scrolledtext.ScrolledText(eve_frame, height=5, wrap="word", bg="#fff4e6", fg="black", insertbackground="black")
        self.eve_view.pack(fill="x", padx=4, pady=4)
        eve_btns = ttk.Frame(eve_frame)
        eve_btns.pack(fill="x", padx=4, pady=2)
        ttk.Button(eve_btns, text="Voltear un byte del dato cifrado/firma",
                   command=self.eve_bitflip).pack(side="left", padx=2)
        ttk.Button(eve_btns, text="Sustituir llave/valor publico",
                   command=self.eve_substitute).pack(side="left", padx=2)
        ttk.Button(eve_btns, text="Reenviar mensaje (replay)",
                   command=self.eve_replay).pack(side="left", padx=2)
        ttk.Button(eve_btns, text="⚠ Escenario separado: FUGA de llave secreta/privada",
                   command=self.eve_leak_key).pack(side="left", padx=12)

        # ---- Alice / Bob (fila central) ----
        mid = ttk.Frame(self)
        mid.pack(fill="both", expand=True, padx=8, pady=4)

        alice_frame = ttk.LabelFrame(mid, text="🔵  ALICE — emisora")
        alice_frame.pack(side="left", fill="both", expand=True, padx=(0, 4))
        ttk.Label(alice_frame, text="Mensaje / dato de entrada:").pack(anchor="w", padx=4)
        self.alice_msg = tk.Text(alice_frame, height=3, wrap="word", bg="white", fg="black", insertbackground="black")
        self.alice_msg.insert("1.0", "Transferir 100 pesos a Bob, cuenta 001")
        self.alice_msg.pack(fill="x", padx=4, pady=2)
        self.alice_pw_label = ttk.Label(alice_frame, text="Contrasena (solo para KDF):")
        self.alice_pw_label.pack(anchor="w", padx=4)
        self.alice_pw = tk.Entry(alice_frame, show="*", bg="white", fg="black", insertbackground="black")
        self.alice_pw.insert(0, "P@ssw0rd!")
        self.alice_pw.pack(fill="x", padx=4, pady=2)
        ttk.Button(alice_frame, text="▶ Ejecutar mecanismo y enviar a Bob",
                   command=self.alice_run).pack(fill="x", padx=4, pady=4)
        ttk.Label(alice_frame, text="Lo que Alice ENVIA (publico):").pack(anchor="w", padx=4)
        self.alice_public_view = scrolledtext.ScrolledText(alice_frame, height=6, wrap="word", bg="#e8f4ff", fg="black", insertbackground="black")
        self.alice_public_view.pack(fill="both", expand=True, padx=4, pady=2)
        ttk.Label(alice_frame, text="Lo que Alice GUARDA en secreto (nunca viaja):").pack(anchor="w", padx=4)
        self.alice_secret_view = scrolledtext.ScrolledText(alice_frame, height=4, wrap="word", bg="#ffe8e8", fg="black", insertbackground="black")
        self.alice_secret_view.pack(fill="x", padx=4, pady=2)

        bob_frame = ttk.LabelFrame(mid, text="🟢  BOB — receptor")
        bob_frame.pack(side="left", fill="both", expand=True, padx=(4, 0))
        ttk.Label(bob_frame, text="Lo que Bob RECIBE del canal:").pack(anchor="w", padx=4)
        self.bob_received_view = scrolledtext.ScrolledText(bob_frame, height=6, wrap="word", bg="#e8f4ff", fg="black", insertbackground="black")
        self.bob_received_view.pack(fill="both", expand=True, padx=4, pady=2)
        ttk.Button(bob_frame, text="▶ Verificar / Descifrar",
                   command=self.bob_run).pack(fill="x", padx=4, pady=4)
        self.bob_result_label = ttk.Label(bob_frame, text="Resultado: —", font=("Segoe UI", 11, "bold"))
        self.bob_result_label.pack(anchor="w", padx=4)
        ttk.Label(bob_frame, text="Explicacion / salida:").pack(anchor="w", padx=4)
        self.bob_result_view = scrolledtext.ScrolledText(bob_frame, height=6, wrap="word", bg="#eaffea", fg="black", insertbackground="black")
        self.bob_result_view.pack(fill="both", expand=True, padx=4, pady=2)

        # ---- Log inferior ----
        log_frame = ttk.LabelFrame(self, text="📋 Informe tecnico de la operacion "
                                                "(entradas, componentes, propiedad, recursos, condiciones de uso)")
        log_frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.log_view = scrolledtext.ScrolledText(log_frame, height=10, wrap="word", bg="#f5f5f5", fg="black", insertbackground="black")
        self.log_view.pack(fill="both", expand=True, padx=4, pady=4)

    # --------------------------------------------------------- sesion --
    def regenerate_session(self):
        """Genera TODO el material criptografico que se asume 'ya distribuido de forma
        segura' antes de que arranque la demostracion (llaves simetricas compartidas,
        pares de llaves asimetricas de cada participante, CAs de la PKI...).
        Nada de esto se copia jamas al canal / a la vista de Eve."""
        s = self.session
        s["sym_key_block"] = os.urandom(16)
        s["sym_key_stream"] = os.urandom(32)
        s["sym_key_aead"] = os.urandom(32)
        s["mac_key_hmac"] = os.urandom(32)
        s["mac_key_cmac"] = os.urandom(16)
        s["bob_rsa_priv"], s["bob_rsa_pub"] = asymmetric.rsa_generate_keypair()
        s["alice_ecdsa_priv"], s["alice_ecdsa_pub"] = asymmetric.ecdsa_generate_keypair()
        s["alice_ecdh_priv"], s["alice_ecdh_pub"] = asymmetric.ecdh_generate_keypair()
        s["bob_ecdh_priv"], s["bob_ecdh_pub"] = asymmetric.ecdh_generate_keypair()
        s["ca_confiable_priv"], s["ca_confiable_cert"] = pki.build_ca("CA Confiable de la Universidad")
        s["ca_atacante_priv"], s["ca_atacante_cert"] = pki.build_ca("CA del Atacante (no confiable)")
        s["use_rogue_ca"] = False
        self._log("Se genero nuevo material criptografico de sesion (llaves simetricas compartidas, "
                   "pares de llaves asimetricas, y dos CAs: una confiable y una 'del atacante' para la demo de PKI). "
                   "Ninguna llave privada/secreta se copio al canal.")

    # --------------------------------------------------------- utilidades --
    def _log(self, text):
        self.log_view.insert("end", text + "\n" + ("=" * 100) + "\n")
        self.log_view.see("end")

    def _set_text(self, widget, text):
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _fmt(self, d):
        if not d:
            return "(vacio)"
        lines = []
        for k, v in d.items():
            s = v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
            if len(s) > 90:
                s = s[:90] + f"...(+{len(s)-90})"
            lines.append(f"  {k}: {s}")
        return "\n".join(lines)

    def select_mechanism(self, mid):
        for i, (m, _, label) in enumerate(MECANISMOS):
            if m == mid:
                self.mech_combo.current(i)
                self.mech_id = mid
                self._refresh_mech_ui()
                return

    def _on_combo_select(self, event):
        idx = self.mech_combo.current()
        self.mech_id = MECANISMOS[idx][0]
        self._refresh_mech_ui()

    def _refresh_mech_ui(self):
        is_kdf = self.mech_id.startswith("kdf_")
        self.alice_pw_label.config(text="Contrasena (" + ("REQUERIDA para KDF)" if is_kdf else "no se usa en este mecanismo)"))
        self.alice_pw.config(state="normal" if is_kdf else "disabled")
        for w in (self.alice_public_view, self.alice_secret_view, self.bob_received_view, self.bob_result_view):
            self._set_text(w, "")
        self.bob_result_label.config(text="Resultado: —")

    # ------------------------------------------------------------- Alice --
    def alice_run(self):
        mid = self.mech_id
        msg = self.alice_msg.get("1.0", "end").strip().encode()
        s = self.session
        try:
            if mid == "hash":
                r = hashing.sha256_hash(msg)
                self.channel.alice_send({"mensaje": msg, "huella_sha256": r.outputs["huella_sha256"]},
                                         "Alice envia el mensaje y su huella SHA-256")
            elif mid == "sponge":
                r = hashing.shake_xof(msg, 32)
                self.channel.alice_send({"mensaje": msg, "salida_xof": r.outputs["salida_xof"]},
                                         "Alice envia el mensaje y la salida de la esponja (SHAKE-256)")
            elif mid == "block":
                r = symmetric.aes_cbc_encrypt(msg, key=s["sym_key_block"])
                self.channel.alice_send({"IV": r.components["IV_16B"], "texto_cifrado": r.outputs["texto_cifrado"]},
                                         "Alice cifra con AES-CBC usando la llave YA compartida con Bob")
            elif mid == "stream":
                r = symmetric.chacha20_encrypt(msg, key=s["sym_key_stream"])
                self.channel.alice_send({"nonce": r.components["nonce_128bits(incluye_contador)"],
                                          "texto_cifrado": r.outputs["texto_cifrado"]},
                                         "Alice cifra con ChaCha20 usando la llave YA compartida con Bob")
            elif mid == "aead":
                r = symmetric.aes_gcm_encrypt(msg, key=s["sym_key_aead"], associated_data=b"canal-demo")
                self.channel.alice_send({"nonce": r.components["nonce_96bits"],
                                          "texto_cifrado": r.outputs["texto_cifrado"],
                                          "etiqueta": r.outputs["etiqueta"],
                                          "AAD": b"canal-demo"},
                                         "Alice cifra y autentica con AES-GCM")
            elif mid == "mac_hmac":
                r = mac.hmac_sha256_sign(msg, key=s["mac_key_hmac"])
                self.channel.alice_send({"mensaje": msg, "etiqueta": r.outputs["etiqueta"]},
                                         "Alice envia el mensaje en claro + etiqueta HMAC")
            elif mid == "mac_cmac":
                r = mac.cmac_aes_sign(msg, key=s["mac_key_cmac"])
                self.channel.alice_send({"mensaje": msg, "etiqueta": r.outputs["etiqueta"]},
                                         "Alice envia el mensaje en claro + etiqueta CMAC")
            elif mid == "kdf_pbkdf2":
                pw = self.alice_pw.get().encode()
                r = kdf.pbkdf2_derive(pw)
                self.channel.alice_send({"sal": r.components["sal_16B"]},
                                         "Alice (el sistema) solo publica la SAL; la contrasena y la llave derivada nunca viajan")
            elif mid == "kdf_scrypt":
                pw = self.alice_pw.get().encode()
                r = kdf.scrypt_derive(pw)
                self.channel.alice_send({"sal": r.components["sal_16B"]},
                                         "Alice (el sistema) solo publica la SAL; la contrasena y la llave derivada nunca viajan")
            elif mid == "kdf_hkdf":
                pw = self.alice_pw.get().encode()
                r = kdf.hkdf_derive(pw)  # con fines didacticos reusamos el campo contrasena como 'secreto de entrada'
                self.channel.alice_send({"sal": r.components["sal"], "info": r.components["info"]},
                                         "Alice publica sal e info; el secreto de entrada y la llave derivada nunca viajan")
            elif mid == "pke":
                r = asymmetric.rsa_oaep_encrypt(msg, s["bob_rsa_pub"])
                self.channel.alice_send({"texto_cifrado": r.outputs["texto_cifrado"]},
                                         "Alice cifra con la llave PUBLICA de Bob (RSA-OAEP)")
            elif mid == "sig":
                r = asymmetric.ecdsa_sign(msg, s["alice_ecdsa_priv"])
                from cryptography.hazmat.primitives import serialization
                pub_bytes = s["alice_ecdsa_pub"].public_bytes(serialization.Encoding.DER,
                                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
                self.channel.alice_send({"mensaje": msg, "firma": r.outputs["firma"],
                                          "llave_publica_de_Alice": pub_bytes},
                                         "Alice firma el mensaje con su llave privada ECDSA")
            elif mid == "kex":
                from cryptography.hazmat.primitives import serialization
                pub_bytes = s["alice_ecdh_pub"].public_bytes(serialization.Encoding.DER,
                                                                serialization.PublicFormat.SubjectPublicKeyInfo)
                r = asymmetric.ecdh_derive_shared(s["alice_ecdh_priv"], s["bob_ecdh_pub"], "Alice")
                s["alice_session_key"] = r.outputs["llave_de_sesion_derivada"]
                self.channel.alice_send({"llave_publica_efimera_de_Alice": pub_bytes},
                                         "Alice envia SOLO su llave publica efimera (ECDH)")
            elif mid == "pki":
                ca_priv, ca_cert = ((s["ca_atacante_priv"], s["ca_atacante_cert"]) if s.get("use_rogue_ca")
                                      else (s["ca_confiable_priv"], s["ca_confiable_cert"]))
                cert_r = pki.issue_certificate(ca_priv, ca_cert, "alice@laboratorio.edu", s["alice_ecdsa_pub"])
                from cryptography.hazmat.primitives import serialization
                cert_der = cert_r.outputs["certificado"].public_bytes(serialization.Encoding.DER)
                self.channel.alice_send({"certificado_X509": cert_der},
                                         f"Alice envia su certificado (emitido por: {ca_cert.subject.rfc4514_string()})")
                r = cert_r
            else:
                return

            self.current_alice_result = r
            self._set_text(self.alice_public_view, self._fmt(self.channel.last_payload))
            self._set_text(self.alice_secret_view, self._fmt(r.secret_info))
            self._update_eve_view()
            self._log(r.pretty())
        except Exception as e:
            messagebox.showerror("Error al ejecutar", str(e))

    # --------------------------------------------------------------- Eve --
    def _update_eve_view(self):
        self._set_text(self.eve_view, "Eve observa en el canal (SOLO datos publicos):\n" +
                        self._fmt(self.channel.eve_observe()))

    def eve_bitflip(self):
        payload = self.channel.last_payload
        candidatos = [k for k, v in payload.items() if isinstance(v, (bytes, bytearray)) and len(v) > 0]
        if not candidatos:
            messagebox.showinfo("Eve", "No hay ningun dato binario en el canal para modificar todavia.")
            return
        campo = candidatos[-1]  # normalmente el texto cifrado / la firma / la etiqueta
        data = bytearray(payload[campo])
        data[0] ^= 0xFF
        self.channel.eve_tamper(campo, bytes(data), f"Eve voltea el primer byte de '{campo}'")
        self._update_eve_view()
        self._log(f"EVE (laboratorio): volteo el primer byte del campo '{campo}'.")

    def eve_substitute(self):
        payload = self.channel.last_payload
        candidatos = [k for k in payload if "llave" in k or "certificado" in k or "publica" in k]
        if not candidatos:
            messagebox.showinfo("Eve", "Este mecanismo no tiene un valor publico (llave/certificado) que sustituir.")
            return
        campo = candidatos[0]
        falso = os.urandom(32)
        self.channel.eve_tamper(campo, falso, f"Eve sustituye '{campo}' por un valor propio (simulando MITM)")
        self._update_eve_view()
        self._log(f"EVE (laboratorio): sustituyo el campo '{campo}' por un valor generado por ella misma "
                    "(simulacion de intermediario / MITM).")

    def eve_replay(self):
        if not self.channel.last_payload:
            messagebox.showinfo("Eve", "Todavia no hay nada en el canal que reenviar.")
            return
        self.channel.eve_replay()
        self._update_eve_view()
        self._log("EVE (laboratorio): reenvio EXACTAMENTE el ultimo mensaje capturado, sin modificarlo "
                   "(ataque de repeticion / replay). Si Bob no lleva control de mensajes ya vistos, lo aceptara de nuevo.")

    def eve_leak_key(self):
        resp = messagebox.askyesno(
            "⚠ Escenario separado: fuga explicita de llave",
            "Esto representa un escenario de laboratorio APARTE, donde se asume que una llave "
            "secreta/privada se filtro por una causa EXTERNA al protocolo (malware, error humano, "
            "mala configuracion...). No es algo que ocurra automaticamente ni es una debilidad del "
            "algoritmo. ¿Deseas simular este escenario y revelar la llave secreta vigente a Eve?",
        )
        if not resp:
            return
        s = self.session
        candidatos = {
            "block": ("sym_key_block", "llave AES-CBC"), "stream": ("sym_key_stream", "llave ChaCha20"),
            "aead": ("sym_key_aead", "llave AES-GCM"), "mac_hmac": ("mac_key_hmac", "llave HMAC"),
            "mac_cmac": ("mac_key_cmac", "llave CMAC"),
        }
        if self.mech_id not in candidatos:
            messagebox.showinfo("Fuga de llave", "Este mecanismo no tiene una llave secreta simetrica propia "
                                                  "para este escenario (prueba con un mecanismo simetrico).")
            return
        key_name, label = candidatos[self.mech_id]
        self.channel.escenario_fuga_de_llave(label, s[key_name])
        self._log(f"⚠ ESCENARIO EXPLICITO DE FUGA DE LLAVE: la {label} fue expuesta deliberadamente a Eve "
                    f"como ejercicio aparte. Valor: {s[key_name].hex()}\n"
                    "A partir de este punto, y SOLO en este escenario, Eve puede descifrar/falsificar "
                    "cualquier mensaje de este mecanismo igual que lo haria Bob.")
        messagebox.showwarning("Llave filtrada", f"La {label} ahora es conocida por Eve en este escenario "
                                                     "separado. Revisa el informe tecnico (panel inferior).")

    # --------------------------------------------------------------- Bob --
    def bob_run(self):
        mid = self.mech_id
        s = self.session
        received = self.channel.bob_receive()
        self._set_text(self.bob_received_view, self._fmt(received))
        if not received:
            messagebox.showinfo("Bob", "Todavia no ha llegado nada por el canal.")
            return
        try:
            if mid == "hash":
                recomputed = hashing.sha256_hash(received["mensaje"])
                ok = recomputed.outputs["huella_sha256"] == received["huella_sha256"]
                r = recomputed
                r.accepted = ok
                r.notes = "Bob recalculo la huella del mensaje recibido y la comparo con la recibida." + \
                          ("" if ok else " ¡NO coinciden! El mensaje o la huella fueron alterados.")
            elif mid == "sponge":
                recomputed = hashing.shake_xof(received["mensaje"], len(received["salida_xof"]))
                ok = recomputed.outputs["salida_xof"] == received["salida_xof"]
                r = recomputed
                r.accepted = ok
                r.notes = "Bob recalculo la salida XOF y la comparo con la recibida." + \
                          ("" if ok else " ¡NO coinciden!")
            elif mid == "block":
                r = symmetric.aes_cbc_decrypt(received["texto_cifrado"], s["sym_key_block"], received["IV"])
            elif mid == "stream":
                r = symmetric.chacha20_decrypt(received["texto_cifrado"], s["sym_key_stream"], received["nonce"])
            elif mid == "aead":
                r = symmetric.aes_gcm_decrypt(received["texto_cifrado"], received["etiqueta"],
                                               s["sym_key_aead"], received["nonce"], received.get("AAD", b""))
            elif mid == "mac_hmac":
                r = mac.hmac_sha256_verify(received["mensaje"], received["etiqueta"], s["mac_key_hmac"])
            elif mid == "mac_cmac":
                r = mac.cmac_aes_verify(received["mensaje"], received["etiqueta"], s["mac_key_cmac"])
            elif mid in ("kdf_pbkdf2", "kdf_scrypt", "kdf_hkdf"):
                messagebox.showinfo("Bob", "Las KDF son una operacion LOCAL (p. ej. del lado del servidor "
                                            "para guardar una contrasena). No hay un 'Bob' que verifique algo "
                                            "por canal en este mecanismo; revisa el panel de Alice y el informe tecnico.")
                return
            elif mid == "pke":
                r = asymmetric.rsa_oaep_decrypt(received["texto_cifrado"], s["bob_rsa_priv"])
            elif mid == "sig":
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                pub = load_der_public_key(received["llave_publica_de_Alice"])
                r = asymmetric.ecdsa_verify(received["mensaje"], received["firma"], pub)
            elif mid == "kex":
                from cryptography.hazmat.primitives.serialization import load_der_public_key
                alice_pub = load_der_public_key(received["llave_publica_efimera_de_Alice"])
                r = asymmetric.ecdh_derive_shared(s["bob_ecdh_priv"], alice_pub, "Bob")
                bob_key = r.outputs["llave_de_sesion_derivada"]
                coincide = s.get("alice_session_key") == bob_key
                r.accepted = coincide
                r.notes = ("Bob derivo su llave de sesion combinando SU llave privada con la llave publica "
                           "recibida. " + ("Coincide con la de Alice: establecieron la MISMA llave de sesion."
                           if coincide else "¡NO coincide con la de Alice! (por ejemplo, si Eve sustituyo la "
                           "llave publica en transito -> ver boton 'Sustituir llave/valor publico' de Eve)."))
            elif mid == "pki":
                from cryptography.x509 import load_der_x509_certificate
                cert = load_der_x509_certificate(received["certificado_X509"])
                r = pki.verify_certificate(cert, [s["ca_confiable_cert"]])
            else:
                return

            self._set_text(self.bob_result_view, r.pretty())
            self.bob_result_label.config(
                text=f"Resultado: {'✅ ACEPTADO' if r.accepted else '❌ RECHAZADO'}" if r.accepted is not None
                else "Resultado: (operacion sin verificacion)",
                foreground=("green" if r.accepted else "red") if r.accepted is not None else "black")
            self._log(r.pretty())
        except Exception as e:
            self.bob_result_label.config(text="Resultado: ❌ ERROR / RECHAZADO", foreground="red")
            self._set_text(self.bob_result_view, f"La operacion fallo: {e}")
            self._log(f"BOB: la operacion fallo con error controlado: {e}")

    # --------------------------------------------------------------- Menu --
    def run_all_demos_popup(self):
        win = tk.Toplevel(self)
        win.title("Las 9 demostraciones de ataque")
        win.geometry("900x650")
        txt = scrolledtext.ScrolledText(win, wrap="word", bg="white", fg="black", insertbackground="black")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", "Ejecutando las 9 demostraciones, un momento...\n")
        win.update()
        resultado = demos.run_all()
        txt.delete("1.0", "end")
        txt.insert("1.0", resultado)


def main():
    app = CryptoLabApp()
    app.mainloop()


if __name__ == "__main__":
    main()
