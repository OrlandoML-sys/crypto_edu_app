# Tabla de mecanismos, componentes y propiedades

Generada a partir de lo que cada funcion de `core/` reporta realmente en su
`OperationResult` (ver `core/common.py`). "Secreto" = nunca debe viajar por
el canal / nunca debe llegar a Eve. "Publico" = puede viajar por el canal.

| # | Mecanismo | Entradas | Componentes criptograficos | Secreto (NO viaja) | Publico (SI viaja) | Salidas | Propiedad proporcionada | Condiciones de uso clave |
|---|-----------|----------|------------------------------|----------------------|------------------------|---------|---------------------------|-----------------------------|
| 1.1 | Hash (SHA-256) | mensaje | — (sin llave) | — | mensaje, huella | huella (32 B) | Integridad (si el hash llega por canal confiable) | No usar sola para contrasenas; es demasiado rapida |
| 1.2 | Esponja / XOF (SHAKE-256) | mensaje, longitud pedida | — (sin llave) | — | mensaje, salida XOF | salida de longitud variable | Integridad / huella extensible | Pedir >= 32 B de salida para 256 bits de seguridad |
| 2.1 | AES-128-CBC | mensaje | llave (16 B), IV (16 B), relleno PKCS7 | llave | IV, texto cifrado | texto cifrado | Confidencialidad UNICAMENTE | IV aleatorio y nunca repetido con la misma llave; combinar con MAC para integridad |
| 2.2 | ChaCha20 (flujo) | mensaje | llave (32 B), nonce (16 B) | llave | nonce, texto cifrado | texto cifrado | Confidencialidad UNICAMENTE | Par (llave,nonce) nunca repetido; en la practica se usa con Poly1305 |
| 2.extra | AES-256-GCM (AEAD) | mensaje, AAD | llave (32 B), nonce (12 B), etiqueta (16 B) | llave | nonce, texto cifrado, etiqueta, AAD | texto cifrado + etiqueta | Confidencialidad + Integridad + Autenticacion | Nonce de 12 B jamas repetido con la misma llave |
| 2.3a | HMAC-SHA256 | mensaje | llave (32 B), etiqueta (32 B) | llave | mensaje, etiqueta | etiqueta | Integridad + Autenticacion de origen | Comparar etiquetas en tiempo constante |
| 2.3b | CMAC-AES-128 | mensaje | llave (16 B), etiqueta (16 B) | llave | mensaje, etiqueta | etiqueta | Integridad + Autenticacion de origen | Igual que HMAC; basado en cifrado por bloques en vez de hash |
| 2.4a | PBKDF2-HMAC-SHA256 | contrasena, iteraciones | sal (16 B), iteraciones | contrasena, llave derivada | sal | llave derivada | Establecimiento de llave desde contrasena | >= 600,000 iteraciones (OWASP); sal unica por usuario |
| 2.4b | Scrypt | contrasena, N/r/p | sal (16 B), N, r, p | contrasena, llave derivada | sal | llave derivada | Establecimiento de llave, costo en tiempo Y memoria | N potencia de 2; memoria ~128·N·r bytes por intento |
| 2.4c | HKDF-SHA256 | secreto ya aleatorio, info | sal, info | secreto de entrada, llave derivada | sal, info | llave(s) derivada(s) | Expansion de un secreto ya fuerte (p.ej. salida de ECDH) | NO usar sobre contrasenas humanas directamente |
| 3.1 | RSA-2048-OAEP | mensaje | llave publica/privada RSA | llave privada de Bob | llave publica, texto cifrado | texto cifrado | Confidencialidad, sin secreto previo compartido | Solo mensajes pequenos (~190 B); usar cifrado hibrido para datos largos |
| 3.2 | Firma ECDSA P-256 | mensaje | llave publica/privada, firma | llave privada de Alice | mensaje, firma, llave publica | firma | Autenticacion + Integridad + No-repudio | El valor aleatorio interno 'k' nunca debe reutilizarse |
| 3.3 | Intercambio ECDH | — | llaves publicas/privadas efimeras | llave privada, secreto compartido, llave de sesion | llave publica efimera | llave de sesion derivada | Establecimiento de llave sin transmitirla | Sin autenticar es vulnerable a MITM (ver demo 7) |
| 3.4 | PKI (certificados X.509) | identidad del sujeto | certificado, llave publica/privada de la CA | llave privada de la CA | certificado | certificado firmado | Autenticacion de identidad | Solo confiar en certificados de CAs del almacen de confianza propio |

**Recursos computacionales**: cada mecanismo, al ejecutarse en `core/`, reporta
`tiempo_ejecucion_ms`, `tamano_entrada_bytes`, `tamano_salida_bytes` y
`memoria_pico_python_bytes` (ver clase `Measure` en `core/common.py`). El
reporte completo con numeros reales de una corrida se genera con:

```bash
python3 demo_cli.py > reporte_evidencias.txt
```

**Limitacion de la medicion de memoria (obligatorio declararla):** la memoria
se mide con `tracemalloc`, que solo contabiliza asignaciones hechas por
objetos de Python. La mayor parte del trabajo criptografico real ocurre
dentro de OpenSSL/libcrypto (codigo nativo en C, usado por el paquete
`cryptography`), cuyas asignaciones de memoria **no** quedan registradas por
`tracemalloc`. Por lo tanto los valores de memoria reportados deben
interpretarse como una cota inferior/aproximacion, nunca como el consumo
real total del proceso.
