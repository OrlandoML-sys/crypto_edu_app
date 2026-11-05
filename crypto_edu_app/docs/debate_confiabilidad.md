# Debate: ¿cuáles mecanismos pueden ser vulnerables y cuáles son más confiables?

Esta discusión se basa directamente en los resultados obtenidos al correr
`python3 demo_cli.py` (los 9 escenarios de `attacks/demos.py`). La conclusión
central del laboratorio es que **"vulnerable" casi nunca significa que el
algoritmo matemático esté roto; casi siempre significa que se usó fuera de
las condiciones para las que fue diseñado, o que se le pidió una propiedad
que nunca prometió dar.**

## 1. Mecanismos que NO pueden romperse con las herramientas de este laboratorio

Con los tamaños de llave usados (AES-128/256, RSA-2048, curva P-256, SHA-256),
ningún ataque de fuerza bruta directo contra el algoritmo es factible con
recursos razonables; esto está respaldado por el consenso criptográfico
actual (NIST SP 800-57), no es una opinión del proyecto. Lo que SÍ logramos
romper en las demostraciones fue siempre una **mala combinación o un mal
uso** del algoritmo, nunca el algoritmo en sí:

- **AES-CBC / ChaCha20 (escenario 3):** no se "rompió" el cifrado — Alice y
  Bob nunca perdieron la confidencialidad del mensaje original. Lo que se
  demostró es que, al no tener un mecanismo de integridad, el atacante puede
  alterar el cifrado y el receptor no lo nota. Esto no vuelve a AES o a
  ChaCha20 "inseguros"; vuelve **insuficiente usarlos solos** cuando también
  se necesita integridad.
- **SHA-256 (escenario 1):** tampoco se "descifró" el hash (es una función de
  un solo sentido). Lo que se automatizó fue adivinar la entrada original
  probando candidatos — viable solo porque la contraseña de prueba era débil
  y estaba en un diccionario pequeño.

## 2. Mecanismos que SÍ fueron vulnerables en algún escenario, y por qué

| Escenario | ¿Qué se rompió realmente? | ¿Es un defecto del algoritmo o de cómo se usó? |
|---|---|---|
| 1. Contraseña débil | Se adivinó la contraseña, no el hash | Uso: contraseña débil + hash sin costo (SHA-256 directo) |
| 2. Derivación de contraseñas | Nada se rompió; se mostró que Scrypt encarece el ataque frente a SHA-256 directo | Comparación de diseño, no una vulnerabilidad |
| 3. Cifrado sin autenticación | Integridad, no confidencialidad | Uso: falta de un MAC/AEAD, no un fallo de AES/ChaCha20 |
| 4. Cifrado autenticado (GCM) | Nada: el ataque fue detectado y rechazado | — (funcionó como debía) |
| 5. HMAC/CMAC | Nada: el ataque fue detectado y rechazado | — (funcionó como debía) |
| 6. Firma digital | Nada: el ataque fue detectado y rechazado | — (funcionó como debía) |
| 7. Acuerdo de llaves sin autenticar | Confidencialidad e integridad de TODA la sesión (MITM) | Diseño: ECDH puro nunca garantiza autenticación; hay que añadirla |
| 8. Repetición de mensajes | Disponibilidad/consistencia (acción repetida), no la criptografía | Uso: falta de control de repetición (nonce/contador), no un fallo de HMAC |
| 9. PKI con CA no confiable | Nada: el certificado falso fue rechazado | — (funcionó como debía), PERO depende 100% de qué CAs decide confiar cada quien |

## 3. Ranking de confiabilidad (de los mecanismos de este laboratorio, usados correctamente)

1. **AES-256-GCM / ChaCha20-Poly1305 (AEAD)** — máxima confiabilidad: dan
   confidencialidad e integridad en una sola operación, difícil de usar mal.
2. **Firmas digitales (ECDSA) + PKI** — muy confiables para autenticar
   identidad y no-repudio, pero dependen críticamente de que la llave privada
   nunca se filtre y de que el almacén de confianza esté bien curado.
3. **HMAC / CMAC** — muy confiables para integridad+autenticación cuando ya
   existe una llave compartida, pero no resuelven repetición por sí solos.
4. **Scrypt (y KDFs con costo de memoria en general)** — confiables para
   proteger contraseñas; muy superiores a un hash "pelado".
5. **PBKDF2** — confiable si se usan suficientes iteraciones, pero más barato
   de acelerar en hardware dedicado que Scrypt.
6. **ECDH sin autenticar** — el eslabón más débil del laboratorio: funciona
   perfectamente en papel, pero es trivialmente vulnerable a MITM si no se
   combina con autenticación (firmas o PKI). **Nunca debe usarse solo.**
7. **AES-CBC / ChaCha20 sin ningún MAC** — confidencialidad confiable, pero
   **no deben usarse solos** cuando la integridad importa (que es casi
   siempre). Se incluyen en el laboratorio precisamente para mostrar ese límite.
8. **SHA-256 "pelado" sobre una contraseña** — el menos confiable para ese
   caso de uso específico (proteger contraseñas); el algoritmo es excelente
   para lo que SÍ fue diseñado (huellas de integridad).

## 4. Conclusión del debate

Ningún mecanismo de este laboratorio es "inseguro" en abstracto. La
confiabilidad depende de tres cosas que el laboratorio aísla una por una:
**(a)** elegir el mecanismo correcto para la propiedad que se necesita
(confidencialidad ≠ integridad ≠ autenticación ≠ no-repudio), **(b)**
respetar sus condiciones de uso (tamaños de llave, no repetir nonces,
suficientes iteraciones/costo), y **(c)** complementar lo que el mecanismo,
por diseño, no promete (p. ej. autenticar un intercambio de llaves, o añadir
control de repetición sobre una autenticación ya correcta).
