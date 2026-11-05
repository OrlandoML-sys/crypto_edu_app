# Laboratorio de Primitivas Criptográficas — Alice, Bob y Eve

Aplicación educativa en Python para comprender y comparar mecanismos
criptográficos **sin uso de llaves**, **simétricos** y **asimétricos**,
mediante una interfaz con tres paneles (Alice = emisora, Bob = receptor,
Eve = observadora/atacante de laboratorio).

> Materia: Ciberseguridad — práctica de primitivas criptográficas.

## 1. Contenido del menú

**Cifrados sin uso de llaves**
- Funciones hash criptográficas (SHA-256)
- Construcción esponja y salida extensible / XOF (SHAKE-256)

**Cifrados simétricos**
- Cifrado simétrico por bloques (AES-128-CBC)
- Cifrado por flujo / stream cipher (ChaCha20)
- *(incluido también)* Cifrado autenticado AES-256-GCM, para comparar contra CBC/ChaCha20 sin autenticar
- Códigos de autenticación de mensajes: HMAC-SHA256 y CMAC-AES
- Derivación de claves (KDF): PBKDF2, Scrypt, HKDF

**Cifrados asimétricos**
- Cifrado de clave pública (RSA-2048-OAEP)
- Firmas digitales (ECDSA P-256)
- Intercambio de llaves (ECDH)
- Infraestructura de clave pública / PKI (certificados X.509)

Para cada uno, el programa calcula y muestra: **entradas**, **componentes
criptográficos** (llaves, IV, nonce, sal, etiqueta, firma, certificado),
**qué es secreto vs. qué es público**, **salidas**, **propiedad
proporcionada** (confidencialidad / integridad / autenticación /
establecimiento de llaves), **recursos consumidos** (tiempo, tamaños,
memoria aproximada) y **condiciones de uso**. Ver la tabla completa en
[`docs/tabla_mecanismos.md`](docs/tabla_mecanismos.md).

## 2. Estructura del proyecto

```
crypto_edu_app/
├── main.py                  # Punto de entrada de la GUI (Alice/Bob/Eve)
├── demo_cli.py               # Corre TODO sin pantalla e imprime el reporte completo
├── channel.py                 # Canal simulado Alice<->Bob que Eve observa/manipula
├── requirements.txt
├── core/                       # Implementación de cada mecanismo (usa el paquete `cryptography`)
│   ├── common.py                  # Estructura comun OperationResult + medicion de recursos
│   ├── hashing.py                  # SHA-256, SHAKE (esponja/XOF)
│   ├── symmetric.py                 # AES-CBC, ChaCha20, AES-GCM
│   ├── mac.py                        # HMAC-SHA256, CMAC-AES
│   ├── kdf.py                         # PBKDF2, Scrypt, HKDF
│   ├── asymmetric.py                   # RSA-OAEP, ECDSA, ECDH
│   └── pki.py                           # CA, emision y verificacion de certificados X.509
├── attacks/
│   └── demos.py              # Las 9 demostraciones de ataque/manipulacion de la tabla de la practica
├── gui/
│   └── app.py                 # Interfaz Tkinter con los paneles de Alice, Bob y Eve
├── tests/
│   ├── test_gui_headless.py     # Prueba automatizada: recorre los 14 mecanismos en la GUI real
│   └── test_gui_rejection.py     # Verifica que la manipulacion SI es rechazada donde debe serlo
└── docs/
    ├── tabla_mecanismos.md         # Tabla completa exigida por la practica
    └── debate_confiabilidad.md      # Debate: que es vulnerable, que no, y ranking de confiabilidad
```

## 3. Instalación

Requiere Python 3.10+.

```bash
git clone <URL-DE-TU-REPOSITORIO>
cd crypto_edu_app
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Linux:** Tkinter no siempre viene incluido con Python; si `main.py` marca
`ModuleNotFoundError: No module named 'tkinter'`, instálalo con:

```bash
sudo apt install python3-tk      # Debian/Ubuntu
sudo dnf install python3-tkinter # Fedora
```

En Windows y macOS, Tkinter ya viene incluido con el instalador oficial de
Python, no se necesita nada adicional.

## 4. Ejecución

**Interfaz gráfica (Alice, Bob y Eve):**
```bash
python3 main.py
```
1. Elige un mecanismo en el menú superior (o en la barra de menú por categoría).
2. En el panel de **Alice**: escribe un mensaje (y una contraseña si el
   mecanismo es una KDF) y pulsa **"Ejecutar mecanismo y enviar a Bob"**.
   Verás separado lo que Alice **envía** (público) de lo que **guarda en
   secreto** (nunca viaja).
3. En el panel de **Eve** (arriba): observa lo que hay en el canal, y
   opcionalmente usa los botones de laboratorio para **voltear un byte**,
   **sustituir una llave/valor público**, o **reenviar (replay)** el mensaje.
4. En el panel de **Bob**: pulsa **"Verificar / Descifrar"** y observa si el
   resultado es **ACEPTADO** o **RECHAZADO**, con la explicación.
5. El panel inferior muestra el **informe técnico completo** de cada
   operación (entradas, componentes, propiedad, recursos, condiciones de uso).
6. El botón **"⚠ Escenario separado: FUGA de llave secreta/privada"** simula,
   de forma explícita y con diálogo de confirmación, que una llave se filtró
   por una causa externa al protocolo. Esto **nunca ocurre automáticamente**
   en ningún otro botón ni mecanismo.
7. Menú **Sesión → "Correr las 9 demostraciones de ataque"** abre una ventana
   con el resultado de los nueve escenarios de la tabla de la práctica.

**Modo consola / evidencia (sin pantalla, útil para generar el reporte):**
```bash
python3 demo_cli.py > reporte_evidencias.txt
```
Corre los 14 mecanismos (operación correcta + verificación) y las 9
demostraciones de ataque (incluido el ataque de diccionario), e imprime el
informe técnico completo de cada uno.

**Pruebas automatizadas** (recorren la GUI real bajo un framebuffer virtual,
sin necesidad de un humano haciendo clic):
```bash
sudo apt install xvfb      # si no lo tienes
xvfb-run -a python3 tests/test_gui_headless.py
xvfb-run -a python3 tests/test_gui_rejection.py
```

## 5. Ataque de diccionario y herramientas de la industria

`attacks/demos.py` implementa un ataque de diccionario **propio, en Python**
(auditable y autocontenido) contra: (a) un hash SHA-256 directo de una
contraseña, y (b) comparado contra una derivación Scrypt de la misma
contraseña, para medir el efecto de los parámetros de costo.

Para explorar el mismo tipo de ataque con herramientas estándar de la
industria (más rápidas y con más reglas de mutación de palabras), el
proyecto es compatible con:

- **[Hashcat](https://hashcat.net/hashcat/)** — para atacar la huella SHA-256
  generada por `core/hashing.py`, puedes exportarla y correr:
  ```bash
  echo "15485a525dc2b7b498110d10da6dad0dcac0fa3c6428f43a26512b8ba433df6a" > hash.txt
  hashcat -m 1400 -a 0 hash.txt diccionario.txt   # -m 1400 = SHA-256 "pelado"
  ```
- **[John the Ripper](https://www.openwall.com/john/)** — alternativa similar,
  particularmente útil para comparar el costo de atacar PBKDF2/Scrypt
  (formatos `pbkdf2-hmac-sha256` y `scrypt` ya incluidos en John).

Estas herramientas **no están invocadas automáticamente por el código**
(dependencias externas al sistema, no paquetes de Python), pero el proyecto
exporta las huellas en un formato que permite usarlas directamente para
extender la demostración.

## 6. Debate: ¿qué es vulnerable y qué es confiable?

Ver el análisis completo, basado en los resultados reales de las 9
demostraciones, en [`docs/debate_confiabilidad.md`](docs/debate_confiabilidad.md).
Resumen: ningún algoritmo del laboratorio se rompió criptográficamente; lo
que sí se demostró repetidamente es que **usar el mecanismo equivocado para
la propiedad que se necesita** (p. ej. cifrar sin autenticar, o un
intercambio de llaves sin autenticar) es la causa real de cada escenario
vulnerable.

## 7. Limitaciones conocidas

- La memoria se mide con `tracemalloc`, que **solo** contabiliza objetos de
  Python; no incluye las asignaciones nativas de OpenSSL/libcrypto que hace
  el paquete `cryptography` por debajo. Los valores de memoria son una
  aproximación/cota inferior, no el consumo real total (declarado también
  en cada resultado y en `docs/tabla_mecanismos.md`).
- El diccionario de contraseñas de la demostración es intencionalmente
  pequeño (fines didácticos); con diccionarios reales (p. ej. `rockyou.txt`)
  el efecto de los parámetros de costo de Scrypt es aún más marcado.
- La PKI implementada es de un solo nivel (CA raíz → certificado de hoja),
  sin cadenas intermedias ni listas de revocación, para mantener el ejemplo
  claro.

## 8. Subir el proyecto a GitHub (para la entrega por Eminus)

```bash
cd crypto_edu_app
git init
git add .
git commit -m "Laboratorio de primitivas criptograficas - Alice, Bob y Eve"
git branch -M main
git remote add origin https://github.com/<tu-usuario>/<tu-repositorio>.git
git push -u origin main
```
Después, comparte el enlace del repositorio desde la plataforma de Eminus,
junto con este código fuente y el reporte generado por `demo_cli.py`.
