"""Prueba automatizada (sin interaccion humana) que recorre los 14 mecanismos
en la GUI real (bajo Xvfb) para detectar errores de ejecucion."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tkinter.messagebox as mb
# Evitar que las ventanas emergentes bloqueen la prueba automatizada (no hay humano para hacer click)
mb.showinfo = lambda *a, **k: print("   [messagebox.showinfo]", a[1] if len(a) > 1 else a)
mb.showerror = lambda *a, **k: (_ for _ in ()).throw(RuntimeError(a[1] if len(a) > 1 else str(a)))
mb.showwarning = lambda *a, **k: print("   [messagebox.showwarning]", a[1] if len(a) > 1 else a)
mb.askyesno = lambda *a, **k: True

from gui.app import CryptoLabApp, MECANISMOS

app = CryptoLabApp()
app.update()

errores = []
for mid, cat, label in MECANISMOS:
    try:
        app.select_mechanism(mid)
        app.update()
        app.alice_run()
        app.update()
        if not mid.startswith("kdf_"):
            app.eve_bitflip()
            app.update()
        app.bob_run()
        app.update()
        print(f"OK  [{mid:12s}] {label}  -> accepted/aceptado tras manipulacion: visible en log")
    except Exception as e:
        errores.append((mid, str(e)))
        print(f"ERROR [{mid}]: {e}")

# Tambien probamos sustitucion y replay en un mecanismo con llave publica, y la fuga explicita
app.select_mechanism("kex")
app.update()
app.alice_run()
app.update()
app.eve_substitute()
app.update()
app.bob_run()
app.update()

app.select_mechanism("block")
app.update()
app.alice_run()
app.update()
app.eve_replay()
app.update()
app.eve_leak_key()   # ahora con los dialogos simulados (askyesno=True)
app.update()
print("OK  [eve_leak_key] escenario de fuga explicita ejecutado sin error")

app.destroy()

if errores:
    print("\n=== ERRORES ENCONTRADOS ===")
    for mid, e in errores:
        print(mid, "->", e)
    sys.exit(1)
else:
    print("\nTODOS LOS MECANISMOS SE EJECUTARON SIN ERRORES.")
